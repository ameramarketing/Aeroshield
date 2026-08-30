//! WPS Auditing module.
//!
//! Handles auditing WPS-enabled access points using `reaver` and `pixiewps`.

use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::io::{BufRead, BufReader};

lazy_static::lazy_static! {
    pub static ref WPS_STATE: Mutex<WpsStatus> = Mutex::new(WpsStatus::new());
    static ref WPS_CHILD: Mutex<Option<Child>> = Mutex::new(None);
}

#[derive(Clone, Debug)]
pub struct WpsStatus {
    pub status: String,
    pub progress: String,
    pub logs: Vec<String>,
    pub pin: Option<String>,
    pub psk: Option<String>,
}

impl WpsStatus {
    fn new() -> Self {
        Self {
            status: "IDLE".to_string(),
            progress: "0%".to_string(),
            logs: Vec::new(),
            pin: None,
            psk: None,
        }
    }
}

/// Check if required WPS auditing dependencies exist (reaver)
pub fn check_dependencies() -> Vec<String> {
    let mut missing = Vec::new();
    if which::which("reaver").is_err() {
        missing.push("reaver".to_string());
    }
    missing
}

/// Start a WPS PIN audit against a target BSSID using Reaver
pub fn start_audit(
    interface: &str,
    bssid: &str,
    channel: &str,
    pixie_dust: bool,
) -> Result<(), String> {
    // 1. Ensure any previous process is stopped
    let _ = stop_audit();

    // 2. Check dependencies
    let missing = check_dependencies();
    if !missing.is_empty() {
        return Err(format!("Missing dependencies: {}", missing.join(", ")));
    }

    // 3. Prepare arguments
    let mut args = vec![
        "-i".to_string(),
        interface.to_string(),
        "-b".to_string(),
        bssid.to_string(),
        "-c".to_string(),
        channel.to_string(),
        "-vv".to_string(),
    ];

    if pixie_dust {
        args.push("-K".to_string()); // Enable Pixie Dust
    }

    log::info!("Starting reaver with arguments: {:?}", args);

    // 4. Spawn reaver process
    let mut child = Command::new("reaver")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Failed to spawn reaver: {e}"))?;

    let stdout = child.stdout.take().ok_or_else(|| "Failed to capture reaver stdout".to_string())?;

    // 5. Store child globally
    *WPS_CHILD.lock().unwrap() = Some(child);

    // 6. Reset global status state
    {
        let mut state = WPS_STATE.lock().unwrap();
        state.status = "RUNNING".to_string();
        state.progress = "0%".to_string();
        state.logs.clear();
        state.pin = None;
        state.psk = None;
    }

    // 7. Spawn stdout parser thread
    thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };

            log::debug!("reaver: {}", line);

            let mut state = WPS_STATE.lock().unwrap();
            
            // Log rotation
            state.logs.push(line.clone());
            if state.logs.len() > 100 {
                state.logs.remove(0);
            }

            // Parse progress percentage
            if line.contains("complete") {
                if let Some(pos) = line.find("%") {
                    let start = line[..pos].rfind(' ').map(|i| i + 1).unwrap_or(0);
                    let pct = line[start..=pos].trim();
                    state.progress = pct.to_string();
                }
            }

            // Parse PIN
            if line.contains("WPS PIN:") {
                if let Some(pos) = line.find("'") {
                    let end = line[pos + 1..].find("'").map(|i| pos + 1 + i).unwrap_or(line.len());
                    let pin = line[pos + 1..end].trim().to_string();
                    state.pin = Some(pin);
                }
            }

            // Parse WPA PSK
            if line.contains("WPA PSK:") {
                if let Some(pos) = line.find("'") {
                    let end = line[pos + 1..].find("'").map(|i| pos + 1 + i).unwrap_or(line.len());
                    let psk = line[pos + 1..end].trim().to_string();
                    state.psk = Some(psk);
                }
            }

            // Parse Success
            if line.contains("PIN cracked") {
                state.status = "SUCCESS".to_string();
            }
        }

        // Child processing finished
        let mut child_lock = WPS_CHILD.lock().unwrap();
        if let Some(mut child) = child_lock.take() {
            let _ = child.kill();
            let exit_status = child.wait();
            log::info!("reaver process exited with status: {:?}", exit_status);
        }

        // Finalize status
        let mut state = WPS_STATE.lock().unwrap();
        if state.status == "RUNNING" {
            state.status = "FAILED".to_string();
        }
    });

    Ok(())
}

/// Stop the running WPS PIN audit
pub fn stop_audit() -> Result<(), String> {
    let mut child_lock = WPS_CHILD.lock().unwrap();
    if let Some(mut child) = child_lock.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let mut state = WPS_STATE.lock().unwrap();
    if state.status == "RUNNING" {
        state.status = "STOPPED".to_string();
    }
    Ok(())
}
