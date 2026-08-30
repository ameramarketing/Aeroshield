//! WPS Auditing module.
//!
//! Handles auditing WPS-enabled access points using `reaver` and `pixiewps`.

use std::process::{Child, Command, Stdio};

#[derive(Debug, thiserror::Error)]
pub enum WpsError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Execution failed: {0}")]
    Execution(String),
}

pub struct WpsAuditor {
    reaver_child: Option<Child>,
}

impl WpsAuditor {
    pub fn new() -> Self {
        Self { reaver_child: None }
    }

    /// Start a WPS PIN audit against a target BSSID using Reaver
    pub fn start_audit(
        &mut self,
        interface: &str,
        bssid: &str,
        channel: &str,
        pixie_dust: bool,
    ) -> Result<(), WpsError> {
        let mut args = vec![
            "-i", interface,
            "-b", bssid,
            "-c", channel,
            "-vv",
        ];

        if pixie_dust {
            args.push("-K"); // Enable Pixie Dust attack
        }

        let child = Command::new("reaver")
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;

        self.reaver_child = Some(child);
        Ok(())
    }

    /// Stop the running WPS PIN audit
    pub fn stop_audit(&mut self) -> Result<(), WpsError> {
        if let Some(mut child) = self.reaver_child.take() {
            child.kill()?;
            child.wait()?;
        }
        Ok(())
    }
}
