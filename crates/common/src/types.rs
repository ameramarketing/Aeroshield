// Copyright (c) 2023-2024 Martin Olivier <martin.olivier@live.fr>
//
//! Wire types shared across the IPC boundary.
//!
//! Everything here derives `Serialize`/`Deserialize` so it can travel over the
//! agent socket. Types that hold live process handles (e.g. the agent's
//! `Child` processes) deliberately do *not* live here — they stay internal to
//! the agent and are projected onto the serializable [`AttackState`] for the
//! wire.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// How the MAC address of an interface should be set when entering monitor mode.
///
/// Resolved GUI-side from the user's [`Settings::mac_address`] and passed to the
/// agent as an explicit request parameter, so the agent never has to read the
/// user's configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MacMode {
    /// Randomize the MAC address (`macchanger -A`).
    Random,
    /// Restore the permanent hardware MAC (`macchanger -p`).
    Default,
    /// Set a specific MAC address (`macchanger -m <mac>`).
    Specific(String),
}

/// Serializable view of which clients of an AP are currently under attack.
///
/// The agent keeps the actual `Child` handles internally; this is the shape the
/// GUI receives so it can paint the affected rows.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AttackTarget {
    /// A broadcast deauth against every client (`FF:FF:FF:FF:FF:FF`).
    All,
    /// A deauth targeting the listed client MAC addresses.
    Selection(Vec<String>),
}

/// A single ongoing deauth attack, as reported to the GUI.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttackState {
    pub ap: AP,
    pub target: AttackTarget,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AP {
    pub essid: String,
    pub bssid: String,
    pub band: String,
    pub channel: String,
    pub power: String,
    pub privacy: String,
    pub hidden: bool,
    pub handshake: bool,
    pub pmkid: bool,
    /// Path of a capture file the *GUI* saved this handshake to. This is GUI-side
    /// overlay state: the agent always leaves it `None` and the GUI fills it in
    /// from its own bookkeeping before display.
    pub saved_handshake: Option<String>,
    pub first_time_seen: String,
    pub last_time_seen: String,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub clients: HashMap<String, Client>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Client {
    pub mac: String,
    pub packets: String,
    pub power: String,
    pub first_time_seen: String,
    pub last_time_seen: String,
    pub vendor: String,
    pub probes: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Settings {
    pub mac_address: String,
    pub display_hidden_ap: bool,
    pub kill_network_manager: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            mac_address: "random".to_string(),
            display_hidden_ap: true,
            kill_network_manager: true,
        }
    }
}

impl Settings {
    /// Resolve the configured MAC preference into a wire [`MacMode`].
    pub fn mac_mode(&self) -> MacMode {
        match self.mac_address.as_str() {
            "random" => MacMode::Random,
            "default" => MacMode::Default,
            mac => MacMode::Specific(mac.to_string()),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditSession {
    pub id: String,
    pub name: String,
    pub status: SessionStatus,
    pub metadata: SessionMetadata,
    pub scope: AssessmentScope,
    pub observations: SessionObservations,
    pub evidence: Vec<SessionEvidence>,
    pub findings: Vec<Finding>,
    pub timeline: Vec<TimelineEvent>,
}

impl Default for AuditSession {
    fn default() -> Self {
        Self {
            id: uuid_v4_placeholder(),
            name: "New Security Assessment".to_string(),
            status: SessionStatus::New,
            metadata: SessionMetadata {
                start_time: chrono_now_placeholder(),
                end_time: None,
            },
            scope: AssessmentScope {
                interface: "None".to_string(),
                target_bssids: Vec::new(),
                target_ssids: Vec::new(),
                operator_notes: String::new(),
                environment: "Authorized Lab Scope".to_string(),
            },
            observations: SessionObservations {
                access_points: HashMap::new(),
                clients: HashMap::new(),
            },
            evidence: Vec::new(),
            findings: Vec::new(),
            timeline: vec![TimelineEvent {
                timestamp: chrono_now_placeholder(),
                event_type: "Lifecycle".to_string(),
                description: "Assessment session initialized.".to_string(),
            }],
        }
    }
}

fn uuid_v4_placeholder() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let start = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    format!("{:x}", start)
}

fn chrono_now_placeholder() -> String {
    // Standard format: YYYY-MM-DD HH:MM:SS
    // Note: Since types.rs is shared and we want to keep it light without adding chrono dependency if possible,
    // we can use standard system time or include chrono. Let's check: types.rs doesn't import chrono but gui/agent do.
    // Actually, we can use a helper or pass it, or just use standard formatting. Let's see: types.rs is in common which doesn't use chrono.
    // Wait, let's check common's Cargo.toml to see if it has chrono. No, common doesn't have chrono in Cargo.toml.
    // Let's format it using std::time:
    let now = std::time::SystemTime::now();
    let seconds = now.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    // Simple conversion placeholder (the GUI can overwrite/update timestamps with chrono)
    format!("UNIX:{}", seconds)
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionStatus {
    New,
    Active,
    Paused,
    Completed,
    Archived,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionMetadata {
    pub start_time: String,
    pub end_time: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssessmentScope {
    pub interface: String,
    pub target_bssids: Vec<String>,
    pub target_ssids: Vec<String>,
    pub operator_notes: String,
    pub environment: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionObservations {
    pub access_points: HashMap<String, AP>,
    pub clients: HashMap<String, Client>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionEvidence {
    pub id: String,
    pub evidence_type: EvidenceType,
    pub target_bssid: String,
    pub target_essid: String,
    pub timestamp: String,
    pub file_path: Option<String>,
    pub details: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum EvidenceType {
    Handshake,
    Pmkid,
    WpsPinResponse,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub category: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub affected_target: String,
    pub evidence_ids: Vec<String>,
    pub timestamp: String,
    pub remediation: String,
    pub references: Vec<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: String,
    pub event_type: String,
    pub description: String,
}
