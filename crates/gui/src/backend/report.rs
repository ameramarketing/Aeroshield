use crate::globals;
use aeroshield_common::types::{AP, Client, AuditSession};

use std::fs::File;
use std::io::Write;

#[derive(thiserror::Error, Debug)]
pub enum CapError {
    #[error("Input/Output error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Json error: {0}")]
    JsonError(#[from] serde_json::Error),
}

/// Save a report of the current security assessment session.
/// Exports to HTML if the path ends with `.html` or `.htm`,
/// to KML if it ends with `.kml`, and falls back to JSON otherwise.
pub fn save_report(path: &str) -> Result<(), CapError> {
    // Clone current global session
    let mut session = globals::CURRENT_SESSION.lock().unwrap().clone();
    
    // Set end time on export/save
    let local = chrono::Local::now();
    session.metadata.end_time = Some(local.format("%Y-%m-%d %H:%M:%S").to_string());
    
    let mut file = File::create(path)?;

    if path.ends_with(".kml") {
        let kml_content = generate_kml_report(&session);
        file.write_all(kml_content.as_bytes())?;
    } else if path.ends_with(".html") || path.ends_with(".htm") {
        let html_content = generate_html_report(&session);
        file.write_all(html_content.as_bytes())?;
    } else {
        let json_data = serde_json::to_string_pretty::<AuditSession>(&session)?;
        file.write_all(json_data.as_bytes())?;
    }

    log::info!("report saved to '{path}'");

    Ok(())
}

fn generate_kml_report(session: &AuditSession) -> String {
    let mut kml = String::new();
    kml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    kml.push_str("<kml xmlns=\"http://www.opengis.net/kml/2.2\">\n");
    kml.push_str("  <Document>\n");
    kml.push_str(&format!("    <name>AeroShield Audit Map - {}</name>\n", session.name));
    kml.push_str("    <description>Wireless security assessment geographic observations.</description>\n");
    kml.push_str("    <Style id=\"ap_style\">\n");
    kml.push_str("      <IconStyle>\n");
    kml.push_str("        <scale>1.1</scale>\n");
    kml.push_str("        <Icon>\n");
    kml.push_str("          <href>http://maps.google.com/mapfiles/kml/shapes/wifi.png</href>\n");
    kml.push_str("        </Icon>\n");
    kml.push_str("      </IconStyle>\n");
    kml.push_str("    </Style>\n");

    for ap in session.observations.access_points.values() {
        if let (Some(lat), Some(lon)) = (ap.latitude, ap.longitude) {
            let essid = if ap.hidden { "<hidden>" } else { &ap.essid };
            kml.push_str("    <Placemark>\n");
            kml.push_str(&format!("      <name>{} ({})</name>\n", essid, ap.bssid));
            kml.push_str(&format!(
                "      <description><![CDATA[Channel: {}<br/>Privacy: {}<br/>Power: {} dBm<br/>Clients: {}]]></description>\n",
                ap.channel, ap.privacy, ap.power, ap.clients.len()
            ));
            kml.push_str("      <styleUrl>#ap_style</styleUrl>\n");
            kml.push_str("      <Point>\n");
            kml.push_str(&format!("        <coordinates>{},{},0</coordinates>\n", lon, lat));
            kml.push_str("      </Point>\n");
            kml.push_str("    </Placemark>\n");
        }
    }

    kml.push_str("  </Document>\n");
    kml.push_str("</kml>\n");
    kml
}

fn generate_html_report(session: &AuditSession) -> String {
    let mut html = String::new();
    html.push_str("<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n");
    html.push_str(&format!("<title>AeroShield Security Assessment Report - {}</title>\n", session.name));
    html.push_str("<style>\n");
    html.push_str("body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 20px; background-color: #f5f7fb; }\n");
    html.push_str("h1, h2, h3 { color: #0f172a; }\n");
    html.push_str(".card { background: white; padding: 25px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); margin-bottom: 25px; }\n");
    html.push_str(".stats { display: flex; gap: 20px; margin-bottom: 25px; }\n");
    html.push_str(".stat-card { flex: 1; background: white; border-top: 4px solid #cbd5e1; padding: 15px; border-radius: 6px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.03); }\n");
    html.push_str(".stat-card.high { border-top-color: #ef4444; color: #991b1b; }\n");
    html.push_str(".stat-card.med { border-top-color: #f97316; color: #c2410c; }\n");
    html.push_str(".stat-card.low { border-top-color: #22c55e; color: #15803d; }\n");
    html.push_str(".stat-val { font-size: 28px; font-weight: bold; margin-top: 5px; }\n");
    html.push_str(".metadata-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; margin-bottom: 15px; }\n");
    html.push_str(".metadata-item { font-size: 14px; color: #475569; }\n");
    html.push_str(".metadata-label { font-weight: bold; color: #1e293b; }\n");
    html.push_str("table { width: 100%; border-collapse: collapse; margin-top: 15px; }\n");
    html.push_str("th, td { padding: 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }\n");
    html.push_str("th { background-color: #f8fafc; color: #475569; font-weight: 600; }\n");
    html.push_str("tr:hover { background-color: #f1f5f9; }\n");
    html.push_str(".badge { display: inline-block; padding: 3px 8px; font-size: 11px; font-weight: 600; border-radius: 9999px; text-transform: uppercase; }\n");
    html.push_str(".badge.critical { background-color: #fecaca; color: #991b1b; }\n");
    html.push_str(".badge.high { background-color: #ffedd5; color: #c2410c; }\n");
    html.push_str(".badge.medium { background-color: #fef9c3; color: #854d0e; }\n");
    html.push_str(".badge.low { background-color: #dcfce7; color: #166534; }\n");
    html.push_str(".badge.info { background-color: #e0f2fe; color: #075985; }\n");
    html.push_str(".finding-item { padding: 15px; border-left: 4px solid #cbd5e1; background-color: #f8fafc; margin-bottom: 15px; border-radius: 0 6px 6px 0; }\n");
    html.push_str(".finding-item.critical { border-left-color: #ef4444; }\n");
    html.push_str(".finding-item.high { border-left-color: #f97316; }\n");
    html.push_str(".finding-item.medium { border-left-color: #eab308; }\n");
    html.push_str(".finding-item.low { border-left-color: #22c55e; }\n");
    html.push_str(".remediation { margin-top: 8px; padding: 8px 12px; background-color: #ecfdf5; border-radius: 4px; border: 1px solid #a7f3d0; font-size: 13px; }\n");
    html.push_str("</style>\n</head>\n<body>\n");

    html.push_str("<h1>🛡️ AeroShield Security Assessment Report</h1>\n");
    html.push_str("<p>Confidential wireless vulnerability audit and posture assessment.</p>\n");

    // 1. Session Metadata
    html.push_str("<div class=\"card\">\n<h2>Assessment Session Context</h2>\n");
    html.push_str("<div class=\"metadata-grid\">\n");
    html.push_str(&format!("<div class=\"metadata-item\"><span class=\"metadata-label\">Session Name:</span> {}</div>\n", session.name));
    html.push_str(&format!("<div class=\"metadata-item\"><span class=\"metadata-label\">Lifecycle Status:</span> {:?}</div>\n", session.status));
    html.push_str(&format!("<div class=\"metadata-item\"><span class=\"metadata-label\">Start Time:</span> {}</div>\n", session.metadata.start_time));
    html.push_str(&format!("<div class=\"metadata-item\"><span class=\"metadata-label\">End Time:</span> {}</div>\n", session.metadata.end_time.as_deref().unwrap_or("Active Session")));
    html.push_str(&format!("<div class=\"metadata-item\"><span class=\"metadata-label\">Interface Used:</span> {}</div>\n", session.scope.interface));
    html.push_str(&format!("<div class=\"metadata-item\"><span class=\"metadata-label\">Environment:</span> {}</div>\n", session.scope.environment));
    html.push_str("</div>\n");
    html.push_str(&format!("<div><span class=\"metadata-label\">Operator Scope/Assessment Notes:</span><br/><p style=\"white-space: pre-wrap; background: #f8fafc; padding: 10px; border-radius: 4px;\">{}</p></div>\n", session.scope.operator_notes));
    html.push_str("</div>\n");

    // Risk Calculations
    let mut high = 0;
    let mut med = 0;
    let mut low = 0;
    for ap in session.observations.access_points.values() {
        let privacy = ap.privacy.to_uppercase();
        if privacy.contains("WEP") || privacy.contains("OPN") {
            high += 1;
        } else if privacy.contains("WPA3") {
            low += 1;
        } else {
            med += 1;
        }
    }

    // 2. Risk Cards
    html.push_str("<div class=\"stats\">\n");
    html.push_str(&format!("<div class=\"stat-card high\"><div class=\"stat-title\">High Risk Targets</div><div class=\"stat-val\">{}</div></div>\n", high));
    html.push_str(&format!("<div class=\"stat-card med\"><div class=\"stat-title\">Medium Risk Targets</div><div class=\"stat-val\">{}</div></div>\n", med));
    html.push_str(&format!("<div class=\"stat-card low\"><div class=\"stat-title\">Low Risk Targets</div><div class=\"stat-val\">{}</div></div>\n", low));
    html.push_str("</div>\n");

    // 3. Security Findings
    html.push_str("<div class=\"card\">\n<h2>Verified Security Findings</h2>\n");
    if session.findings.is_empty() {
        html.push_str("<p>No security findings verified in this session scope.</p>\n");
    } else {
        for f in &session.findings {
            let severity_class = format!("{:?}", f.severity).to_lowercase();
            html.push_str(&format!("<div class=\"finding-item {}\">\n", severity_class));
            html.push_str(&format!("<h3><span class=\"badge {}\">{:?}</span> {}</h3>\n", severity_class, f.severity, f.title));
            html.push_str(&format!("<p style=\"font-size: 14px;\"><strong>Affected Target:</strong> <code>{}</code> | <strong>Category:</strong> {}</p>\n", f.affected_target, f.category));
            html.push_str(&format!("<p>{}</p>\n", f.description));
            html.push_str(&format!("<div class=\"remediation\"><strong>Suggested Remediation:</strong> {}</div>\n", f.remediation));
            html.push_str("</div>\n");
        }
    }
    html.push_str("</div>\n");

    // 4. Collected Evidence
    html.push_str("<div class=\"card\">\n<h2>Captured Assessment Evidence</h2>\n");
    if session.evidence.is_empty() {
        html.push_str("<p>No cryptographic or access point evidence collected.</p>\n");
    } else {
        html.push_str("<table>\n<thead>\n<tr><th>Type</th><th>Target BSSID</th><th>Timestamp</th><th>Evidence Details</th></tr>\n</thead>\n<tbody>\n");
        for ev in &session.evidence {
            html.push_str(&format!(
                "<tr><td><span class=\"badge info\">{:?}</span></td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>\n",
                ev.evidence_type, ev.target_bssid, ev.timestamp, ev.details
            ));
        }
        html.push_str("</tbody>\n</table>\n");
    }
    html.push_str("</div>\n");

    // 5. General Inventory Observations
    html.push_str("<div class=\"card\">\n<h2>Discovered Wireless Observations</h2>\n");
    if session.observations.access_points.is_empty() {
        html.push_str("<p>No wireless networks observed.</p>\n");
    } else {
        html.push_str("<table>\n<thead>\n<tr><th>ESSID</th><th>BSSID</th><th>Channel</th><th>Encryption</th><th>Power</th><th>GPS Location</th></tr>\n</thead>\n<tbody>\n");
        for ap in session.observations.access_points.values() {
            let essid = if ap.hidden { "<i>&lt;hidden&gt;</i>" } else { &ap.essid };
            let gps_coord = match (ap.latitude, ap.longitude) {
                (Some(lat), Some(lon)) => format!("{:.5}, {:.5}", lat, lon),
                _ => "N/A".to_string(),
            };
            html.push_str(&format!(
                "<tr><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{} dBm</td><td>{}</td></tr>\n",
                essid, ap.bssid, ap.channel, ap.privacy, ap.power, gps_coord
            ));
        }
        html.push_str("</tbody>\n</table>\n");
    }
    html.push_str("</div>\n");

    // 6. Assessment Timeline
    html.push_str("<div class=\"card\">\n<h2>Assessment Timeline Logs</h2>\n");
    html.push_str("<table>\n<thead>\n<tr><th style=\"width: 150px;\">Timestamp</th><th style=\"width: 120px;\">Event Type</th><th>Description</th></tr>\n</thead>\n<tbody>\n");
    for t in &session.timeline {
        html.push_str(&format!(
            "<tr><td><code>{}</code></td><td><strong>{}</strong></td><td>{}</td></tr>\n",
            t.timestamp, t.event_type, t.description
        ));
    }
    html.push_str("</tbody>\n</table>\n");
    html.push_str("</div>\n");

    html.push_str("</body>\n</html>\n");
    html
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use aeroshield_common::types::{AP, AuditSession};

    #[test]
    fn test_kml_generation() {
        let ap = AP {
            essid: "TestNet".to_string(),
            bssid: "00:11:22:33:44:55".to_string(),
            band: "2.4 GHz".to_string(),
            channel: "6".to_string(),
            power: "-50".to_string(),
            privacy: "WPA2".to_string(),
            hidden: false,
            handshake: false,
            pmkid: false,
            saved_handshake: None,
            first_time_seen: "2026-08-30 14:00:00".to_string(),
            last_time_seen: "2026-08-30 14:05:00".to_string(),
            latitude: Some(37.7749),
            longitude: Some(-122.4194),
            clients: HashMap::new(),
        };

        let mut session = AuditSession::default();
        session.observations.access_points.insert(ap.bssid.clone(), ap);

        let kml = generate_kml_report(&session);
        assert!(kml.contains("<kml"));
        assert!(kml.contains("TestNet"));
        assert!(kml.contains("-122.4194,37.7749,0"));
    }

    #[test]
    fn test_html_generation() {
        let ap = AP {
            essid: "TestNet".to_string(),
            bssid: "00:11:22:33:44:55".to_string(),
            band: "2.4 GHz".to_string(),
            channel: "6".to_string(),
            power: "-50".to_string(),
            privacy: "WPA2".to_string(),
            hidden: false,
            handshake: false,
            pmkid: false,
            saved_handshake: None,
            first_time_seen: "2026-08-30 14:00:00".to_string(),
            last_time_seen: "2026-08-30 14:05:00".to_string(),
            latitude: Some(37.7749),
            longitude: Some(-122.4194),
            clients: HashMap::new(),
        };

        let mut session = AuditSession::default();
        session.observations.access_points.insert(ap.bssid.clone(), ap);

        let html = generate_html_report(&session);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("AeroShield Security Assessment Report"));
        assert!(html.contains("TestNet"));
    }
}
