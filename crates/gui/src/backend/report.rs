use super::{get_aps, get_unlinked_clients};
use aeroshield_common::types::{AP, Client};

use serde::Serialize;
use std::fs::File;
use std::io::Write;

#[derive(Debug, Serialize)]
struct Report {
    pub access_points: Vec<AP>,
    pub unlinked_clients: Vec<Client>,
}

#[derive(thiserror::Error, Debug)]
pub enum CapError {
    #[error("Input/Output error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Json error: {0}")]
    JsonError(#[from] serde_json::Error),
}

/// Save a report of the current scan snapshot. Exports to HTML if the path ends
/// with `.html` or `.htm`, to KML if it ends with `.kml`, and falls back to JSON otherwise.
pub fn save_report(path: &str) -> Result<(), CapError> {
    let access_points = get_aps().values().cloned().collect::<Vec<AP>>();
    let unlinked_clients = get_unlinked_clients()
        .values()
        .cloned()
        .collect::<Vec<Client>>();

    let report = Report {
        access_points,
        unlinked_clients,
    };

    let mut file = File::create(path)?;

    if path.ends_with(".kml") {
        let kml_content = generate_kml_report(&report);
        file.write_all(kml_content.as_bytes())?;
    } else if path.ends_with(".html") || path.ends_with(".htm") {
        let html_content = generate_html_report(&report);
        file.write_all(html_content.as_bytes())?;
    } else {
        let json_data = serde_json::to_string::<Report>(&report)?;
        file.write_all(json_data.as_bytes())?;
    }

    log::info!("report saved to '{path}'");

    Ok(())
}

fn generate_kml_report(report: &Report) -> String {
    let mut kml = String::new();
    kml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    kml.push_str("<kml xmlns=\"http://www.opengis.net/kml/2.2\">\n");
    kml.push_str("  <Document>\n");
    kml.push_str("    <name>AeroShield WiFi Audit Map</name>\n");
    kml.push_str("    <description>Wireless security audit snapshot containing geographical coordinates of access points.</description>\n");
    kml.push_str("    <Style id=\"ap_style\">\n");
    kml.push_str("      <IconStyle>\n");
    kml.push_str("        <scale>1.1</scale>\n");
    kml.push_str("        <Icon>\n");
    kml.push_str("          <href>http://maps.google.com/mapfiles/kml/shapes/wifi.png</href>\n");
    kml.push_str("        </Icon>\n");
    kml.push_str("      </IconStyle>\n");
    kml.push_str("    </Style>\n");

    for ap in &report.access_points {
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

fn generate_html_report(report: &Report) -> String {
    let mut html = String::new();
    html.push_str("<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n<title>AeroShield Wireless Security Audit Report</title>\n");
    html.push_str("<style>\n");
    html.push_str("body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 20px; background-color: #f5f7fb; }\n");
    html.push_str("h1, h2 { color: #1e293b; }\n");
    html.push_str(".card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); margin-bottom: 20px; }\n");
    html.push_str(".stats { display: flex; gap: 20px; margin-bottom: 20px; }\n");
    html.push_str(".stat-card { flex: 1; background: #e2e8f0; padding: 15px; border-radius: 6px; text-align: center; }\n");
    html.push_str(".stat-card.vulnerable { background: #fee2e2; color: #991b1b; }\n");
    html.push_str(".stat-val { font-size: 24px; font-weight: bold; margin-top: 5px; }\n");
    html.push_str("table { width: 100%; border-collapse: collapse; margin-top: 10px; }\n");
    html.push_str("th, td { padding: 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }\n");
    html.push_str("th { background-color: #f8fafc; color: #475569; font-weight: 600; }\n");
    html.push_str("tr:hover { background-color: #f1f5f9; }\n");
    html.push_str(".badge { display: inline-block; padding: 3px 8px; font-size: 12px; font-weight: 600; border-radius: 9999px; }\n");
    html.push_str(".badge.success { background-color: #d1fae5; color: #065f46; }\n");
    html.push_str(".badge.danger { background-color: #fee2e2; color: #991b1b; }\n");
    html.push_str("</style>\n</head>\n<body>\n");
    
    html.push_str("<h1>🛡️ AeroShield Security Audit Report</h1>\n");
    html.push_str("<p>Generated by AeroShield Wireless Auditing Utility. Security audit snapshot for nearby wireless networks.</p>\n");
    
    let total_aps = report.access_points.len();
    let captured_handshakes = report.access_points.iter().filter(|ap| ap.handshake).count();
    let hidden_aps = report.access_points.iter().filter(|ap| ap.hidden).count();
    
    html.push_str("<div class=\"stats\">\n");
    html.push_str(&format!("<div class=\"stat-card\"><div class=\"stat-title\">Total Access Points Discovered</div><div class=\"stat-val\">{}</div></div>\n", total_aps));
    html.push_str(&format!("<div class=\"stat-card vulnerable\"><div class=\"stat-title\">Captured Handshakes/PMKIDs</div><div class=\"stat-val\">{}</div></div>\n", captured_handshakes));
    html.push_str(&format!("<div class=\"stat-card\"><div class=\"stat-title\">Hidden SSIDs</div><div class=\"stat-val\">{}</div></div>\n", hidden_aps));
    html.push_str("</div>\n");
    
    html.push_str("<div class=\"card\">\n<h2>Discovered Access Points</h2>\n");
    if total_aps == 0 {
        html.push_str("<p>No access points discovered in this session.</p>\n");
    } else {
        html.push_str("<table>\n<thead>\n<tr><th>ESSID</th><th>BSSID</th><th>Channel</th><th>Privacy</th><th>Signal (Power)</th><th>GPS Coordinates</th><th>Handshake/PMKID Captured</th></tr>\n</thead>\n<tbody>\n");
        for ap in &report.access_points {
            let hs_badge = if ap.handshake {
                "<span class=\"badge success\">Yes (Ready to Decrypt)</span>"
            } else {
                "<span class=\"badge danger\">No</span>"
            };
            let essid = if ap.hidden { "<i>&lt;hidden&gt;</i>" } else { &ap.essid };
            let gps_coord = match (ap.latitude, ap.longitude) {
                (Some(lat), Some(lon)) => format!("{:.5}, {:.5}", lat, lon),
                _ => "N/A".to_string(),
            };
            html.push_str(&format!(
                "<tr><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{} dBm</td><td>{}</td><td>{}</td></tr>\n",
                essid, ap.bssid, ap.channel, ap.privacy, ap.power, gps_coord, hs_badge
            ));
        }
        html.push_str("</tbody>\n</table>\n");
    }
    html.push_str("</div>\n");
    
    html.push_str("<div class=\"card\">\n<h2>Unlinked Clients</h2>\n");
    if report.unlinked_clients.is_empty() {
        html.push_str("<p>No unlinked clients discovered in this session.</p>\n");
    } else {
        html.push_str("<table>\n<thead>\n<tr><th>MAC Address</th><th>Packets</th><th>Power</th><th>Vendor</th></tr>\n</thead>\n<tbody>\n");
        for client in &report.unlinked_clients {
            html.push_str(&format!(
                "<tr><td><code>{}</code></td><td>{}</td><td>{} dBm</td><td>{}</td></tr>\n",
                client.mac, client.packets, client.power, client.vendor
            ));
        }
        html.push_str("</tbody>\n</table>\n");
    }
    html.push_str("</div>\n");
    
    html.push_str("</body>\n</html>\n");
    html
}
