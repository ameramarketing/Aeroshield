//! GPS tracking module.
//!
//! Connects asynchronously to a local `gpsd` daemon on localhost:2947
//! and parses JSON data messages (specifically TPV - Time-Position-Velocity)
//! to maintain live GPS coordinates.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use serde::Deserialize;

lazy_static::lazy_static! {
    static ref CURRENT_GPS: Mutex<Option<(f64, f64)>> = Mutex::new(None);
}

#[derive(Deserialize, Debug)]
struct GpsResponse {
    class: String,
    lat: Option<f64>,
    lon: Option<f64>,
}

/// Retrieve the current GPS coordinates (latitude, longitude) if available.
pub fn get_current_coordinates() -> Option<(f64, f64)> {
    *CURRENT_GPS.lock().unwrap()
}

/// Start a background thread that connects to gpsd and listens for coordinates.
pub fn start_gps_thread() {
    thread::spawn(|| {
        log::info!("Starting GPS logging thread...");
        loop {
            match TcpStream::connect("127.0.0.1:2947") {
                Ok(mut stream) => {
                    log::info!("Successfully connected to gpsd at localhost:2947");
                    // Send command to watch JSON data
                    if let Err(e) = stream.write_all(b"?WATCH={\"enable\":true,\"json\":true};\n") {
                        log::error!("Failed to write initialization to gpsd: {e}");
                        thread::sleep(Duration::from_secs(5));
                        continue;
                    }

                    let reader = BufReader::new(stream);
                    for line in reader.lines() {
                        let line = match line {
                            Ok(l) => l,
                            Err(e) => {
                                log::error!("Error reading line from gpsd: {e}");
                                break;
                            }
                        };

                        if let Ok(response) = serde_json::from_str::<GpsResponse>(&line) {
                            if response.class == "TPV" {
                                if let (Some(lat), Some(lon)) = (response.lat, response.lon) {
                                    let mut gps = CURRENT_GPS.lock().unwrap();
                                    *gps = Some((lat, lon));
                                }
                            }
                        }
                    }
                }
                Err(_) => {
                    // Fail silently/log debug warning to avoid crashing if gpsd is offline
                    log::debug!("gpsd not running on localhost:2947, retrying in 10s...");
                }
            }
            thread::sleep(Duration::from_secs(10));
        }
    });
}
