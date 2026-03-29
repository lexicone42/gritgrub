//! Live event stream — watch repository activity in real-time.
//!
//! `forge watch` connects to the local repo's event log and displays
//! events as they happen. For remote servers, it polls the event log
//! endpoint. Useful for humans supervising agent activity.

use anyhow::Result;
use gritgrub_store::Repository;

pub fn run(from_seq: Option<u64>) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;

    let mut seq = from_seq.unwrap_or_else(|| {
        repo.latest_event_seq().unwrap_or(0)
    });

    eprintln!("Watching events from seq {} (Ctrl+C to stop)", seq);
    eprintln!();

    loop {
        match repo.read_events(seq + 1, 50) {
            Ok(events) if !events.is_empty() => {
                for (event_seq, data) in events {
                    seq = event_seq;
                    let text = String::from_utf8_lossy(&data);

                    // Try to parse as JSON for pretty printing.
                    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
                        let kind = value.get("kind")
                            .and_then(|v| v.as_str())
                            .unwrap_or("event");
                        let detail = value.get("detail")
                            .or_else(|| value.get("message"))
                            .or_else(|| value.get("ref"))
                            .map(|v| v.to_string())
                            .unwrap_or_default();

                        let now = chrono_lite_now();
                        println!("\x1b[2m{}\x1b[0m \x1b[33m#{}\x1b[0m \x1b[1m{}\x1b[0m {}",
                            now, event_seq, kind, detail);
                    } else {
                        println!("\x1b[33m#{}\x1b[0m {}", event_seq, text);
                    }
                }
            }
            _ => {
                // No new events — sleep briefly.
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        }
    }
}

/// Simple timestamp without pulling in chrono.
fn chrono_lite_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let secs = now % 60;
    let mins = (now / 60) % 60;
    let hours = (now / 3600) % 24;
    format!("{:02}:{:02}:{:02}", hours, mins, secs)
}
