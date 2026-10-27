//! The control socket: a Unix stream socket answering one request per
//! connection. The request is one line; `stats` is answered with the
//! counters as one line of JSON, anything else with an `error` object.
//!
//! ```sh
//! echo stats | socat - UNIX-CONNECT:/run/insomnia/dhcp-relay/control
//! ```

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::stats::Stats;

/// Longest request read; requests are single words.
const MAX_REQUEST: u64 = 256;
const TIMEOUT: Duration = Duration::from_secs(5);

/// Binds `path` (replacing a stale socket) and serves it forever. A
/// failure to bind is logged and the relay runs without it.
pub async fn serve(path: &Path, stats: Arc<Mutex<Stats>>) {
    let _ = std::fs::remove_file(path);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let listener = match UnixListener::bind(path) {
        Ok(listener) => listener,
        Err(e) => {
            tracing::error!("control socket {}: {e}", path.display());
            return;
        }
    };
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(handle(stream, stats.clone()));
            }
            Err(e) => {
                tracing::warn!("control socket accept: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn handle(stream: UnixStream, stats: Arc<Mutex<Stats>>) {
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read.take(MAX_REQUEST));
    let mut line = String::new();
    // The first line is the whole request: a client may keep its end
    // open after sending it.
    match tokio::time::timeout(TIMEOUT, reader.read_line(&mut line)).await {
        Ok(Ok(_)) => {}
        _ => return,
    }
    let reply = answer(&line, &stats);
    let _ = tokio::time::timeout(TIMEOUT, write.write_all(reply.as_bytes())).await;
}

/// The answer to one request line.
pub fn answer(request: &str, stats: &Mutex<Stats>) -> String {
    let body = match request.trim() {
        "stats" => match stats.lock() {
            Ok(stats) => stats.to_json(),
            Err(_) => serde_json::json!({"error": "statistics unavailable"}),
        },
        other => serde_json::json!({"error": format!("unknown request {other:?}")}),
    };
    format!("{body}\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::Family;

    #[test]
    fn answers() {
        let stats = Mutex::new(Stats::default());
        stats
            .lock()
            .unwrap()
            .entry(Family::V4, "default", "eth1")
            .received += 1;
        let reply = answer("stats\n", &stats);
        let json: serde_json::Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(json["dhcp4"][0]["received"], 1);
        assert!(reply.ends_with('\n'));
        let reply = answer("reboot", &stats);
        assert!(reply.contains("error"), "{reply}");
    }

    #[tokio::test]
    async fn serves_stats() {
        let dir = std::env::temp_dir().join(format!("dhcp-relay-control-{}", std::process::id()));
        let path = dir.join("control");
        let stats = Arc::new(Mutex::new(Stats::default()));
        let server = tokio::spawn({
            let path = path.clone();
            let stats = stats.clone();
            async move { serve(&path, stats).await }
        });
        let mut stream = loop {
            match UnixStream::connect(&path).await {
                Ok(stream) => break stream,
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        };
        stream.write_all(b"stats\n").await.unwrap();
        let mut reply = String::new();
        stream.read_to_string(&mut reply).await.unwrap();
        assert!(reply.starts_with("{\"dhcp4\":[]"), "{reply}");
        server.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
