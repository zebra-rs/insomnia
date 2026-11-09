//! insomnia-dhcp-relay process control.
//!
//! The DHCP relay agent is a separate, unprivileged process
//! (design/dhcp.md §10.1): it parses packets from every client on
//! every listen interface, so it runs sandboxed under its own systemd
//! unit rather than inside the root insomnia daemon. insomnia renders
//! `relay.json` into `--dhcp-relay-dir` and gets the agent to load it
//! (`process.rs`): `systemctl` on `insomnia-dhcp-relay.service`, or
//! `SIGHUP` to `relay.pid` in that directory for hosts without systemd
//! and for the BDD namespaces. An empty config stops the unit in
//! systemd mode; in signal mode the agent reloads it and closes every
//! socket.
//!
//! `show dhcp relay statistics` asks the agent's control socket, which
//! answers `stats` with its counters as JSON.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::process::{self, Applied, Control, Managed, Registry};

/// How long a statistics query may take.
const STATS_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone)]
pub struct Relayd {
    /// Holds `relay.json`, and `relay.pid` in signal mode.
    pub dir: PathBuf,
    pub control: Control,
    pub unit: String,
    /// The agent's control socket.
    pub socket: PathBuf,
    pub registry: Arc<Registry>,
}

/// The agent's name in `show process`: one process for every VRF.
pub const PROCESS_NAME: &str = "dhcp-relay";

impl Relayd {
    pub fn conf(&self) -> PathBuf {
        self.dir.join("relay.json")
    }

    pub fn pid(&self) -> PathBuf {
        self.dir.join("relay.pid")
    }

    /// Put `conf` in place and get the agent to load it; `empty` says
    /// it configures nothing.
    pub async fn apply(&self, conf: &str, empty: bool) -> anyhow::Result<Applied> {
        tokio::fs::create_dir_all(&self.dir)
            .await
            .with_context(|| format!("create {}", self.dir.display()))?;
        // No secrets, and the agent runs as an unprivileged dynamic
        // user: world-readable.
        let changed = process::write_if_changed(&self.conf(), conf, 0o644).await?;
        let pid = self.pid();
        let managed = Managed {
            name: PROCESS_NAME,
            // It binds its own sockets in every VRF: no VRF binding.
            vrf: None,
            control: self.control,
            unit: &self.unit,
            pid_file: &pid,
        };
        process::reload(&self.registry, &managed, changed, empty).await
    }

    /// The agent's counters: `{"dhcp4": [rows], "dhcp6": [rows]}`.
    pub async fn stats(&self) -> anyhow::Result<serde_json::Value> {
        let query = async {
            let mut stream = tokio::net::UnixStream::connect(&self.socket)
                .await
                .with_context(|| format!("connect {}", self.socket.display()))?;
            stream.write_all(b"stats\n").await?;
            let mut reply = String::new();
            stream.read_to_string(&mut reply).await?;
            let value: serde_json::Value =
                serde_json::from_str(&reply).context("unreadable reply")?;
            if let Some(err) = value.get("error") {
                anyhow::bail!("{err}");
            }
            Ok(value)
        };
        tokio::time::timeout(STATS_TIMEOUT, query)
            .await
            .unwrap_or_else(|_| Err(anyhow::anyhow!("no answer within 3 s")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("insomnia-relayd-test-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn relayd(dir: &std::path::Path) -> Relayd {
        Relayd {
            dir: dir.to_path_buf(),
            control: Control::Signal,
            unit: "insomnia-dhcp-relay.service".to_string(),
            socket: dir.join("control"),
            registry: {
                let (_tx, rx) =
                    tokio::sync::watch::channel(Arc::new(crate::links::Snapshot::default()));
                Arc::new(Registry::new(dir.join("holds"), None, rx))
            },
        }
    }

    /// Signal mode with no agent: the file lands world-readable,
    /// unchanged content is detected, and nothing is signalled.
    #[tokio::test]
    async fn apply_writes_the_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch("apply");
        let r = relayd(&dir);
        let conf = "{\"dhcp4\": [], \"dhcp6\": []}\n";
        assert_eq!(r.apply(conf, true).await.unwrap(), Applied::NotRunning);
        assert_eq!(std::fs::read_to_string(r.conf()).unwrap(), conf);
        let mode = std::fs::metadata(r.conf()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o644);

        // A live pid that is us: changed content signals, unchanged
        // does not. SIGHUP would end the test process, so only the
        // unchanged path is exercised with a real pid.
        std::fs::write(r.pid(), format!("{}\n", std::process::id())).unwrap();
        assert_eq!(r.apply(conf, true).await.unwrap(), Applied::Unchanged);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A small stand-in for the agent's control socket.
    #[tokio::test]
    async fn stats_reads_the_control_socket() {
        let dir = scratch("stats");
        std::fs::create_dir_all(&dir).unwrap();
        let r = relayd(&dir);
        assert!(r.stats().await.is_err(), "no socket yet");

        let listener = tokio::net::UnixListener::bind(&r.socket).unwrap();
        let server = tokio::spawn(async move {
            for reply in [
                "{\"dhcp4\":[{\"vrf\":\"default\",\"interface\":\"eth1\",\"received\":2}],\"dhcp6\":[]}\n",
                "{\"error\":\"unknown request\"}\n",
            ] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 16];
                let _ = stream.read(&mut buf).await.unwrap();
                stream.write_all(reply.as_bytes()).await.unwrap();
            }
        });
        let value = r.stats().await.unwrap();
        assert_eq!(value["dhcp4"][0]["received"], 2);
        assert!(r.stats().await.is_err(), "an error object is an error");
        server.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
