//! The Kea instances insomnia drives: one `kea-dhcp4` and one
//! `kea-dhcp6` per VRF (design/dhcp.md §8).
//!
//! Layout, per instance (`<vrf>` is `default` for the global table):
//! - `<dir>/<vrf>/kea-dhcp{4,6}.conf`: the rendered configuration, the
//!   file Kea is started with and re-reads on `config-reload`;
//! - `<dir>/<vrf>/kea{4,6}-ctrl-socket`: Kea's control socket, the only
//!   way insomnia talks to it (no control agent, never TCP);
//! - `<state-dir>/<vrf>/kea-leases{4,6}.csv`: the memfile lease
//!   database, and the DHCPv6 server DUID beside it.
//!
//! Applying a render (design/dhcp.md §8.2):
//! 1. nothing to serve: `systemctl stop` the instance (systemd mode); in
//!    socket mode the instance is loaded with the idle render instead,
//!    which listens nowhere;
//! 2. the render equals the file in place and Kea answers: nothing to
//!    do (the file is only ever written after Kea accepted it);
//! 3. Kea answers: `config-test` with the render inline; when Kea
//!    accepts it, write the file and `config-reload`, which keeps the
//!    leases. When Kea refuses it, the file and Kea's running
//!    configuration stay as they were, and the refusal is returned;
//! 4. Kea does not answer: write the file; in systemd mode check it
//!    with `kea-dhcp{4,6} -t` and `systemctl start` the instance. In
//!    socket mode there is nobody to start it.
//!
//! A configuration change therefore never restarts Kea: VyOS restarts
//! it on every commit, which drops the packets that arrive meanwhile
//! and lets a configuration Kea rejects take the service down.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::process;

/// How insomnia gets a Kea instance to run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Control {
    /// Start and stop the `insomnia-kea-dhcp{4,6}@<vrf>` template units.
    Systemd,
    /// Only talk to an instance somebody else started on the instance's
    /// config file and control socket (containers, the BDD harness).
    Socket,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub fn digit(self) -> u8 {
        match self {
            Family::V4 => 4,
            Family::V6 => 6,
        }
    }

    /// `kea-dhcp4` / `kea-dhcp6`: the daemon, and its logger name.
    pub fn daemon(self) -> &'static str {
        match self {
            Family::V4 => "kea-dhcp4",
            Family::V6 => "kea-dhcp6",
        }
    }

    /// `Dhcp4` / `Dhcp6`: the configuration's top-level key.
    pub fn root(self) -> &'static str {
        match self {
            Family::V4 => "Dhcp4",
            Family::V6 => "Dhcp6",
        }
    }

    /// `dhcp-server` / `dhcpv6-server`: the config tree, for messages.
    pub fn tree(self) -> &'static str {
        match self {
            Family::V4 => "dhcp-server",
            Family::V6 => "dhcpv6-server",
        }
    }
}

/// What [`Kea::apply`] did.
#[derive(Debug, PartialEq, Eq)]
pub enum Applied {
    /// `config-reload` with the new file.
    Loaded,
    /// The instance was started on the new file (systemd mode).
    Started,
    /// The file in place is the render, and Kea is running it.
    Unchanged,
    /// Nothing to serve: the instance was stopped (systemd mode).
    Stopped,
    /// The file is in place but no Kea answered to load it (socket
    /// mode).
    NotRunning,
    /// Kea refused the render; it keeps running its previous
    /// configuration. Kea's own message.
    Rejected(String),
}

/// Paths and control of every instance.
#[derive(Debug)]
pub struct Kea {
    pub dir: PathBuf,
    pub state_dir: PathBuf,
    pub control: Control,
    /// Template units; `@.` becomes `@<vrf>.`.
    pub unit4: String,
    pub unit6: String,
    /// Kea's hook libraries (lease_cmds, stat_cmds, run_script).
    pub hooks_dir: PathBuf,
    /// The program Kea's `run_script` hook runs for DHCPv6 lease events
    /// (design/dhcp.md §7.5).
    pub notify: PathBuf,
}

/// Kea answers within milliseconds; a reload re-opens sockets and the
/// lease file, so leave room.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

/// The group Kea runs as on Debian and Ubuntu; it owns the instance
/// directory and may read the config file.
const KEA_GROUP: &str = "_kea";

impl Kea {
    pub fn instance_dir(&self, vrf: &str) -> PathBuf {
        self.dir.join(vrf)
    }

    pub fn conf(&self, family: Family, vrf: &str) -> PathBuf {
        self.instance_dir(vrf)
            .join(format!("{}.conf", family.daemon()))
    }

    pub fn socket(&self, family: Family, vrf: &str) -> PathBuf {
        self.instance_dir(vrf)
            .join(format!("kea{}-ctrl-socket", family.digit()))
    }

    /// The memfile lease database, and (DHCPv6) the server DUID's data
    /// directory.
    pub fn data_dir(&self, vrf: &str) -> PathBuf {
        self.state_dir.join(vrf)
    }

    pub fn lease_file(&self, family: Family, vrf: &str) -> PathBuf {
        self.data_dir(vrf)
            .join(format!("kea-leases{}.csv", family.digit()))
    }

    /// The link to `kea-notify` the instance's `run_script` hook runs;
    /// kea-notify finds the `events` socket beside it.
    pub fn notify_link(&self, vrf: &str) -> PathBuf {
        self.instance_dir(vrf).join("kea-notify")
    }

    /// The `events` socket of the instance, after making sure its
    /// directory and the `kea-notify` link exist.
    pub async fn prepare_events(&self, vrf: &str) -> anyhow::Result<PathBuf> {
        self.prepare(vrf).await?;
        let link = self.notify_link(vrf);
        if std::fs::read_link(&link).ok().as_deref() != Some(self.notify.as_path()) {
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(&self.notify, &link)
                .with_context(|| format!("link {} to {}", link.display(), self.notify.display()))?;
        }
        Ok(self.instance_dir(vrf).join("events"))
    }

    pub fn unit(&self, family: Family, vrf: &str) -> String {
        let template = match family {
            Family::V4 => &self.unit4,
            Family::V6 => &self.unit6,
        };
        template.replacen("@.", &format!("@{vrf}."), 1)
    }

    /// One control-socket command. Kea answers with one JSON object and
    /// closes the connection. Errors are transport failures; Kea's own
    /// `result` is left to the caller.
    pub async fn command(
        &self,
        family: Family,
        vrf: &str,
        command: &str,
        arguments: Option<Value>,
    ) -> anyhow::Result<Value> {
        let path = self.socket(family, vrf);
        let mut request = serde_json::json!({ "command": command });
        if let Some(arguments) = arguments {
            request["arguments"] = arguments;
        }
        let exchange = async {
            let mut stream = tokio::net::UnixStream::connect(&path).await?;
            stream.write_all(request.to_string().as_bytes()).await?;
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).await?;
            anyhow::Ok(reply)
        };
        let reply = tokio::time::timeout(COMMAND_TIMEOUT, exchange)
            .await
            .with_context(|| format!("{command}: no answer on {}", path.display()))?
            .with_context(|| format!("{command} on {}", path.display()))?;
        serde_json::from_slice(&reply)
            .with_context(|| format!("{command}: malformed answer on {}", path.display()))
    }

    /// Whether an instance answers on its control socket.
    pub async fn running(&self, family: Family, vrf: &str) -> bool {
        match self.command(family, vrf, "status-get", None).await {
            Ok(reply) => result(&reply) == 0,
            Err(_) => false,
        }
    }

    /// Bring instance (`family`, `vrf`) to `text`, which serves something
    /// when `serving`. See the module doc for the sequence.
    pub async fn apply(
        &self,
        family: Family,
        vrf: &str,
        text: &str,
        serving: bool,
    ) -> anyhow::Result<Applied> {
        if !serving && self.control == Control::Systemd {
            process::systemctl("stop", &self.unit(family, vrf)).await?;
            return Ok(Applied::Stopped);
        }
        let conf = self.conf(family, vrf);
        let running = self.running(family, vrf).await;
        let current = tokio::fs::read_to_string(&conf).await.ok();
        if running && current.as_deref() == Some(text) {
            return Ok(Applied::Unchanged);
        }
        self.prepare(vrf).await?;
        if running {
            let config: Value = serde_json::from_str(text).context("render is not JSON")?;
            let reply = self
                .command(family, vrf, "config-test", Some(config))
                .await?;
            if result(&reply) != 0 {
                return Ok(Applied::Rejected(reply_text(&reply)));
            }
            write_conf(&conf, text).await?;
            let reply = self.command(family, vrf, "config-reload", None).await?;
            if result(&reply) != 0 {
                return Ok(Applied::Rejected(reply_text(&reply)));
            }
            return Ok(Applied::Loaded);
        }
        write_conf(&conf, text).await?;
        match self.control {
            Control::Socket => Ok(Applied::NotRunning),
            Control::Systemd => {
                if let Some(err) = check(family, &conf).await {
                    return Ok(Applied::Rejected(err));
                }
                process::systemctl("start", &self.unit(family, vrf)).await?;
                Ok(Applied::Started)
            }
        }
    }

    /// The instance directory: Kea creates its control socket and lock
    /// files there, so it is group-writable by Kea's group (when that
    /// group exists; the BDD harness runs Kea as root).
    async fn prepare(&self, vrf: &str) -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let dir = self.instance_dir(vrf);
        tokio::fs::create_dir_all(&dir)
            .await
            .with_context(|| format!("create {}", dir.display()))?;
        match kea_gid() {
            Some(gid) => {
                chown(&dir, gid)?;
                tokio::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o770)).await?;
            }
            None => {
                tokio::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).await?;
            }
        }
        Ok(())
    }
}

/// Kea's `result`: 0 success, 1 error, 2 unsupported command, 3 empty
/// (e.g. no leases).
pub fn result(reply: &Value) -> i64 {
    reply.get("result").and_then(Value::as_i64).unwrap_or(1)
}

pub fn reply_text(reply: &Value) -> String {
    reply
        .get("text")
        .and_then(Value::as_str)
        .unwrap_or("no reason given")
        .to_string()
}

/// The config file: readable by Kea's group, nobody else.
async fn write_conf(path: &Path, text: &str) -> anyhow::Result<()> {
    process::write_atomic(path, text, 0o640).await?;
    if let Some(gid) = kea_gid() {
        chown(path, gid)?;
    }
    Ok(())
}

/// `kea-dhcp{4,6} -t <file>`: `None` when the file passes (or there is
/// no Kea binary to ask), else Kea's error.
async fn check(family: Family, conf: &Path) -> Option<String> {
    let output = match tokio::process::Command::new(family.daemon())
        .arg("-t")
        .arg(conf)
        .output()
        .await
    {
        Ok(output) => output,
        Err(err) => {
            tracing::warn!("{}: cannot run -t: {err}", family.daemon());
            return None;
        }
    };
    if output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).into_owned()
        + &String::from_utf8_lossy(&output.stderr);
    Some(
        text.lines()
            .find_map(|l| l.split_once("Error encountered: ").map(|(_, e)| e))
            .unwrap_or(text.trim())
            .to_string(),
    )
}

fn kea_gid() -> Option<libc::gid_t> {
    let name = std::ffi::CString::new(KEA_GROUP).ok()?;
    // SAFETY: getgrnam returns a pointer into static storage or null;
    // only gr_gid is read, before any other call can overwrite it.
    let group = unsafe { libc::getgrnam(name.as_ptr()) };
    if group.is_null() {
        None
    } else {
        // SAFETY: non-null result of getgrnam, see above.
        Some(unsafe { (*group).gr_gid })
    }
}

/// Hand `path` to root and Kea's group, when that group exists.
pub fn chown_to_kea(path: &Path) -> anyhow::Result<()> {
    match kea_gid() {
        Some(gid) => chown(path, gid),
        None => Ok(()),
    }
}

/// Hand `path` to root and Kea's group. Only root can; anyone else
/// (the unit tests) keeps their own ownership.
fn chown(path: &Path, gid: libc::gid_t) -> anyhow::Result<()> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }
    std::os::unix::fs::chown(path, Some(0), Some(gid))
        .with_context(|| format!("chown root:{KEA_GROUP} {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kea() -> Kea {
        Kea {
            dir: "/run/insomnia/kea".into(),
            state_dir: "/var/lib/insomnia/kea".into(),
            control: Control::Systemd,
            unit4: "insomnia-kea-dhcp4@.service".into(),
            unit6: "insomnia-kea-dhcp6@.service".into(),
            hooks_dir: "/usr/lib/x86_64-linux-gnu/kea/hooks".into(),
            notify: "/usr/lib/insomnia/kea-notify".into(),
        }
    }

    #[test]
    fn paths_and_units() {
        let kea = kea();
        assert_eq!(
            kea.conf(Family::V4, "red"),
            Path::new("/run/insomnia/kea/red/kea-dhcp4.conf")
        );
        assert_eq!(
            kea.socket(Family::V6, "default"),
            Path::new("/run/insomnia/kea/default/kea6-ctrl-socket")
        );
        assert_eq!(
            kea.lease_file(Family::V6, "blue"),
            Path::new("/var/lib/insomnia/kea/blue/kea-leases6.csv")
        );
        assert_eq!(
            kea.unit(Family::V4, "default"),
            "insomnia-kea-dhcp4@default.service"
        );
        assert_eq!(
            kea.unit(Family::V6, "red"),
            "insomnia-kea-dhcp6@red.service"
        );
        // A 15-character VRF name stays far below sun_path's 108 bytes.
        let longest = kea.socket(Family::V4, "abcdefghijklmno");
        assert!(longest.as_os_str().len() < 60);
    }

    #[test]
    fn results() {
        let ok: Value = serde_json::from_str(r#"{ "result": 0, "text": "ok" }"#).unwrap();
        assert_eq!(result(&ok), 0);
        let refused: Value = serde_json::from_str(
            r#"{ "result": 1, "text": "Failed to select interface: interface 'nosuch0' doesn't exist in the system (<wire>:0:88) (<wire>:0:88)" }"#,
        )
        .unwrap();
        assert_eq!(result(&refused), 1);
        assert!(reply_text(&refused).starts_with("Failed to select interface"));
        assert_eq!(result(&Value::Null), 1);
    }

    /// No Kea on the socket: not running, and in socket mode the file is
    /// written and nothing else happens.
    #[tokio::test]
    async fn socket_mode_without_kea() {
        let tmp = std::env::temp_dir().join(format!("insomnia-kea-{}", std::process::id()));
        let kea = Kea {
            dir: tmp.join("run"),
            state_dir: tmp.join("lib"),
            control: Control::Socket,
            ..kea()
        };
        assert!(!kea.running(Family::V4, "default").await);
        let applied = kea
            .apply(Family::V4, "default", "{\"Dhcp4\": {}}\n", true)
            .await
            .unwrap();
        assert_eq!(applied, Applied::NotRunning);
        let written = std::fs::read_to_string(kea.conf(Family::V4, "default")).unwrap();
        assert_eq!(written, "{\"Dhcp4\": {}}\n");
        std::fs::remove_dir_all(&tmp).unwrap();
    }
}
