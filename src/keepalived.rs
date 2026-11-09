//! keepalived process control.
//!
//! One keepalived *instance* per VRF lives under
//! `--keepalived-dir/<vrf>/` (`default` for the global routing table):
//! the rendered `keepalived.conf`, the parent/child pid files and the
//! dump files keepalived writes on request (steered there through
//! `TMPDIR`, which keepalived honours). `default` serves the top of the
//! `vrrp` tree, and each `vrrp vrf <name>` entry its own instance
//! (design/vrrp.md §13). A VRF instance's unit is bound
//! to its VRF by the pinned socket program its template names
//! (`BPFProgram=`, design/process.md §4), which `process::reload` makes
//! sure of before the unit starts; the instance is registered as
//! `keepalived@<vrf>` for `show process`.
//!
//! keepalived stays a separately supervised process (a package upgrade
//! restarts insomnia, and killing the VRRP master for that would force
//! a failover). insomnia writes the file and asks for a reload — via
//! `systemctl` on the template unit, or by `SIGHUP` to the pid file for
//! hosts without systemd and for the BDD namespaces (`process.rs`). An
//! empty config stops the unit in systemd mode; in signal mode it is
//! reloaded, which makes keepalived withdraw every instance and idle.
//!
//! `show vrrp` reads keepalived's JSON dump: send the JSON signal
//! (`keepalived --signum=JSON`, SIGRTMIN+2 on this build), wait for
//! `keepalived.json` in the instance directory, parse, delete.

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;

use crate::process::{self, Managed, Registry, live_pid, signal, write_if_changed};
pub use crate::process::{Applied, Control};

/// Per-daemon keepalived settings, shared by every instance.
#[derive(Clone)]
pub struct Keepalived {
    pub dir: PathBuf,
    pub control: Control,
    /// Template unit (`name@.service`); a unit without `@.` is used as
    /// is for every instance.
    pub unit: String,
    /// Signal that makes keepalived write its JSON dump.
    pub json_signal: i32,
    pub registry: Arc<Registry>,
}

/// Every path of one instance.
#[derive(Clone, Debug)]
pub struct InstancePaths {
    pub dir: PathBuf,
    pub conf: PathBuf,
    /// Parent pid file (`--pid`). keepalived's child pid files
    /// (`--vrrp_pid`, `--checkers_pid`) live next to it too, named by
    /// the unit / node script; insomnia never reads them.
    pub pid: PathBuf,
    pub json: PathBuf,
}

/// Why [`collect_json`] returned nothing — the messages match VyOS's
/// `VRRPNoData` texts.
#[derive(Debug)]
pub enum CollectError {
    NotRunning,
    Timeout,
    Other(anyhow::Error),
}

impl fmt::Display for CollectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CollectError::NotRunning => write!(
                f,
                "VRRP data is not available (process not running or no active groups)"
            ),
            CollectError::Timeout => {
                write!(f, "VRRP data is not available (wait time exceeded)")
            }
            CollectError::Other(err) => write!(f, "VRRP data is not available ({err:#})"),
        }
    }
}

/// `keepalived --signum=JSON` is asked at startup; this is what the
/// 2.x builds answer when the probe cannot run.
fn default_json_signal() -> i32 {
    libc::SIGRTMIN() + 2
}

impl Keepalived {
    pub fn new(dir: PathBuf, control: Control, unit: String, registry: Arc<Registry>) -> Self {
        Self {
            dir,
            control,
            unit,
            json_signal: default_json_signal(),
            registry,
        }
    }

    /// Ask the installed keepalived for its JSON signal and check that
    /// it was built with JSON support. Missing keepalived or missing
    /// JSON only warn: configuration is still rendered, and a later
    /// install picks it up on the next commit.
    pub async fn probe(mut self) -> Self {
        match tokio::process::Command::new("keepalived")
            .arg("--version")
            .output()
            .await
        {
            Ok(output) => {
                // keepalived prints the banner on stderr.
                let text = format!(
                    "{}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                let json = text
                    .lines()
                    .find(|l| l.starts_with("Config options:"))
                    .map(|l| l.split_whitespace().any(|w| w == "JSON"));
                match json {
                    Some(true) => {}
                    Some(false) => tracing::warn!(
                        "vrrp: keepalived was built without JSON support; show vrrp will have no data"
                    ),
                    None => tracing::debug!(
                        "vrrp: keepalived --version banner has no config options line"
                    ),
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                tracing::warn!(
                    "vrrp: keepalived not installed; VRRP configuration will be rendered but not loaded"
                );
                return self;
            }
            Err(err) => tracing::warn!("vrrp: keepalived --version failed: {err}"),
        }
        if let Ok(output) = tokio::process::Command::new("keepalived")
            .arg("--signum=JSON")
            .output()
            .await
            && let Ok(num) = String::from_utf8_lossy(&output.stdout)
                .trim()
                .parse::<i32>()
        {
            self.json_signal = num;
        }
        self
    }

    pub fn instance(&self, name: &str) -> InstancePaths {
        let dir = self.dir.join(name);
        InstancePaths {
            conf: dir.join("keepalived.conf"),
            pid: dir.join("keepalived.pid"),
            json: dir.join("keepalived.json"),
            dir,
        }
    }

    /// `insomnia-keepalived@.service` + `default` →
    /// `insomnia-keepalived@default.service`.
    pub fn unit_for(&self, name: &str) -> String {
        match self.unit.find("@.") {
            Some(i) => format!("{}@{}.{}", &self.unit[..i], name, &self.unit[i + 2..]),
            None => self.unit.clone(),
        }
    }

    /// The registry name of instance `name`: `keepalived@red`.
    pub fn process_name(name: &str) -> String {
        format!("keepalived@{name}")
    }
}

/// Put `conf` in place for instance `name` and get keepalived to load
/// it. An empty `conf` means "no configuration": stop the unit in
/// systemd mode, reload to an idle daemon in signal mode.
pub async fn apply(ka: &Keepalived, name: &str, conf: &str) -> anyhow::Result<Applied> {
    let paths = ka.instance(name);
    tokio::fs::create_dir_all(&paths.dir)
        .await
        .with_context(|| format!("create {}", paths.dir.display()))?;
    // The config can hold an authentication password: owner-only.
    let changed = write_if_changed(&paths.conf, conf, 0o600).await?;
    let unit = ka.unit_for(name);
    let process = Keepalived::process_name(name);
    let managed = Managed {
        name: &process,
        vrf: Some(name),
        control: ka.control,
        unit: &unit,
        pid_file: &paths.pid,
    };
    process::reload(&ka.registry, &managed, changed, conf.is_empty()).await
}

/// keepalived's JSON dump for instance `name`: one object per VRRP
/// instance, `{ "data": {…}, "stats": {…} }` (json_version 1).
pub async fn collect_json(
    ka: &Keepalived,
    name: &str,
) -> Result<Vec<serde_json::Value>, CollectError> {
    let paths = ka.instance(name);
    let Some(pid) = live_pid(&paths.pid).await else {
        return Err(CollectError::NotRunning);
    };
    let _ = tokio::fs::remove_file(&paths.json).await;
    signal(pid, ka.json_signal).map_err(|e| CollectError::Other(e.into()))?;

    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Ok(bytes) = tokio::fs::read(&paths.json).await
            && !bytes.is_empty()
            && let Ok(value) = serde_json::from_slice::<Vec<serde_json::Value>>(&bytes)
        {
            let _ = tokio::fs::remove_file(&paths.json).await;
            return Ok(value);
        }
        if Instant::now() >= deadline {
            let _ = tokio::fs::remove_file(&paths.json).await;
            return Err(CollectError::Timeout);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn registry() -> Arc<Registry> {
        let (_tx, rx) = tokio::sync::watch::channel(Arc::new(crate::links::Snapshot::default()));
        let holds = std::env::temp_dir().join(format!("insomnia-ka-holds-{}", std::process::id()));
        Arc::new(Registry::new(holds, None, rx))
    }

    fn ka(dir: &Path, control: Control) -> Keepalived {
        Keepalived::new(
            dir.to_path_buf(),
            control,
            "insomnia-keepalived@.service".to_string(),
            registry(),
        )
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "insomnia-keepalived-test-{}-{tag}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn unit_naming() {
        let ka = ka(Path::new("/run/insomnia/vrrp"), Control::Systemd);
        assert_eq!(
            ka.unit_for("default"),
            "insomnia-keepalived@default.service"
        );
        assert_eq!(ka.unit_for("red"), "insomnia-keepalived@red.service");
        assert_eq!(Keepalived::process_name("red"), "keepalived@red");
        let plain = Keepalived::new(
            PathBuf::from("/x"),
            Control::Systemd,
            "keepalived.service".to_string(),
            registry(),
        );
        assert_eq!(plain.unit_for("default"), "keepalived.service");

        let paths = ka.instance("red");
        assert_eq!(paths.dir, Path::new("/run/insomnia/vrrp/red"));
        assert_eq!(
            paths.conf,
            Path::new("/run/insomnia/vrrp/red/keepalived.conf")
        );
        assert_eq!(
            paths.json,
            Path::new("/run/insomnia/vrrp/red/keepalived.json")
        );
    }

    /// Signal mode with no daemon: the files land, unchanged content
    /// is detected, and nothing is signalled.
    #[tokio::test]
    async fn apply_writes_files_and_detects_unchanged() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch("apply");
        let ka = ka(&dir, Control::Signal);
        let conf = "global_defs {\n    dynamic_interfaces\n}\n";

        assert_eq!(
            apply(&ka, "default", conf).await.unwrap(),
            Applied::NotRunning
        );
        let paths = ka.instance("default");
        assert_eq!(std::fs::read_to_string(&paths.conf).unwrap(), conf);
        assert_eq!(
            std::fs::metadata(&paths.conf).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(!paths.conf.with_extension("zebra-tmp").exists());

        // A stale pid file naming a dead process is "not running".
        std::fs::write(&paths.pid, "999999999\n").unwrap();
        assert_eq!(
            apply(&ka, "default", conf).await.unwrap(),
            Applied::NotRunning
        );
        std::fs::remove_file(&paths.pid).unwrap();

        // Our own pid is alive: unchanged content is not signalled
        // (a SIGHUP to ourselves would be fatal for the test).
        std::fs::write(&paths.pid, format!("{}\n", std::process::id())).unwrap();
        assert_eq!(
            apply(&ka, "default", conf).await.unwrap(),
            Applied::Unchanged
        );

        // Every instance is registered for `show process`.
        assert_eq!(apply(&ka, "red", "").await.unwrap(), Applied::NotRunning);
        let names: Vec<String> = ka.registry.entries().into_iter().map(|e| e.name).collect();
        assert_eq!(names, ["keepalived@default", "keepalived@red"]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn collect_reports_not_running_without_pid() {
        let dir = scratch("collect");
        let ka = ka(&dir, Control::Signal);
        std::fs::create_dir_all(ka.instance("default").dir).unwrap();
        let err = collect_json(&ka, "default").await.unwrap_err();
        assert!(matches!(err, CollectError::NotRunning));
        assert_eq!(
            err.to_string(),
            "VRRP data is not available (process not running or no active groups)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
