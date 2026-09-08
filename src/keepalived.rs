//! keepalived process control.
//!
//! One keepalived *instance* per VRF lives under
//! `--keepalived-dir/<vrf>/` (`default` for the global routing table):
//! the rendered `keepalived.conf`, the parent/child pid files, the
//! dump files keepalived writes on request (steered there through
//! `TMPDIR`, which keepalived honours), and the per-instance `env`
//! file the systemd template unit reads. The first release only ever
//! creates `default`; the per-VRF expansion (design/vrrp.md §13) adds
//! instances without changing any path.
//!
//! keepalived stays a separately supervised process (a package upgrade
//! restarts insomnia, and killing the VRRP master for that would force
//! a failover). insomnia writes the file and asks for a reload — via
//! `systemctl` on the template unit, or by `SIGHUP` to the pid file for
//! hosts without systemd and for the BDD namespaces. An empty config
//! stops the unit in systemd mode; in signal mode it is reloaded, which
//! makes keepalived withdraw every instance and idle.
//!
//! `show vrrp` reads keepalived's JSON dump: send the JSON signal
//! (`keepalived --signum=JSON`, SIGRTMIN+2 on this build), wait for
//! `keepalived.json` in the instance directory, parse, delete.

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Context;

/// How a rendered config is pushed into the running keepalived.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Control {
    /// `systemctl reload-or-restart` / `stop` on the template unit.
    Systemd,
    /// `SIGHUP` to the pid in the instance's pid file; never starts
    /// or stops a process.
    Signal,
}

/// Per-daemon keepalived settings, shared by every instance.
#[derive(Clone, Debug)]
pub struct Keepalived {
    pub dir: PathBuf,
    pub control: Control,
    /// Template unit (`name@.service`); a unit without `@.` is used as
    /// is for every instance.
    pub unit: String,
    /// `LD_PRELOAD` shim written into non-default instances' `env`.
    pub vrf_preload: PathBuf,
    /// Signal that makes keepalived write its JSON dump.
    pub json_signal: i32,
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
    pub env: PathBuf,
}

/// What [`apply`] did.
#[derive(Debug, PartialEq, Eq)]
pub enum Applied {
    /// Reloaded (or started) with the new file.
    Loaded,
    /// File identical to the one already in place; nothing reloaded.
    Unchanged,
    /// Empty config: the instance was stopped (systemd mode).
    Stopped,
    /// The file is in place but no keepalived was there to load it.
    NotRunning,
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
    pub fn new(dir: PathBuf, control: Control, unit: String, vrf_preload: PathBuf) -> Self {
        Self {
            dir,
            control,
            unit,
            vrf_preload,
            json_signal: default_json_signal(),
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
            env: dir.join("env"),
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

    /// Contents of the instance's `env` file: empty for the global
    /// table, the VRF shim for everything else.
    pub fn env_for(&self, name: &str) -> String {
        if name == "default" {
            String::new()
        } else {
            format!("LD_PRELOAD={}\nVRF={}\n", self.vrf_preload.display(), name)
        }
    }
}

async fn read_pid(path: &Path) -> Option<i32> {
    let text = tokio::fs::read_to_string(path).await.ok()?;
    text.trim().parse().ok()
}

fn alive(pid: i32) -> bool {
    pid > 0 && unsafe { libc::kill(pid, 0) } == 0
}

fn signal(pid: i32, sig: i32) -> std::io::Result<()> {
    if unsafe { libc::kill(pid, sig) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Live parent pid of an instance, if the pid file names a process
/// that still exists.
async fn live_pid(paths: &InstancePaths) -> Option<i32> {
    read_pid(&paths.pid).await.filter(|&pid| alive(pid))
}

/// Write `content` to `path` atomically (temp file in the same
/// directory, then rename) with the given mode.
async fn write_atomic(path: &Path, content: &str, mode: u32) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let tmp = path.with_extension("zebra-tmp");
    tokio::fs::write(&tmp, content)
        .await
        .with_context(|| format!("write {}", tmp.display()))?;
    tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode)).await?;
    tokio::fs::rename(&tmp, path)
        .await
        .with_context(|| format!("rename into {}", path.display()))?;
    Ok(())
}

/// Write only when the content differs, so an unchanged file keeps
/// its mtime and no reload is triggered for nothing.
async fn write_if_changed(path: &Path, content: &str, mode: u32) -> anyhow::Result<bool> {
    let current = tokio::fs::read_to_string(path).await.ok();
    if current.as_deref() == Some(content) {
        return Ok(false);
    }
    write_atomic(path, content, mode).await?;
    Ok(true)
}

async fn systemctl(verb: &str, unit: &str) -> anyhow::Result<Option<()>> {
    let output = match tokio::process::Command::new("systemctl")
        .args([verb, unit])
        .output()
        .await
    {
        Ok(output) => output,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    if !output.status.success() {
        anyhow::bail!(
            "systemctl {verb} {unit} exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(Some(()))
}

/// Put `conf` in place for instance `name` and get keepalived to load
/// it. An empty `conf` means "no configuration": stop the unit in
/// systemd mode, reload to an idle daemon in signal mode.
pub async fn apply(ka: &Keepalived, name: &str, conf: &str) -> anyhow::Result<Applied> {
    let paths = ka.instance(name);
    tokio::fs::create_dir_all(&paths.dir)
        .await
        .with_context(|| format!("create {}", paths.dir.display()))?;
    write_if_changed(&paths.env, &ka.env_for(name), 0o644).await?;
    // The config can hold an authentication password: owner-only.
    let changed = write_if_changed(&paths.conf, conf, 0o600).await?;
    let empty = conf.is_empty();

    match ka.control {
        Control::Systemd => {
            let unit = ka.unit_for(name);
            let verb = match (empty, changed) {
                (true, false) => return Ok(Applied::Unchanged),
                (true, true) => "stop",
                (false, true) => "reload-or-restart",
                // Same file, but make sure the daemon is actually up
                // (a no-op when it is).
                (false, false) => "start",
            };
            match systemctl(verb, &unit).await? {
                None => Ok(Applied::NotRunning),
                Some(()) => Ok(match (empty, changed) {
                    (true, _) => Applied::Stopped,
                    (false, true) => Applied::Loaded,
                    (false, false) => Applied::Unchanged,
                }),
            }
        }
        Control::Signal => {
            let Some(pid) = live_pid(&paths).await else {
                return Ok(Applied::NotRunning);
            };
            if !changed {
                return Ok(Applied::Unchanged);
            }
            signal(pid, libc::SIGHUP).with_context(|| format!("SIGHUP keepalived pid {pid}"))?;
            Ok(if empty {
                Applied::Stopped
            } else {
                Applied::Loaded
            })
        }
    }
}

/// keepalived's JSON dump for instance `name`: one object per VRRP
/// instance, `{ "data": {…}, "stats": {…} }` (json_version 1).
pub async fn collect_json(
    ka: &Keepalived,
    name: &str,
) -> Result<Vec<serde_json::Value>, CollectError> {
    let paths = ka.instance(name);
    let Some(pid) = live_pid(&paths).await else {
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

    fn ka(dir: &Path, control: Control) -> Keepalived {
        Keepalived::new(
            dir.to_path_buf(),
            control,
            "insomnia-keepalived@.service".to_string(),
            PathBuf::from("/usr/lib/insomnia/vrf.o"),
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
    fn unit_and_env_naming() {
        let ka = ka(Path::new("/run/insomnia/vrrp"), Control::Systemd);
        assert_eq!(
            ka.unit_for("default"),
            "insomnia-keepalived@default.service"
        );
        assert_eq!(ka.unit_for("red"), "insomnia-keepalived@red.service");
        assert_eq!(ka.env_for("default"), "");
        assert_eq!(
            ka.env_for("red"),
            "LD_PRELOAD=/usr/lib/insomnia/vrf.o\nVRF=red\n"
        );
        let plain = Keepalived::new(
            PathBuf::from("/x"),
            Control::Systemd,
            "keepalived.service".to_string(),
            PathBuf::from("/x/vrf.o"),
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
        assert_eq!(std::fs::read_to_string(&paths.env).unwrap(), "");
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

        // Non-default instances carry the VRF shim in env.
        assert_eq!(apply(&ka, "red", "").await.unwrap(), Applied::NotRunning);
        assert_eq!(
            std::fs::read_to_string(ka.instance("red").env).unwrap(),
            format!("LD_PRELOAD={}/vrf.o\nVRF=red\n", "/usr/lib/insomnia")
        );

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
