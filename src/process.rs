//! The daemons insomnia renders configuration for and keeps running
//! beside it (design/process.md): keepalived (`keepalived.rs`), the
//! DHCP relay agent (`relayd.rs`) and Kea (`kea.rs`).
//!
//! Each stays a separately supervised process, so an insomnia restart
//! (a package upgrade) does not interrupt it. insomnia writes the file
//! and asks for a reload: through `systemctl` on the daemon's unit, or
//! by `SIGHUP` to its pid file for hosts without systemd and for the
//! BDD namespaces. An empty config stops the unit in systemd mode; in
//! signal mode the daemon is reloaded and idles.
//!
//! The [`Registry`] holds every instance under a stable name, which is
//! the unit's instance name: `keepalived@red`, `kea-dhcp4@default`,
//! `dhcp-relay`. It answers `show process` and carries out
//! `start|stop|restart process` (design/process.md §6):
//! - `stop process` is an operator *hold*, a file in the holds
//!   directory (`/run/insomnia/holds/<name>`): commits still render the
//!   instance's file but never start or reload it, and it survives an
//!   insomnia restart (not a reboot). The configuration's `disable`
//!   leaves stay the persistent switch;
//! - before a per-VRF unit starts, [`Registry::bind`] makes sure its
//!   VRF's socket program is pinned (`vrf.rs`);
//! - in signal mode the processes belong to whoever started them (the
//!   BDD harness), so `show process` reads their pid files and the
//!   actions are refused.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::Context;
use serde_json::json;
use tokio::sync::{mpsc, watch};

use crate::api::ShowRequest;
use crate::links::Snapshot;
use crate::text::{seconds_to_human, table};
use crate::vrf::{self, Pins};

/// How a rendered config is pushed into the running daemon.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Control {
    /// `systemctl reload-or-restart` / `stop` on the unit.
    Systemd,
    /// `SIGHUP` to the pid in the daemon's pid file; never starts or
    /// stops a process.
    Signal,
}

/// What [`reload`] did.
#[derive(Debug, PartialEq, Eq)]
pub enum Applied {
    /// Reloaded (or started) with the new file.
    Loaded,
    /// File identical to the one already in place; nothing reloaded.
    Unchanged,
    /// Empty config: the daemon was stopped (systemd mode).
    Stopped,
    /// The file is in place but no daemon was there to load it.
    NotRunning,
    /// Stopped by an operator (`stop process`): the file is in place,
    /// the daemon stays down until `start process`.
    Held,
}

pub async fn read_pid(path: &Path) -> Option<i32> {
    let text = tokio::fs::read_to_string(path).await.ok()?;
    text.trim().parse().ok()
}

pub fn alive(pid: i32) -> bool {
    pid > 0 && unsafe { libc::kill(pid, 0) } == 0
}

pub fn signal(pid: i32, sig: i32) -> std::io::Result<()> {
    if unsafe { libc::kill(pid, sig) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// The pid in `path`, if it names a process that still exists.
pub async fn live_pid(path: &Path) -> Option<i32> {
    read_pid(path).await.filter(|&pid| alive(pid))
}

/// Write `content` to `path` atomically (temp file in the same
/// directory, then rename) with the given mode.
pub async fn write_atomic(path: &Path, content: &str, mode: u32) -> anyhow::Result<()> {
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
pub async fn write_if_changed(path: &Path, content: &str, mode: u32) -> anyhow::Result<bool> {
    let current = tokio::fs::read_to_string(path).await.ok();
    if current.as_deref() == Some(content) {
        return Ok(false);
    }
    write_atomic(path, content, mode).await?;
    Ok(true)
}

/// `systemctl <verb> <unit>`; `None` when there is no systemctl.
pub async fn systemctl(verb: &str, unit: &str) -> anyhow::Result<Option<()>> {
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

/// One instance a backend manages, as [`reload`] and the registry see
/// it.
pub struct Managed<'a> {
    /// The registry name: `keepalived@red`, `dhcp-relay`.
    pub name: &'a str,
    /// The VRF of a per-VRF template instance, bound through its pinned
    /// socket program before the unit starts; `None` for a daemon that
    /// binds its own sockets per VRF (the relay agent).
    pub vrf: Option<&'a str>,
    pub control: Control,
    pub unit: &'a str,
    pub pid_file: &'a Path,
}

impl Managed<'_> {
    fn runner(&self) -> Runner {
        match self.control {
            Control::Systemd => Runner::Unit(self.unit.to_string()),
            Control::Signal => Runner::External(self.pid_file.to_path_buf()),
        }
    }
}

/// Get the daemon to load a config file the caller has just put in
/// place: `changed` says whether the file is new, `empty` whether it
/// configures nothing. The instance is (re)registered with `reg`, and
/// an operator hold keeps it stopped.
pub async fn reload(
    reg: &Registry,
    m: &Managed<'_>,
    changed: bool,
    empty: bool,
) -> anyhow::Result<Applied> {
    reg.register(m.name, m.vrf, m.runner(), !empty);
    let result = reload_unit(reg, m, changed, empty).await;
    reg.note(m.name, result.as_ref().err().map(|e| format!("{e:#}")));
    result
}

async fn reload_unit(
    reg: &Registry,
    m: &Managed<'_>,
    changed: bool,
    empty: bool,
) -> anyhow::Result<Applied> {
    match m.control {
        Control::Systemd => {
            if reg.held(m.name) {
                // Also after an insomnia restart or a package upgrade
                // that restarted the unit: a hold keeps it down.
                systemctl("stop", m.unit).await?;
                return Ok(Applied::Held);
            }
            if !empty && let Some(vrf) = m.vrf {
                reg.bind(vrf)?;
            }
            reload_systemd(m.unit, changed, empty).await
        }
        Control::Signal => {
            let Some(pid) = live_pid(m.pid_file).await else {
                return Ok(Applied::NotRunning);
            };
            if !changed {
                return Ok(Applied::Unchanged);
            }
            signal(pid, libc::SIGHUP).with_context(|| format!("SIGHUP pid {pid}"))?;
            Ok(if empty {
                Applied::Stopped
            } else {
                Applied::Loaded
            })
        }
    }
}

async fn reload_systemd(unit: &str, changed: bool, empty: bool) -> anyhow::Result<Applied> {
    let verb = match (empty, changed) {
        // Even when nothing changed: a package upgrade restarts
        // every unit the package ships, and stopping a stopped
        // unit is a no-op.
        (true, _) => "stop",
        (false, true) => "reload-or-restart",
        // Same file, but make sure the daemon is actually up
        // (a no-op when it is).
        (false, false) => "start",
    };
    let ran = systemctl(verb, unit).await?;
    Ok(match (ran, empty, changed) {
        (_, true, false) => Applied::Unchanged,
        (None, true, true) => Applied::Stopped,
        (None, false, _) => Applied::NotRunning,
        (Some(()), true, _) => Applied::Stopped,
        (Some(()), false, true) => Applied::Loaded,
        (Some(()), false, false) => Applied::Unchanged,
    })
}

// ---------------------------------------------------------------
// The process registry (design/process.md §5–§7)
// ---------------------------------------------------------------

/// How an instance runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Runner {
    /// A systemd unit insomnia starts, reloads and stops.
    Unit(String),
    /// Started by somebody else (signal and socket modes: the BDD
    /// harness); observed through its pid file, never controlled.
    External(PathBuf),
}

/// One registered instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub vrf: Option<String>,
    pub runner: Runner,
    /// The last render wants it running.
    pub wanted: bool,
    /// The last apply's failure.
    pub error: Option<String>,
}

/// What `show process` reports about a running (or not) instance.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Observed {
    /// `running`, `stopped`, `failed`, `starting`, `stopping`, …
    pub state: String,
    pub pid: Option<u32>,
    pub uptime: Option<u64>,
    pub restarts: Option<u32>,
}

/// Every instance insomnia manages, its holds and its VRF pins.
#[derive(Debug)]
pub struct Registry {
    entries: Mutex<BTreeMap<String, Entry>>,
    /// One empty file per held instance.
    holds: PathBuf,
    /// VRF socket programs; `None` when nothing runs under systemd.
    pins: Option<Pins>,
    links: watch::Receiver<Arc<Snapshot>>,
}

const NOT_SUPPORTED: &str =
    "% Not supported in signal mode: the process is managed outside insomnia\n";

impl Registry {
    pub fn new(
        holds: PathBuf,
        pins: Option<Pins>,
        links: watch::Receiver<Arc<Snapshot>>,
    ) -> Registry {
        Registry {
            entries: Mutex::new(BTreeMap::new()),
            holds,
            pins,
            links,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Entry>> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Add or update an instance; its last error is kept.
    pub fn register(&self, name: &str, vrf: Option<&str>, runner: Runner, wanted: bool) {
        let mut entries = self.lock();
        let entry = entries.entry(name.to_string()).or_insert_with(|| Entry {
            name: name.to_string(),
            vrf: None,
            runner: runner.clone(),
            wanted,
            error: None,
        });
        entry.vrf = vrf.map(str::to_string);
        entry.runner = runner;
        entry.wanted = wanted;
    }

    /// Record the outcome of the last apply.
    pub fn note(&self, name: &str, error: Option<String>) {
        if let Some(entry) = self.lock().get_mut(name) {
            entry.error = error;
        }
    }

    pub fn entries(&self) -> Vec<Entry> {
        self.lock().values().cloned().collect()
    }

    fn entry(&self, name: &str) -> Option<Entry> {
        self.lock().get(name).cloned()
    }

    fn hold_path(&self, name: &str) -> PathBuf {
        self.holds.join(name)
    }

    pub fn held(&self, name: &str) -> bool {
        self.hold_path(name).exists()
    }

    fn hold(&self, name: &str) -> anyhow::Result<()> {
        std::fs::create_dir_all(&self.holds)
            .with_context(|| format!("create {}", self.holds.display()))?;
        std::fs::write(self.hold_path(name), "")
            .with_context(|| format!("write {}", self.hold_path(name).display()))
    }

    fn release(&self, name: &str) -> anyhow::Result<()> {
        match std::fs::remove_file(self.hold_path(name)) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err).context("remove hold"),
        }
    }

    /// Make sure `vrf`'s socket program is pinned for its current
    /// interface index, before a unit of that VRF starts. Fails when the
    /// VRF does not exist (the unit's `AssertPathExists=` would refuse
    /// the start anyway) or the program cannot be pinned.
    pub fn bind(&self, vrf: &str) -> anyhow::Result<()> {
        let Some(pins) = &self.pins else {
            return Ok(());
        };
        let links = self.links.borrow().clone();
        let index =
            vrf::ifindex(&links, vrf).with_context(|| format!("VRF {vrf} does not exist"))?;
        if pins
            .ensure(vrf, index)
            .with_context(|| format!("pin the socket program of VRF {vrf}"))?
        {
            tracing::info!("vrf {vrf}: socket program pinned for interface index {index}");
        }
        Ok(())
    }

    fn units_of(&self, vrf: &str) -> Vec<(String, String)> {
        self.lock()
            .values()
            .filter(|e| e.vrf.as_deref() == Some(vrf))
            .filter_map(|e| match &e.runner {
                Runner::Unit(unit) => Some((e.name.clone(), unit.clone())),
                Runner::External(_) => None,
            })
            .collect()
    }

    /// The VRF is gone: stop its instances (their sockets point at a
    /// dead device).
    pub async fn stop_vrf(&self, vrf: &str) {
        for (name, unit) in self.units_of(vrf) {
            match systemctl("stop", &unit).await {
                Ok(_) => tracing::info!("{name}: stopped (VRF {vrf} deleted)"),
                Err(err) => tracing::error!("{name}: {err:#}"),
            }
        }
    }

    /// The VRF was re-created and re-pinned: restart its running
    /// instances, so they pick up the new program.
    pub async fn restart_vrf(&self, vrf: &str) {
        for (name, unit) in self.units_of(vrf) {
            if self.held(&name) {
                continue;
            }
            match systemctl("try-restart", &unit).await {
                Ok(_) => tracing::info!("{name}: restarted (VRF {vrf} re-created)"),
                Err(err) => tracing::error!("{name}: {err:#}"),
            }
        }
    }

    /// One `show|start|stop|restart process` order.
    pub async fn order(&self, path: &str, args: &[String], json: bool) -> String {
        let verb = path
            .trim_start_matches('/')
            .split('/')
            .next()
            .unwrap_or_default();
        let name = args.first().map(String::as_str);
        match (verb, name) {
            ("show", None) => self.show(None, json).await,
            ("show", Some(name)) => self.show(Some(name), json).await,
            (verb @ ("start" | "stop" | "restart"), Some(name)) => {
                match self.action(verb, name).await {
                    Ok(text) | Err(text) => text,
                }
            }
            _ => format!("% Unknown process command {path}\n"),
        }
    }

    async fn action(&self, verb: &str, name: &str) -> Result<String, String> {
        let entry = self
            .entry(name)
            .ok_or_else(|| format!("% No process \"{name}\"; see show process\n"))?;
        let Runner::Unit(unit) = &entry.runner else {
            return Err(NOT_SUPPORTED.to_string());
        };
        let fail = |e: anyhow::Error| format!("% {name}: {e:#}\n");
        match verb {
            "stop" => {
                if self.held(name) {
                    return Ok(format!("{name} is already stopped by an operator\n"));
                }
                self.hold(name).map_err(fail)?;
                systemctl("stop", unit).await.map_err(fail)?;
                tracing::info!("{name}: stopped by an operator (stop process)");
                Ok(format!(
                    "Stopped {name}; it stays stopped until start process {name}\n"
                ))
            }
            "start" => {
                let was_held = self.held(name);
                self.release(name).map_err(fail)?;
                if !entry.wanted {
                    return Err(format!("% Nothing configured for \"{name}\"\n"));
                }
                if let Some(vrf) = &entry.vrf {
                    self.bind(vrf).map_err(fail)?;
                }
                systemctl("start", unit).await.map_err(fail)?;
                if was_held {
                    tracing::info!("{name}: started by an operator (start process)");
                }
                Ok(format!("Started {name}\n"))
            }
            _ => {
                if self.held(name) {
                    return Err(format!(
                        "% \"{name}\" was stopped by an operator; use start process\n"
                    ));
                }
                if !entry.wanted {
                    return Err(format!("% Nothing configured for \"{name}\"\n"));
                }
                if let Some(vrf) = &entry.vrf {
                    self.bind(vrf).map_err(fail)?;
                }
                systemctl("restart", unit).await.map_err(fail)?;
                tracing::info!("{name}: restarted by an operator (restart process)");
                Ok(format!("Restarted {name}\n"))
            }
        }
    }

    fn admin(&self, entry: &Entry) -> &'static str {
        if self.held(&entry.name) {
            "held"
        } else if entry.wanted {
            "up"
        } else {
            "down"
        }
    }

    async fn show(&self, name: Option<&str>, json: bool) -> String {
        let entries: Vec<Entry> = match name {
            Some(name) => match self.entry(name) {
                Some(entry) => vec![entry],
                None => return format!("% No process \"{name}\"; see show process\n"),
            },
            None => self.entries(),
        };
        let mut rows = Vec::new();
        let mut list = Vec::new();
        for entry in &entries {
            let seen = observe(&entry.runner).await;
            let admin = self.admin(entry);
            if json {
                list.push(json!({
                    "name": entry.name,
                    "vrf": entry.vrf,
                    "state": seen.state,
                    "admin": admin,
                    "pid": seen.pid,
                    "uptime": seen.uptime,
                    "restarts": seen.restarts,
                    "error": entry.error,
                    "unit": match &entry.runner {
                        Runner::Unit(unit) => Some(unit.clone()),
                        Runner::External(_) => None,
                    },
                }));
            }
            rows.push(vec![
                entry.name.clone(),
                entry.vrf.clone().unwrap_or_else(|| "-".to_string()),
                seen.state.clone(),
                admin.to_string(),
                seen.pid.map_or("-".to_string(), |p| p.to_string()),
                seen.uptime.map_or("-".to_string(), seconds_to_human),
                seen.restarts.map_or("-".to_string(), |r| r.to_string()),
                entry.error.clone().unwrap_or_default(),
            ]);
        }
        if json {
            return serde_json::to_string_pretty(&list).unwrap_or_default() + "\n";
        }
        table(
            &[
                "Name",
                "VRF",
                "State",
                "Admin",
                "PID",
                "Uptime",
                "Restarts",
                "Last error",
            ],
            &rows,
        )
    }
}

/// Answer the `process` orders the provider routes here.
pub async fn serve(registry: Arc<Registry>, mut rx: mpsc::Receiver<ShowRequest>) {
    while let Some(req) = rx.recv().await {
        let text = registry.order(&req.path, &req.args, req.json).await;
        let _ = req.resp.send(text);
    }
}

/// The instance's state, from systemd or its pid file.
pub async fn observe(runner: &Runner) -> Observed {
    match runner {
        Runner::Unit(unit) => observe_unit(unit).await,
        Runner::External(pid_file) => match live_pid(pid_file).await {
            Some(pid) => Observed {
                state: "running".to_string(),
                pid: Some(pid as u32),
                uptime: pid_uptime(pid as u32),
                restarts: None,
            },
            None => Observed {
                state: "stopped".to_string(),
                ..Default::default()
            },
        },
    }
}

async fn observe_unit(unit: &str) -> Observed {
    let output = tokio::process::Command::new("systemctl")
        .args([
            "show",
            unit,
            "-p",
            "ActiveState",
            "-p",
            "SubState",
            "-p",
            "MainPID",
            "-p",
            "ExecMainStartTimestampMonotonic",
            "-p",
            "NRestarts",
            "-p",
            "LoadState",
        ])
        .output()
        .await;
    match output {
        Ok(output) => parse_unit(&String::from_utf8_lossy(&output.stdout), monotonic_us()),
        Err(_) => Observed {
            state: "unknown".to_string(),
            ..Default::default()
        },
    }
}

/// `systemctl show -p …` output → [`Observed`], with `now` in µs of
/// `CLOCK_MONOTONIC` (systemd's `…TimestampMonotonic` clock).
pub fn parse_unit(text: &str, now: u64) -> Observed {
    let props: BTreeMap<&str, &str> = text.lines().filter_map(|l| l.split_once('=')).collect();
    let get = |k: &str| props.get(k).copied().unwrap_or_default();
    if get("LoadState") == "not-found" {
        return Observed {
            state: "not-installed".to_string(),
            ..Default::default()
        };
    }
    let state = match get("ActiveState") {
        "active" if get("SubState") == "reload" => "reloading",
        "active" => "running",
        "inactive" => "stopped",
        "activating" => "starting",
        "deactivating" => "stopping",
        "reloading" => "reloading",
        "failed" => "failed",
        "" => "unknown",
        other => other,
    }
    .to_string();
    let running = state == "running" || state == "reloading";
    let pid = get("MainPID").parse::<u32>().ok().filter(|&p| p > 0);
    let started = get("ExecMainStartTimestampMonotonic").parse::<u64>().ok();
    Observed {
        state,
        pid: if running { pid } else { None },
        uptime: match started {
            Some(t) if running && t > 0 && now >= t => Some((now - t) / 1_000_000),
            _ => None,
        },
        restarts: get("NRestarts").parse().ok(),
    }
}

fn monotonic_us() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes one timespec through a valid pointer.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000 + ts.tv_nsec as u64 / 1_000
}

/// Seconds since `pid` started, from `/proc/<pid>/stat` (field 22,
/// clock ticks after boot) and `/proc/uptime`.
fn pid_uptime(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = stat.rsplit_once(')')?.1;
    let start: u64 = rest.split_whitespace().nth(19)?.parse().ok()?;
    let uptime: f64 = std::fs::read_to_string("/proc/uptime")
        .ok()?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    // SAFETY: sysconf has no preconditions.
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks <= 0 {
        return None;
    }
    let started = start as f64 / ticks as f64;
    Some((uptime - started).max(0.0) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry(tag: &str) -> (Registry, PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("insomnia-process-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (_tx, rx) = watch::channel(Arc::new(Snapshot::default()));
        (Registry::new(dir.join("holds"), None, rx), dir)
    }

    #[test]
    fn unit_states() {
        let now = 10_000_000_000;
        let running = "ActiveState=active\nSubState=running\nMainPID=4242\nExecMainStartTimestampMonotonic=9000000000\nNRestarts=2\nLoadState=loaded\n";
        assert_eq!(
            parse_unit(running, now),
            Observed {
                state: "running".into(),
                pid: Some(4242),
                uptime: Some(1000),
                restarts: Some(2),
            }
        );
        let stopped = "ActiveState=inactive\nSubState=dead\nMainPID=0\nExecMainStartTimestampMonotonic=0\nNRestarts=0\nLoadState=loaded\n";
        assert_eq!(
            parse_unit(stopped, now),
            Observed {
                state: "stopped".into(),
                pid: None,
                uptime: None,
                restarts: Some(0),
            }
        );
        let failed =
            "ActiveState=failed\nSubState=failed\nMainPID=0\nNRestarts=5\nLoadState=loaded\n";
        assert_eq!(parse_unit(failed, now).state, "failed");
        let missing = "ActiveState=inactive\nLoadState=not-found\n";
        assert_eq!(parse_unit(missing, now).state, "not-installed");
    }

    /// The §6.2 table, as far as it can run without systemd: unknown
    /// names, signal mode refusals, holds on disk.
    #[tokio::test]
    async fn orders() {
        let (reg, dir) = registry("orders");
        assert_eq!(
            reg.order("/stop/process", &["kea-dhcp4@red".into()], false)
                .await,
            "% No process \"kea-dhcp4@red\"; see show process\n"
        );
        reg.register(
            "dhcp-relay",
            None,
            Runner::External(dir.join("relay.pid")),
            true,
        );
        for verb in ["start", "stop", "restart"] {
            assert_eq!(
                reg.order(&format!("/{verb}/process"), &["dhcp-relay".into()], false)
                    .await,
                NOT_SUPPORTED
            );
        }
        assert!(!reg.held("dhcp-relay"));

        // A held unit: restart is refused, start of an instance with
        // nothing configured clears the hold and says so.
        reg.register(
            "keepalived@default",
            Some("default"),
            Runner::Unit("insomnia-keepalived@default.service".into()),
            false,
        );
        reg.hold("keepalived@default").unwrap();
        assert!(reg.held("keepalived@default"));
        assert_eq!(
            reg.order("/restart/process", &["keepalived@default".into()], false)
                .await,
            "% \"keepalived@default\" was stopped by an operator; use start process\n"
        );
        assert_eq!(
            reg.order("/stop/process", &["keepalived@default".into()], false)
                .await,
            "keepalived@default is already stopped by an operator\n"
        );
        assert_eq!(
            reg.order("/start/process", &["keepalived@default".into()], false)
                .await,
            "% Nothing configured for \"keepalived@default\"\n"
        );
        assert!(!reg.held("keepalived@default"));
        assert_eq!(
            reg.order("/restart/process", &["keepalived@default".into()], false)
                .await,
            "% Nothing configured for \"keepalived@default\"\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn show_rows() {
        let (reg, dir) = registry("show");
        std::fs::create_dir_all(&dir).unwrap();
        let pid = dir.join("relay.pid");
        std::fs::write(&pid, format!("{}\n", std::process::id())).unwrap();
        reg.register("dhcp-relay", None, Runner::External(pid), false);
        reg.register(
            "kea-dhcp4@red",
            Some("red"),
            Runner::External(dir.join("nope.pid")),
            true,
        );
        reg.note("kea-dhcp4@red", Some("VRF red does not exist".into()));
        let text = reg.order("/show/process", &[], false).await;
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines[0].starts_with("Name           VRF  State    Admin  PID"));
        assert!(lines[2].starts_with("dhcp-relay     -    running  down   "));
        assert!(
            lines[3].starts_with("kea-dhcp4@red  red  stopped  up     -")
                && lines[3].ends_with("VRF red does not exist")
        );
        let one = reg
            .order("/show/process", &["kea-dhcp4@red".into()], true)
            .await;
        let v: serde_json::Value = serde_json::from_str(&one).unwrap();
        assert_eq!(v[0]["state"], "stopped");
        assert_eq!(v[0]["vrf"], "red");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
