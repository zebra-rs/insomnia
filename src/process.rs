//! Control of the daemons insomnia renders config for and keeps
//! running separately: keepalived (`keepalived.rs`) and the DHCP relay
//! agent (`relayd.rs`).
//!
//! Each stays a separately supervised process, so an insomnia restart
//! (a package upgrade) does not interrupt it. insomnia writes the file
//! and asks for a reload: through `systemctl` on the daemon's unit, or
//! by `SIGHUP` to its pid file for hosts without systemd and for the
//! BDD namespaces. An empty config stops the unit in systemd mode; in
//! signal mode the daemon is reloaded and idles.

use std::path::Path;

use anyhow::Context;

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

/// Get the daemon to load a config file the caller has just put in
/// place: `changed` says whether the file is new, `empty` whether it
/// configures nothing. `unit` serves systemd mode, `pid_file` signal
/// mode.
pub async fn reload(
    control: Control,
    unit: &str,
    pid_file: &Path,
    changed: bool,
    empty: bool,
) -> anyhow::Result<Applied> {
    match control {
        Control::Systemd => {
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
        Control::Signal => {
            let Some(pid) = live_pid(pid_file).await else {
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
