//! VRF binding for daemons insomnia runs under systemd
//! (design/process.md §4).
//!
//! `ip vrf exec` binds a process to a VRF with a cgroup-BPF program at
//! the `BPF_CGROUP_INET_SOCK_CREATE` hook: on every IPv4 and IPv6 socket
//! a process in the cgroup creates, it sets `bound_dev_if` to the VRF
//! device, so binds, connects and route lookups happen in the VRF's
//! table. systemd attaches such a program to a unit's own cgroup with
//! `BPFProgram=sock_create:<pin>`. The per-VRF template units
//! (`insomnia-keepalived@`, `insomnia-kea-dhcp{4,6}@`) name
//! `/sys/fs/bpf/insomnia/vrf/%i`, and guard it with `AssertPathExists=`
//! in `[Unit]`: systemd starts a unit whose program is missing anyway,
//! unbound, and only logs a warning.
//!
//! This module owns those pins:
//! - the program is iproute2's (`ip/ipvrf.c`, `prog_load`), built from
//!   raw instructions and loaded with `bpf(BPF_PROG_LOAD)`, pinned with
//!   `bpf(BPF_OBJ_PIN)`; no compiler, libbpf or aya;
//! - `default` gets the same program with interface index 0, which
//!   leaves sockets unbound, so one template serves every instance;
//! - the interface index each pin was built for is recorded in
//!   `<state>/<vrf>.ifindex`, because a VRF that is deleted and
//!   re-created comes back under a new index: its pin is rebuilt and
//!   its running instances restarted (a running unit keeps the program
//!   it was started with);
//! - pins outlive an insomnia restart (bpffs lasts until reboot);
//!   [`run`] reconciles them with the kernel's VRFs at startup and on
//!   every link change.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::io;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::watch;

use crate::links::{DEFAULT_VRF, Snapshot};

/// Where the pins live, and where their interface indexes are recorded.
#[derive(Clone, Debug)]
pub struct Pins {
    /// bpffs directory (`/sys/fs/bpf/insomnia/vrf`).
    pub root: PathBuf,
    /// `/run/insomnia/vrf`: `<vrf>.ifindex` per pin.
    pub state: PathBuf,
}

/// The interface index a VRF's program binds sockets to: its VRF
/// device's, or 0 (unbound) for the global table. `None` when the VRF
/// does not exist.
pub fn ifindex(links: &Snapshot, vrf: &str) -> Option<u32> {
    if vrf == DEFAULT_VRF {
        return Some(0);
    }
    if !links.has_vrf(vrf) {
        return None;
    }
    links
        .links
        .values()
        .find(|l| l.name == vrf && l.kind.as_deref() == Some("vrf"))
        .map(|l| l.index)
}

impl Pins {
    pub fn path(&self, vrf: &str) -> PathBuf {
        self.root.join(vrf)
    }

    fn record(&self, vrf: &str) -> PathBuf {
        self.state.join(format!("{vrf}.ifindex"))
    }

    /// The interface index `vrf` is pinned for, if it is pinned.
    pub fn pinned(&self, vrf: &str) -> Option<u32> {
        if !self.path(vrf).exists() {
            return None;
        }
        std::fs::read_to_string(self.record(vrf))
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    /// Every pinned VRF and its interface index.
    pub fn all(&self) -> BTreeMap<String, Option<u32>> {
        let mut out = BTreeMap::new();
        if let Ok(entries) = std::fs::read_dir(&self.root) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                let index = self.pinned(&name);
                out.insert(name, index);
            }
        }
        out
    }

    /// Pin `vrf`'s program for `ifindex`, unless it already is. `true`
    /// when a program was (re)pinned.
    pub fn ensure(&self, vrf: &str, ifindex: u32) -> io::Result<bool> {
        if self.pinned(vrf) == Some(ifindex) {
            return Ok(false);
        }
        std::fs::create_dir_all(&self.root)?;
        std::fs::create_dir_all(&self.state)?;
        let prog = load(ifindex)?;
        let path = self.path(vrf);
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
        pin(&prog, &path)?;
        std::fs::write(self.record(vrf), format!("{ifindex}\n"))?;
        Ok(true)
    }

    /// Unpin `vrf`. A missing pin is fine.
    pub fn remove(&self, vrf: &str) -> io::Result<()> {
        for path in [self.path(vrf), self.record(vrf)] {
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------
// The program and the bpf(2) calls
// ---------------------------------------------------------------

const BPF_PROG_LOAD: libc::c_long = 5;
const BPF_OBJ_PIN: libc::c_long = 6;
const BPF_PROG_TYPE_CGROUP_SOCK: u32 = 9;
const BPF_CGROUP_INET_SOCK_CREATE: u32 = 2;

/// One `struct bpf_insn`: opcode, dst/src registers (low/high nibble on
/// a little-endian host), offset, immediate.
fn insn(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[0] = code;
    out[1] = if cfg!(target_endian = "little") {
        (src << 4) | dst
    } else {
        (dst << 4) | src
    };
    out[2..4].copy_from_slice(&off.to_ne_bytes());
    out[4..8].copy_from_slice(&imm.to_ne_bytes());
    out
}

/// iproute2's VRF program: `ctx->bound_dev_if = ifindex; return 1`.
pub fn program(ifindex: u32) -> Vec<u8> {
    const MOV64_X: u8 = 0xbf; // BPF_ALU64 | BPF_MOV | BPF_X
    const MOV64_K: u8 = 0xb7; // BPF_ALU64 | BPF_MOV | BPF_K
    const STX_W: u8 = 0x63; // BPF_STX | BPF_MEM | BPF_W
    const EXIT: u8 = 0x95; // BPF_JMP | BPF_EXIT
    // offsetof(struct bpf_sock, bound_dev_if)
    const BOUND_DEV_IF: i16 = 0;
    [
        insn(MOV64_X, 6, 1, 0, 0),              // r6 = r1 (the context)
        insn(MOV64_K, 3, 0, 0, ifindex as i32), // r3 = ifindex
        insn(STX_W, 1, 3, BOUND_DEV_IF, 0),     // ctx->bound_dev_if = r3
        insn(MOV64_K, 0, 0, 0, 1),              // r0 = 1: allow the socket
        insn(EXIT, 0, 0, 0, 0),                 // exit
    ]
    .concat()
}

/// `union bpf_attr` for `BPF_PROG_LOAD`, up to `expected_attach_type`.
#[repr(C)]
#[derive(Default)]
struct ProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
}

/// `union bpf_attr` for `BPF_OBJ_PIN`.
#[repr(C)]
#[derive(Default)]
struct ObjPinAttr {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
}

fn bpf<T>(cmd: libc::c_long, attr: &mut T) -> io::Result<libc::c_long> {
    // SAFETY: `attr` is a valid, initialised bpf_attr prefix of the
    // size passed; the kernel reads (and for PROG_LOAD's log, writes
    // through pointers inside it to buffers that outlive the call).
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd,
            (attr as *mut T).cast::<libc::c_void>(),
            std::mem::size_of::<T>() as libc::c_uint,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// Load the program for `ifindex`. On failure, the verifier's log is
/// added to the error.
fn load(ifindex: u32) -> io::Result<OwnedFd> {
    let code = program(ifindex);
    let license = c"GPL";
    let mut attr = ProgLoadAttr {
        prog_type: BPF_PROG_TYPE_CGROUP_SOCK,
        insn_cnt: (code.len() / 8) as u32,
        insns: code.as_ptr() as u64,
        license: license.as_ptr() as u64,
        expected_attach_type: BPF_CGROUP_INET_SOCK_CREATE,
        ..Default::default()
    };
    match bpf(BPF_PROG_LOAD, &mut attr) {
        // SAFETY: a successful BPF_PROG_LOAD returns a new fd we own.
        Ok(fd) => Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) }),
        Err(err) => {
            let mut log = vec![0u8; 4096];
            attr.log_level = 1;
            attr.log_size = log.len() as u32;
            attr.log_buf = log.as_mut_ptr() as u64;
            let _ = bpf(BPF_PROG_LOAD, &mut attr);
            let end = log.iter().position(|&b| b == 0).unwrap_or(0);
            let text = String::from_utf8_lossy(&log[..end]);
            Err(io::Error::new(
                err.kind(),
                format!("bpf(BPF_PROG_LOAD): {err}; {}", text.trim()),
            ))
        }
    }
}

fn pin(prog: &OwnedFd, path: &Path) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let path_c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in pin path"))?;
    let mut attr = ObjPinAttr {
        pathname: path_c.as_ptr() as u64,
        bpf_fd: prog.as_raw_fd() as u32,
        file_flags: 0,
    };
    bpf(BPF_OBJ_PIN, &mut attr)
        .map(drop)
        .map_err(|err| io::Error::new(err.kind(), format!("pin {}: {err}", path.display())))
}

// ---------------------------------------------------------------
// Reconciling pins with the kernel's VRFs
// ---------------------------------------------------------------

/// What a link change means for the pinned VRFs.
#[derive(Debug, PartialEq, Eq)]
pub enum Change {
    /// The VRF is gone: stop its instances, then unpin.
    Gone(String),
    /// The VRF came back under another interface index: re-pin, then
    /// restart its running instances.
    Moved(String, u32),
}

/// Compare the pins with the kernel's VRFs.
pub fn changes(pinned: &BTreeMap<String, Option<u32>>, links: &Snapshot) -> Vec<Change> {
    let mut out = Vec::new();
    for (vrf, recorded) in pinned {
        match ifindex(links, vrf) {
            None => out.push(Change::Gone(vrf.clone())),
            Some(now) if *recorded != Some(now) => out.push(Change::Moved(vrf.clone(), now)),
            Some(_) => {}
        }
    }
    out
}

/// Keep the pins in step with the kernel: at startup and after every
/// link change, unpin deleted VRFs (stopping their instances first)
/// and rebuild the pins of VRFs re-created under a new index
/// (restarting their running instances).
pub async fn run(
    pins: Pins,
    registry: Arc<crate::process::Registry>,
    mut links: watch::Receiver<Arc<Snapshot>>,
) {
    loop {
        let snapshot = links.borrow_and_update().clone();
        for change in changes(&pins.all(), &snapshot) {
            match change {
                Change::Gone(vrf) => {
                    registry.stop_vrf(&vrf).await;
                    match pins.remove(&vrf) {
                        Ok(()) => tracing::info!("vrf {vrf}: deleted; program unpinned"),
                        Err(err) => tracing::error!("vrf {vrf}: unpin failed: {err}"),
                    }
                }
                Change::Moved(vrf, index) => match pins.ensure(&vrf, index) {
                    Ok(_) => {
                        tracing::info!("vrf {vrf}: now interface index {index}; program re-pinned");
                        registry.restart_vrf(&vrf).await;
                    }
                    Err(err) => tracing::error!("vrf {vrf}: re-pin failed: {err}"),
                },
            }
        }
        if links.changed().await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::links::Link;

    /// The program iproute2's `ip vrf exec` builds, for ifindex 7,
    /// instruction by instruction (little-endian host).
    #[test]
    #[cfg(target_endian = "little")]
    fn program_bytes() {
        assert_eq!(
            program(7),
            [
                0xbf, 0x16, 0, 0, 0, 0, 0, 0, // r6 = r1
                0xb7, 0x03, 0, 0, 7, 0, 0, 0, // r3 = 7
                0x63, 0x31, 0, 0, 0, 0, 0, 0, // *(u32 *)(r1 + 0) = r3
                0xb7, 0x00, 0, 0, 1, 0, 0, 0, // r0 = 1
                0x95, 0x00, 0, 0, 0, 0, 0, 0, // exit
            ]
        );
        assert_eq!(std::mem::size_of::<ProgLoadAttr>(), 72);
        assert_eq!(std::mem::size_of::<ObjPinAttr>(), 16);
    }

    fn vrf(index: u32, name: &str) -> Link {
        Link {
            index,
            name: name.into(),
            kind: Some("vrf".into()),
            master: None,
            up: true,
        }
    }

    #[test]
    fn indexes_and_changes() {
        let mut links = Snapshot::default();
        links.links.insert(5, vrf(5, "red"));
        links.links.insert(
            6,
            Link {
                index: 6,
                name: "blue".into(),
                kind: Some("bridge".into()),
                master: None,
                up: true,
            },
        );
        assert_eq!(ifindex(&links, "default"), Some(0));
        assert_eq!(ifindex(&links, "red"), Some(5));
        assert_eq!(ifindex(&links, "blue"), None, "a bridge is not a VRF");

        let pinned: BTreeMap<String, Option<u32>> = [
            ("default".to_string(), Some(0)),
            ("red".to_string(), Some(4)),
            ("blue".to_string(), Some(9)),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            changes(&pinned, &links),
            [Change::Gone("blue".into()), Change::Moved("red".into(), 5)]
        );
    }

    /// Every per-VRF template guards its `BPFProgram=` with an
    /// `AssertPathExists=` on the same pin, and the guard sits in
    /// `[Unit]`: systemd ignores it in `[Service]` and would then start
    /// the daemon unbound when the pin is missing (design/process.md
    /// §4.3, rows 3, 4 and 9). The relay agent binds its own sockets and
    /// has neither.
    #[test]
    fn templates_guard_their_program() {
        let templates = [
            (
                "insomnia-keepalived@.service",
                include_str!("../packaging/systemd/insomnia-keepalived@.service"),
            ),
            (
                "insomnia-kea-dhcp4@.service",
                include_str!("../packaging/systemd/insomnia-kea-dhcp4@.service"),
            ),
            (
                "insomnia-kea-dhcp6@.service",
                include_str!("../packaging/systemd/insomnia-kea-dhcp6@.service"),
            ),
        ];
        for (name, text) in templates {
            let mut section = "";
            let mut assert_path = None;
            let mut program = None;
            for line in text.lines().map(str::trim) {
                if line.starts_with('[') {
                    section = line;
                } else if let Some(v) = line.strip_prefix("AssertPathExists=") {
                    assert_eq!(
                        section, "[Unit]",
                        "{name}: AssertPathExists= outside [Unit]"
                    );
                    assert_path = Some(v.to_string());
                } else if let Some(v) = line.strip_prefix("BPFProgram=") {
                    assert_eq!(
                        section, "[Service]",
                        "{name}: BPFProgram= outside [Service]"
                    );
                    program = Some(v.to_string());
                }
                assert!(
                    !line.contains("LD_PRELOAD") && !line.starts_with("EnvironmentFile="),
                    "{name}: the VRF shim is gone"
                );
            }
            let pin = "/sys/fs/bpf/insomnia/vrf/%i";
            assert_eq!(assert_path.as_deref(), Some(pin), "{name}");
            assert_eq!(
                program.as_deref(),
                Some(format!("sock_create:{pin}").as_str()),
                "{name}"
            );
        }
        let relay = include_str!("../packaging/systemd/insomnia-dhcp-relay.service");
        assert!(!relay.contains("BPFProgram="));
    }

    /// Records without a pin (the bpffs was not there) read as unpinned.
    #[test]
    fn records_need_the_pin() {
        let tmp = std::env::temp_dir().join(format!("insomnia-vrf-{}", std::process::id()));
        let pins = Pins {
            root: tmp.join("bpf"),
            state: tmp.join("state"),
        };
        std::fs::create_dir_all(&pins.state).unwrap();
        std::fs::write(pins.state.join("red.ifindex"), "5\n").unwrap();
        assert_eq!(pins.pinned("red"), None);
        std::fs::create_dir_all(&pins.root).unwrap();
        std::fs::write(pins.path("red"), "").unwrap();
        assert_eq!(pins.pinned("red"), Some(5));
        assert_eq!(pins.all().get("red"), Some(&Some(5)));
        pins.remove("red").unwrap();
        assert_eq!(pins.pinned("red"), None);
        pins.remove("red").unwrap();
        std::fs::remove_dir_all(&tmp).unwrap();
    }
}
