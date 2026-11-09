//! `kea-notify`: the program Kea's `run_script` hook runs on every
//! DHCPv6 lease event of an instance insomnia drives (design/dhcp.md
//! §7.5). Installed as `/usr/lib/insomnia/kea-notify`.
//!
//! It only forwards: the hook point (argv[1]) and Kea's lease variables
//! (`QUERY6_*`, `LEASE6_*`, `LEASES6_*`, `DELETED_LEASES6_*`) go, as
//! `KEY=VALUE` lines in one datagram, to the `events` socket in the
//! directory it was started from. insomnia links
//! `<kea-dir>/<vrf>/kea-notify` to this program and names that link in
//! the instance's configuration, so argv[0] says which instance the
//! event belongs to; Kea's `run_script` passes no arguments of its own
//! and no environment beyond its variables.
//!
//! insomnia treats the datagram only as a claim: before installing or
//! removing a route it asks Kea for the lease itself. Errors are
//! ignored (insomnia not running, socket gone): Kea must never wait on
//! or fail because of this program, and the periodic sweep catches
//! anything missed.

use std::os::unix::net::UnixDatagram;
use std::path::Path;

const PREFIXES: [&str; 4] = ["QUERY6_", "LEASE6_", "LEASES6_", "DELETED_LEASES6_"];

fn main() {
    let mut args = std::env::args_os();
    let Some(argv0) = args.next() else {
        return;
    };
    let hook = args
        .next()
        .map(|a| a.to_string_lossy().into_owned())
        .unwrap_or_default();
    let socket = Path::new(&argv0)
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("events");
    let mut message = format!("HOOK={hook}\n");
    for (key, value) in std::env::vars() {
        if PREFIXES.iter().any(|p| key.starts_with(p)) && !value.contains('\n') {
            message.push_str(&format!("{key}={value}\n"));
        }
    }
    if let Ok(sock) = UnixDatagram::unbound() {
        let _ = sock.send_to(message.as_bytes(), socket);
    }
}
