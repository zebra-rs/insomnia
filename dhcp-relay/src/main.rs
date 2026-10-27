//! insomnia-dhcp-relay — the DHCPv4 / DHCPv6 relay agent insomnia
//! drives.
//!
//! insomnia renders the relay part of the running config into
//! `relay.json` (format in `config.rs`) and sends `SIGHUP`; this process
//! relays and counts. It is a separate process on purpose: it parses
//! packets from every client on every listen interface, so it runs
//! unprivileged and sandboxed (`DynamicUser`, `CAP_NET_BIND_SERVICE`,
//! `CAP_NET_RAW`) instead of inside the root insomnia daemon, and an
//! insomnia restart does not interrupt relaying.
//!
//! It replaces ISC `dhcrelay` as VyOS runs it (design/dhcp.md §5, §10):
//! one process for both families and every VRF, binding its own
//! per-interface and per-VRF sockets.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;

mod config;
mod control;
mod ifaces;
mod relay;
mod stats;
mod sys;
mod v4;
mod v6;

/// How often interfaces are re-read and missing sockets retried.
const RESYNC_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The relay configuration insomnia renders; re-read on SIGHUP. A
    /// missing file is an empty configuration.
    #[arg(long, default_value = "/run/insomnia/dhcp-relay/relay.json")]
    config: PathBuf,

    /// Unix socket answering `stats` with the counters as JSON.
    #[arg(long, default_value = "/run/insomnia/dhcp-relay/control")]
    control: PathBuf,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();

    let mut hangup = signal(SignalKind::hangup())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;

    let stats = Arc::new(Mutex::new(stats::Stats::default()));
    tokio::spawn({
        let (path, stats) = (args.control.clone(), stats.clone());
        async move { control::serve(&path, stats).await }
    });

    let (tx, mut rx) = mpsc::channel(256);
    let mut relay = relay::Relay::new(stats, tx);
    relay.reload(&args.config);
    tracing::info!("insomnia-dhcp-relay started ({})", args.config.display());

    let mut resync = tokio::time::interval(RESYNC_INTERVAL);
    resync.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            Some(incoming) = rx.recv() => relay.handle(incoming),
            _ = hangup.recv() => {
                tracing::info!("SIGHUP: reloading {}", args.config.display());
                relay.reload(&args.config);
            }
            _ = resync.tick() => relay.resync(),
            _ = terminate.recv() => break,
            _ = interrupt.recv() => break,
        }
    }
    let _ = std::fs::remove_file(&args.control);
    tracing::info!("insomnia-dhcp-relay stopped");
    Ok(())
}
