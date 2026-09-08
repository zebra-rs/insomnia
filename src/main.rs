//! insomnia — out-of-process firewall / IPsec / VRRP enforcement daemon
//! for zebra-rs.
//!
//! zebra-rs owns the configuration (YANG schema, candidate/running
//! stores, commit); insomnia enforces it: it subscribes to the
//! `firewall`, `vpn ipsec` and `vrrp` running-config subtrees over the
//! zebra.config.v1 gRPC API (one whole-subtree JSON batch per
//! touching commit, snapshot first) and renders them into nftables,
//! strongSwan (swanctl) and keepalived state. It also registers as the
//! zebra.show.v1 show provider for the three trees, so `show firewall`,
//! `show vpn ipsec …` and `show vrrp …` on the zebra-rs CLI are
//! answered here.
//!
//! Every connection retries forever: zebra-rs restarting is a normal
//! condition, and the subscription's snapshot-first contract makes
//! reconnection self-resynchronizing.

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tokio::sync::mpsc;

mod api;
mod endpoint;
mod firewall;
mod ipsec;
mod json;
mod keepalived;
mod pb;
mod provider;
mod subscribe;
mod text;
mod vici;
mod vrrp;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// zebra-rs vty gRPC endpoint: unix:NAME (Linux abstract socket),
    /// tcp://HOST:PORT, or bare HOST (port 2666).
    #[arg(long, default_value = "unix:zebra-rs/vty")]
    host: String,

    /// swanctl configuration directory the IPsec backend renders into.
    #[arg(long, default_value = "/etc/swanctl")]
    swanctl_dir: PathBuf,

    /// strongSwan VICI control socket (show vpn ipsec sa/connections).
    #[arg(long, default_value = "/var/run/charon.vici")]
    vici_socket: PathBuf,

    /// Directory holding one keepalived instance per VRF (`default` for
    /// the global table): the rendered keepalived.conf, pid files,
    /// keepalived's dump files (via TMPDIR) and the instance env file.
    #[arg(long, default_value = "/run/insomnia/vrrp")]
    keepalived_dir: PathBuf,

    /// How keepalived picks up a new config: `systemd` reloads or stops
    /// the template unit, `signal` sends SIGHUP to the instance's pid
    /// file (containers, the BDD harness).
    #[arg(long, value_enum, default_value_t = keepalived::Control::Systemd)]
    keepalived_control: keepalived::Control,

    /// systemd template unit for keepalived instances; `@.` is replaced
    /// by `@<vrf>.`.
    #[arg(long, default_value = "insomnia-keepalived@.service")]
    keepalived_unit: String,

    /// LD_PRELOAD shim written into non-default VRF instances' env file.
    #[arg(long, default_value = "/usr/lib/insomnia/vrf.o")]
    vrf_preload: PathBuf,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();

    let (firewall_show_tx, firewall_show_rx) = mpsc::channel(8);
    let (ipsec_show_tx, ipsec_show_rx) = mpsc::channel(8);
    let (vrrp_show_tx, vrrp_show_rx) = mpsc::channel(8);

    let ka = Arc::new(
        keepalived::Keepalived::new(
            args.keepalived_dir,
            args.keepalived_control,
            args.keepalived_unit,
            args.vrf_preload,
        )
        .probe()
        .await,
    );

    tokio::spawn(firewall::run(args.host.clone(), firewall_show_rx));
    tokio::spawn(ipsec::run(
        args.host.clone(),
        args.swanctl_dir,
        args.vici_socket,
        ipsec_show_rx,
    ));
    tokio::spawn(vrrp::run(args.host.clone(), ka, vrrp_show_rx));

    tracing::info!("insomnia started (zebra-rs at {})", args.host);
    provider::run(args.host, firewall_show_tx, ipsec_show_tx, vrrp_show_tx).await;
}
