//! insomnia — out-of-process firewall / IPsec enforcement daemon for
//! zebra-rs.
//!
//! zebra-rs owns the configuration (YANG schema, candidate/running
//! stores, commit); insomnia enforces it: it subscribes to the
//! `firewall` and `vpn ipsec` running-config subtrees over the
//! zebra.config.v1 gRPC API (one whole-subtree JSON batch per
//! touching commit, snapshot first) and renders them into nftables
//! and strongSwan (swanctl) state. It also registers as the
//! zebra.show.v1 show provider for both trees, so `show firewall` and
//! `show vpn ipsec …` on the zebra-rs CLI are answered here.
//!
//! Every connection retries forever: zebra-rs restarting is a normal
//! condition, and the subscription's snapshot-first contract makes
//! reconnection self-resynchronizing.

use std::path::PathBuf;

use clap::Parser;
use tokio::sync::mpsc;

mod api;
mod endpoint;
mod firewall;
mod ipsec;
mod json;
mod pb;
mod provider;
mod subscribe;
mod vici;

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

    tokio::spawn(firewall::run(args.host.clone(), firewall_show_rx));
    tokio::spawn(ipsec::run(
        args.host.clone(),
        args.swanctl_dir,
        args.vici_socket,
        ipsec_show_rx,
    ));

    tracing::info!("insomnia started (zebra-rs at {})", args.host);
    provider::run(args.host, firewall_show_tx, ipsec_show_tx).await;
}
