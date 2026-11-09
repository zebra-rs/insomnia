//! insomnia — out-of-process firewall / IPsec / VRRP / DHCP server and
//! relay enforcement daemon for zebra-rs.
//!
//! zebra-rs owns the configuration (YANG schema, candidate/running
//! stores, commit); insomnia enforces it: it subscribes to the
//! `firewall`, `vpn ipsec`, `vrrp`, `service dhcp-server`,
//! `service dhcpv6-server`, `service dhcp-relay` and
//! `service dhcpv6-relay` running-config subtrees over the
//! zebra.config.v1 gRPC API (one whole-subtree JSON batch per
//! touching commit, snapshot first) and renders them into nftables,
//! strongSwan (swanctl), keepalived, Kea and insomnia-dhcp-relay
//! state. It also registers as the zebra.show.v1 show provider for
//! those trees, so `show firewall`, `show vpn ipsec …`, `show vrrp …`,
//! `show dhcp[v6] server …` and `show dhcp[v6] relay statistics` on
//! the zebra-rs CLI are answered here.
//!
//! Every connection retries forever: zebra-rs restarting is a normal
//! condition, and the subscription's snapshot-first contract makes
//! reconnection self-resynchronizing.

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tokio::sync::mpsc;

mod api;
mod dhcp4;
mod dhcp6;
mod dhcp_relay;
mod dhcp_server;
mod endpoint;
mod firewall;
mod ipsec;
mod json;
mod kea;
mod keepalived;
mod links;
mod pb;
mod pd_routes;
mod process;
mod provider;
mod relayd;
mod subscribe;
mod text;
mod vici;
mod vrf;
mod vrrp;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// zebra-rs vty gRPC endpoint: unix:NAME (Linux abstract socket),
    /// unix:/PATH (filesystem socket), tcp:HOST:PORT, or bare HOST
    /// (port 2666).
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
    #[arg(long, value_enum, default_value_t = process::Control::Systemd)]
    keepalived_control: process::Control,

    /// systemd template unit for keepalived instances; `@.` is replaced
    /// by `@<vrf>.`.
    #[arg(long, default_value = "insomnia-keepalived@.service")]
    keepalived_unit: String,

    /// Operator holds (`stop process`): one file per held instance.
    /// Survive an insomnia restart, not a reboot.
    #[arg(long, default_value = "/run/insomnia/holds")]
    holds_dir: PathBuf,

    /// bpffs directory of the VRF socket programs the per-VRF template
    /// units attach (`BPFProgram=sock_create:<dir>/%i`).
    #[arg(long, default_value = "/sys/fs/bpf/insomnia/vrf")]
    vrf_bpf_dir: PathBuf,

    /// Where the interface index of each pinned VRF program is recorded.
    #[arg(long, default_value = "/run/insomnia/vrf")]
    vrf_state_dir: PathBuf,

    /// Directory the DHCP relay backend renders relay.json into, for
    /// the insomnia-dhcp-relay agent; also holds the agent's relay.pid
    /// in signal mode.
    #[arg(long, default_value = "/run/insomnia/dhcp-relay")]
    dhcp_relay_dir: PathBuf,

    /// How the relay agent picks up a new config: `systemd` starts,
    /// reloads or stops its unit, `signal` sends SIGHUP to relay.pid
    /// (containers, the BDD harness).
    #[arg(long, value_enum, default_value_t = process::Control::Systemd)]
    dhcp_relay_control: process::Control,

    /// systemd unit of the relay agent.
    #[arg(long, default_value = "insomnia-dhcp-relay.service")]
    dhcp_relay_unit: String,

    /// The relay agent's control socket (`show dhcp relay statistics`).
    #[arg(long, default_value = "/run/insomnia-dhcp-relay/control")]
    dhcp_relay_socket: PathBuf,
    /// Directory holding one directory per Kea instance (`<vrf>/`): the
    /// rendered kea-dhcp4.conf / kea-dhcp6.conf, the control sockets
    /// and Kea's lock files.
    #[arg(long, default_value = "/run/insomnia/kea")]
    kea_dir: PathBuf,
    /// Kea's state, one directory per VRF: the lease files and the
    /// DHCPv6 server DUID.
    #[arg(long, default_value = "/var/lib/insomnia/kea")]
    kea_state_dir: PathBuf,
    /// How Kea instances run: `systemd` starts and stops the template
    /// units, `socket` only talks to instances somebody else started on
    /// the instance's config file (containers, the BDD harness).
    #[arg(long, value_enum, default_value_t = kea::Control::Systemd)]
    kea_control: kea::Control,
    /// systemd template unit for kea-dhcp4 instances; `@.` is replaced
    /// by `@<vrf>.`.
    #[arg(long, default_value = "insomnia-kea-dhcp4@.service")]
    kea_unit4: String,
    /// systemd template unit for kea-dhcp6 instances.
    #[arg(long, default_value = "insomnia-kea-dhcp6@.service")]
    kea_unit6: String,
    /// Kea's hook libraries; default `/usr/lib/<multiarch>/kea/hooks`.
    #[arg(long)]
    kea_hooks_dir: Option<PathBuf>,
    /// The program Kea's run_script hook calls for DHCPv6 lease events.
    #[arg(long, default_value = "/usr/lib/insomnia/kea-notify")]
    kea_notify: PathBuf,
}

/// Debian's multiarch hooks directory for this build's architecture.
fn default_kea_hooks_dir() -> PathBuf {
    let triplet = match std::env::consts::ARCH {
        "arm" => "arm-linux-gnueabihf".to_string(),
        arch => format!("{arch}-linux-gnu"),
    };
    PathBuf::from(format!("/usr/lib/{triplet}/kea/hooks"))
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
    let (dhcp_show_tx, dhcp_show_rx) = mpsc::channel(8);
    let (dhcp_server_show_tx, dhcp_server_show_rx) = mpsc::channel(8);
    let (process_show_tx, process_show_rx) = mpsc::channel(8);

    let links = links::spawn().await;
    // VRF socket programs are pinned only for daemons systemd runs; in
    // signal and socket mode whoever starts the daemon binds it (the BDD
    // harness uses `ip vrf exec`).
    let pins = (args.keepalived_control == process::Control::Systemd
        || args.kea_control == kea::Control::Systemd)
        .then_some(vrf::Pins {
            root: args.vrf_bpf_dir,
            state: args.vrf_state_dir,
        });
    let registry = Arc::new(process::Registry::new(
        args.holds_dir,
        pins.clone(),
        links.clone(),
    ));
    if let Some(pins) = pins {
        tokio::spawn(vrf::run(pins, Arc::clone(&registry), links.clone()));
    }
    tokio::spawn(process::serve(Arc::clone(&registry), process_show_rx));

    let ka = Arc::new(
        keepalived::Keepalived::new(
            args.keepalived_dir,
            args.keepalived_control,
            args.keepalived_unit,
            Arc::clone(&registry),
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
    let relayd = Arc::new(relayd::Relayd {
        dir: args.dhcp_relay_dir,
        control: args.dhcp_relay_control,
        unit: args.dhcp_relay_unit,
        socket: args.dhcp_relay_socket,
        registry: Arc::clone(&registry),
    });
    tokio::spawn(dhcp_relay::run(
        args.host.clone(),
        relayd,
        links.clone(),
        dhcp_show_rx,
    ));
    let kea = Arc::new(kea::Kea {
        dir: args.kea_dir,
        state_dir: args.kea_state_dir,
        control: args.kea_control,
        unit4: args.kea_unit4,
        unit6: args.kea_unit6,
        hooks_dir: args.kea_hooks_dir.unwrap_or_else(default_kea_hooks_dir),
        notify: args.kea_notify,
        registry,
    });
    tokio::spawn(dhcp_server::run(
        args.host.clone(),
        kea,
        links,
        dhcp_server_show_rx,
    ));

    tracing::info!("insomnia started (zebra-rs at {})", args.host);
    provider::run(
        args.host,
        provider::Backends {
            firewall: firewall_show_tx,
            ipsec: ipsec_show_tx,
            vrrp: vrrp_show_tx,
            dhcp: dhcp_show_tx,
            dhcp_server: dhcp_server_show_tx,
            process: process_show_tx,
        },
    )
    .await;
}
