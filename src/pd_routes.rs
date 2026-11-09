//! Routes for DHCPv6 delegated prefixes (design/dhcp.md §7.5, DH9).
//!
//! Kea's `run_script` hook runs `kea-notify` (src/bin/
//! insomnia-kea-notify.rs) on every lease event; it forwards Kea's
//! variables in one datagram to `<kea-dir>/<vrf>/events`, a socket this
//! module binds per DHCPv6 instance (mode 0660, group `_kea`, so only
//! Kea's user can send). A datagram is only a claim:
//! - a prefix granted (`leases6_committed`, `lease6_renew`,
//!   `lease6_rebind`) is routed only after `lease6-get` confirms an
//!   active IA_PD lease for exactly that prefix, inside a configured
//!   `prefix-delegation` range of the instance;
//! - a prefix taken back (`lease6_release`, `lease6_expire`,
//!   `lease6_decline`, or a deleted lease in `leases6_committed`) loses
//!   its route only when Kea has no active lease for it any more. The
//!   hook runs asynchronously, before Kea has finished the release, so
//!   the check is made after a short delay, and again later.
//!
//! The route is `<prefix> via <requester link-local> dev <interface>
//! proto dhcp`, in the instance's VRF table. zebra-rs imports `proto
//! dhcp` kernel routes as `D` routes, so they are visible and
//! redistributable. Kea itself keeps only `CAP_NET_BIND_SERVICE` and
//! `CAP_NET_RAW`: insomnia, not Kea, changes the routing table.
//!
//! A sweep at startup and every [`SWEEP`] removes `proto dhcp` routes
//! inside a configured range that no active lease backs, and every such
//! route when the instance has `disable-route-autoinstall` or `disable`.
//! An instance that only stops serving for a while (its interface flaps)
//! keeps its routes: Kea still holds the leases. insomnia
//! touches only routes inside configured ranges, which keeps it clear of
//! the default route a future DHCP client installs with the same
//! protocol.

use std::collections::BTreeMap;
use std::net::Ipv6Addr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::net::UnixDatagram;
use tokio::sync::mpsc;

use crate::dhcp_server::Net6;
use crate::kea::{self, Family, Kea};
use crate::links::DEFAULT_VRF;

/// How often routes are checked against Kea's leases.
pub const SWEEP: Duration = Duration::from_secs(60);
/// Re-checks of a prefix taken back: Kea may still be finishing the
/// release when the event arrives.
const RECHECK: [Duration; 2] = [Duration::from_secs(1), Duration::from_secs(5)];

/// One event: the instance's VRF and kea-notify's `KEY=VALUE` lines.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Event {
    pub hook: String,
    pub vars: BTreeMap<String, String>,
}

pub fn parse(text: &str) -> Event {
    let mut event = Event::default();
    for line in text.lines() {
        if let Some((key, value)) = line.split_once('=') {
            if key == "HOOK" {
                event.hook = value.to_string();
            } else {
                event.vars.insert(key.to_string(), value.to_string());
            }
        }
    }
    event
}

/// What an event says about one delegated prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claim {
    Granted {
        prefix: Net6,
        via: Ipv6Addr,
        dev: String,
    },
    Revoked {
        prefix: Net6,
    },
}

fn pd(vars: &BTreeMap<String, String>, stem: &str) -> Option<Net6> {
    if vars.get(&format!("{stem}_TYPE"))?.as_str() != "IA_PD" {
        return None;
    }
    let addr: Ipv6Addr = vars.get(&format!("{stem}_ADDRESS"))?.parse().ok()?;
    let len: u8 = vars.get(&format!("{stem}_PREFIX_LEN"))?.parse().ok()?;
    Net6::new(addr, len)
}

/// The IA_PD claims of an event; everything else (addresses, unknown
/// hooks) is ignored.
pub fn claims(event: &Event) -> Vec<Claim> {
    let vars = &event.vars;
    let via = vars
        .get("QUERY6_REMOTE_ADDR")
        .and_then(|a| a.parse::<Ipv6Addr>().ok());
    let dev = vars.get("QUERY6_IFACE_NAME").filter(|d| !d.is_empty());
    let granted = |prefix: Net6| match (via, dev) {
        (Some(via), Some(dev)) => Some(Claim::Granted {
            prefix,
            via,
            dev: dev.clone(),
        }),
        _ => None,
    };
    let list = |name: &str| -> Vec<Net6> {
        let n: usize = vars
            .get(&format!("{name}_SIZE"))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        (0..n.min(1024))
            .filter_map(|i| pd(vars, &format!("{name}_AT{i}")))
            .collect()
    };
    match event.hook.as_str() {
        "leases6_committed" => list("LEASES6")
            .into_iter()
            .filter_map(granted)
            .chain(
                list("DELETED_LEASES6")
                    .into_iter()
                    .map(|prefix| Claim::Revoked { prefix }),
            )
            .collect(),
        "lease6_renew" | "lease6_rebind" => {
            pd(vars, "LEASE6").and_then(granted).into_iter().collect()
        }
        "lease6_release" | "lease6_expire" | "lease6_decline" => pd(vars, "LEASE6")
            .map(|prefix| Claim::Revoked { prefix })
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

/// Bind `path` (replacing a stale socket) and forward every datagram to
/// `tx` as `(vrf, text)`, until `tx` closes.
pub fn listen(
    path: &Path,
    vrf: String,
    tx: mpsc::Sender<(String, String)>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    use std::os::unix::fs::PermissionsExt;

    let _ = std::fs::remove_file(path);
    let sock = UnixDatagram::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    kea::chown_to_kea(path)?;
    Ok(tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match sock.recv(&mut buf).await {
                Ok(n) => {
                    let text = String::from_utf8_lossy(&buf[..n]).into_owned();
                    if tx.send((vrf.clone(), text)).await.is_err() {
                        return;
                    }
                }
                Err(err) => {
                    tracing::warn!("kea-notify events ({vrf}): {err}");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }))
}

/// The instance's delegation ranges, and whether it installs routes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ranges {
    pub ranges: Vec<Net6>,
    pub install: bool,
}

impl Ranges {
    fn owns(&self, prefix: &Net6) -> bool {
        self.ranges.iter().any(|r| r.covers(prefix))
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Whether Kea holds an active IA_PD lease for exactly `prefix`.
/// `None` when Kea did not answer: no decision can be made.
async fn leased(kea: &Kea, vrf: &str, prefix: &Net6) -> Option<bool> {
    let args = json!({
        "ip-address": Ipv6Addr::from(prefix.addr).to_string(),
        "type": "IA_PD",
    });
    let reply = kea
        .command(Family::V6, vrf, "lease6-get", Some(args))
        .await
        .ok()?;
    Some(match kea::result(&reply) {
        0 => active(&reply["arguments"], prefix.len, now()),
        3 => false,
        _ => return None,
    })
}

/// An IA_PD lease (`lease6-get`'s arguments) that is current and of the
/// prefix length claimed.
pub fn active(lease: &Value, len: u8, now: i64) -> bool {
    let cltt = lease["cltt"].as_i64().unwrap_or(0);
    let lft = lease["valid-lft"].as_i64().unwrap_or(0);
    lease["type"].as_str() == Some("IA_PD")
        && lease["state"].as_i64() == Some(0)
        && lease["prefix-len"].as_u64() == Some(u64::from(len))
        && lft > 0
        && cltt + lft > now
}

fn vrf_args(vrf: &str) -> Vec<String> {
    if vrf == DEFAULT_VRF {
        vec!["table".into(), "main".into()]
    } else {
        vec!["vrf".into(), vrf.into()]
    }
}

async fn ip(args: &[String]) -> anyhow::Result<String> {
    let output = tokio::process::Command::new("ip")
        .args(args)
        .output()
        .await?;
    if !output.status.success() {
        anyhow::bail!(
            "ip {} exited {}: {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// `ip -6 route replace <prefix> via <via> dev <dev> proto dhcp`, in the
/// VRF's table.
async fn install(vrf: &str, prefix: &Net6, via: Ipv6Addr, dev: &str) -> anyhow::Result<()> {
    let mut args: Vec<String> = ["-6", "route", "replace"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    args.extend([
        prefix.to_prefix(),
        "via".into(),
        via.to_string(),
        "dev".into(),
        dev.to_string(),
        "proto".into(),
        "dhcp".into(),
    ]);
    args.extend(vrf_args(vrf));
    ip(&args).await.map(drop)
}

async fn remove(vrf: &str, prefix: &Net6) -> anyhow::Result<()> {
    let mut args: Vec<String> = ["-6", "route", "del"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    args.extend([prefix.to_prefix(), "proto".into(), "dhcp".into()]);
    args.extend(vrf_args(vrf));
    ip(&args).await.map(drop)
}

/// The `proto dhcp` routes of the VRF's table.
async fn dhcp_routes(vrf: &str) -> anyhow::Result<Vec<Net6>> {
    let mut args: Vec<String> = ["-6", "-j", "route", "show", "proto", "dhcp"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    args.extend(vrf_args(vrf));
    let text = ip(&args).await?;
    let routes: Value = serde_json::from_str(if text.trim().is_empty() { "[]" } else { &text })?;
    Ok(routes
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|r| r["dst"].as_str())
                .filter_map(Net6::parse)
                .collect()
        })
        .unwrap_or_default())
}

/// Act on one event of instance `vrf`.
pub fn handle(kea: &Arc<Kea>, vrf: &str, ranges: &Ranges, text: &str) {
    let event = parse(text);
    for claim in claims(&event) {
        let prefix = match &claim {
            Claim::Granted { prefix, .. } | Claim::Revoked { prefix } => *prefix,
        };
        if !ranges.owns(&prefix) {
            tracing::debug!(
                "kea-dhcp6 {vrf}: {} {} is outside every prefix-delegation range; ignored",
                event.hook,
                prefix.to_prefix()
            );
            continue;
        }
        let kea = Arc::clone(kea);
        let vrf = vrf.to_string();
        let install_routes = ranges.install;
        tokio::spawn(async move {
            match claim {
                Claim::Granted { prefix, via, dev } => {
                    if !install_routes {
                        return;
                    }
                    if leased(&kea, &vrf, &prefix).await != Some(true) {
                        tracing::warn!(
                            "kea-dhcp6 {vrf}: no active lease for {}; no route installed",
                            prefix.to_prefix()
                        );
                        return;
                    }
                    match install(&vrf, &prefix, via, &dev).await {
                        Ok(()) => tracing::info!(
                            "kea-dhcp6 {vrf}: route {} via {via} dev {dev} proto dhcp installed",
                            prefix.to_prefix()
                        ),
                        Err(err) => tracing::error!("kea-dhcp6 {vrf}: {err:#}"),
                    }
                }
                Claim::Revoked { prefix } => {
                    for delay in RECHECK {
                        tokio::time::sleep(delay).await;
                        if leased(&kea, &vrf, &prefix).await == Some(false) {
                            withdraw(&vrf, &prefix).await;
                            return;
                        }
                    }
                }
            }
        });
    }
}

async fn withdraw(vrf: &str, prefix: &Net6) {
    let present = dhcp_routes(vrf)
        .await
        .map(|routes| routes.contains(prefix))
        .unwrap_or(true);
    if !present {
        return;
    }
    match remove(vrf, prefix).await {
        Ok(()) => tracing::info!(
            "kea-dhcp6 {vrf}: route {} removed (no active lease)",
            prefix.to_prefix()
        ),
        Err(err) => tracing::error!("kea-dhcp6 {vrf}: {err:#}"),
    }
}

/// Remove the instance's routes that no active lease backs (all of them
/// when it does not install routes).
pub async fn sweep(kea: &Kea, vrf: &str, ranges: &Ranges) {
    let Ok(routes) = dhcp_routes(vrf).await else {
        return;
    };
    for prefix in routes.iter().filter(|p| ranges.owns(p)) {
        let keep = ranges.install && leased(kea, vrf, prefix).await != Some(false);
        if !keep {
            withdraw(vrf, prefix).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> Net6 {
        Net6::parse(s).unwrap()
    }

    #[test]
    fn committed_and_deleted() {
        let event = parse(
            "HOOK=leases6_committed\n\
             QUERY6_IFACE_NAME=lan1\n\
             QUERY6_REMOTE_ADDR=fe80::2\n\
             LEASES6_SIZE=2\n\
             LEASES6_AT0_TYPE=IA_NA\n\
             LEASES6_AT0_ADDRESS=2001:db8:1::100\n\
             LEASES6_AT0_PREFIX_LEN=128\n\
             LEASES6_AT1_TYPE=IA_PD\n\
             LEASES6_AT1_ADDRESS=2001:db8:8000:100::\n\
             LEASES6_AT1_PREFIX_LEN=56\n\
             DELETED_LEASES6_SIZE=1\n\
             DELETED_LEASES6_AT0_TYPE=IA_PD\n\
             DELETED_LEASES6_AT0_ADDRESS=2001:db8:8000:200::\n\
             DELETED_LEASES6_AT0_PREFIX_LEN=56\n",
        );
        assert_eq!(event.hook, "leases6_committed");
        assert_eq!(
            claims(&event),
            [
                Claim::Granted {
                    prefix: net("2001:db8:8000:100::/56"),
                    via: "fe80::2".parse().unwrap(),
                    dev: "lan1".into()
                },
                Claim::Revoked {
                    prefix: net("2001:db8:8000:200::/56")
                },
            ]
        );
    }

    #[test]
    fn single_lease_hooks() {
        let vars = "LEASE6_TYPE=IA_PD\nLEASE6_ADDRESS=2001:db8:8000:100::\nLEASE6_PREFIX_LEN=56\n";
        let expire = parse(&format!("HOOK=lease6_expire\n{vars}"));
        assert_eq!(
            claims(&expire),
            [Claim::Revoked {
                prefix: net("2001:db8:8000:100::/56")
            }]
        );
        // A renewal without the requester's address cannot be routed.
        let renew = parse(&format!("HOOK=lease6_renew\n{vars}"));
        assert!(claims(&renew).is_empty());
        let renew = parse(&format!(
            "HOOK=lease6_renew\nQUERY6_IFACE_NAME=lan1\nQUERY6_REMOTE_ADDR=fe80::2\n{vars}"
        ));
        assert_eq!(claims(&renew).len(), 1);
        // Address leases and unknown hooks claim nothing.
        let na = parse(
            "HOOK=lease6_release\nLEASE6_TYPE=IA_NA\nLEASE6_ADDRESS=2001:db8:1::100\nLEASE6_PREFIX_LEN=128\n",
        );
        assert!(claims(&na).is_empty());
        assert!(claims(&parse(&format!("HOOK=lease6_recover\n{vars}"))).is_empty());
    }

    #[test]
    fn ownership_and_activity() {
        let ranges = Ranges {
            ranges: vec![net("2001:db8:8000::/48")],
            install: true,
        };
        assert!(ranges.owns(&net("2001:db8:8000:100::/56")));
        assert!(!ranges.owns(&net("2001:db8:9000::/56")));
        assert!(!ranges.owns(&net("2001:db8::/32")));

        let lease: Value = serde_json::from_str(
            r#"{ "cltt": 1000, "valid-lft": 100, "state": 0, "type": "IA_PD", "prefix-len": 56 }"#,
        )
        .unwrap();
        assert!(active(&lease, 56, 1050));
        assert!(!active(&lease, 56, 1100));
        assert!(!active(&lease, 64, 1050));
        let mut reclaimed = lease.clone();
        reclaimed["state"] = json!(2);
        assert!(!active(&reclaimed, 56, 1050));
    }
}
