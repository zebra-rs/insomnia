//! VyOS-derived DHCP relay → insomnia-dhcp-relay backend.
//!
//! Consumes the `/service/dhcp-relay` and `/service/dhcpv6-relay`
//! config subtrees as JSON batches (see `ConfigManager::subscribe_json`):
//! every commit that touches a subtree delivers the whole post-commit
//! tree in one message. The backend deserializes both into
//! [`Relay4Tree`] / [`Relay6Tree`], renders one `relay.json` for the
//! relay agent (`dhcp_relay::config`, the agent's own types) and hands
//! it to [`Relayd::apply`]. This mirrors VyOS, which re-renders
//! dhcrelay's command line on every commit (vyos-1x
//! `data/templates/dhcp-relay/dhcrelay{,6}.conf.j2`); the agent
//! replaces ISC dhcrelay (design/dhcp.md §5, §10).
//!
//! Nothing is rendered until both subtrees have delivered their
//! snapshot, so a reconnect or an insomnia restart never reloads the
//! agent with one family missing.
//!
//! VyOS's verify() rules become warnings, and what fails one is
//! skipped; the rest is still served:
//! - an instance needs a `server` (v4), and an upstream interface with
//!   an address (v6);
//! - it needs both a listen and an upstream interface;
//! - a DHCPv6 upstream interface without an address is dropped;
//! - `lo` is refused as a DHCPv4 listen or upstream interface;
//! - an interface may be a listen interface of one instance only.
//!
//! VyOS also refuses a DHCPv6 listen interface without a global
//! address at commit time. That is live state, so the agent checks it
//! per request instead and counts `no-link-address` drops.
//!
//! Deviations from VyOS, all deliberate:
//! - `vrf <name>` instances (VyOS has no per-VRF relay): the same
//!   leaves, relayed through sockets bound to that VRF;
//! - option 82 is always added to DHCPv4 requests, as VyOS's
//!   `dhcrelay -a` does, but replies are accepted on a listen interface
//!   only from a configured server that is also upstream there
//!   (the agent's v4.rs and v6.rs);
//! - `show dhcp relay statistics` / `show dhcpv6 relay statistics` are
//!   extensions; VyOS has no relay counters.

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use dhcp_relay::config::{AgentPolicy, Binding4, Binding6, Config, DEFAULT_VRF, Server6};
use serde::Deserialize;
use tokio::sync::mpsc;

use crate::api::ShowRequest;
use crate::json::{Flex, de_flex_vec, de_presence};
use crate::process::Applied;
use crate::relayd::Relayd;
use crate::text::table;

/// Running-config subtrees this backend subscribes to.
const V4_PATH: &[&str] = &["service", "dhcp-relay"];
const V6_PATH: &[&str] = &["service", "dhcpv6-relay"];

/// VyOS defaults (`relay-options` and `max-hop-count`).
const DEFAULT_HOP_COUNT: u8 = 10;
const DEFAULT_MAX_SIZE: u16 = 576;

/// The last snapshot or commit of each subtree; `None` until the
/// current subscription delivered it.
#[derive(Default)]
struct Trees {
    v4: Option<Relay4Tree>,
    v6: Option<Relay6Tree>,
}

/// Backend task: JSON subscriptions to both relay subtrees (snapshot
/// first, then one whole-subtree batch per touching commit) selected
/// with the show orders the provider routes here. Reconnects with
/// backoff when either stream drops; the fresh snapshots re-render
/// relay.json, and an unchanged file is not reloaded.
pub async fn run(host: String, relayd: Arc<Relayd>, mut show_rx: mpsc::Receiver<ShowRequest>) {
    loop {
        let mut v4 = crate::subscribe::subscribe_json(&host, V4_PATH).await;
        let mut v6 = crate::subscribe::subscribe_json(&host, V6_PATH).await;
        let mut trees = Trees::default();
        loop {
            tokio::select! {
                msg = v4.message() => match msg {
                    Ok(Some(event)) => {
                        trees.v4 = parse("dhcp-relay", &event.json);
                        apply(&relayd, &trees).await;
                    }
                    Ok(None) => break,
                    Err(err) => {
                        tracing::warn!("dhcp-relay: subscription error: {err}");
                        break;
                    }
                },
                msg = v6.message() => match msg {
                    Ok(Some(event)) => {
                        trees.v6 = parse("dhcpv6-relay", &event.json);
                        apply(&relayd, &trees).await;
                    }
                    Ok(None) => break,
                    Err(err) => {
                        tracing::warn!("dhcpv6-relay: subscription error: {err}");
                        break;
                    }
                },
                Some(req) = show_rx.recv() => process_show(&relayd, req).await,
            }
        }
        tracing::warn!("dhcp-relay: subscription ended; reconnecting");
        tokio::time::sleep(crate::endpoint::RECONNECT_DELAY).await;
    }
}

/// A subtree that does not deserialize keeps the agent on its current
/// config: rendering it as empty would stop relaying.
fn parse<T: for<'de> Deserialize<'de> + Default>(tree: &str, json: &str) -> Option<T> {
    match serde_json::from_str(json) {
        Ok(model) => Some(model),
        Err(err) => {
            tracing::error!("{tree}: config parse failed: {err}");
            None
        }
    }
}

async fn apply(relayd: &Relayd, trees: &Trees) {
    let (Some(v4), Some(v6)) = (&trees.v4, &trees.v6) else {
        return;
    };
    let (config, warnings) = render(v4, v6);
    for warn in &warnings {
        tracing::warn!("dhcp-relay: {warn}");
    }
    let empty = config.dhcp4.is_empty() && config.dhcp6.is_empty();
    let text = match serde_json::to_string_pretty(&config) {
        Ok(text) => text + "\n",
        Err(err) => {
            tracing::error!("dhcp-relay: rendering relay.json failed: {err}");
            return;
        }
    };
    match relayd.apply(&text, empty).await {
        Ok(Applied::Loaded) => tracing::info!(
            "dhcp-relay: relay agent loaded {} DHCPv4 and {} DHCPv6 listen interfaces",
            config.dhcp4.len(),
            config.dhcp6.len()
        ),
        Ok(Applied::Unchanged) => tracing::info!("dhcp-relay: relay configuration unchanged"),
        Ok(Applied::Stopped) => {
            tracing::info!("dhcp-relay: relay agent stopped (no configuration)")
        }
        Ok(Applied::Held) => tracing::info!(
            "dhcp-relay: relay agent stopped by an operator (stop process); configuration written, not loaded"
        ),
        Ok(Applied::NotRunning) => tracing::warn!(
            "dhcp-relay: relay agent not running; configuration rendered to {} but not loaded",
            relayd.conf().display()
        ),
        Err(err) => tracing::error!("dhcp-relay: relay agent apply failed: {err:#}"),
    }
}

// ---------------------------------------------------------------
// Config model
//
// Deserialized from `Config::json()` output with the shared helpers
// in `super::json` (numeric-looking scalars → `Flex`, `type empty` →
// `de_presence`, leaf-lists → `de_flex_vec`). Each tree holds the
// default-VRF leaves inline and the per-VRF copies under `vrf`.
// ---------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Relay4Tree {
    #[serde(flatten)]
    pub default: Relay4,
    pub vrf: Vec<Relay4Vrf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Relay4Vrf {
    pub name: Option<Flex>,
    #[serde(flatten)]
    pub relay: Relay4,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Relay4 {
    #[serde(deserialize_with = "de_presence")]
    pub disable: bool,
    #[serde(deserialize_with = "de_flex_vec")]
    pub listen_interface: Vec<Flex>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub upstream_interface: Vec<Flex>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub server: Vec<Flex>,
    pub relay_options: RelayOptions,
}

impl Relay4 {
    fn is_empty(&self) -> bool {
        self.listen_interface.is_empty()
            && self.upstream_interface.is_empty()
            && self.server.is_empty()
            && self.relay_options.hop_count.is_none()
            && self.relay_options.max_size.is_none()
            && self.relay_options.relay_agents_packets.is_none()
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct RelayOptions {
    pub hop_count: Option<Flex>,
    pub max_size: Option<Flex>,
    pub relay_agents_packets: Option<Flex>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Relay6Tree {
    #[serde(flatten)]
    pub default: Relay6,
    pub vrf: Vec<Relay6Vrf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Relay6Vrf {
    pub name: Option<Flex>,
    #[serde(flatten)]
    pub relay: Relay6,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Relay6 {
    #[serde(deserialize_with = "de_presence")]
    pub disable: bool,
    pub listen_interface: Vec<Listen6>,
    pub upstream_interface: Vec<Upstream6>,
    pub max_hop_count: Option<Flex>,
    #[serde(deserialize_with = "de_presence")]
    pub use_interface_id_option: bool,
}

impl Relay6 {
    fn is_empty(&self) -> bool {
        self.listen_interface.is_empty()
            && self.upstream_interface.is_empty()
            && self.max_hop_count.is_none()
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Listen6 {
    pub name: Option<Flex>,
    pub address: Option<Flex>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Upstream6 {
    pub name: Option<Flex>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub address: Vec<Flex>,
}

// ---------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------

/// Both trees → the agent's config, plus a warning for everything
/// skipped.
pub fn render(v4: &Relay4Tree, v6: &Relay6Tree) -> (Config, Vec<String>) {
    let mut config = Config::default();
    let mut warnings = Vec::new();

    let mut seen = BTreeSet::new();
    let v4_instances = std::iter::once((DEFAULT_VRF.to_string(), &v4.default)).chain(
        v4.vrf
            .iter()
            .filter_map(|v| v.name.as_ref().map(|n| (n.to_string(), &v.relay))),
    );
    for (vrf, relay) in v4_instances {
        render4(&vrf, relay, &mut seen, &mut config, &mut warnings);
    }

    let mut seen = BTreeSet::new();
    let v6_instances = std::iter::once((DEFAULT_VRF.to_string(), &v6.default)).chain(
        v6.vrf
            .iter()
            .filter_map(|v| v.name.as_ref().map(|n| (n.to_string(), &v.relay))),
    );
    for (vrf, relay) in v6_instances {
        render6(&vrf, relay, &mut seen, &mut config, &mut warnings);
    }
    (config, warnings)
}

/// `service dhcp-relay` or `service dhcp-relay vrf red`, for warnings.
fn scope(tree: &str, vrf: &str) -> String {
    if vrf == DEFAULT_VRF {
        format!("service {tree}")
    } else {
        format!("service {tree} vrf {vrf}")
    }
}

fn render4(
    vrf: &str,
    relay: &Relay4,
    seen: &mut BTreeSet<String>,
    config: &mut Config,
    warnings: &mut Vec<String>,
) {
    if relay.disable || relay.is_empty() {
        return;
    }
    let scope = scope("dhcp-relay", vrf);

    let mut servers = Vec::new();
    for server in &relay.server {
        match server.to_string().parse::<Ipv4Addr>() {
            Ok(addr) => servers.push(addr),
            Err(_) => warnings.push(format!("{scope}: server {server}: not an IPv4 address")),
        }
    }
    let interfaces = |list: &[Flex], what: &str, warnings: &mut Vec<String>| -> Vec<String> {
        list.iter()
            .map(|i| i.to_string())
            .filter(|name| {
                let lo = name == "lo";
                if lo {
                    warnings.push(format!(
                        "{scope}: {what} lo: the loopback interface is not supported; skipped"
                    ));
                }
                !lo
            })
            .collect()
    };
    let listen = interfaces(&relay.listen_interface, "listen-interface", warnings);
    let upstream = interfaces(&relay.upstream_interface, "upstream-interface", warnings);
    if servers.is_empty() {
        warnings.push(format!("{scope}: no server configured; skipped"));
        return;
    }
    if listen.is_empty() {
        warnings.push(format!("{scope}: no listen-interface configured; skipped"));
        return;
    }
    if upstream.is_empty() {
        warnings.push(format!(
            "{scope}: no upstream-interface configured; skipped"
        ));
        return;
    }

    let options = &relay.relay_options;
    let hop_count = number(
        options.hop_count.as_ref(),
        1,
        DEFAULT_HOP_COUNT,
        &scope,
        "hop-count",
        warnings,
    );
    let max_size = number(
        options.max_size.as_ref(),
        64,
        DEFAULT_MAX_SIZE,
        &scope,
        "max-size",
        warnings,
    );
    let policy = match options.relay_agents_packets.as_ref().map(|p| p.to_string()) {
        None => AgentPolicy::Forward,
        Some(p) => match p.as_str() {
            "forward" => AgentPolicy::Forward,
            "append" => AgentPolicy::Append,
            "replace" => AgentPolicy::Replace,
            "discard" => AgentPolicy::Discard,
            other => {
                warnings.push(format!(
                    "{scope}: relay-agents-packets {other}: unknown; using forward"
                ));
                AgentPolicy::Forward
            }
        },
    };

    for interface in listen {
        if !seen.insert(interface.clone()) {
            warnings.push(format!(
                "{scope}: listen-interface {interface} already relays for another instance; skipped"
            ));
            continue;
        }
        config.dhcp4.push(Binding4 {
            vrf: vrf.to_string(),
            interface,
            servers: servers.clone(),
            upstream_interfaces: upstream.clone(),
            hop_count,
            max_size,
            // VyOS always runs `dhcrelay -a`.
            agent_information: true,
            relay_agents_packets: policy,
        });
    }
}

fn render6(
    vrf: &str,
    relay: &Relay6,
    seen: &mut BTreeSet<String>,
    config: &mut Config,
    warnings: &mut Vec<String>,
) {
    if relay.disable || relay.is_empty() {
        return;
    }
    let scope = scope("dhcpv6-relay", vrf);

    let mut servers = Vec::new();
    for upstream in &relay.upstream_interface {
        let Some(name) = upstream.name.as_ref().map(|n| n.to_string()) else {
            continue;
        };
        if upstream.address.is_empty() {
            warnings.push(format!(
                "{scope}: upstream-interface {name} has no address; skipped"
            ));
            continue;
        }
        for address in &upstream.address {
            match address.to_string().parse::<Ipv6Addr>() {
                Ok(address) => servers.push(Server6 {
                    address,
                    interface: Some(name.clone()),
                }),
                Err(_) => warnings.push(format!(
                    "{scope}: upstream-interface {name} address {address}: not an IPv6 address"
                )),
            }
        }
    }
    if servers.is_empty() {
        warnings.push(format!(
            "{scope}: no upstream-interface with an address; skipped"
        ));
        return;
    }
    if relay.listen_interface.is_empty() {
        warnings.push(format!("{scope}: no listen-interface configured; skipped"));
        return;
    }
    let max_hop_count = number(
        relay.max_hop_count.as_ref(),
        1,
        DEFAULT_HOP_COUNT,
        &scope,
        "max-hop-count",
        warnings,
    );

    for listen in &relay.listen_interface {
        let Some(interface) = listen.name.as_ref().map(|n| n.to_string()) else {
            continue;
        };
        let link_address = match &listen.address {
            None => None,
            Some(address) => match address.to_string().parse::<Ipv6Addr>() {
                Ok(address) => Some(address),
                Err(_) => {
                    warnings.push(format!(
                        "{scope}: listen-interface {interface} address {address}: not an IPv6 address; using the interface's"
                    ));
                    None
                }
            },
        };
        if !seen.insert(interface.clone()) {
            warnings.push(format!(
                "{scope}: listen-interface {interface} already relays for another instance; skipped"
            ));
            continue;
        }
        config.dhcp6.push(Binding6 {
            vrf: vrf.to_string(),
            interface,
            link_address,
            servers: servers.clone(),
            max_hop_count,
            interface_id: relay.use_interface_id_option,
        });
    }
}

/// A numeric leaf at least `min`, or `default` when unset. The schema
/// enforces the ranges; anything else falls back with a warning.
fn number<T>(
    value: Option<&Flex>,
    min: T,
    default: T,
    scope: &str,
    leaf: &str,
    warnings: &mut Vec<String>,
) -> T
where
    T: std::str::FromStr + PartialOrd + std::fmt::Display + Copy,
{
    let Some(value) = value else {
        return default;
    };
    match value.to_string().parse::<T>() {
        Ok(n) if n >= min => n,
        _ => {
            warnings.push(format!(
                "{scope}: {leaf} {value}: out of range; using {default}"
            ));
            default
        }
    }
}

// ---------------------------------------------------------------
// Show
// ---------------------------------------------------------------

async fn process_show(relayd: &Relayd, req: ShowRequest) {
    let (family, label) = match req.path.as_str() {
        "/show/dhcp/relay/statistics" => ("dhcp4", "DHCP"),
        "/show/dhcpv6/relay/statistics" => ("dhcp6", "DHCPv6"),
        _ => {
            let _ = req.resp.send(String::from("% Unknown dhcp show command\n"));
            return;
        }
    };
    let out = match relayd.stats().await {
        Ok(stats) => {
            let rows = stats[family].as_array().cloned().unwrap_or_default();
            if req.json {
                format!("{:#}\n", serde_json::Value::Array(rows))
            } else {
                statistics_text(&rows, family == "dhcp4")
            }
        }
        Err(err) => {
            tracing::debug!("dhcp-relay: statistics: {err:#}");
            if req.json {
                "[]\n".to_string()
            } else {
                format!("{label} relay statistics are not available (relay agent not running)\n")
            }
        }
    };
    let _ = req.resp.send(out);
}

/// One row per VRF and interface: requests count on their listen
/// interface, replies on the interface they arrived on. Then the drops
/// by reason, when there are any.
fn statistics_text(rows: &[serde_json::Value], v4: bool) -> String {
    if rows.is_empty() {
        return "No relay traffic\n".to_string();
    }
    let count = |row: &serde_json::Value, key: &str| row[key].as_u64().unwrap_or(0).to_string();
    let mut headers = vec![
        "VRF",
        "Interface",
        "Received",
        "Forwarded",
        "Dropped",
        "Send errors",
    ];
    if v4 {
        headers.push("No option 82");
    }
    let mut lines = Vec::new();
    let mut drops = Vec::new();
    for row in rows {
        let vrf = row["vrf"].as_str().unwrap_or_default().to_string();
        let interface = row["interface"].as_str().unwrap_or_default().to_string();
        let dropped = row["dropped"].as_object();
        let total: u64 = dropped
            .map(|d| d.values().filter_map(|v| v.as_u64()).sum())
            .unwrap_or(0);
        let mut line = vec![
            vrf.clone(),
            interface.clone(),
            count(row, "received"),
            count(row, "forwarded"),
            total.to_string(),
            count(row, "send-errors"),
        ];
        if v4 {
            line.push(count(row, "agent-option-omitted"));
        }
        lines.push(line);
        for (reason, n) in dropped.into_iter().flatten() {
            drops.push(vec![
                vrf.clone(),
                interface.clone(),
                reason.clone(),
                n.as_u64().unwrap_or(0).to_string(),
            ]);
        }
    }
    let mut out = table(&headers, &lines);
    if !drops.is_empty() {
        out.push('\n');
        out.push_str(&table(&["VRF", "Interface", "Dropped", "Count"], &drops));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The JSON zebra-rs delivers for the two subtrees, verbatim from
    /// its `dhcp_relay_json_marshal_contract` test.
    const V4_JSON: &str = r#"{"listen-interface": ["eth1","eth2"],"relay-options":{"hop-count":4,"relay-agents-packets":"replace"},"server": ["192.0.2.10","192.0.2.11"],"upstream-interface": ["eth0"],"vrf": [{"name":"red","disable":null,"listen-interface": ["eth3"],"server": ["198.51.100.10"],"upstream-interface": ["eth4"]}]}"#;
    const V6_JSON: &str = r#"{"listen-interface": [{"name":"eth1","address":"2001:db8:1::1"},{"name":"eth2"}],"max-hop-count":8,"upstream-interface": [{"name":"eth0","address": ["2001:db8::10","ff05::1:3"]}],"use-interface-id-option":null,"vrf": [{"name":"red","listen-interface": [{"name":"eth3"}],"upstream-interface": [{"name":"eth4","address": ["2001:db8:4::10"]}]}]}"#;

    fn render_str(v4: &str, v6: &str) -> (Config, Vec<String>) {
        let v4: Relay4Tree = serde_json::from_str(v4).unwrap();
        let v6: Relay6Tree = serde_json::from_str(v6).unwrap();
        render(&v4, &v6)
    }

    /// The marshal contract renders to exactly this relay.json, and the
    /// agent's own parser accepts it without a warning.
    #[test]
    fn golden_render() {
        let (config, warnings) = render_str(V4_JSON, V6_JSON);
        assert!(warnings.is_empty(), "{warnings:?}");
        let text = serde_json::to_string_pretty(&config).unwrap();
        assert_eq!(
            text,
            r#"{
  "dhcp4": [
    {
      "vrf": "default",
      "interface": "eth1",
      "servers": [
        "192.0.2.10",
        "192.0.2.11"
      ],
      "upstream-interfaces": [
        "eth0"
      ],
      "hop-count": 4,
      "max-size": 576,
      "agent-information": true,
      "relay-agents-packets": "replace"
    },
    {
      "vrf": "default",
      "interface": "eth2",
      "servers": [
        "192.0.2.10",
        "192.0.2.11"
      ],
      "upstream-interfaces": [
        "eth0"
      ],
      "hop-count": 4,
      "max-size": 576,
      "agent-information": true,
      "relay-agents-packets": "replace"
    }
  ],
  "dhcp6": [
    {
      "vrf": "default",
      "interface": "eth1",
      "link-address": "2001:db8:1::1",
      "servers": [
        {
          "address": "2001:db8::10",
          "interface": "eth0"
        },
        {
          "address": "ff05::1:3",
          "interface": "eth0"
        }
      ],
      "max-hop-count": 8,
      "interface-id": true
    },
    {
      "vrf": "default",
      "interface": "eth2",
      "servers": [
        {
          "address": "2001:db8::10",
          "interface": "eth0"
        },
        {
          "address": "ff05::1:3",
          "interface": "eth0"
        }
      ],
      "max-hop-count": 8,
      "interface-id": true
    },
    {
      "vrf": "red",
      "interface": "eth3",
      "servers": [
        {
          "address": "2001:db8:4::10",
          "interface": "eth4"
        }
      ],
      "max-hop-count": 10,
      "interface-id": false
    }
  ]
}"#
        );
        // The disabled v4 VRF instance renders nothing.
        assert!(config.dhcp4.iter().all(|b| b.vrf == "default"));
        let (parsed, agent_warnings) = Config::parse(&text).unwrap();
        assert!(agent_warnings.is_empty(), "{agent_warnings:?}");
        assert_eq!(parsed, config);
    }

    #[test]
    fn empty_and_disabled() {
        let (config, warnings) = render_str("{}", "{}");
        assert_eq!(config, Config::default());
        assert!(warnings.is_empty());
        let (config, warnings) = render_str(
            r#"{"disable":null,"listen-interface":["eth1"],"server":["192.0.2.10"],"upstream-interface":["eth0"]}"#,
            r#"{"disable":null,"listen-interface":[{"name":"eth1"}],"upstream-interface":[{"name":"eth0","address":["2001:db8::10"]}]}"#,
        );
        assert_eq!(config, Config::default());
        assert!(warnings.is_empty());
    }

    /// VyOS's verify() rules, as warnings with the instance skipped.
    #[test]
    fn verify_rules_skip_with_warning() {
        let cases = [
            (
                r#"{"listen-interface":["eth1"],"upstream-interface":["eth0"]}"#,
                "service dhcp-relay: no server configured; skipped",
            ),
            (
                r#"{"server":["192.0.2.10"],"upstream-interface":["eth0"]}"#,
                "service dhcp-relay: no listen-interface configured; skipped",
            ),
            (
                r#"{"server":["192.0.2.10"],"listen-interface":["eth1"]}"#,
                "service dhcp-relay: no upstream-interface configured; skipped",
            ),
            (
                r#"{"relay-options":{"hop-count":4}}"#,
                "service dhcp-relay: no server configured; skipped",
            ),
        ];
        for (v4, want) in cases {
            let (config, warnings) = render_str(v4, "{}");
            assert!(config.dhcp4.is_empty(), "{v4}");
            assert_eq!(warnings, [want], "{v4}");
        }

        let cases = [
            (
                r#"{"listen-interface":[{"name":"eth1"}],"upstream-interface":[{"name":"eth0"}]}"#,
                vec![
                    "service dhcpv6-relay: upstream-interface eth0 has no address; skipped",
                    "service dhcpv6-relay: no upstream-interface with an address; skipped",
                ],
            ),
            (
                r#"{"upstream-interface":[{"name":"eth0","address":["2001:db8::10"]}]}"#,
                vec!["service dhcpv6-relay: no listen-interface configured; skipped"],
            ),
        ];
        for (v6, want) in cases {
            let (config, warnings) = render_str("{}", v6);
            assert!(config.dhcp6.is_empty(), "{v6}");
            assert_eq!(warnings, want, "{v6}");
        }
    }

    /// `lo` is dropped, the rest of the instance served; an interface
    /// claimed by two instances goes to the first.
    #[test]
    fn loopback_and_duplicates() {
        let (config, warnings) = render_str(
            r#"{"listen-interface":["lo","eth1"],"server":["192.0.2.10"],"upstream-interface":["eth0"],
                "vrf":[{"name":"red","listen-interface":["eth1"],"server":["192.0.2.20"],"upstream-interface":["eth4"]}]}"#,
            r#"{"listen-interface":[{"name":"eth1"}],"upstream-interface":[{"name":"eth0","address":["2001:db8::10"]}],
                "vrf":[{"name":"red","listen-interface":[{"name":"eth1"},{"name":"eth5"}],"upstream-interface":[{"name":"eth4","address":["2001:db8:4::10"]}]}]}"#,
        );
        let v4: Vec<(&str, &str)> = config
            .dhcp4
            .iter()
            .map(|b| (b.vrf.as_str(), b.interface.as_str()))
            .collect();
        assert_eq!(v4, [("default", "eth1")]);
        let v6: Vec<(&str, &str)> = config
            .dhcp6
            .iter()
            .map(|b| (b.vrf.as_str(), b.interface.as_str()))
            .collect();
        assert_eq!(v6, [("default", "eth1"), ("red", "eth5")]);
        assert_eq!(
            warnings,
            [
                "service dhcp-relay: listen-interface lo: the loopback interface is not supported; skipped",
                "service dhcp-relay vrf red: listen-interface eth1 already relays for another instance; skipped",
                "service dhcpv6-relay vrf red: listen-interface eth1 already relays for another instance; skipped",
            ]
        );
    }

    #[test]
    fn defaults_follow_vyos() {
        let (config, _) = render_str(
            r#"{"listen-interface":["eth1"],"server":["192.0.2.10"],"upstream-interface":["eth0"]}"#,
            "{}",
        );
        let b = &config.dhcp4[0];
        assert_eq!((b.hop_count, b.max_size), (10, 576));
        assert_eq!(b.relay_agents_packets, AgentPolicy::Forward);
        assert!(b.agent_information);
    }

    #[test]
    fn statistics_table() {
        let rows: Vec<serde_json::Value> = serde_json::from_str(
            r#"[{"vrf":"default","interface":"r0","received":4,"forwarded":4,"send-errors":0,"agent-option-omitted":0,"dropped":{}},
                {"vrf":"default","interface":"r1","received":5,"forwarded":4,"send-errors":0,"agent-option-omitted":1,"dropped":{"wrong-upstream":1}}]"#,
        )
        .unwrap();
        assert_eq!(
            statistics_text(&rows, true),
            "\
VRF      Interface  Received  Forwarded  Dropped  Send errors  No option 82
-------  ---------  --------  ---------  -------  -----------  ------------
default  r0         4         4          0        0            0
default  r1         5         4          1        0            1

VRF      Interface  Dropped         Count
-------  ---------  --------------  -----
default  r1         wrong-upstream  1
"
        );
        assert_eq!(statistics_text(&[], false), "No relay traffic\n");
    }
}
