//! `relay.json`: what the relay serves.
//!
//! insomnia renders this file from the running config and sends
//! `SIGHUP`; the daemon never talks to zebra-rs. The format is
//! deliberately independent of the config schema: one *binding* per
//! listen (downstream, client-facing) interface, each carrying its own
//! upstream targets and relay options.
//!
//! - VyOS's `service dhcp-relay` (one server list and one option set for
//!   every listen interface) renders as one binding per
//!   `listen-interface`, all with the same `servers`,
//!   `upstream-interfaces` and options. `service dhcpv6-relay` renders
//!   one binding per `listen-interface`, its servers being every
//!   `upstream-interface <if> address <a>` pair.
//! - A per-interface server-group model (an interface bound to a named
//!   group of server addresses) renders each binding from its group.
//!
//! ```json
//! {
//!   "dhcp4": [
//!     {
//!       "vrf": "default",
//!       "interface": "eth1",
//!       "servers": ["192.0.2.10", "192.0.2.11"],
//!       "upstream-interfaces": ["eth0"],
//!       "hop-count": 10,
//!       "max-size": 576,
//!       "agent-information": true,
//!       "relay-agents-packets": "forward"
//!     }
//!   ],
//!   "dhcp6": [
//!     {
//!       "vrf": "default",
//!       "interface": "eth1",
//!       "link-address": "2001:db8:1::1",
//!       "servers": [
//!         { "address": "2001:db8::547", "interface": "eth0" },
//!         { "address": "ff05::1:3", "interface": "eth0" }
//!       ],
//!       "max-hop-count": 10,
//!       "interface-id": false
//!     }
//!   ]
//! }
//! ```
//!
//! | Field | Default | Meaning |
//! |:--|:--|:--|
//! | `vrf` | `"default"` | VRF of the listen interface. Upstream traffic uses a socket bound to the VRF device of that name; `default` is the main table |
//! | `interface` | required | Listen interface. Unique per family and VRF |
//! | `servers` (v4) | required, non-empty | Every BOOTREQUEST is unicast to each, UDP 67 |
//! | `upstream-interfaces` (v4) | `[]` | Accept BOOTREPLYs only when they arrive on one of these; empty accepts any interface in the VRF that is not a listen interface. A listen interface listed here accepts replies from `servers` only |
//! | `hop-count` (v4) | 10 | Drop a request whose `hops` is already at this value; 1–255 |
//! | `max-size` (v4) | 576 | Never grow a request past this many bytes (before BOOTP padding) by adding option 82 |
//! | `agent-information` (v4) | `true` | Add option 82 (circuit ID = `interface`) and strip it from replies |
//! | `relay-agents-packets` (v4) | `"forward"` | A request already carrying option 82: `forward` unchanged, `append` ours, `replace` it, or `discard` the request |
//! | `link-address` (v6) | first global address of `interface` | Relay-forw `link-address` for client messages |
//! | `servers` (v6) | required, non-empty | `address`, and `interface` to send through; `interface` is required for link-local and multicast addresses. When every server has one, Relay-repl is accepted only there. A listen interface accepts Relay-repl only from a unicast server pinned to it |
//! | `max-hop-count` (v6) | 10 | Drop a Relay-forw from a downstream relay at this hop count; 1–255 |
//! | `interface-id` (v6) | `false` | Add Interface-ID (18) = `interface` to Relay-forw; always added when relaying another relay's Relay-forw |
//!
//! Unknown fields are ignored, so a newer insomnia can render fields an
//! older relay binary does not know yet. A binding that fails
//! validation is skipped with a warning and the others are served.

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use serde::Deserialize;

pub const DEFAULT_VRF: &str = "default";

/// Linux interface names are at most 15 bytes (IFNAMSIZ - 1).
const IFNAME_MAX: usize = 15;

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    #[serde(default)]
    pub dhcp4: Vec<Binding4>,
    #[serde(default)]
    pub dhcp6: Vec<Binding6>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct Binding4 {
    #[serde(default = "default_vrf")]
    pub vrf: String,
    pub interface: String,
    pub servers: Vec<Ipv4Addr>,
    #[serde(default)]
    pub upstream_interfaces: Vec<String>,
    #[serde(default = "default_hops")]
    pub hop_count: u8,
    #[serde(default = "default_max_size")]
    pub max_size: u16,
    #[serde(default = "default_true")]
    pub agent_information: bool,
    #[serde(default)]
    pub relay_agents_packets: AgentPolicy,
}

/// What to do with a request that already carries option 82 (VyOS
/// `relay-options relay-agents-packets`, `dhcrelay -m`).
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AgentPolicy {
    #[default]
    Forward,
    Append,
    Replace,
    Discard,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct Binding6 {
    #[serde(default = "default_vrf")]
    pub vrf: String,
    pub interface: String,
    #[serde(default)]
    pub link_address: Option<Ipv6Addr>,
    pub servers: Vec<Server6>,
    #[serde(default = "default_hops")]
    pub max_hop_count: u8,
    #[serde(default)]
    pub interface_id: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct Server6 {
    pub address: Ipv6Addr,
    #[serde(default)]
    pub interface: Option<String>,
}

fn default_vrf() -> String {
    DEFAULT_VRF.to_string()
}

fn default_hops() -> u8 {
    10
}

fn default_max_size() -> u16 {
    576
}

fn default_true() -> bool {
    true
}

impl Config {
    /// Reads and validates `path`. A missing file is an empty config: the
    /// relay starts before insomnia has rendered anything.
    pub fn load(path: &Path) -> anyhow::Result<(Config, Vec<String>)> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok((Config::default(), Vec::new()));
            }
            Err(e) => return Err(anyhow::anyhow!("{}: {e}", path.display())),
        };
        Config::parse(&text)
    }

    /// Parses and validates. A syntax error fails the whole file; a bad
    /// binding is dropped and named in the returned warnings.
    pub fn parse(text: &str) -> anyhow::Result<(Config, Vec<String>)> {
        let mut config: Config = serde_json::from_str(text)?;
        let mut warnings = Vec::new();
        let mut seen = BTreeSet::new();
        config.dhcp4.retain(|b| {
            let problem = check_names(&b.vrf, &b.interface)
                .or_else(|| b.servers.is_empty().then(|| "no servers".to_string()))
                .or_else(|| (b.hop_count == 0).then(|| "hop-count 0".to_string()))
                .or_else(|| {
                    b.upstream_interfaces
                        .iter()
                        .find(|i| !valid_ifname(i))
                        .map(|i| format!("bad upstream interface name {i:?}"))
                })
                .or_else(|| check_unique(&b.interface, &mut seen));
            keep(
                problem,
                "dhcp4",
                b.vrf.as_str(),
                b.interface.as_str(),
                &mut warnings,
            )
        });
        let mut seen = BTreeSet::new();
        config.dhcp6.retain_mut(|b| {
            let (vrf, interface) = (b.vrf.clone(), b.interface.clone());
            b.servers.retain(|s| {
                let problem = match &s.interface {
                    Some(i) if !valid_ifname(i) => Some(format!("bad interface name {i:?}")),
                    None if needs_interface(&s.address) => {
                        Some("link-local or multicast address without an interface".to_string())
                    }
                    _ => None,
                };
                if let Some(problem) = &problem {
                    warnings.push(format!(
                        "dhcp6 {vrf}/{interface}: server {} skipped: {problem}",
                        s.address
                    ));
                }
                problem.is_none()
            });
            let problem = check_names(&b.vrf, &b.interface)
                .or_else(|| {
                    b.servers
                        .is_empty()
                        .then(|| "no usable servers".to_string())
                })
                .or_else(|| (b.max_hop_count == 0).then(|| "max-hop-count 0".to_string()))
                .or_else(|| check_unique(&b.interface, &mut seen));
            keep(problem, "dhcp6", &vrf, &interface, &mut warnings)
        });
        Ok((config, warnings))
    }
}

fn check_names(vrf: &str, interface: &str) -> Option<String> {
    if !valid_ifname(vrf) {
        return Some(format!("bad vrf name {vrf:?}"));
    }
    if !valid_ifname(interface) {
        return Some(format!("bad interface name {interface:?}"));
    }
    None
}

/// Last check, so only a binding that is otherwise served claims its
/// interface. An interface belongs to one VRF, so the name is the key.
fn check_unique(interface: &str, seen: &mut BTreeSet<String>) -> Option<String> {
    (!seen.insert(interface.to_string())).then(|| "duplicate binding".to_string())
}

fn keep(
    problem: Option<String>,
    family: &str,
    vrf: &str,
    interface: &str,
    warnings: &mut Vec<String>,
) -> bool {
    match problem {
        Some(problem) => {
            warnings.push(format!("{family} {vrf}/{interface}: skipped: {problem}"));
            false
        }
        None => true,
    }
}

pub fn valid_ifname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= IFNAME_MAX
        && !name.contains(['/', ':'])
        && !name.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// Addresses that do not say which link to use on their own.
fn needs_interface(addr: &Ipv6Addr) -> bool {
    addr.is_multicast() || addr.is_unicast_link_local()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_doc_example() {
        let text = r#"{
          "dhcp4": [
            {
              "vrf": "default",
              "interface": "eth1",
              "servers": ["192.0.2.10", "192.0.2.11"],
              "upstream-interfaces": ["eth0"],
              "hop-count": 10,
              "max-size": 576,
              "agent-information": true,
              "relay-agents-packets": "forward"
            }
          ],
          "dhcp6": [
            {
              "vrf": "default",
              "interface": "eth1",
              "link-address": "2001:db8:1::1",
              "servers": [
                { "address": "2001:db8::547", "interface": "eth0" },
                { "address": "ff05::1:3", "interface": "eth0" }
              ],
              "max-hop-count": 10,
              "interface-id": false
            }
          ]
        }"#;
        let (config, warnings) = Config::parse(text).unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(config.dhcp4.len(), 1);
        assert_eq!(config.dhcp6[0].servers.len(), 2);
    }

    #[test]
    fn defaults() {
        let (config, _) = Config::parse(
            r#"{"dhcp4": [{"interface": "eth1", "servers": ["192.0.2.10"]}],
                "dhcp6": [{"interface": "eth1", "servers": [{"address": "2001:db8::1"}]}],
                "some-future-field": 1}"#,
        )
        .unwrap();
        let b = &config.dhcp4[0];
        assert_eq!(b.vrf, "default");
        assert!(b.upstream_interfaces.is_empty());
        assert_eq!((b.hop_count, b.max_size), (10, 576));
        assert!(b.agent_information);
        assert_eq!(b.relay_agents_packets, AgentPolicy::Forward);
        let b = &config.dhcp6[0];
        assert_eq!(b.link_address, None);
        assert_eq!(b.max_hop_count, 10);
        assert!(!b.interface_id);
        assert_eq!(Config::parse("{}").unwrap().0, Config::default());
    }

    #[test]
    fn bad_bindings_are_skipped() {
        let (config, warnings) = Config::parse(
            r#"{"dhcp4": [
                  {"interface": "eth1", "servers": []},
                  {"interface": "eth2", "servers": ["192.0.2.1"], "hop-count": 0},
                  {"interface": "eth3", "servers": ["192.0.2.1"]},
                  {"interface": "eth3", "servers": ["192.0.2.2"]},
                  {"interface": "a-very-long-interface", "servers": ["192.0.2.1"]},
                  {"interface": "eth4", "servers": ["192.0.2.1"], "upstream-interfaces": [""]}
                ],
                "dhcp6": [
                  {"interface": "eth1", "servers": [{"address": "ff05::1:3"}]},
                  {"interface": "eth2", "servers": [{"address": "ff05::1:3"},
                                                    {"address": "2001:db8::1"}]}
                ]}"#,
        )
        .unwrap();
        let v4: Vec<&str> = config.dhcp4.iter().map(|b| b.interface.as_str()).collect();
        assert_eq!(v4, ["eth3"]);
        assert_eq!(
            config.dhcp4[0].servers,
            ["192.0.2.1".parse::<Ipv4Addr>().unwrap()]
        );
        let v6: Vec<&str> = config.dhcp6.iter().map(|b| b.interface.as_str()).collect();
        assert_eq!(v6, ["eth2"]);
        assert_eq!(config.dhcp6[0].servers.len(), 1);
        assert_eq!(warnings.len(), 8, "{warnings:#?}");
    }

    #[test]
    fn syntax_error_fails() {
        assert!(Config::parse("{").is_err());
        assert!(Config::parse(r#"{"dhcp4": [{"interface": "eth1"}]}"#).is_err());
        assert!(Config::parse(r#"{"dhcp4": [{"interface": "eth1", "servers": ["x"]}]}"#).is_err());
    }
}
