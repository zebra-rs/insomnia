//! `service dhcpv6-server` → `kea-dhcp6` configuration.
//!
//! A line-for-line port of VyOS's `kea-dhcp6.conf.j2` and the helpers
//! it calls (vyos-1x `python/vyos/kea.py` `kea6_parse_options`,
//! `kea6_parse_subnet`; `python/vyos/template.py`
//! `kea6_shared_network_json`). One render per instance, as in
//! `dhcp4.rs`, with VyOS's verify() rules as skip-with-warning.
//!
//! Deviations from VyOS, all deliberate:
//! - Kea never listens on `"*"` (DH8): with no `listen-interface`, the
//!   listen set is the shared-network and subnet `interface` leaves
//!   plus the interfaces of the instance's VRF that carry an address
//!   inside an enabled subnet. An interface joins only once its
//!   link-local address has finished duplicate address detection:
//!   kea-dhcp6 joins ff02::1:2 through a socket on that address, and
//!   when the bind fails on a tentative address it never retries and
//!   serves unicast only (design/dhcp.md §7.3). The address event that
//!   ends DAD re-renders and adds it;
//! - the server DUID is `EN`, persisted in the instance's state
//!   directory (`server-id`, `data-directory`), so it survives restarts
//!   and needs no interface at first start;
//! - delegated-prefix routes: the `run_script` hook calls insomnia's
//!   `kea-notify`, not VyOS's `on-dhcpv6-event.sh` with `sudo ip`
//!   (design/dhcp.md §7.5);
//! - `vendor-option cisco tftp-server` is rendered, as Kea's vendor
//!   option 17 for enterprise 9 (VyOS looks the leaf up under the wrong
//!   key and never renders it);
//! - `stat_cmds` is loaded, as for DHCPv4;
//! - an `interface` leaf naming an interface that does not exist is
//!   dropped with a warning (Kea would refuse the whole configuration);
//! - a subnet with no `interface` of its own or of its shared network
//!   gets the one interface of the VRF that carries an address inside
//!   it: Kea 2.4 selects a subnet for a directly connected client only
//!   by `interface`, and answers NoAddrsAvail otherwise (relayed
//!   requests are still selected by link-address).

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv6Addr};

use serde::Deserialize;
use serde_json::{Value, json};

use crate::dhcp_server::{Context, Instance, Mapping, Net6, Render, loggers};
use crate::json::{Flex, de_flex_vec, de_presence};
use crate::pd_routes::Ranges;

/// Cisco's enterprise number, for `vendor-option cisco`.
const CISCO: u32 = 9;

// ---------------------------------------------------------------
// Config model
// ---------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Server6Tree {
    #[serde(flatten)]
    pub default: Server6,
    pub vrf: Vec<Server6Vrf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Server6Vrf {
    pub name: Option<Flex>,
    #[serde(flatten)]
    pub server: Server6,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Server6 {
    #[serde(deserialize_with = "de_presence")]
    pub disable: bool,
    #[serde(deserialize_with = "de_presence")]
    pub disable_route_autoinstall: bool,
    #[serde(deserialize_with = "de_flex_vec")]
    pub listen_interface: Vec<Flex>,
    pub log_level: Option<Flex>,
    pub preference: Option<Flex>,
    pub global_parameters: Option<GlobalParameters>,
    pub shared_network_name: Vec<SharedNetwork6>,
}

impl Server6 {
    pub fn is_empty(&self) -> bool {
        self.shared_network_name.is_empty() && self.listen_interface.is_empty()
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct GlobalParameters {
    #[serde(deserialize_with = "de_flex_vec")]
    pub name_server: Vec<Flex>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct SharedNetwork6 {
    pub name: Option<Flex>,
    pub description: Option<Flex>,
    #[serde(deserialize_with = "de_presence")]
    pub disable: bool,
    pub interface: Option<Flex>,
    pub option: Option<Options6>,
    pub subnet: Vec<Subnet6>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Subnet6 {
    pub prefix: Option<Flex>,
    pub subnet_id: Option<Flex>,
    pub option: Option<Options6>,
    pub interface: Option<Flex>,
    pub lease_time: Option<LeaseTime>,
    pub range: Vec<Range6>,
    pub prefix_delegation: Option<PrefixDelegation>,
    pub static_mapping: Vec<StaticMapping6>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct LeaseTime {
    pub default: Option<Flex>,
    pub maximum: Option<Flex>,
    pub minimum: Option<Flex>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Range6 {
    pub name: Option<Flex>,
    pub prefix: Option<Flex>,
    pub start: Option<Flex>,
    pub stop: Option<Flex>,
    pub option: Option<Options6>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct PrefixDelegation {
    pub prefix: Vec<PdPrefix>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct PdPrefix {
    pub prefix: Option<Flex>,
    pub prefix_length: Option<Flex>,
    pub delegated_length: Option<Flex>,
    pub excluded_prefix: Option<Flex>,
    pub excluded_prefix_length: Option<Flex>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct StaticMapping6 {
    pub name: Option<Flex>,
    #[serde(deserialize_with = "de_presence")]
    pub disable: bool,
    pub mac: Option<Flex>,
    pub duid: Option<Flex>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub ipv6_address: Vec<Flex>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub ipv6_prefix: Vec<Flex>,
    pub option: Option<Options6>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Options6 {
    pub captive_portal: Option<Flex>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub domain_search: Vec<Flex>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub name_server: Vec<Flex>,
    pub capwap_controller: Option<Flex>,
    pub nis_domain: Option<Flex>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub nis_server: Vec<Flex>,
    pub nisplus_domain: Option<Flex>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub nisplus_server: Vec<Flex>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub sip_server: Vec<Flex>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub sntp_server: Vec<Flex>,
    pub info_refresh_time: Option<Flex>,
    pub time_zone: Option<Flex>,
    pub vendor_option: Option<VendorOption6>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct VendorOption6 {
    pub cisco: Option<Cisco>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Cisco {
    #[serde(deserialize_with = "de_flex_vec")]
    pub tftp_server: Vec<Flex>,
}

pub fn instances(tree: &Server6Tree) -> Vec<(String, &Server6)> {
    std::iter::once((crate::links::DEFAULT_VRF.to_string(), &tree.default))
        .chain(
            tree.vrf
                .iter()
                .filter_map(|v| v.name.as_ref().map(|n| (n.to_string(), &v.server))),
        )
        .collect()
}

// ---------------------------------------------------------------
// Options — kea6_options / kea6_parse_options
// ---------------------------------------------------------------

fn join(values: &[Flex]) -> String {
    values
        .iter()
        .map(Flex::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn options(opt: &Options6, ctx: &Context, scope: &str, warnings: &mut Vec<String>) -> Value {
    let mut out: Vec<Value> = Vec::new();
    let mut push = |name: &str, data: String| out.push(json!({ "name": name, "data": data }));
    if let Some(v) = &opt.info_refresh_time {
        push("information-refresh-time", v.to_string());
    }
    if !opt.name_server.is_empty() {
        push("dns-servers", join(&opt.name_server));
    }
    if !opt.domain_search.is_empty() {
        push("domain-search", join(&opt.domain_search));
    }
    if let Some(v) = &opt.nis_domain {
        push("nis-domain-name", v.to_string());
    }
    if !opt.nis_server.is_empty() {
        push("nis-servers", join(&opt.nis_server));
    }
    if let Some(v) = &opt.nisplus_domain {
        push("nisp-domain-name", v.to_string());
    }
    if !opt.nisplus_server.is_empty() {
        push("nisp-servers", join(&opt.nisplus_server));
    }
    if !opt.sntp_server.is_empty() {
        push("sntp-servers", join(&opt.sntp_server));
    }
    if let Some(v) = &opt.captive_portal {
        push("v6-captive-portal", v.to_string());
    }
    if let Some(v) = &opt.capwap_controller {
        push("capwap-ac-v6", v.to_string());
    }
    if !opt.sip_server.is_empty() {
        let (addrs, hosts): (Vec<String>, Vec<String>) = opt
            .sip_server
            .iter()
            .map(Flex::to_string)
            .partition(|s| s.parse::<Ipv6Addr>().is_ok());
        if !addrs.is_empty() {
            out.push(json!({ "name": "sip-server-addr", "data": addrs.join(", ") }));
        }
        if !hosts.is_empty() {
            out.push(json!({ "name": "sip-server-dns", "data": hosts.join(", ") }));
        }
    }
    if let Some(zone) = &opt.time_zone {
        let zone = zone.to_string();
        match (ctx.tz)(&zone) {
            Some(posix) => {
                out.push(
                    json!({ "name": "new-posix-timezone", "data": posix.replace(',', "\\,") }),
                );
                out.push(json!({ "name": "new-tzdb-timezone", "data": zone }));
            }
            None => warnings.push(format!(
                "{scope}: option time-zone {zone} skipped: no such time zone"
            )),
        }
    }
    if let Some(cisco) = opt.vendor_option.as_ref().and_then(|v| v.cisco.as_ref())
        && !cisco.tftp_server.is_empty()
    {
        if cisco.tftp_server.len() > 2 {
            warnings.push(format!(
                "{scope}: option vendor-option cisco tftp-server skipped: no more than two servers"
            ));
        } else {
            out.push(json!({ "name": "vendor-opts", "data": CISCO.to_string() }));
            out.push(json!({
                "name": "tftp-servers",
                "space": format!("vendor-{CISCO}"),
                "data": join(&cisco.tftp_server),
            }));
        }
    }
    Value::Array(out)
}

fn add_options(
    obj: &mut serde_json::Map<String, Value>,
    opt: Option<&Options6>,
    ctx: &Context,
    scope: &str,
    warnings: &mut Vec<String>,
) {
    if let Some(opt) = opt {
        obj.insert("option-data".into(), options(opt, ctx, scope, warnings));
    }
}

// ---------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------

fn scope(vrf: &str) -> String {
    if vrf == crate::links::DEFAULT_VRF {
        "service dhcpv6-server".to_string()
    } else {
        format!("service dhcpv6-server vrf {vrf}")
    }
}

fn v6(value: &Flex) -> Option<u128> {
    value.to_string().parse::<Ipv6Addr>().ok().map(u128::from)
}

fn u8_of(value: Option<&Flex>) -> Option<u8> {
    value.and_then(|v| v.to_string().parse().ok())
}

/// One instance → its Kea configuration.
pub fn render(server: &Server6, ctx: &Context) -> Render {
    let scope = scope(ctx.vrf);
    let mut warnings = Vec::new();
    let mut instance = Instance::default();
    let members: BTreeMap<String, u32> = ctx
        .links
        .members(ctx.vrf)
        .map(|l| (l.name.clone(), l.index))
        .collect();

    let mut networks: Vec<Value> = Vec::new();
    let mut ids = BTreeSet::new();
    let mut nets: Vec<Net6> = Vec::new();
    let mut named: BTreeSet<String> = BTreeSet::new();
    let mut delegated: Vec<Net6> = Vec::new();
    for network in &server.shared_network_name {
        let Some(name) = network.name.as_ref().map(Flex::to_string) else {
            continue;
        };
        if network.disable {
            continue;
        }
        let nscope = format!("{scope} shared-network-name {name}");
        if network.subnet.is_empty() {
            warnings.push(format!("{nscope} skipped: no subnet"));
            continue;
        }
        let mut subnets: Vec<Value> = Vec::new();
        for subnet in &network.subnet {
            let prefix = subnet
                .prefix
                .as_ref()
                .map(Flex::to_string)
                .unwrap_or_default();
            let sscope = format!("{nscope} subnet {prefix}");
            let Some((net, id, mut value, mappings, pd)) =
                render_subnet(subnet, &prefix, &sscope, ctx, &mut warnings)
            else {
                continue;
            };
            if !ids.insert(id) {
                warnings.push(format!(
                    "{sscope} skipped: subnet-id {id} is used by another subnet"
                ));
                continue;
            }
            if let Some(other) = nets.iter().find(|n| n.overlaps(&net)) {
                warnings.push(format!(
                    "{sscope} skipped: overlaps subnet {}",
                    other.to_prefix()
                ));
                ids.remove(&id);
                continue;
            }
            if let Some(ifname) = &subnet.interface {
                let ifname = ifname.to_string();
                if members.contains_key(&ifname) {
                    value
                        .as_object_mut()
                        .unwrap()
                        .insert("interface".into(), Value::String(ifname.clone()));
                    named.insert(ifname);
                } else {
                    warnings.push(format!(
                        "{sscope}: interface {ifname} does not exist{}; not set",
                        vrf_suffix(ctx.vrf)
                    ));
                }
            } else if network.interface.is_none() {
                // Kea selects a subnet for a directly connected client
                // only by its `interface`; name the one interface of the
                // VRF connected to the subnet.
                let connected: Vec<&String> = members
                    .iter()
                    .filter(|(_, index)| {
                        ctx.links.addrs_of(**index).any(|a| match a.addr {
                            IpAddr::V6(v6) => {
                                !v6.is_unicast_link_local() && net.contains(u128::from(v6))
                            }
                            IpAddr::V4(_) => false,
                        })
                    })
                    .map(|(name, _)| name)
                    .collect();
                if let [ifname] = connected.as_slice() {
                    value
                        .as_object_mut()
                        .unwrap()
                        .insert("interface".into(), Value::String((*ifname).clone()));
                }
            }
            delegated.extend(pd);
            nets.push(net);
            instance.subnets.insert(id, (name.clone(), net.to_prefix()));
            instance.mappings.extend(mappings.into_iter().map(|mut m| {
                m.pool = name.clone();
                m
            }));
            subnets.push(value);
        }
        if subnets.is_empty() {
            continue;
        }
        let mut obj = serde_json::Map::new();
        obj.insert("name".into(), Value::String(name.clone()));
        obj.insert("subnet6".into(), Value::Array(subnets));
        add_options(
            &mut obj,
            network.option.as_ref(),
            ctx,
            &nscope,
            &mut warnings,
        );
        if let Some(ifname) = &network.interface {
            let ifname = ifname.to_string();
            if members.contains_key(&ifname) {
                obj.insert("interface".into(), Value::String(ifname.clone()));
                named.insert(ifname);
            } else {
                warnings.push(format!(
                    "{nscope}: interface {ifname} does not exist{}; not set",
                    vrf_suffix(ctx.vrf)
                ));
            }
        }
        networks.push(Value::Object(obj));
        instance.pools.push(name);
    }

    let interfaces = listen_set(server, &nets, &named, ctx, &scope, &mut warnings);
    let mut serving = !server.disable && !networks.is_empty() && !interfaces.is_empty();
    if !server.disable && !networks.is_empty() && interfaces.is_empty() {
        warnings.push(format!(
            "{scope}: no interface to listen on (none carries an address in a configured subnet with a usable link-local address, and no listen-interface or interface is usable); not serving"
        ));
    }
    if server.disable || networks.is_empty() {
        serving = false;
    }
    // Whether delegated prefixes are routed follows the configuration,
    // not whether Kea serves at this moment: an interface that flaps (or
    // whose link-local is back in DAD) must not cost the clients their
    // routes. The sweep still removes routes Kea no longer backs.
    let install = !server.disable && !delegated.is_empty() && !server.disable_route_autoinstall;
    let pd = Ranges {
        ranges: delegated,
        install,
    };
    let (interfaces, networks) = if serving {
        (interfaces, networks)
    } else {
        instance = Instance::default();
        (Vec::new(), Vec::new())
    };

    let mut dhcp6 = serde_json::Map::new();
    dhcp6.insert(
        "interfaces-config".into(),
        json!({
            "interfaces": interfaces,
            "service-sockets-max-retries": 60,
            "service-sockets-retry-wait-time": 5000
        }),
    );
    dhcp6.insert(
        "control-socket".into(),
        json!({ "socket-type": "unix", "socket-name": ctx.socket }),
    );
    dhcp6.insert(
        "lease-database".into(),
        json!({ "type": "memfile", "persist": true, "name": ctx.lease_file }),
    );
    dhcp6.insert("data-directory".into(), Value::String(ctx.data_dir.clone()));
    dhcp6.insert("server-id".into(), json!({ "type": "EN", "persist": true }));
    let mut hooks = Vec::new();
    if serving && pd.install {
        hooks.push(json!({
            "library": ctx.hook("libdhcp_run_script.so"),
            "parameters": { "name": ctx.notify, "sync": false }
        }));
    }
    hooks.push(json!({ "library": ctx.hook("libdhcp_lease_cmds.so"), "parameters": {} }));
    hooks.push(json!({ "library": ctx.hook("libdhcp_stat_cmds.so"), "parameters": {} }));
    dhcp6.insert("hooks-libraries".into(), Value::Array(hooks));
    if networks
        .iter()
        .any(|n| n.to_string().contains("\"vendor-opts\""))
    {
        dhcp6.insert(
            "option-def".into(),
            json!([{
                "name": "tftp-servers",
                "code": 2,
                "space": format!("vendor-{CISCO}"),
                "type": "ipv6-address",
                "array": true
            }]),
        );
    }
    let mut global = Vec::new();
    if let Some(gp) = &server.global_parameters
        && !gp.name_server.is_empty()
    {
        global.push(json!({
            "name": "dns-servers",
            "code": 23,
            "space": "dhcp6",
            "csv-format": true,
            "data": join(&gp.name_server)
        }));
    }
    if let Some(pref) = &server.preference {
        global.push(json!({
            "name": "preference",
            "code": 7,
            "space": "dhcp6",
            "csv-format": true,
            "data": pref.to_string()
        }));
    }
    dhcp6.insert("option-data".into(), Value::Array(global));
    if !networks.is_empty() {
        dhcp6.insert("shared-networks".into(), Value::Array(networks));
    }
    dhcp6.insert(
        "loggers".into(),
        loggers("kea-dhcp6", server.log_level.as_ref()),
    );
    let config = json!({ "Dhcp6": Value::Object(dhcp6) });
    Render {
        text: serde_json::to_string_pretty(&config).unwrap_or_default() + "\n",
        serving,
        warnings,
        instance,
        pd,
    }
}

/// `(net, id, subnet6 entry, mappings, delegated prefixes)`.
type Rendered = (Net6, u32, Value, Vec<Mapping>, Vec<Net6>);

fn render_subnet(
    subnet: &Subnet6,
    prefix: &str,
    sscope: &str,
    ctx: &Context,
    warnings: &mut Vec<String>,
) -> Option<Rendered> {
    let Some(net) = Net6::parse(prefix) else {
        warnings.push(format!(
            "{sscope} skipped: not a network prefix (host bits set?)"
        ));
        return None;
    };
    let Some(id) = subnet
        .subnet_id
        .as_ref()
        .and_then(|v| v.to_string().parse::<u32>().ok())
    else {
        warnings.push(format!("{sscope} skipped: no subnet-id"));
        return None;
    };

    // Address ranges.
    let mut pools: Vec<Value> = Vec::new();
    let mut taken: Vec<(u128, u128)> = Vec::new();
    for range in &subnet.range {
        let rname = range.name.as_ref().map(Flex::to_string).unwrap_or_default();
        let rscope = format!("{sscope} range {rname}");
        let (pool, lo, hi) = if let Some(p) = &range.prefix {
            let Some(rnet) = Net6::parse(&p.to_string()) else {
                warnings.push(format!(
                    "{rscope} skipped: prefix {p} is not a network prefix"
                ));
                continue;
            };
            if !net.covers(&rnet) {
                warnings.push(format!("{rscope} skipped: not inside the subnet"));
                continue;
            }
            (rnet.to_prefix(), rnet.addr, rnet.addr | !rnet.mask())
        } else {
            let (Some(start), Some(stop)) = (
                range.start.as_ref().and_then(v6),
                range.stop.as_ref().and_then(v6),
            ) else {
                warnings.push(format!(
                    "{rscope} skipped: needs a prefix, or a start and a stop address"
                ));
                continue;
            };
            if !net.contains(start) || !net.contains(stop) {
                warnings.push(format!("{rscope} skipped: not inside the subnet"));
                continue;
            }
            if stop < start {
                warnings.push(format!("{rscope} skipped: stop is below start"));
                continue;
            }
            (
                format!("{} - {}", Ipv6Addr::from(start), Ipv6Addr::from(stop)),
                start,
                stop,
            )
        };
        if taken.iter().any(|&(a, b)| lo <= b && a <= hi) {
            warnings.push(format!("{rscope} skipped: overlaps another range"));
            continue;
        }
        taken.push((lo, hi));
        let mut obj = serde_json::Map::new();
        obj.insert("pool".into(), Value::String(pool));
        add_options(&mut obj, range.option.as_ref(), ctx, &rscope, warnings);
        pools.push(Value::Object(obj));
    }

    // Delegated prefixes.
    let mut pd_pools: Vec<Value> = Vec::new();
    let mut pd_nets: Vec<Net6> = Vec::new();
    for pd in subnet
        .prefix_delegation
        .as_ref()
        .map(|p| p.prefix.as_slice())
        .unwrap_or_default()
    {
        let p = pd.prefix.as_ref().map(Flex::to_string).unwrap_or_default();
        let pscope = format!("{sscope} prefix-delegation prefix {p}");
        let (Some(plen), Some(dlen)) = (
            u8_of(pd.prefix_length.as_ref()),
            u8_of(pd.delegated_length.as_ref()),
        ) else {
            warnings.push(format!(
                "{pscope} skipped: needs a prefix-length and a delegated-length"
            ));
            continue;
        };
        if plen > dlen {
            warnings.push(format!(
                "{pscope} skipped: prefix-length {plen} is longer than delegated-length {dlen}"
            ));
            continue;
        }
        let Some(pnet) = p.parse::<Ipv6Addr>().ok().and_then(|a| Net6::new(a, plen)) else {
            warnings.push(format!(
                "{pscope} skipped: {p}/{plen} is not a network prefix"
            ));
            continue;
        };
        if let Some(other) = pd_nets.iter().find(|n| n.overlaps(&pnet)) {
            warnings.push(format!(
                "{pscope} skipped: overlaps prefix {}",
                other.to_prefix()
            ));
            continue;
        }
        let mut obj = serde_json::Map::new();
        obj.insert(
            "prefix".into(),
            Value::String(Ipv6Addr::from(pnet.addr).to_string()),
        );
        obj.insert("prefix-len".into(), json!(plen));
        obj.insert("delegated-len".into(), json!(dlen));
        if let Some(ex) = &pd.excluded_prefix {
            let elen = u8_of(pd.excluded_prefix_length.as_ref());
            let enet = elen.and_then(|l| {
                ex.to_string()
                    .parse::<Ipv6Addr>()
                    .ok()
                    .and_then(|a| Net6::new(a, l))
            });
            match (elen, enet) {
                (None, _) => {
                    warnings.push(format!(
                        "{pscope} skipped: excluded-prefix needs an excluded-prefix-length"
                    ));
                    continue;
                }
                (Some(l), _) if l <= dlen => {
                    warnings.push(format!(
                        "{pscope} skipped: excluded-prefix-length {l} is not longer than delegated-length {dlen}"
                    ));
                    continue;
                }
                (Some(l), Some(e)) if pnet.covers(&e) => {
                    obj.insert("excluded-prefix".into(), Value::String(ex.to_string()));
                    obj.insert("excluded-prefix-len".into(), json!(l));
                }
                _ => {
                    warnings.push(format!(
                        "{pscope} skipped: excluded-prefix {ex} is not inside the prefix"
                    ));
                    continue;
                }
            }
        }
        pd_nets.push(pnet);
        pd_pools.push(Value::Object(obj));
    }

    // Static mappings.
    let mut reservations: Vec<Value> = Vec::new();
    let mut mappings = Vec::new();
    let (mut addrs_seen, mut prefixes_seen) = (BTreeSet::new(), BTreeSet::new());
    let (mut macs, mut duids) = (BTreeSet::new(), BTreeSet::new());
    'mapping: for mapping in &subnet.static_mapping {
        let host = mapping
            .name
            .as_ref()
            .map(Flex::to_string)
            .unwrap_or_default();
        if mapping.disable {
            continue;
        }
        let mscope = format!("{sscope} static-mapping {host}");
        let mac = mapping.mac.as_ref().map(|m| m.to_string().to_lowercase());
        let duid = mapping.duid.as_ref().map(|d| d.to_string().to_lowercase());
        if mac.is_some() == duid.is_some() {
            warnings.push(format!("{mscope} skipped: needs either a mac or a duid"));
            continue;
        }
        if mapping.ipv6_address.is_empty() && mapping.ipv6_prefix.is_empty() {
            warnings.push(format!(
                "{mscope} skipped: needs an ipv6-address or an ipv6-prefix"
            ));
            continue;
        }
        let mut addresses = Vec::new();
        for a in &mapping.ipv6_address {
            let Some(addr) = v6(a).filter(|&x| net.contains(x)) else {
                warnings.push(format!(
                    "{mscope} skipped: ipv6-address {a} is not inside the subnet"
                ));
                continue 'mapping;
            };
            if addrs_seen.contains(&addr) {
                warnings.push(format!(
                    "{mscope} skipped: ipv6-address {a} is used by another static mapping"
                ));
                continue 'mapping;
            }
            addresses.push(Ipv6Addr::from(addr).to_string());
        }
        let mut prefixes = Vec::new();
        for p in &mapping.ipv6_prefix {
            let p = p.to_string();
            if prefixes_seen.contains(&p) {
                warnings.push(format!(
                    "{mscope} skipped: ipv6-prefix {p} is used by another static mapping"
                ));
                continue 'mapping;
            }
            prefixes.push(p);
        }
        if let Some(m) = &mac
            && macs.contains(m)
        {
            warnings.push(format!(
                "{mscope} skipped: mac {m} is used by another static mapping"
            ));
            continue;
        }
        if let Some(d) = &duid
            && duids.contains(d)
        {
            warnings.push(format!(
                "{mscope} skipped: duid {d} is used by another static mapping"
            ));
            continue;
        }
        addrs_seen.extend(
            addresses
                .iter()
                .filter_map(|a| a.parse::<Ipv6Addr>().ok().map(u128::from)),
        );
        prefixes_seen.extend(prefixes.iter().cloned());
        macs.extend(mac.clone());
        duids.extend(duid.clone());
        let mut obj = serde_json::Map::new();
        obj.insert("hostname".into(), Value::String(host.clone()));
        if let Some(m) = &mac {
            obj.insert("hw-address".into(), Value::String(m.clone()));
        }
        if let Some(d) = &duid {
            obj.insert("duid".into(), Value::String(d.clone()));
        }
        if !addresses.is_empty() {
            obj.insert("ip-addresses".into(), json!(addresses));
        }
        if !prefixes.is_empty() {
            obj.insert("prefixes".into(), json!(prefixes));
        }
        add_options(&mut obj, mapping.option.as_ref(), ctx, &mscope, warnings);
        reservations.push(Value::Object(obj));
        mappings.push(Mapping {
            pool: String::new(),
            subnet: net.to_prefix(),
            hostname: host,
            addresses: addresses.into_iter().chain(prefixes).collect(),
            mac: mac.unwrap_or_default(),
            duid: duid.unwrap_or_default(),
            description: String::new(),
        });
    }

    let mut obj = serde_json::Map::new();
    obj.insert("subnet".into(), Value::String(net.to_prefix()));
    obj.insert("id".into(), json!(id));
    add_options(&mut obj, subnet.option.as_ref(), ctx, sscope, warnings);
    if !pools.is_empty() {
        obj.insert("pools".into(), Value::Array(pools));
    }
    if !pd_pools.is_empty() {
        obj.insert("pd-pools".into(), Value::Array(pd_pools));
    }
    if let Some(lt) = &subnet.lease_time {
        let n = |v: &Option<Flex>| v.as_ref().and_then(|v| v.to_string().parse::<u32>().ok());
        if let Some(v) = n(&lt.default) {
            obj.insert("valid-lifetime".into(), json!(v));
        }
        if let Some(v) = n(&lt.maximum) {
            obj.insert("max-valid-lifetime".into(), json!(v));
        }
        if let Some(v) = n(&lt.minimum) {
            obj.insert("min-valid-lifetime".into(), json!(v));
        }
    }
    if !reservations.is_empty() {
        obj.insert("reservations".into(), Value::Array(reservations));
    }
    Some((net, id, Value::Object(obj), mappings, pd_nets))
}

/// The listen set (DH8, design/dhcp.md §7.3): `listen-interface`, else
/// the `interface` leaves plus every interface of the instance's VRF
/// with an address inside a rendered subnet; in both cases only
/// interfaces whose link-local address has finished DAD.
fn listen_set(
    server: &Server6,
    nets: &[Net6],
    named: &BTreeSet<String>,
    ctx: &Context,
    scope: &str,
    warnings: &mut Vec<String>,
) -> Vec<String> {
    let links = ctx.links;
    let members: Vec<_> = links.members(ctx.vrf).collect();
    let ready = |index: u32| {
        links
            .addrs_of(index)
            .any(|a| matches!(a.addr, IpAddr::V6(v6) if v6.is_unicast_link_local()) && !a.tentative)
    };
    let mut out: BTreeMap<u32, String> = BTreeMap::new();
    if !server.listen_interface.is_empty() {
        for name in &server.listen_interface {
            let name = name.to_string();
            match members.iter().find(|l| l.name == name) {
                Some(link) if ready(link.index) => {
                    out.insert(link.index, name);
                }
                Some(_) => {}
                None => warnings.push(format!(
                    "{scope}: listen-interface {name} does not exist{}; dropped",
                    vrf_suffix(ctx.vrf)
                )),
            }
        }
        return out.into_values().collect();
    }
    for link in &members {
        let connected = links.addrs_of(link.index).any(|a| match a.addr {
            IpAddr::V6(v6) => nets.iter().any(|n| n.contains(u128::from(v6))),
            IpAddr::V4(_) => false,
        });
        if (connected || named.contains(&link.name)) && ready(link.index) {
            out.insert(link.index, link.name.clone());
        }
    }
    out.into_values().collect()
}

fn vrf_suffix(vrf: &str) -> String {
    if vrf == crate::links::DEFAULT_VRF {
        String::new()
    } else {
        format!(" in VRF {vrf}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dhcp_server::tests::{context, link, snapshot};

    fn ctx6<'a>(vrf: &'a str, links: &'a crate::links::Snapshot) -> Context<'a> {
        let mut ctx = context(vrf, links);
        ctx.socket = format!("/run/insomnia/kea/{vrf}/kea6-ctrl-socket");
        ctx.lease_file = format!("/var/lib/insomnia/kea/{vrf}/kea-leases6.csv");
        ctx
    }

    fn render_str(json: &str, links: &crate::links::Snapshot) -> Render {
        let tree: Server6Tree = serde_json::from_str(json).unwrap();
        render(&tree.default, &ctx6("default", links))
    }

    #[test]
    fn golden_render() {
        let links = snapshot(&[
            link(2, "lan1", None, &["fe80::1/64", "2001:db8:1::1/64"]),
            link(3, "lan2", None, &["fe80::2/64"]),
            link(4, "wan1", None, &["fe80::3/64", "2001:db8::1/64"]),
        ]);
        let json = r#"{
            "global-parameters": {"name-server": ["2001:db8::53"]},
            "preference": 10,
            "shared-network-name": [
                {"name":"LAN","interface":"lan2",
                 "option":{"domain-search": ["example.com"],"sip-server": ["2001:db8::5060","sip.example"]},
                 "subnet": [{"prefix":"2001:db8:1::/64","subnet-id":1,
                    "lease-time":{"default":3600,"maximum":7200},
                    "range": [{"name":0,"start":"2001:db8:1::100","stop":"2001:db8:1::1ff"},
                              {"name":1,"prefix":"2001:db8:1:0:8000::/65"}],
                    "prefix-delegation":{"prefix": [{"prefix":"2001:db8:8000::","delegated-length":56,"prefix-length":48}]},
                    "static-mapping": [{"name":"c1","duid":"00:03:00:01:02:00:00:00:00:01","ipv6-address": ["2001:db8:1::10"]}],
                    "option":{"name-server": ["2001:db8::54"],"vendor-option":{"cisco":{"tftp-server": ["2001:db8::69"]}}}}]}
            ]
        }"#;
        let r = render_str(json, &links);
        assert_eq!(r.warnings, Vec::<String>::new());
        assert!(r.serving);
        assert_eq!(
            r.text,
            r#"{
  "Dhcp6": {
    "interfaces-config": {
      "interfaces": [
        "lan1",
        "lan2"
      ],
      "service-sockets-max-retries": 60,
      "service-sockets-retry-wait-time": 5000
    },
    "control-socket": {
      "socket-type": "unix",
      "socket-name": "/run/insomnia/kea/default/kea6-ctrl-socket"
    },
    "lease-database": {
      "type": "memfile",
      "persist": true,
      "name": "/var/lib/insomnia/kea/default/kea-leases6.csv"
    },
    "data-directory": "/var/lib/insomnia/kea/default",
    "server-id": {
      "type": "EN",
      "persist": true
    },
    "hooks-libraries": [
      {
        "library": "/usr/lib/kea/hooks/libdhcp_run_script.so",
        "parameters": {
          "name": "/run/insomnia/kea/default/kea-notify",
          "sync": false
        }
      },
      {
        "library": "/usr/lib/kea/hooks/libdhcp_lease_cmds.so",
        "parameters": {}
      },
      {
        "library": "/usr/lib/kea/hooks/libdhcp_stat_cmds.so",
        "parameters": {}
      }
    ],
    "option-def": [
      {
        "name": "tftp-servers",
        "code": 2,
        "space": "vendor-9",
        "type": "ipv6-address",
        "array": true
      }
    ],
    "option-data": [
      {
        "name": "dns-servers",
        "code": 23,
        "space": "dhcp6",
        "csv-format": true,
        "data": "2001:db8::53"
      },
      {
        "name": "preference",
        "code": 7,
        "space": "dhcp6",
        "csv-format": true,
        "data": "10"
      }
    ],
    "shared-networks": [
      {
        "name": "LAN",
        "subnet6": [
          {
            "subnet": "2001:db8:1::/64",
            "id": 1,
            "option-data": [
              {
                "name": "dns-servers",
                "data": "2001:db8::54"
              },
              {
                "name": "vendor-opts",
                "data": "9"
              },
              {
                "name": "tftp-servers",
                "space": "vendor-9",
                "data": "2001:db8::69"
              }
            ],
            "pools": [
              {
                "pool": "2001:db8:1::100 - 2001:db8:1::1ff"
              },
              {
                "pool": "2001:db8:1:0:8000::/65"
              }
            ],
            "pd-pools": [
              {
                "prefix": "2001:db8:8000::",
                "prefix-len": 48,
                "delegated-len": 56
              }
            ],
            "valid-lifetime": 3600,
            "max-valid-lifetime": 7200,
            "reservations": [
              {
                "hostname": "c1",
                "duid": "00:03:00:01:02:00:00:00:00:01",
                "ip-addresses": [
                  "2001:db8:1::10"
                ]
              }
            ]
          }
        ],
        "option-data": [
          {
            "name": "domain-search",
            "data": "example.com"
          },
          {
            "name": "sip-server-addr",
            "data": "2001:db8::5060"
          },
          {
            "name": "sip-server-dns",
            "data": "sip.example"
          }
        ],
        "interface": "lan2"
      }
    ],
    "loggers": [
      {
        "name": "kea-dhcp6",
        "output_options": [
          {
            "output": "stdout",
            "pattern": "%-5p %m\n"
          }
        ],
        "severity": "INFO",
        "debuglevel": 0
      }
    ]
  }
}
"#
        );
        assert_eq!(r.instance.mappings[0].addresses, ["2001:db8:1::10"]);
    }

    /// A tentative link-local keeps the interface out until DAD ends;
    /// `disable-route-autoinstall` drops the run_script hook.
    #[test]
    fn listen_waits_for_dad_and_route_hook() {
        let (l, mut a) = link(2, "lan1", None, &["fe80::1/64", "2001:db8:1::1/64"]);
        a[0].tentative = true;
        let links = snapshot(&[(l, a)]);
        let json = r#"{"disable-route-autoinstall":null,"shared-network-name": [{"name":"LAN","subnet": [{"prefix":"2001:db8:1::/64","subnet-id":1,
            "range": [{"name":0,"start":"2001:db8:1::100","stop":"2001:db8:1::1ff"}],
            "prefix-delegation":{"prefix": [{"prefix":"2001:db8:8000::","delegated-length":56,"prefix-length":48}]}}]}]}"#;
        let r = render_str(json, &links);
        assert!(!r.serving);
        assert!(r.warnings[0].contains("no interface to listen on"));
        // Not serving for now: no hook, but the routes are not given up.
        assert!(!r.text.contains("run_script"));
        let tree: Server6Tree =
            serde_json::from_str(&json.replace("\"disable-route-autoinstall\":null,", "")).unwrap();
        let r = render(&tree.default, &ctx6("default", &links));
        assert!(!r.serving);
        assert!(r.pd.install);

        let links = snapshot(&[link(2, "lan1", None, &["fe80::1/64", "2001:db8:1::1/64"])]);
        let r = render_str(json, &links);
        assert!(r.serving);
        assert!(!r.text.contains("run_script"));
        assert!(r.text.contains("pd-pools"));
        assert_eq!(
            r.pd,
            Ranges {
                ranges: vec![Net6::parse("2001:db8:8000::/48").unwrap()],
                install: false
            }
        );
    }

    /// A directly connected subnet gets its interface named, unless the
    /// subnet or its shared network names one.
    #[test]
    fn connected_subnet_gets_interface() {
        let links = snapshot(&[
            link(2, "lan1", None, &["fe80::1/64", "2001:db8:1::1/64"]),
            link(3, "lan2", None, &["fe80::2/64", "2001:db8:2::1/64"]),
        ]);
        let json = r#"{"shared-network-name": [
            {"name":"A","subnet": [{"prefix":"2001:db8:1::/64","subnet-id":1,"range": [{"name":0,"start":"2001:db8:1::100","stop":"2001:db8:1::1ff"}]}]},
            {"name":"B","interface":"lan1","subnet": [{"prefix":"2001:db8:2::/64","subnet-id":2,"range": [{"name":0,"start":"2001:db8:2::100","stop":"2001:db8:2::1ff"}]}]}
        ]}"#;
        let r = render_str(json, &links);
        let v: Value = serde_json::from_str(&r.text).unwrap();
        let nets = &v["Dhcp6"]["shared-networks"];
        assert_eq!(nets[0]["subnet6"][0]["interface"], "lan1");
        assert_eq!(nets[1]["interface"], "lan1");
        assert!(nets[1]["subnet6"][0].get("interface").is_none());
    }

    #[test]
    fn skips_with_warnings() {
        let links = snapshot(&[link(2, "lan1", None, &["fe80::1/64", "2001:db8:1::1/64"])]);
        let json = r#"{"shared-network-name": [{"name":"LAN","subnet": [
            {"prefix":"2001:db8:1::/64","subnet-id":1,"interface":"eth9",
             "range": [
                {"name":"half","start":"2001:db8:1::100"},
                {"name":"out","prefix":"2001:db8:2::/80"},
                {"name":"a","start":"2001:db8:1::100","stop":"2001:db8:1::1ff"},
                {"name":"b","start":"2001:db8:1::1ff","stop":"2001:db8:1::2ff"}
             ],
             "prefix-delegation":{"prefix": [
                {"prefix":"2001:db8:8000::","prefix-length":56,"delegated-length":48},
                {"prefix":"2001:db8:9000::","prefix-length":48,"delegated-length":56,"excluded-prefix":"2001:db8:9000::","excluded-prefix-length":56}
             ]},
             "static-mapping": [
                {"name":"none","duid":"00:01"},
                {"name":"far","duid":"00:02","ipv6-address": ["2001:db8:2::1"]},
                {"name":"ok","duid":"00:03","ipv6-address": ["2001:db8:1::10"]},
                {"name":"dup","duid":"00:04","ipv6-address": ["2001:db8:1::10"]}
             ]},
            {"prefix":"2001:db8:1::/48","subnet-id":2}
        ]}]}"#;
        let r = render_str(json, &links);
        let n = "service dhcpv6-server shared-network-name LAN subnet";
        assert_eq!(
            r.warnings,
            [
                format!(
                    "{n} 2001:db8:1::/64 range half skipped: needs a prefix, or a start and a stop address"
                ),
                format!("{n} 2001:db8:1::/64 range out skipped: not inside the subnet"),
                format!("{n} 2001:db8:1::/64 range b skipped: overlaps another range"),
                format!(
                    "{n} 2001:db8:1::/64 prefix-delegation prefix 2001:db8:8000:: skipped: prefix-length 56 is longer than delegated-length 48"
                ),
                format!(
                    "{n} 2001:db8:1::/64 prefix-delegation prefix 2001:db8:9000:: skipped: excluded-prefix-length 56 is not longer than delegated-length 56"
                ),
                format!(
                    "{n} 2001:db8:1::/64 static-mapping none skipped: needs an ipv6-address or an ipv6-prefix"
                ),
                format!(
                    "{n} 2001:db8:1::/64 static-mapping far skipped: ipv6-address 2001:db8:2::1 is not inside the subnet"
                ),
                format!(
                    "{n} 2001:db8:1::/64 static-mapping dup skipped: ipv6-address 2001:db8:1::10 is used by another static mapping"
                ),
                format!("{n} 2001:db8:1::/64: interface eth9 does not exist; not set"),
                format!("{n} 2001:db8:1::/48 skipped: overlaps subnet 2001:db8:1::/64"),
            ]
        );
        assert!(r.serving);
    }
}
