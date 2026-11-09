//! `service dhcp-server` → `kea-dhcp4` configuration.
//!
//! A line-for-line port of VyOS's `kea-dhcp4.conf.j2` and the helpers
//! it calls (vyos-1x `python/vyos/kea.py` `kea_parse_options`,
//! `kea_parse_subnet`, `kea_build_client_class_test`;
//! `python/vyos/template.py` `kea_shared_network_json`,
//! `kea_client_class_json`, `kea_address_json`; the `exclude` slicing of
//! `src/conf_mode/service_dhcp-server.py` `dhcp_slice_range`). One
//! render per instance: the default VRF's leaves, or one `vrf <name>`
//! entry's.
//!
//! VyOS's verify() rules become skip-with-warning (design/dhcp.md §7.6).
//! Skipping never widens who is served: a range or subnet naming a
//! client class that is missing, disabled or unusable is skipped, not
//! served to every client.
//!
//! Deviations from VyOS, all deliberate:
//! - Kea never listens on `"*"` (DH8): with neither `listen-address`
//!   nor `listen-interface`, the listen set is the interfaces of the
//!   instance's VRF that carry an address inside an enabled subnet;
//!   with nothing to listen on, nothing is served;
//! - option 121 is rendered as raw RFC 3442 data, because Kea 2.4.1 has
//!   no `classless-static-route` definition; `default-router` is
//!   appended as `0.0.0.0/0`, as VyOS does;
//! - `stat_cmds` is loaded beside `lease_cmds`, for
//!   `show dhcp server statistics`;
//! - no `ping-check`, DDNS, `hostfile-update` or high availability
//!   (not in the schema; dhcp.yang's module description says why), so
//!   no `user-context` either;
//! - ranges sliced around `exclude` addresses keep their client class
//!   (VyOS's slices keep only the options);
//! - `bootfile-server` becomes `next-server` only when it is an IPv4
//!   address, which is all Kea accepts there;
//! - paths: the control socket, lease file and hooks are insomnia's
//!   (kea.rs), not `/run/kea` and `/config/dhcp`.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

use serde::Deserialize;
use serde_json::{Value, json};

use crate::dhcp_server::{Context, Instance, Mapping, Net4, Render, client_class_test, loggers};
use crate::json::{Flex, de_flex_vec, de_presence};

/// VyOS's `lease` default.
const DEFAULT_LEASE: u32 = 86400;

// ---------------------------------------------------------------
// Config model
// ---------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Server4Tree {
    #[serde(flatten)]
    pub default: Server4,
    pub vrf: Vec<Server4Vrf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Server4Vrf {
    pub name: Option<Flex>,
    #[serde(flatten)]
    pub server: Server4,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Server4 {
    #[serde(deserialize_with = "de_presence")]
    pub disable: bool,
    #[serde(deserialize_with = "de_flex_vec")]
    pub listen_address: Vec<Flex>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub listen_interface: Vec<Flex>,
    pub log_level: Option<Flex>,
    pub client_class: Vec<ClientClass>,
    pub shared_network_name: Vec<SharedNetwork4>,
}

impl Server4 {
    pub fn is_empty(&self) -> bool {
        self.shared_network_name.is_empty()
            && self.client_class.is_empty()
            && self.listen_address.is_empty()
            && self.listen_interface.is_empty()
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct ClientClass {
    pub name: Option<Flex>,
    #[serde(deserialize_with = "de_presence")]
    pub disable: bool,
    pub relay_agent_information: Option<RelayAgentInformation>,
    pub hostname: Option<ClassMatch>,
    pub vendor_class_id: Option<ClassMatch>,
    pub option: Option<Options4>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct RelayAgentInformation {
    pub circuit_id: Option<Flex>,
    pub remote_id: Option<Flex>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct ClassMatch {
    pub value: Option<Flex>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct SharedNetwork4 {
    pub name: Option<Flex>,
    #[serde(deserialize_with = "de_presence")]
    pub authoritative: bool,
    pub description: Option<Flex>,
    #[serde(deserialize_with = "de_presence")]
    pub disable: bool,
    pub option: Option<Options4>,
    pub subnet: Vec<Subnet4>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Subnet4 {
    pub prefix: Option<Flex>,
    pub subnet_id: Option<Flex>,
    pub option: Option<Options4>,
    pub client_class: Option<Flex>,
    pub description: Option<Flex>,
    #[serde(deserialize_with = "de_presence")]
    pub disable: bool,
    #[serde(deserialize_with = "de_flex_vec")]
    pub exclude: Vec<Flex>,
    #[serde(deserialize_with = "de_presence")]
    pub ignore_client_id: bool,
    pub lease: Option<Flex>,
    pub range: Vec<Range4>,
    pub static_mapping: Vec<StaticMapping4>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Range4 {
    pub name: Option<Flex>,
    pub start: Option<Flex>,
    pub stop: Option<Flex>,
    pub client_class: Option<Flex>,
    pub option: Option<Options4>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct StaticMapping4 {
    pub name: Option<Flex>,
    pub ip_address: Option<Flex>,
    pub mac: Option<Flex>,
    pub duid: Option<Flex>,
    pub description: Option<Flex>,
    #[serde(deserialize_with = "de_presence")]
    pub disable: bool,
    pub option: Option<Options4>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Options4 {
    pub captive_portal: Option<Flex>,
    pub domain_name: Option<Flex>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub domain_search: Vec<Flex>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub ntp_server: Vec<Flex>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub name_server: Vec<Flex>,
    pub bootfile_name: Option<Flex>,
    pub bootfile_server: Option<Flex>,
    pub bootfile_size: Option<Flex>,
    pub client_prefix_length: Option<Flex>,
    pub capwap_controller: Option<Flex>,
    pub default_router: Option<Flex>,
    pub interface_mtu: Option<Flex>,
    #[serde(deserialize_with = "de_presence")]
    pub ip_forwarding: bool,
    pub ipv6_only_preferred: Option<Flex>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub pop_server: Vec<Flex>,
    pub server_identifier: Option<Flex>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub smtp_server: Vec<Flex>,
    pub static_route: Vec<StaticRoute>,
    pub tftp_server_name: Option<Flex>,
    pub time_offset: Option<Flex>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub time_server: Vec<Flex>,
    pub time_zone: Option<Flex>,
    pub vendor_option: Option<VendorOption4>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub wins_server: Vec<Flex>,
    pub wpad_url: Option<Flex>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct StaticRoute {
    pub prefix: Option<Flex>,
    pub next_hop: Option<Flex>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct VendorOption4 {
    pub ubiquiti: Option<Ubiquiti>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Ubiquiti {
    pub unifi_controller: Option<Flex>,
}

/// Every instance of the tree: the default VRF first, then each `vrf`
/// entry.
pub fn instances(tree: &Server4Tree) -> Vec<(String, &Server4)> {
    std::iter::once((crate::links::DEFAULT_VRF.to_string(), &tree.default))
        .chain(
            tree.vrf
                .iter()
                .filter_map(|v| v.name.as_ref().map(|n| (n.to_string(), &v.server))),
        )
        .collect()
}

// ---------------------------------------------------------------
// Options — kea4_options / kea_parse_options
// ---------------------------------------------------------------

fn join(values: &[Flex]) -> String {
    values
        .iter()
        .map(Flex::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// `option-data`, plus `boot-file-name` / `next-server` for the
/// element that carries the options.
fn options(opt: &Options4, ctx: &Context, scope: &str, warnings: &mut Vec<String>) -> Value {
    let mut out: Vec<Value> = Vec::new();
    let mut push = |name: &str, data: String| out.push(json!({ "name": name, "data": data }));
    // kea4_options, in its order.
    if !opt.name_server.is_empty() {
        push("domain-name-servers", join(&opt.name_server));
    }
    if let Some(v) = &opt.domain_name {
        push("domain-name", v.to_string());
    }
    if !opt.domain_search.is_empty() {
        push("domain-search", join(&opt.domain_search));
    }
    if !opt.ntp_server.is_empty() {
        push("ntp-servers", join(&opt.ntp_server));
    }
    if !opt.pop_server.is_empty() {
        push("pop-server", join(&opt.pop_server));
    }
    if !opt.smtp_server.is_empty() {
        push("smtp-server", join(&opt.smtp_server));
    }
    if !opt.time_server.is_empty() {
        push("time-servers", join(&opt.time_server));
    }
    if !opt.wins_server.is_empty() {
        push("netbios-name-servers", join(&opt.wins_server));
    }
    if let Some(v) = &opt.default_router {
        push("routers", v.to_string());
    }
    if let Some(v) = &opt.server_identifier {
        push("dhcp-server-identifier", v.to_string());
    }
    if let Some(v) = &opt.tftp_server_name {
        push("tftp-server-name", v.to_string());
    }
    if let Some(v) = &opt.bootfile_size {
        push("boot-size", v.to_string());
    }
    if let Some(v) = &opt.time_offset {
        push("time-offset", v.to_string());
    }
    if let Some(v) = &opt.wpad_url {
        push("wpad-url", v.to_string());
    }
    if let Some(v) = &opt.ipv6_only_preferred {
        push("v6-only-preferred", v.to_string());
    }
    if let Some(v) = &opt.captive_portal {
        push("v4-captive-portal", v.to_string());
    }
    if let Some(v) = &opt.capwap_controller {
        push("capwap-ac-v4", v.to_string());
    }
    if let Some(v) = &opt.interface_mtu {
        push("interface-mtu", v.to_string());
    }
    if let Some(v) = &opt.bootfile_name {
        push("boot-file-name", v.to_string());
    }
    if let Some(len) = opt
        .client_prefix_length
        .as_ref()
        .and_then(|v| v.to_string().parse::<u8>().ok())
        .filter(|&len| len <= 32)
    {
        push("subnet-mask", Ipv4Addr::from(prefix_mask(len)).to_string());
    }
    if opt.ip_forwarding {
        push("ip-forwarding", "true".to_string());
    }
    if !opt.static_route.is_empty() {
        match classless_static_routes(&opt.static_route, opt.default_router.as_ref()) {
            Ok(data) => out.push(json!({ "code": 121, "csv-format": false, "data": data })),
            Err(err) => warnings.push(format!("{scope}: option static-route skipped: {err}")),
        }
    }
    if let Some(zone) = &opt.time_zone {
        let zone = zone.to_string();
        match (ctx.tz)(&zone) {
            Some(posix) => {
                out.push(json!({ "name": "pcode", "data": posix.replace(',', "\\,") }));
                out.push(json!({ "name": "tcode", "data": zone }));
            }
            None => warnings.push(format!(
                "{scope}: option time-zone {zone} skipped: no such time zone"
            )),
        }
    }
    if let Some(controller) = opt
        .vendor_option
        .as_ref()
        .and_then(|v| v.ubiquiti.as_ref())
        .and_then(|u| u.unifi_controller.as_ref())
    {
        out.push(json!({ "name": "vendor-encapsulated-options" }));
        out.push(json!({
            "name": "ubnt",
            "data": controller.to_string(),
            "space": "vendor-encapsulated-options-space",
        }));
    }
    Value::Array(out)
}

/// Add `option-data`, `boot-file-name` and `next-server` to `obj`.
fn add_options(
    obj: &mut serde_json::Map<String, Value>,
    opt: Option<&Options4>,
    ctx: &Context,
    scope: &str,
    warnings: &mut Vec<String>,
) {
    let Some(opt) = opt else {
        return;
    };
    obj.insert("option-data".into(), options(opt, ctx, scope, warnings));
    if let Some(name) = &opt.bootfile_name {
        obj.insert("boot-file-name".into(), Value::String(name.to_string()));
    }
    if let Some(server) = &opt.bootfile_server {
        match server.to_string().parse::<Ipv4Addr>() {
            Ok(addr) => {
                obj.insert("next-server".into(), Value::String(addr.to_string()));
            }
            Err(_) => warnings.push(format!(
                "{scope}: option bootfile-server {server}: next-server must be an IPv4 address; not set"
            )),
        }
    }
}

fn prefix_mask(len: u8) -> u32 {
    if len == 0 { 0 } else { u32::MAX << (32 - len) }
}

/// Option 121 (RFC 3442) as hex: per route a width octet, the
/// significant octets of the destination, then the router. A
/// `default-router` is appended as the `0.0.0.0/0` route, because a
/// client that honours option 121 ignores option 3.
pub fn classless_static_routes(
    routes: &[StaticRoute],
    default_router: Option<&Flex>,
) -> Result<String, String> {
    let mut bytes = Vec::new();
    let mut add = |net: Net4, router: Ipv4Addr| {
        bytes.push(net.len);
        let octets = net.addr.to_be_bytes();
        bytes.extend_from_slice(&octets[..usize::from(net.len).div_ceil(8)]);
        bytes.extend_from_slice(&router.octets());
    };
    for route in routes {
        let prefix = route
            .prefix
            .as_ref()
            .map(Flex::to_string)
            .unwrap_or_default();
        let net = Net4::parse(&prefix).ok_or(format!("{prefix} is not a network prefix"))?;
        let hop = route
            .next_hop
            .as_ref()
            .map(Flex::to_string)
            .unwrap_or_default();
        let router = hop
            .parse::<Ipv4Addr>()
            .map_err(|_| format!("{prefix} next-hop {hop:?} is not an IPv4 address"))?;
        add(net, router);
    }
    if let Some(router) = default_router {
        let router = router
            .to_string()
            .parse::<Ipv4Addr>()
            .map_err(|_| format!("default-router {router} is not an IPv4 address"))?;
        add(Net4 { addr: 0, len: 0 }, router);
    }
    Ok(bytes.iter().map(|b| format!("{b:02X}")).collect())
}

// ---------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------

/// `service dhcp-server` or `service dhcp-server vrf red`, for warnings.
fn scope(vrf: &str) -> String {
    if vrf == crate::links::DEFAULT_VRF {
        "service dhcp-server".to_string()
    } else {
        format!("service dhcp-server vrf {vrf}")
    }
}

/// `exclude` slicing (`dhcp_slice_range`): the range minus the
/// excluded addresses inside it, as consecutive sub-ranges.
pub fn slice_range(start: u32, stop: u32, exclude: &BTreeSet<u32>) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    let mut from = start;
    for &e in exclude.range(start..=stop) {
        if e > from {
            out.push((from, e - 1));
        }
        from = e.saturating_add(1);
        if e == u32::MAX {
            return out;
        }
    }
    if from <= stop {
        out.push((from, stop));
    }
    out
}

/// One instance → its Kea configuration.
pub fn render(server: &Server4, ctx: &Context) -> Render {
    let scope = scope(ctx.vrf);
    let mut warnings = Vec::new();
    let mut instance = Instance::default();

    // Client classes: the enabled, usable ones, by name.
    let mut classes: Vec<Value> = Vec::new();
    let mut usable = BTreeSet::new();
    for class in &server.client_class {
        let Some(name) = class.name.as_ref().map(Flex::to_string) else {
            continue;
        };
        if class.disable {
            continue;
        }
        let cscope = format!("{scope} client-class {name}");
        let rai = class.relay_agent_information.as_ref();
        let conditions = [
            (
                "relay-agent-information circuit-id",
                "relay4[1]",
                rai.and_then(|r| r.circuit_id.as_ref()),
            ),
            (
                "relay-agent-information remote-id",
                "relay4[2]",
                rai.and_then(|r| r.remote_id.as_ref()),
            ),
            (
                "hostname",
                "option[12]",
                class.hostname.as_ref().and_then(|m| m.value.as_ref()),
            ),
            (
                "vendor-class-id",
                "option[60]",
                class
                    .vendor_class_id
                    .as_ref()
                    .and_then(|m| m.value.as_ref()),
            ),
        ];
        let test = match client_class_test(&conditions) {
            Ok(test) => test,
            Err(err) => {
                warnings.push(format!("{cscope} skipped: {err}"));
                continue;
            }
        };
        let mut obj = serde_json::Map::new();
        obj.insert("name".into(), Value::String(name.clone()));
        obj.insert("test".into(), Value::String(test));
        add_options(&mut obj, class.option.as_ref(), ctx, &cscope, &mut warnings);
        classes.push(Value::Object(obj));
        usable.insert(name);
    }
    let class_ok = |name: &Flex| usable.contains(&name.to_string());

    // Shared networks.
    let mut networks: Vec<Value> = Vec::new();
    let mut ids = BTreeSet::new();
    let mut nets: Vec<Net4> = Vec::new();
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
            if subnet.disable {
                continue;
            }
            let prefix = subnet
                .prefix
                .as_ref()
                .map(Flex::to_string)
                .unwrap_or_default();
            let sscope = format!("{nscope} subnet {prefix}");
            match render_subnet(subnet, &prefix, &sscope, ctx, &class_ok, &mut warnings) {
                Some((net, id, value, mappings)) => {
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
                    nets.push(net);
                    instance.subnets.insert(id, (name.clone(), net.to_prefix()));
                    instance.mappings.extend(mappings.into_iter().map(|mut m| {
                        m.pool = name.clone();
                        m
                    }));
                    subnets.push(value);
                }
                None => continue,
            }
        }
        if subnets.is_empty() {
            continue;
        }
        let mut obj = serde_json::Map::new();
        obj.insert("name".into(), Value::String(name.clone()));
        obj.insert("authoritative".into(), Value::Bool(network.authoritative));
        obj.insert("subnet4".into(), Value::Array(subnets));
        add_options(
            &mut obj,
            network.option.as_ref(),
            ctx,
            &nscope,
            &mut warnings,
        );
        networks.push(Value::Object(obj));
        instance.pools.push(name);
    }

    // Where Kea listens (DH8).
    let (interfaces, socket_type) = listen_set(server, &nets, ctx, &scope, &mut warnings);
    let mut serving = !server.disable && !networks.is_empty() && !interfaces.is_empty();
    if !server.disable && !networks.is_empty() && interfaces.is_empty() {
        warnings.push(format!(
            "{scope}: no interface to listen on (none carries an address in a configured subnet, and no listen-address or listen-interface is usable); not serving"
        ));
    }
    if server.disable || networks.is_empty() {
        serving = false;
    }
    let (interfaces, networks, classes) = if serving {
        (interfaces, networks, classes)
    } else {
        instance = Instance::default();
        (Vec::new(), Vec::new(), Vec::new())
    };

    let mut dhcp4 = serde_json::Map::new();
    let mut ifc = serde_json::Map::new();
    ifc.insert(
        "interfaces".into(),
        Value::Array(interfaces.into_iter().map(Value::String).collect()),
    );
    ifc.insert("dhcp-socket-type".into(), Value::String(socket_type.into()));
    ifc.insert("service-sockets-max-retries".into(), json!(60));
    ifc.insert("service-sockets-retry-wait-time".into(), json!(5000));
    dhcp4.insert("interfaces-config".into(), Value::Object(ifc));
    dhcp4.insert(
        "control-socket".into(),
        json!({ "socket-type": "unix", "socket-name": ctx.socket }),
    );
    dhcp4.insert(
        "lease-database".into(),
        json!({ "type": "memfile", "persist": true, "name": ctx.lease_file }),
    );
    dhcp4.insert(
        "multi-threading".into(),
        json!({ "enable-multi-threading": true }),
    );
    if !classes.is_empty() {
        dhcp4.insert("client-classes".into(), Value::Array(classes));
    }
    dhcp4.insert(
        "option-def".into(),
        json!([
            { "name": "wpad-url", "code": 252, "type": "string" },
            {
                "name": "ubnt",
                "code": 1,
                "type": "ipv4-address",
                "space": "vendor-encapsulated-options-space"
            }
        ]),
    );
    dhcp4.insert(
        "hooks-libraries".into(),
        json!([
            { "library": ctx.hook("libdhcp_lease_cmds.so"), "parameters": {} },
            { "library": ctx.hook("libdhcp_stat_cmds.so"), "parameters": {} }
        ]),
    );
    if !networks.is_empty() {
        dhcp4.insert("shared-networks".into(), Value::Array(networks));
    }
    dhcp4.insert(
        "loggers".into(),
        loggers("kea-dhcp4", server.log_level.as_ref()),
    );
    let config = json!({ "Dhcp4": Value::Object(dhcp4) });
    Render {
        text: serde_json::to_string_pretty(&config).unwrap_or_default() + "\n",
        serving,
        warnings,
        instance,
        pd: Default::default(),
    }
}

type Rendered = (Net4, u32, Value, Vec<Mapping>);

fn render_subnet(
    subnet: &Subnet4,
    prefix: &str,
    sscope: &str,
    ctx: &Context,
    class_ok: &dyn Fn(&Flex) -> bool,
    warnings: &mut Vec<String>,
) -> Option<Rendered> {
    let Some(net) = Net4::parse(prefix) else {
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
    if let Some(class) = &subnet.client_class
        && !class_ok(class)
    {
        warnings.push(format!(
            "{sscope} skipped: client-class {class} is missing, disabled or unusable"
        ));
        return None;
    }

    // exclude: addresses inside the subnet.
    let mut exclude = BTreeSet::new();
    for addr in &subnet.exclude {
        match addr.to_string().parse::<Ipv4Addr>() {
            Ok(a) if net.contains(u32::from(a)) => {
                exclude.insert(u32::from(a));
            }
            _ => warnings.push(format!(
                "{sscope}: exclude {addr} is not inside the subnet; ignored"
            )),
        }
    }

    // Ranges.
    let mut pools: Vec<Value> = Vec::new();
    let mut taken: Vec<(u32, u32)> = Vec::new();
    for range in &subnet.range {
        let rname = range.name.as_ref().map(Flex::to_string).unwrap_or_default();
        let rscope = format!("{sscope} range {rname}");
        let addr = |v: &Option<Flex>| {
            v.as_ref()
                .and_then(|v| v.to_string().parse::<Ipv4Addr>().ok())
                .map(u32::from)
        };
        let (Some(start), Some(stop)) = (addr(&range.start), addr(&range.stop)) else {
            warnings.push(format!(
                "{rscope} skipped: needs a start and a stop address"
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
        if taken.iter().any(|&(a, b)| start <= b && a <= stop) {
            warnings.push(format!("{rscope} skipped: overlaps another range"));
            continue;
        }
        if let Some(class) = &range.client_class
            && !class_ok(class)
        {
            warnings.push(format!(
                "{rscope} skipped: client-class {class} is missing, disabled or unusable"
            ));
            continue;
        }
        taken.push((start, stop));
        for (a, b) in slice_range(start, stop, &exclude) {
            let mut obj = serde_json::Map::new();
            obj.insert(
                "pool".into(),
                Value::String(format!("{} - {}", Ipv4Addr::from(a), Ipv4Addr::from(b))),
            );
            add_options(&mut obj, range.option.as_ref(), ctx, &rscope, warnings);
            if let Some(class) = &range.client_class {
                obj.insert("client-class".into(), Value::String(class.to_string()));
            }
            pools.push(Value::Object(obj));
        }
    }

    // Static mappings: the enabled, valid ones; the later of duplicates
    // is skipped.
    let mut reservations: Vec<Value> = Vec::new();
    let mut mappings = Vec::new();
    let (mut ips, mut macs, mut duids) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    for mapping in &subnet.static_mapping {
        let host = mapping
            .name
            .as_ref()
            .map(Flex::to_string)
            .unwrap_or_default();
        if mapping.disable {
            continue;
        }
        let mscope = format!("{sscope} static-mapping {host}");
        let ip = match &mapping.ip_address {
            Some(v) => match v.to_string().parse::<Ipv4Addr>() {
                Ok(a) if net.contains(u32::from(a)) => Some(a),
                _ => {
                    warnings.push(format!(
                        "{mscope} skipped: ip-address {v} is not inside the subnet"
                    ));
                    continue;
                }
            },
            None => None,
        };
        let mac = mapping.mac.as_ref().map(|m| m.to_string().to_lowercase());
        let duid = mapping.duid.as_ref().map(|d| d.to_string().to_lowercase());
        if mac.is_some() == duid.is_some() {
            warnings.push(format!("{mscope} skipped: needs either a mac or a duid"));
            continue;
        }
        if let Some(ip) = ip
            && ips.contains(&ip)
        {
            warnings.push(format!(
                "{mscope} skipped: ip-address {ip} is used by another static mapping"
            ));
            continue;
        }
        if let Some(mac) = &mac
            && macs.contains(mac)
        {
            warnings.push(format!(
                "{mscope} skipped: mac {mac} is used by another static mapping"
            ));
            continue;
        }
        if let Some(duid) = &duid
            && duids.contains(duid)
        {
            warnings.push(format!(
                "{mscope} skipped: duid {duid} is used by another static mapping"
            ));
            continue;
        }
        ips.extend(ip);
        macs.extend(mac.clone());
        duids.extend(duid.clone());
        let mut obj = serde_json::Map::new();
        obj.insert("hostname".into(), Value::String(host.clone()));
        if let Some(mac) = &mac {
            obj.insert("hw-address".into(), Value::String(mac.clone()));
        }
        if let Some(duid) = &duid {
            obj.insert("duid".into(), Value::String(duid.clone()));
        }
        if let Some(ip) = ip {
            obj.insert("ip-address".into(), Value::String(ip.to_string()));
        }
        add_options(&mut obj, mapping.option.as_ref(), ctx, &mscope, warnings);
        reservations.push(Value::Object(obj));
        mappings.push(Mapping {
            pool: String::new(),
            subnet: net.to_prefix(),
            hostname: host,
            addresses: ip.map(|a| a.to_string()).into_iter().collect(),
            mac: mac.unwrap_or_default(),
            duid: duid.unwrap_or_default(),
            description: mapping
                .description
                .as_ref()
                .map(Flex::to_string)
                .unwrap_or_default(),
        });
    }

    if pools.is_empty() && reservations.is_empty() {
        warnings.push(format!(
            "{sscope} skipped: no usable range and no enabled static mapping"
        ));
        return None;
    }

    let mut obj = serde_json::Map::new();
    obj.insert("subnet".into(), Value::String(net.to_prefix()));
    obj.insert("id".into(), json!(id));
    add_options(&mut obj, subnet.option.as_ref(), ctx, sscope, warnings);
    if subnet.ignore_client_id {
        obj.insert("match-client-id".into(), Value::Bool(false));
    }
    let lease = subnet
        .lease
        .as_ref()
        .and_then(|v| v.to_string().parse::<u32>().ok())
        .unwrap_or(DEFAULT_LEASE);
    obj.insert("valid-lifetime".into(), json!(lease));
    obj.insert("max-valid-lifetime".into(), json!(lease));
    if let Some(class) = &subnet.client_class {
        obj.insert("client-class".into(), Value::String(class.to_string()));
    }
    if !pools.is_empty() {
        obj.insert("pools".into(), Value::Array(pools));
    }
    if !reservations.is_empty() {
        obj.insert("reservations".into(), Value::Array(reservations));
    }
    Some((net, id, Value::Object(obj), mappings))
}

/// The listen set and socket type (DH8, design/dhcp.md §7.3), from the
/// interfaces of the instance's VRF:
/// - `listen-address`: UDP sockets, `<if>/<addr>` for each address
///   assigned to an interface (unassigned ones are dropped);
/// - else `listen-interface`: raw sockets on those that exist;
/// - else raw sockets on every interface with an address inside a
///   rendered subnet.
fn listen_set(
    server: &Server4,
    nets: &[Net4],
    ctx: &Context,
    scope: &str,
    warnings: &mut Vec<String>,
) -> (Vec<String>, &'static str) {
    let links = ctx.links;
    let members: Vec<_> = links.members(ctx.vrf).collect();
    let v4_of = |index: u32| {
        links.addrs_of(index).filter_map(|a| match a.addr {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        })
    };
    if !server.listen_address.is_empty() {
        if !server.listen_interface.is_empty() {
            warnings.push(format!(
                "{scope}: listen-address and listen-interface are both set; using listen-address"
            ));
        }
        let mut out = Vec::new();
        for addr in &server.listen_address {
            let Ok(want) = addr.to_string().parse::<Ipv4Addr>() else {
                continue;
            };
            match members.iter().find(|l| v4_of(l.index).any(|a| a == want)) {
                Some(link) => out.push(format!("{}/{want}", link.name)),
                None => warnings.push(format!(
                    "{scope}: listen-address {want} is not assigned to an interface{}; dropped",
                    vrf_suffix(ctx.vrf)
                )),
            }
        }
        return (out, "udp");
    }
    if !server.listen_interface.is_empty() {
        let mut out = Vec::new();
        for name in &server.listen_interface {
            let name = name.to_string();
            if members.iter().any(|l| l.name == name) {
                out.push(name);
            } else {
                warnings.push(format!(
                    "{scope}: listen-interface {name} does not exist{}; dropped",
                    vrf_suffix(ctx.vrf)
                ));
            }
        }
        return (out, "raw");
    }
    let mut out: BTreeMap<u32, String> = BTreeMap::new();
    for link in &members {
        if v4_of(link.index).any(|a| nets.iter().any(|n| n.contains(u32::from(a)))) {
            out.insert(link.index, link.name.clone());
        }
    }
    (out.into_values().collect(), "raw")
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

    fn render_str(json: &str, links: &crate::links::Snapshot) -> Render {
        let tree: Server4Tree = serde_json::from_str(json).unwrap();
        render(&tree.default, &context("default", links))
    }

    #[test]
    fn slicing() {
        let a = |s: &str| u32::from(s.parse::<Ipv4Addr>().unwrap());
        // dhcp_slice_range's docstring example.
        let exclude = [a("192.0.2.74"), a("192.0.2.75")].into_iter().collect();
        let slices = slice_range(a("192.0.2.1"), a("192.0.2.100"), &exclude);
        assert_eq!(
            slices,
            [
                (a("192.0.2.1"), a("192.0.2.73")),
                (a("192.0.2.76"), a("192.0.2.100"))
            ]
        );
        // Excluding the first and last address, and an address outside.
        let exclude = [a("10.0.0.10"), a("10.0.0.20"), a("10.0.0.99")]
            .into_iter()
            .collect();
        assert_eq!(
            slice_range(a("10.0.0.10"), a("10.0.0.20"), &exclude),
            [(a("10.0.0.11"), a("10.0.0.19"))]
        );
        // Everything excluded.
        let exclude = [a("10.0.0.1")].into_iter().collect();
        assert!(slice_range(a("10.0.0.1"), a("10.0.0.1"), &exclude).is_empty());
    }

    /// The vector verified with `kea-dhcp4 -t` (design/dhcp.md §7.2).
    #[test]
    fn option_121() {
        let route = StaticRoute {
            prefix: Some(Flex::Str("10.0.0.0/8".into())),
            next_hop: Some(Flex::Str("192.0.2.254".into())),
        };
        let router = Flex::Str("192.0.2.1".into());
        assert_eq!(
            classless_static_routes(&[route], Some(&router)).unwrap(),
            "080AC00002FE00C0000201"
        );
        let route = StaticRoute {
            prefix: Some(Flex::Str("198.51.100.0/24".into())),
            next_hop: Some(Flex::Str("10.1.0.1".into())),
        };
        assert_eq!(
            classless_static_routes(&[route], None).unwrap(),
            "18C633640A010001"
        );
    }

    /// Every mapping row of design/dhcp.md §7.2 in one render, with the
    /// JSON zebra-rs delivers (its marshal-contract test pins the same
    /// shapes).
    #[test]
    fn golden_render() {
        let links = snapshot(&[
            link(2, "lan1", None, &["10.1.0.1/24"]),
            link(3, "lan2", None, &["10.2.0.1/24"]),
            link(4, "lan3", None, &["10.3.0.1/24"]),
            link(5, "wan1", None, &["192.0.2.1/24"]),
        ]);
        let json = r#"{
            "client-class": [
                {"name":"VOIP","vendor-class-id":{"value":"voip"}},
                {"name":"OFF","disable":null,"hostname":{"value":"x"}}
            ],
            "log-level": "debug",
            "shared-network-name": [
                {"name":"LAN","authoritative":null,
                 "option":{"name-server": ["192.0.2.53","192.0.2.54"],"domain-name":"example.com"},
                 "subnet": [{"prefix":"10.1.0.0/24","subnet-id":1,"lease":3600,
                    "exclude": ["10.1.0.100"],
                    "option":{"default-router":"10.1.0.1","ntp-server": ["192.0.2.123"],
                        "static-route": [{"prefix":"198.51.100.0/24","next-hop":"10.1.0.1"}],
                        "time-zone":"Asia/Tokyo","bootfile-name":"pxelinux.0","bootfile-server":"10.1.0.9"},
                    "range": [{"name":0,"start":"10.1.0.100","stop":"10.1.0.199"}],
                    "static-mapping": [{"name":"printer","ip-address":"10.1.0.10","mac":"02:00:00:00:00:01","description":"lobby"}]}]},
                {"name":"LAN2",
                 "subnet": [{"prefix":"10.2.0.0/24","subnet-id":2,"ignore-client-id":null,
                    "range": [{"name":"voip","start":"10.2.0.50","stop":"10.2.0.59","client-class":"VOIP"}]}]},
                {"name":"OFFNET","disable":null,
                 "subnet": [{"prefix":"10.3.0.0/24","subnet-id":3,"range": [{"name":0,"start":"10.3.0.10","stop":"10.3.0.20"}]}]}
            ]
        }"#;
        let r = render_str(json, &links);
        assert!(r.serving);
        assert_eq!(r.warnings, Vec::<String>::new());
        assert_eq!(
            r.text,
            r#"{
  "Dhcp4": {
    "interfaces-config": {
      "interfaces": [
        "lan1",
        "lan2"
      ],
      "dhcp-socket-type": "raw",
      "service-sockets-max-retries": 60,
      "service-sockets-retry-wait-time": 5000
    },
    "control-socket": {
      "socket-type": "unix",
      "socket-name": "/run/insomnia/kea/default/kea4-ctrl-socket"
    },
    "lease-database": {
      "type": "memfile",
      "persist": true,
      "name": "/var/lib/insomnia/kea/default/kea-leases4.csv"
    },
    "multi-threading": {
      "enable-multi-threading": true
    },
    "client-classes": [
      {
        "name": "VOIP",
        "test": "option[60].hex == 0x766f6970"
      }
    ],
    "option-def": [
      {
        "name": "wpad-url",
        "code": 252,
        "type": "string"
      },
      {
        "name": "ubnt",
        "code": 1,
        "type": "ipv4-address",
        "space": "vendor-encapsulated-options-space"
      }
    ],
    "hooks-libraries": [
      {
        "library": "/usr/lib/kea/hooks/libdhcp_lease_cmds.so",
        "parameters": {}
      },
      {
        "library": "/usr/lib/kea/hooks/libdhcp_stat_cmds.so",
        "parameters": {}
      }
    ],
    "shared-networks": [
      {
        "name": "LAN",
        "authoritative": true,
        "subnet4": [
          {
            "subnet": "10.1.0.0/24",
            "id": 1,
            "option-data": [
              {
                "name": "ntp-servers",
                "data": "192.0.2.123"
              },
              {
                "name": "routers",
                "data": "10.1.0.1"
              },
              {
                "name": "boot-file-name",
                "data": "pxelinux.0"
              },
              {
                "code": 121,
                "csv-format": false,
                "data": "18C633640A010001000A010001"
              },
              {
                "name": "pcode",
                "data": "JST-9"
              },
              {
                "name": "tcode",
                "data": "Asia/Tokyo"
              }
            ],
            "boot-file-name": "pxelinux.0",
            "next-server": "10.1.0.9",
            "valid-lifetime": 3600,
            "max-valid-lifetime": 3600,
            "pools": [
              {
                "pool": "10.1.0.101 - 10.1.0.199"
              }
            ],
            "reservations": [
              {
                "hostname": "printer",
                "hw-address": "02:00:00:00:00:01",
                "ip-address": "10.1.0.10"
              }
            ]
          }
        ],
        "option-data": [
          {
            "name": "domain-name-servers",
            "data": "192.0.2.53, 192.0.2.54"
          },
          {
            "name": "domain-name",
            "data": "example.com"
          }
        ]
      },
      {
        "name": "LAN2",
        "authoritative": false,
        "subnet4": [
          {
            "subnet": "10.2.0.0/24",
            "id": 2,
            "match-client-id": false,
            "valid-lifetime": 86400,
            "max-valid-lifetime": 86400,
            "pools": [
              {
                "pool": "10.2.0.50 - 10.2.0.59",
                "client-class": "VOIP"
              }
            ]
          }
        ]
      }
    ],
    "loggers": [
      {
        "name": "kea-dhcp4",
        "output_options": [
          {
            "output": "stdout",
            "pattern": "%-5p %m\n"
          }
        ],
        "severity": "DEBUG",
        "debuglevel": 0
      }
    ]
  }
}
"#
        );
        assert_eq!(r.instance.pools, ["LAN", "LAN2"]);
        assert_eq!(
            r.instance.subnets.get(&2),
            Some(&("LAN2".to_string(), "10.2.0.0/24".to_string()))
        );
        assert_eq!(r.instance.mappings.len(), 1);
        assert_eq!(r.instance.mappings[0].pool, "LAN");
        assert_eq!(r.instance.mappings[0].description, "lobby");
    }

    /// Each §7.6 rule skips only what fails it, with a warning naming it.
    #[test]
    fn skips_with_warnings() {
        let links = snapshot(&[link(2, "lan1", None, &["10.1.0.1/24", "10.9.0.1/24"])]);
        let json = r#"{
            "client-class": [
                {"name":"EMPTY"},
                {"name":"BADHEX","hostname":{"value":"0xZZ"}},
                {"name":"OFF","disable":null,"hostname":{"value":"x"}}
            ],
            "shared-network-name": [
                {"name":"NOSUB"},
                {"name":"LAN","subnet": [
                    {"prefix":"10.1.0.0/24","subnet-id":1,
                     "exclude": ["10.7.0.1"],
                     "range": [
                        {"name":"out","start":"10.2.0.1","stop":"10.2.0.9"},
                        {"name":"rev","start":"10.1.0.9","stop":"10.1.0.1"},
                        {"name":"a","start":"10.1.0.100","stop":"10.1.0.150"},
                        {"name":"b","start":"10.1.0.150","stop":"10.1.0.160"},
                        {"name":"cls","start":"10.1.0.200","stop":"10.1.0.210","client-class":"OFF"}
                     ],
                     "static-mapping": [
                        {"name":"far","ip-address":"10.2.0.5","mac":"02:00:00:00:00:01"},
                        {"name":"both","ip-address":"10.1.0.5","mac":"02:00:00:00:00:02","duid":"00:01"},
                        {"name":"first","ip-address":"10.1.0.6","mac":"02:00:00:00:00:03"},
                        {"name":"dupip","ip-address":"10.1.0.6","mac":"02:00:00:00:00:04"},
                        {"name":"dupmac","ip-address":"10.1.0.7","mac":"02:00:00:00:00:03"}
                     ]},
                    {"prefix":"10.1.0.0/25","subnet-id":2,"range": [{"name":0,"start":"10.1.0.10","stop":"10.1.0.20"}]},
                    {"prefix":"10.9.0.0/24","subnet-id":1,"range": [{"name":0,"start":"10.9.0.10","stop":"10.9.0.20"}]},
                    {"prefix":"10.8.0.0/24","subnet-id":4,"client-class":"BADHEX","range": [{"name":0,"start":"10.8.0.10","stop":"10.8.0.20"}]},
                    {"prefix":"10.6.0.0/24","subnet-id":5},
                    {"prefix":"10.5.0.1/24","subnet-id":6}
                ]}
            ]
        }"#;
        let r = render_str(json, &links);
        let s = "service dhcp-server";
        let n = "service dhcp-server shared-network-name LAN";
        assert_eq!(
            r.warnings,
            [
                format!("{s} client-class EMPTY skipped: no match condition"),
                format!(
                    "{s} client-class BADHEX skipped: hostname value 0xZZ is not text or 0x-prefixed hex"
                ),
                format!("{s} shared-network-name NOSUB skipped: no subnet"),
                format!(
                    "{n} subnet 10.1.0.0/24: exclude 10.7.0.1 is not inside the subnet; ignored"
                ),
                format!("{n} subnet 10.1.0.0/24 range out skipped: not inside the subnet"),
                format!("{n} subnet 10.1.0.0/24 range rev skipped: stop is below start"),
                format!("{n} subnet 10.1.0.0/24 range b skipped: overlaps another range"),
                format!(
                    "{n} subnet 10.1.0.0/24 range cls skipped: client-class OFF is missing, disabled or unusable"
                ),
                format!(
                    "{n} subnet 10.1.0.0/24 static-mapping far skipped: ip-address 10.2.0.5 is not inside the subnet"
                ),
                format!(
                    "{n} subnet 10.1.0.0/24 static-mapping both skipped: needs either a mac or a duid"
                ),
                format!(
                    "{n} subnet 10.1.0.0/24 static-mapping dupip skipped: ip-address 10.1.0.6 is used by another static mapping"
                ),
                format!(
                    "{n} subnet 10.1.0.0/24 static-mapping dupmac skipped: mac 02:00:00:00:00:03 is used by another static mapping"
                ),
                format!("{n} subnet 10.1.0.0/25 skipped: overlaps subnet 10.1.0.0/24"),
                format!("{n} subnet 10.9.0.0/24 skipped: subnet-id 1 is used by another subnet"),
                format!(
                    "{n} subnet 10.8.0.0/24 skipped: client-class BADHEX is missing, disabled or unusable"
                ),
                format!(
                    "{n} subnet 10.6.0.0/24 skipped: no usable range and no enabled static mapping"
                ),
                format!("{n} subnet 10.5.0.1/24 skipped: not a network prefix (host bits set?)"),
            ]
        );
        assert!(r.serving);
        assert_eq!(r.instance.subnets.len(), 1);
        assert!(r.text.contains(r#""pool": "10.1.0.100 - 10.1.0.150""#));
        assert!(!r.text.contains("10.1.0.200"));
        assert!(r.text.contains(r#""hostname": "first""#));
        assert!(!r.text.contains("dupip"));
    }

    /// DH8: never "*". The listen set follows the addresses, the VRF,
    /// `listen-interface` and `listen-address`.
    #[test]
    fn listen_set_rules() {
        let links = snapshot(&[
            link(2, "lan1", None, &["10.1.0.1/24"]),
            link(3, "wan1", None, &["192.0.2.1/24"]),
            link(5, "red", Some("vrf"), &[]),
            link_in(6, "lanred", 5, &["10.1.0.1/24"]),
        ]);
        let base = r#""shared-network-name": [{"name":"LAN","subnet": [{"prefix":"10.1.0.0/24","subnet-id":1,"range": [{"name":0,"start":"10.1.0.100","stop":"10.1.0.199"}]}]}]"#;
        let ifc = |r: &Render| {
            let v: Value = serde_json::from_str(&r.text).unwrap();
            let ifc = &v["Dhcp4"]["interfaces-config"];
            (
                ifc["interfaces"].clone(),
                ifc["dhcp-socket-type"].as_str().unwrap().to_string(),
            )
        };

        let r = render_str(&format!("{{{base}}}"), &links);
        assert_eq!(ifc(&r), (json!(["lan1"]), "raw".into()));

        // The same tree in VRF red listens on red's member only.
        let tree: Server4Tree = serde_json::from_str(&format!("{{{base}}}")).unwrap();
        let r = render(&tree.default, &context("red", &links));
        assert_eq!(ifc(&r), (json!(["lanred"]), "raw".into()));
        assert!(r.text.contains("/run/insomnia/kea/red/kea4-ctrl-socket"));

        let r = render_str(
            &format!(r#"{{"listen-interface": ["wan1","eth9"],{base}}}"#),
            &links,
        );
        assert_eq!(ifc(&r), (json!(["wan1"]), "raw".into()));
        assert_eq!(
            r.warnings,
            ["service dhcp-server: listen-interface eth9 does not exist; dropped"]
        );

        let r = render_str(
            &format!(
                r#"{{"listen-address": ["192.0.2.1","192.0.2.9"],"listen-interface": ["lan1"],{base}}}"#
            ),
            &links,
        );
        assert_eq!(ifc(&r), (json!(["wan1/192.0.2.1"]), "udp".into()));
        assert_eq!(
            r.warnings,
            [
                "service dhcp-server: listen-address and listen-interface are both set; using listen-address",
                "service dhcp-server: listen-address 192.0.2.9 is not assigned to an interface; dropped",
            ]
        );

        // No interface in a configured subnet: nothing is served.
        let links = snapshot(&[link(3, "wan1", None, &["192.0.2.1/24"])]);
        let r = render_str(&format!("{{{base}}}"), &links);
        assert!(!r.serving);
        assert_eq!(ifc(&r), (json!([]), "raw".into()));
        assert!(!r.text.contains("shared-networks"));
        assert!(r.warnings[0].contains("no interface to listen on"));
    }

    fn link_in(
        index: u32,
        name: &str,
        master: u32,
        addrs: &[&str],
    ) -> (crate::links::Link, Vec<crate::links::Addr>) {
        let (mut l, a) = link(index, name, None, addrs);
        l.master = Some(master);
        (l, a)
    }

    /// `disable`, or nothing configured: the idle render, not serving.
    #[test]
    fn disabled_and_empty() {
        let links = snapshot(&[link(2, "lan1", None, &["10.1.0.1/24"])]);
        let r = render_str(
            r#"{"disable":null,"shared-network-name": [{"name":"LAN","subnet": [{"prefix":"10.1.0.0/24","subnet-id":1,"range": [{"name":0,"start":"10.1.0.100","stop":"10.1.0.199"}]}]}]}"#,
            &links,
        );
        assert!(!r.serving);
        assert!(r.warnings.is_empty());
        assert!(!r.text.contains("shared-networks"));
        let r = render_str("{}", &links);
        assert!(!r.serving);
        assert!(r.text.contains(r#""interfaces": []"#));
    }
}
