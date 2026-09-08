//! VyOS-derived VRRP → keepalived backend.
//!
//! Consumes the `/vrrp` config subtree as a JSON batch (see
//! `ConfigManager::subscribe_json`): every commit that touches the
//! subtree delivers the whole post-commit tree in one message. The
//! backend deserializes it into [`VrrpConfig`], renders a complete
//! `keepalived.conf` and hands it to [`keepalived::apply`], which
//! writes the file for the `default` instance and reloads keepalived
//! (or stops it when nothing is configured). This mirrors VyOS, which
//! re-renders `keepalived.conf` from the config tree on every commit
//! (vyos-1x `data/templates/high-availability/keepalived.conf.j2`,
//! which this renderer follows line for line where it can); the show
//! views mirror `src/op_mode/vrrp.py` + `python/vyos/ifconfig/vrrp.py`.
//!
//! Deviations from VyOS, all deliberate (design/vrrp.md):
//! - the tree is rooted at a top-level `vrrp` node; VyOS's
//!   `high-availability` wrapper (which also holds the IPVS load
//!   balancer) is dropped — below `vrrp` the leaves are VyOS's;
//! - `transition-script` renders as native `notify_master` /
//!   `notify_backup` / `notify_fault` / `notify_stop` lines instead of
//!   VyOS's `notify_fifo` plus Python dispatcher;
//! - no `enable_traps` / SNMP, no conntrack-sync notify helper, and no
//!   `virtual_server` (IPVS) blocks;
//! - three extension leaves keepalived supports but VyOS does not
//!   expose: per-group `version`, `v3-checksum-as-v2`, and a fractional
//!   `advertise-interval` (VRRPv2 groups are rounded up to whole
//!   seconds, VRRPv3 groups are clamped to the 40.95 s wire maximum);
//! - defaults are filled here (VyOS fills them in the config store);
//! - `show vrrp … group NAME` for an unknown group answers a `%`
//!   message where VyOS prints nothing.
//!
//! Anything the renderer cannot express safely is skipped with a
//! warning naming the group — the rendered file is always syntactically
//! valid keepalived config, so one bad group cannot wedge the whole
//! commit.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use serde::Deserialize;
use tokio::sync::mpsc;

use crate::api::{JsonConfigUpdate, ShowRequest};
use crate::json::{Flex, de_flex_vec, de_presence};
use crate::keepalived::{self, Applied, Keepalived};
use crate::text::{seconds_to_human, table};

/// Running-config subtree this backend subscribes to.
const CONFIG_PATH: &[&str] = &["vrrp"];

/// keepalived instance serving the global routing table.
pub const DEFAULT_INSTANCE: &str = "default";

/// What the task retains between commits: the last committed model,
/// so `show vrrp` can list disabled groups the way VyOS does.
#[derive(Default)]
struct ShowState {
    model: Option<VrrpConfig>,
}

/// Backend task: a JSON subscription to `/vrrp` (snapshot first, then
/// one whole-subtree batch per touching commit) selected with the show
/// orders the provider routes here. Reconnects with backoff when the
/// stream drops; the fresh snapshot re-renders keepalived.conf, and an
/// unchanged file is not reloaded.
pub async fn run(host: String, ka: Arc<Keepalived>, mut show_rx: mpsc::Receiver<ShowRequest>) {
    let mut state = ShowState::default();
    loop {
        let mut stream = crate::subscribe::subscribe_json(&host, CONFIG_PATH).await;
        loop {
            tokio::select! {
                msg = stream.message() => match msg {
                    Ok(Some(event)) => {
                        let update = JsonConfigUpdate {
                            path: CONFIG_PATH.iter().map(|s| s.to_string()).collect(),
                            json: event.json,
                        };
                        process(update, &ka, &mut state).await;
                    }
                    Ok(None) => break,
                    Err(err) => {
                        tracing::warn!("vrrp: subscription error: {err}");
                        break;
                    }
                },
                Some(req) = show_rx.recv() => process_show(&ka, &state, req).await,
            }
        }
        tracing::warn!("vrrp: subscription ended; reconnecting");
        tokio::time::sleep(crate::endpoint::RECONNECT_DELAY).await;
    }
}

async fn process(update: JsonConfigUpdate, ka: &Keepalived, state: &mut ShowState) {
    tracing::debug!("vrrp: config update for /{}", update.path.join("/"));
    let cfg: VrrpConfig = match serde_json::from_str(&update.json) {
        Ok(cfg) => cfg,
        Err(err) => {
            tracing::error!("vrrp: config parse failed: {err}");
            return;
        }
    };
    let (conf, warnings) = render(&cfg);
    for warn in &warnings {
        tracing::warn!("vrrp: {warn}");
    }
    state.model = if cfg.is_empty() { None } else { Some(cfg) };
    let paths = ka.instance(DEFAULT_INSTANCE);
    match keepalived::apply(ka, DEFAULT_INSTANCE, &conf).await {
        Ok(Applied::Loaded) => tracing::info!("vrrp: keepalived configuration loaded"),
        Ok(Applied::Unchanged) => tracing::info!("vrrp: keepalived configuration unchanged"),
        Ok(Applied::Stopped) => tracing::info!("vrrp: keepalived stopped (no configuration)"),
        Ok(Applied::NotRunning) => tracing::warn!(
            "vrrp: keepalived not running; configuration rendered to {} but not loaded",
            paths.conf.display()
        ),
        Err(err) => tracing::error!("vrrp: keepalived apply failed: {err:#}"),
    }
}

// ---------------------------------------------------------------
// Config model
//
// Deserialized from `Config::json()` output with the shared helpers
// in `super::json` — see that module for the marshal shapes (numeric
// scalars unquoted → `Flex`, `type empty` → null → `de_presence`,
// keyed lists as arrays, leaf-lists via `de_flex_vec`).
// ---------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct VrrpConfig {
    #[serde(deserialize_with = "de_presence")]
    pub disable: bool,
    pub global_parameters: GlobalParameters,
    pub group: Vec<Group>,
    pub sync_group: Vec<SyncGroup>,
}

impl VrrpConfig {
    /// Nothing to run: keepalived is stopped (systemd) or reloaded to
    /// idle (signal).
    pub fn is_empty(&self) -> bool {
        self.disable || (self.group.is_empty() && self.sync_group.is_empty())
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct GlobalParameters {
    pub garp: Option<Garp>,
    pub startup_delay: Option<Flex>,
    pub version: Option<Flex>,
}

/// Gratuitous-ARP tuning, the same five leaves globally and per group
/// (vyos-1x `include/vrrp/garp.xml.i`).
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Garp {
    pub interval: Option<Flex>,
    pub master_delay: Option<Flex>,
    pub master_refresh: Option<Flex>,
    pub master_refresh_repeat: Option<Flex>,
    pub master_repeat: Option<Flex>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Group {
    pub name: Option<Flex>,
    pub interface: Option<Flex>,
    pub vrid: Option<Flex>,
    /// Extension: per-group VRRP version (VyOS has only the global one).
    pub version: Option<Flex>,
    /// Extension: keepalived `v3_checksum_as_v2` (VRRPv3 IPv4 checksum
    /// without the pseudo-header, for interop).
    #[serde(deserialize_with = "de_presence")]
    pub v3_checksum_as_v2: bool,
    pub address: Vec<VirtualAddress>,
    pub excluded_address: Vec<VirtualAddress>,
    pub advertise_interval: Option<Flex>,
    pub authentication: Option<Authentication>,
    pub description: Option<Flex>,
    #[serde(deserialize_with = "de_presence")]
    pub disable: bool,
    pub garp: Option<Garp>,
    pub health_check: Option<HealthCheck>,
    pub hello_source_address: Option<Flex>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub peer_address: Vec<Flex>,
    #[serde(deserialize_with = "de_presence")]
    pub no_preempt: bool,
    pub preempt_delay: Option<Flex>,
    pub priority: Option<Flex>,
    #[serde(deserialize_with = "de_presence")]
    pub rfc3768_compatibility: bool,
    pub track: Option<Track>,
    pub transition_script: Option<TransitionScript>,
}

/// One `address` / `excluded-address` entry: the address (with an
/// optional prefix length) and the device it goes on when that is
/// not the group's interface.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct VirtualAddress {
    #[serde(alias = "ip")]
    pub address: Option<Flex>,
    pub interface: Option<Flex>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Authentication {
    pub password: Option<Flex>,
    #[serde(rename = "type")]
    pub kind: Option<Flex>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct HealthCheck {
    pub failure_count: Option<Flex>,
    pub interval: Option<Flex>,
    pub ping: Option<Flex>,
    pub script: Option<Flex>,
    pub timeout: Option<Flex>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Track {
    #[serde(deserialize_with = "de_presence")]
    pub exclude_vrrp_interface: bool,
    #[serde(deserialize_with = "de_flex_vec")]
    pub interface: Vec<Flex>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct TransitionScript {
    pub master: Option<Flex>,
    pub backup: Option<Flex>,
    pub fault: Option<Flex>,
    pub stop: Option<Flex>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct SyncGroup {
    pub name: Option<Flex>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub member: Vec<Flex>,
    pub health_check: Option<HealthCheck>,
    pub transition_script: Option<TransitionScript>,
}

// ---------------------------------------------------------------
// Renderer
// ---------------------------------------------------------------

// VyOS schema defaults (high-availability.xml.in), applied here.
const DEFAULT_PRIORITY: &str = "100";
const DEFAULT_ADVERT_INTERVAL: &str = "1";
const DEFAULT_PREEMPT_DELAY: &str = "0";
const DEFAULT_HC_INTERVAL: &str = "60";
const DEFAULT_HC_FAILURE_COUNT: &str = "3";
const DEFAULT_GARP_INTERVAL: &str = "0";
const DEFAULT_GARP_MASTER_DELAY: &str = "5";
const DEFAULT_GARP_MASTER_REFRESH: &str = "5";
const DEFAULT_GARP_MASTER_REFRESH_REPEAT: &str = "1";
const DEFAULT_GARP_MASTER_REPEAT: &str = "5";
/// VRRPv3 advertisement interval is a 12-bit centisecond field.
const MAX_V3_ADVERT_INTERVAL: f64 = 40.95;
/// IFNAMSIZ - 1: the longest VMAC name keepalived can create.
const MAX_IFNAME: usize = 15;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Fam {
    V4,
    V6,
}

impl Fam {
    fn of(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => Fam::V4,
            IpAddr::V6(_) => Fam::V6,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Fam::V4 => "IPv4",
            Fam::V6 => "IPv6",
        }
    }

    /// keepalived's default protocol version for the family.
    fn default_version(self) -> u8 {
        match self {
            Fam::V4 => 2,
            Fam::V6 => 3,
        }
    }

    fn vmac_suffix(self) -> &'static str {
        match self {
            Fam::V4 => "4",
            Fam::V6 => "6",
        }
    }
}

struct Render {
    out: String,
    warnings: Vec<String>,
}

impl Render {
    fn line(&mut self, indent: usize, text: &str) {
        for _ in 0..indent {
            self.out.push_str("    ");
        }
        self.out.push_str(text);
        self.out.push('\n');
    }

    /// Blank line between top-level blocks.
    fn gap(&mut self) {
        self.out.push('\n');
    }

    fn warn(&mut self, text: String) {
        self.warnings.push(text);
    }
}

fn flex(v: &Option<Flex>) -> Option<String> {
    v.as_ref().map(|f| f.to_string())
}

/// Names that go into the config unquoted: group and interface names.
fn safe_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'))
}

/// Values that go into the config inside double quotes.
fn quotable(s: &str) -> bool {
    !s.is_empty() && !s.chars().any(|c| matches!(c, '"' | '\n' | '\r' | '\\'))
}

/// `A.B.C.D`, `A.B.C.D/N`, `X::Y`, `X::Y/N` → the address and whether
/// a prefix length was given (kept as typed for the output).
fn parse_addr(s: &str) -> Option<IpAddr> {
    let (ip, len) = match s.split_once('/') {
        Some((ip, len)) => (ip, Some(len)),
        None => (s, None),
    };
    let ip: IpAddr = ip.parse().ok()?;
    if let Some(len) = len {
        let len: u8 = len.parse().ok()?;
        let max = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if len > max {
            return None;
        }
    }
    Some(ip)
}

/// A group that passed validation, with everything the instance block
/// needs already resolved.
struct Instance<'a> {
    group: &'a Group,
    name: String,
    interface: String,
    vrid: u8,
    fam: Fam,
    /// Effective protocol version (group leaf, then global, then the
    /// family default) — decides the advert-interval rule.
    version: u8,
    /// Emit `version N` (only when the group leaf is set).
    explicit_version: bool,
    /// (address text, dev) pairs, validated.
    vips: Vec<(String, Option<String>)>,
    evips: Vec<(String, Option<String>)>,
    peers: Vec<String>,
    src_ip: Option<String>,
    auth: Option<(String, &'static str)>,
    track_ifs: Vec<String>,
}

/// Validate one group; `None` means it renders nothing (disabled, or
/// skipped with a warning already recorded).
fn check_group<'a>(
    cfg: &VrrpConfig,
    g: &'a Group,
    seen: &mut HashSet<(String, u8, Fam)>,
    r: &mut Render,
) -> Option<Instance<'a>> {
    let Some(name) = flex(&g.name) else {
        r.warn("group without a name; skipped".to_string());
        return None;
    };
    let skip = |r: &mut Render, why: &str| {
        r.warn(format!("group {name}: {why}; skipped"));
        None
    };
    if !safe_name(&name) {
        return skip(r, "name is not a plain token");
    }
    if g.disable {
        return None;
    }
    let Some(interface) = flex(&g.interface) else {
        return skip(r, "interface is required but not set");
    };
    if !safe_name(&interface) {
        return skip(r, "interface name is not a plain token");
    }
    let vrid = match flex(&g.vrid).and_then(|v| v.parse::<u8>().ok()) {
        Some(v) if v >= 1 => v,
        Some(_) => return skip(r, "vrid must be 1-255"),
        None => return skip(r, "vrid is required but not set"),
    };

    // Virtual addresses: at least one, all of one family, parseable.
    if g.address.is_empty() {
        return skip(r, "virtual IP address is required but not set");
    }
    let mut vips = Vec::new();
    let mut fam: Option<Fam> = None;
    for a in &g.address {
        let Some(text) = flex(&a.address) else {
            return skip(r, "address entry without an address");
        };
        let Some(ip) = parse_addr(&text) else {
            return skip(r, &format!("address {text} is not an IP address"));
        };
        match fam {
            None => fam = Some(Fam::of(ip)),
            Some(f) if f != Fam::of(ip) => {
                return skip(
                    r,
                    "mixes IPv4 and IPv6 virtual addresses; create separate groups per family",
                );
            }
            Some(_) => {}
        }
        let dev = match flex(&a.interface) {
            Some(dev) if safe_name(&dev) => Some(dev),
            Some(dev) => {
                r.warn(format!(
                    "group {name}: address {text}: interface {dev} is not a plain token; dev dropped"
                ));
                None
            }
            None => None,
        };
        vips.push((text, dev));
    }
    let fam = fam.expect("at least one address");
    if !seen.insert((interface.clone(), vrid, fam)) {
        return skip(
            r,
            &format!(
                "VRID {vrid} is already used on interface {interface} for {}",
                fam.label()
            ),
        );
    }

    let mut evips = Vec::new();
    for a in &g.excluded_address {
        let Some(text) = flex(&a.address) else {
            continue;
        };
        if parse_addr(&text).is_none() {
            r.warn(format!(
                "group {name}: excluded-address {text} is not an IP address; dropped"
            ));
            continue;
        }
        let dev = flex(&a.interface).filter(|d| safe_name(d));
        evips.push((text, dev));
    }

    // Family-consistent unicast settings.
    let mut peers = Vec::new();
    for p in &g.peer_address {
        let text = p.to_string();
        match parse_addr(&text) {
            Some(ip) if Fam::of(ip) == fam => peers.push(text),
            Some(_) => {
                return skip(
                    r,
                    &format!(
                        "uses {} but peer-address {text} is {}",
                        fam.label(),
                        Fam::of(parse_addr(&text).expect("parsed")).label()
                    ),
                );
            }
            None => return skip(r, &format!("peer-address {text} is not an IP address")),
        }
    }
    let src_ip = match flex(&g.hello_source_address) {
        None => None,
        Some(text) => match parse_addr(&text) {
            Some(ip) if Fam::of(ip) == fam => Some(text),
            Some(ip) => {
                return skip(
                    r,
                    &format!(
                        "uses {} but hello-source-address is {}",
                        fam.label(),
                        Fam::of(ip).label()
                    ),
                );
            }
            None => {
                return skip(
                    r,
                    &format!("hello-source-address {text} is not an IP address"),
                );
            }
        },
    };

    let auth = match &g.authentication {
        None => None,
        Some(a) => {
            let (Some(password), Some(kind)) = (flex(&a.password), flex(&a.kind)) else {
                return skip(r, "authentication requires both type and password");
            };
            let kind = match kind.as_str() {
                "plaintext-password" => "PASS",
                "ah" => "AH",
                other => return skip(r, &format!("authentication type {other} is unknown")),
            };
            if !quotable(&password) {
                return skip(r, "password contains characters keepalived cannot quote");
            }
            if password.len() > 8 {
                r.warn(format!(
                    "group {name}: password is longer than 8 characters; keepalived truncates it"
                ));
            }
            Some((password, kind))
        }
    };

    // Protocol version: group leaf, then global-parameters, then the
    // family default. IPv6 always runs VRRPv3: keepalived upgrades a
    // global `vrrp_version 2` silently, so only an explicit per-group
    // `version 2` is worth a warning.
    let parse_version = |v: Option<String>| {
        v.and_then(|v| v.parse::<u8>().ok())
            .filter(|v| matches!(v, 2 | 3))
    };
    let explicit = parse_version(flex(&g.version));
    let global = parse_version(flex(&cfg.global_parameters.version));
    let mut version = explicit.or(global).unwrap_or_else(|| fam.default_version());
    if fam == Fam::V6 && version == 2 {
        if explicit == Some(2) {
            r.warn(format!(
                "group {name}: VRRPv2 cannot carry IPv6; using version 3"
            ));
        }
        version = 3;
    }
    let explicit_version = explicit.is_some();

    let track_ifs = g
        .track
        .as_ref()
        .map(|t| {
            t.interface
                .iter()
                .map(|i| i.to_string())
                .filter(|i| {
                    let ok = safe_name(i);
                    if !ok {
                        r.warn(format!(
                            "group {name}: track interface {i} is not a plain token; dropped"
                        ));
                    }
                    ok
                })
                .collect()
        })
        .unwrap_or_default();

    Some(Instance {
        group: g,
        name,
        interface,
        vrid,
        fam,
        version,
        explicit_version,
        vips,
        evips,
        peers,
        src_ip,
        auth,
        track_ifs,
    })
}

/// A validated `health-check`: what the `vrrp_script` block prints.
struct Script {
    command: String,
    interval: String,
    timeout: Option<String>,
    fall: String,
}

/// VyOS `_validate_health_check`: exactly one of `script` / `ping`,
/// else the check is dropped with a warning; a timeout shorter than
/// the interval only warns.
fn check_health(label: &str, hc: &HealthCheck, r: &mut Render) -> Option<Script> {
    let command = match (flex(&hc.script), flex(&hc.ping)) {
        (Some(script), None) if quotable(&script) => script,
        (Some(_), None) => {
            r.warn(format!(
                "{label}: health-check script contains characters keepalived cannot quote; health check omitted"
            ));
            return None;
        }
        (None, Some(ping)) if parse_addr(&ping).is_some() && !ping.contains('/') => {
            format!("/usr/bin/ping -c1 {ping}")
        }
        (None, Some(ping)) => {
            r.warn(format!(
                "{label}: health-check ping target {ping} is not an IP address; health check omitted"
            ));
            return None;
        }
        _ => {
            r.warn(format!(
                "{label}: health-check needs exactly one of script / ping; health check omitted"
            ));
            return None;
        }
    };
    let interval = flex(&hc.interval).unwrap_or_else(|| DEFAULT_HC_INTERVAL.to_string());
    let fall = flex(&hc.failure_count).unwrap_or_else(|| DEFAULT_HC_FAILURE_COUNT.to_string());
    let timeout = flex(&hc.timeout);
    if let (Some(t), Ok(i)) = (&timeout, interval.parse::<u64>())
        && let Ok(t) = t.parse::<u64>()
        && t < i
    {
        r.warn(format!(
            "{label}: health-check timeout ({t}s) is less than interval ({i}s); the script may be killed before completion"
        ));
    }
    Some(Script {
        command,
        interval,
        timeout,
        fall,
    })
}

fn render_script(r: &mut Render, name: &str, script: &Script) {
    r.line(0, &format!("vrrp_script {name} {{"));
    r.line(1, &format!("script \"{}\"", script.command));
    r.line(1, &format!("interval {}", script.interval));
    if let Some(t) = &script.timeout {
        r.line(1, &format!("timeout {t}"));
    }
    r.line(1, &format!("fall {}", script.fall));
    r.line(1, "rise 1");
    r.line(0, "}");
    r.gap();
}

/// `advert_int`: whole seconds for VRRPv2 (rounded up with a warning),
/// fractional up to 40.95 s for VRRPv3 (clamped with a warning).
fn advert_interval(r: &mut Render, name: &str, value: Option<String>, version: u8) -> String {
    let raw = value.unwrap_or_else(|| DEFAULT_ADVERT_INTERVAL.to_string());
    let secs = match raw.parse::<f64>() {
        Ok(v) if v > 0.0 && v.is_finite() => v,
        _ => {
            r.warn(format!(
                "group {name}: advertise-interval {raw} is not a positive number; using 1"
            ));
            return DEFAULT_ADVERT_INTERVAL.to_string();
        }
    };
    if version == 2 {
        if secs.fract() != 0.0 {
            let up = secs.ceil();
            r.warn(format!(
                "group {name}: advertise-interval {raw} rounded up to {up}s (VRRPv2 uses whole seconds)"
            ));
            return format!("{}", up as u64);
        }
        return format!("{}", secs as u64);
    }
    if secs > MAX_V3_ADVERT_INTERVAL {
        r.warn(format!(
            "group {name}: advertise-interval {raw} clamped to {MAX_V3_ADVERT_INTERVAL}s (VRRPv3 maximum)"
        ));
        return format_decimal(MAX_V3_ADVERT_INTERVAL);
    }
    format_decimal(secs)
}

/// `1` for integral values, else at most two decimals without
/// trailing zeros.
fn format_decimal(v: f64) -> String {
    if v.fract() == 0.0 {
        return format!("{}", v as u64);
    }
    let s = format!("{v:.2}");
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

/// The five GARP leaves in the order the VyOS template emits them at
/// the given scope; VyOS applies the schema defaults to every leaf once
/// the `garp` node exists.
fn render_garp(r: &mut Render, prefix: &str, garp: &Garp, global: bool) {
    let leaves: [(&str, &Option<Flex>, &str); 5] = if global {
        [
            ("interval", &garp.interval, DEFAULT_GARP_INTERVAL),
            (
                "master_delay",
                &garp.master_delay,
                DEFAULT_GARP_MASTER_DELAY,
            ),
            (
                "master_refresh",
                &garp.master_refresh,
                DEFAULT_GARP_MASTER_REFRESH,
            ),
            (
                "master_refresh_repeat",
                &garp.master_refresh_repeat,
                DEFAULT_GARP_MASTER_REFRESH_REPEAT,
            ),
            (
                "master_repeat",
                &garp.master_repeat,
                DEFAULT_GARP_MASTER_REPEAT,
            ),
        ]
    } else {
        [
            ("interval", &garp.interval, DEFAULT_GARP_INTERVAL),
            (
                "master_delay",
                &garp.master_delay,
                DEFAULT_GARP_MASTER_DELAY,
            ),
            (
                "master_repeat",
                &garp.master_repeat,
                DEFAULT_GARP_MASTER_REPEAT,
            ),
            (
                "master_refresh",
                &garp.master_refresh,
                DEFAULT_GARP_MASTER_REFRESH,
            ),
            (
                "master_refresh_repeat",
                &garp.master_refresh_repeat,
                DEFAULT_GARP_MASTER_REFRESH_REPEAT,
            ),
        ]
    };
    for (key, value, default) in leaves {
        let value = flex(value).unwrap_or_else(|| default.to_string());
        r.line(1, &format!("{prefix}{key} {value}"));
    }
}

fn render_notify(r: &mut Render, label: &str, ts: &TransitionScript) {
    for (event, value) in [
        ("master", &ts.master),
        ("backup", &ts.backup),
        ("fault", &ts.fault),
        ("stop", &ts.stop),
    ] {
        if let Some(script) = flex(value) {
            if quotable(&script) {
                r.line(1, &format!("notify_{event} \"{script}\""));
            } else {
                r.warn(format!(
                    "{label}: transition-script {event} contains characters keepalived cannot quote; dropped"
                ));
            }
        }
    }
}

fn render_addresses(r: &mut Render, keyword: &str, addrs: &[(String, Option<String>)]) {
    if addrs.is_empty() {
        return;
    }
    r.line(1, &format!("{keyword} {{"));
    for (addr, dev) in addrs {
        match dev {
            Some(dev) => r.line(2, &format!("{addr} dev {dev}")),
            None => r.line(2, addr),
        }
    }
    r.line(1, "}");
}

fn render_instance(r: &mut Render, inst: &Instance, script: Option<&str>) {
    let g = inst.group;
    let name = &inst.name;
    r.line(0, &format!("vrrp_instance {name} {{"));
    if let Some(desc) = flex(&g.description) {
        let desc: String = desc.chars().filter(|c| !matches!(c, '\n' | '\r')).collect();
        r.line(1, &format!("# {desc}"));
    }
    r.line(1, "state BACKUP");
    r.line(1, &format!("interface {}", inst.interface));
    r.line(1, &format!("virtual_router_id {}", inst.vrid));
    r.line(
        1,
        &format!(
            "priority {}",
            flex(&g.priority).unwrap_or_else(|| DEFAULT_PRIORITY.to_string())
        ),
    );
    let advert = advert_interval(r, name, flex(&g.advertise_interval), inst.version);
    r.line(1, &format!("advert_int {advert}"));
    if inst.explicit_version {
        r.line(1, &format!("version {}", inst.version));
    }
    if g.v3_checksum_as_v2 {
        r.line(1, "v3_checksum_as_v2");
    }
    if let Some(garp) = &g.garp {
        render_garp(r, "garp_", garp, false);
    }
    if g.track.as_ref().is_some_and(|t| t.exclude_vrrp_interface) {
        r.line(1, "dont_track_primary");
    }
    if g.no_preempt {
        r.line(1, "nopreempt");
    } else {
        r.line(
            1,
            &format!(
                "preempt_delay {}",
                flex(&g.preempt_delay).unwrap_or_else(|| DEFAULT_PREEMPT_DELAY.to_string())
            ),
        );
    }
    if !inst.peers.is_empty() {
        r.line(1, "unicast_peer {");
        for p in &inst.peers {
            r.line(2, p);
        }
        r.line(1, "}");
    }
    if let Some(src) = &inst.src_ip {
        if inst.peers.is_empty() {
            r.line(1, &format!("mcast_src_ip {src}"));
        } else {
            r.line(1, &format!("unicast_src_ip {src}"));
        }
    }
    if g.rfc3768_compatibility {
        let vmac = format!(
            "{}v{}v{}",
            inst.interface,
            inst.vrid,
            inst.fam.vmac_suffix()
        );
        if vmac.len() > MAX_IFNAME {
            r.warn(format!(
                "group {name}: rfc3768-compatibility ignored: VMAC name {vmac} exceeds {MAX_IFNAME} characters"
            ));
        } else {
            r.line(1, &format!("use_vmac {vmac}"));
            if !inst.peers.is_empty() {
                r.line(1, "vmac_xmit_base");
            }
        }
    }
    if let Some((password, kind)) = &inst.auth {
        r.line(1, "authentication {");
        r.line(2, &format!("auth_pass \"{password}\""));
        r.line(2, &format!("auth_type {kind}"));
        r.line(1, "}");
    }
    render_addresses(r, "virtual_ipaddress", &inst.vips);
    render_addresses(r, "virtual_ipaddress_excluded", &inst.evips);
    if !inst.track_ifs.is_empty() {
        r.line(1, "track_interface {");
        for i in &inst.track_ifs {
            r.line(2, i);
        }
        r.line(1, "}");
    }
    if let Some(script) = script {
        r.line(1, "track_script {");
        r.line(2, script);
        r.line(1, "}");
    }
    if let Some(ts) = &g.transition_script {
        render_notify(r, &format!("group {name}"), ts);
    }
    r.line(0, "}");
    r.gap();
}

/// Parse the subtree JSON and render the full keepalived.conf. Serves
/// the test suite; the event loop parses and renders separately
/// because it retains the model for `show vrrp`.
#[cfg(test)]
pub fn render_str(json: &str) -> anyhow::Result<(String, Vec<String>)> {
    let cfg: VrrpConfig =
        serde_json::from_str(json).map_err(|e| anyhow::anyhow!("vrrp config JSON: {e}"))?;
    Ok(render(&cfg))
}

/// Render the whole `keepalived.conf`. An empty tree (or a disabled
/// one) renders the empty string, which [`keepalived::apply`] treats
/// as "stop".
pub fn render(cfg: &VrrpConfig) -> (String, Vec<String>) {
    let mut r = Render {
        out: String::new(),
        warnings: Vec::new(),
    };
    if cfg.is_empty() {
        return (r.out, r.warnings);
    }

    // global_defs — `notify_fifo` lines deliberately not emitted.
    let gp = &cfg.global_parameters;
    r.line(0, "global_defs {");
    r.line(1, "dynamic_interfaces");
    r.line(1, "script_user root");
    if let Some(delay) = flex(&gp.startup_delay) {
        r.line(1, &format!("vrrp_startup_delay {delay}"));
    }
    if let Some(garp) = &gp.garp {
        render_garp(&mut r, "vrrp_garp_", garp, true);
    }
    if let Some(version) = flex(&gp.version) {
        r.line(1, &format!("vrrp_version {version}"));
    }
    r.line(0, "}");
    r.gap();

    // Validate groups first: sync-group membership needs the set of
    // groups that will actually exist.
    let mut seen = HashSet::new();
    let instances: Vec<Instance> = cfg
        .group
        .iter()
        .filter_map(|g| check_group(cfg, g, &mut seen, &mut r))
        .collect();
    let names: HashSet<&str> = instances.iter().map(|i| i.name.as_str()).collect();

    // Sync groups: members must exist; a member's own health check is
    // ignored in favour of the sync group's (VyOS rejects that commit).
    let mut member_of: HashMap<String, String> = HashMap::new();
    let mut sync_groups: Vec<(String, &SyncGroup, Vec<String>, Option<Script>)> = Vec::new();
    for sg in &cfg.sync_group {
        let Some(name) = flex(&sg.name) else {
            r.warn("sync-group without a name; skipped".to_string());
            continue;
        };
        if !safe_name(&name) {
            r.warn(format!(
                "sync-group {name}: name is not a plain token; skipped"
            ));
            continue;
        }
        let mut members = Vec::new();
        for m in &sg.member {
            let m = m.to_string();
            if !names.contains(m.as_str()) {
                r.warn(format!(
                    "sync-group {name}: member {m} does not exist or is disabled; dropped"
                ));
                continue;
            }
            if let Some(other) = member_of.get(&m) {
                r.warn(format!(
                    "sync-group {name}: member {m} already belongs to sync-group {other}; dropped"
                ));
                continue;
            }
            if instances
                .iter()
                .any(|i| i.name == m && i.group.health_check.is_some())
            {
                r.warn(format!(
                    "sync-group {name}: member {m} has its own health-check, which is ignored; only the sync-group health check is used"
                ));
            }
            member_of.insert(m.clone(), name.clone());
            members.push(m);
        }
        if members.is_empty() {
            r.warn(format!("sync-group {name}: no valid members; skipped"));
            continue;
        }
        let script = sg
            .health_check
            .as_ref()
            .and_then(|hc| check_health(&format!("sync-group {name}"), hc, &mut r));
        sync_groups.push((name, sg, members, script));
    }

    for (name, _, _, script) in &sync_groups {
        if let Some(script) = script {
            render_script(&mut r, &format!("healthcheck_sg_{name}"), script);
        }
    }

    for inst in &instances {
        let script_name = match (&inst.group.health_check, member_of.contains_key(&inst.name)) {
            (Some(hc), false) => {
                check_health(&format!("group {}", inst.name), hc, &mut r).map(|script| {
                    let script_name = format!("healthcheck_{}", inst.name);
                    render_script(&mut r, &script_name, &script);
                    script_name
                })
            }
            _ => None,
        };
        render_instance(&mut r, inst, script_name.as_deref());
    }

    for (name, sg, members, script) in &sync_groups {
        r.line(0, &format!("vrrp_sync_group {name} {{"));
        r.line(1, "group {");
        for m in members {
            r.line(2, m);
        }
        r.line(1, "}");
        if script.is_some() {
            r.line(1, "track_script {");
            r.line(2, &format!("healthcheck_sg_{name}"));
            r.line(1, "}");
        }
        if let Some(ts) = &sg.transition_script {
            render_notify(&mut r, &format!("sync-group {name}"), ts);
        }
        r.line(0, "}");
        r.gap();
    }

    let mut out = r.out;
    while out.ends_with("\n\n") {
        out.pop();
    }
    (out, r.warnings)
}

// ---------------------------------------------------------------
// show vrrp — keepalived's JSON dump rendered the VyOS way
// ---------------------------------------------------------------

async fn process_show(ka: &Keepalived, state: &ShowState, req: ShowRequest) {
    let path = req.path.as_str();
    // `/show/vrrp/<view>[/group]` with the group name in args.
    let (view, filter) = match path {
        "/show/vrrp" => ("summary", None),
        "/show/vrrp/statistics" => ("statistics", None),
        "/show/vrrp/statistics/group" => ("statistics", req.args.first().cloned()),
        "/show/vrrp/detail" => ("detail", None),
        "/show/vrrp/detail/group" => ("detail", req.args.first().cloned()),
        _ => {
            let _ = req.resp.send(String::from("% Unknown vrrp show command\n"));
            return;
        }
    };

    let data = match keepalived::collect_json(ka, DEFAULT_INSTANCE).await {
        Ok(data) => data,
        Err(err) => {
            tracing::debug!("vrrp: {err}");
            // VyOS still lists disabled groups when keepalived has
            // nothing to say.
            let out = match (view, req.json) {
                ("summary", false) if state.model.is_some() => {
                    summary_text(&[], &disabled_rows(state.model.as_ref()), now_secs())
                }
                (_, true) => "[]\n".to_string(),
                _ => format!("{err}\n"),
            };
            let _ = req.resp.send(out);
            return;
        }
    };
    let data = match &filter {
        Some(name) => {
            let filtered: Vec<serde_json::Value> = data
                .into_iter()
                .filter(|rec| rec["data"]["iname"].as_str() == Some(name))
                .collect();
            if filtered.is_empty() && !req.json {
                let _ = req
                    .resp
                    .send(format!("% VRRP group \"{name}\" not found\n"));
                return;
            }
            filtered
        }
        None => data,
    };

    let out = if req.json {
        format!("{:#}\n", serde_json::Value::Array(data))
    } else {
        match view {
            "summary" => summary_text(&data, &disabled_rows(state.model.as_ref()), now_secs()),
            "statistics" => statistics_text(&data),
            _ => detail_text(&data),
        }
    };
    let _ = req.resp.send(out);
}

fn now_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// keepalived `vrrp_state` codes (vrrp.h).
fn state_name(code: i64) -> &'static str {
    match code {
        0 => "INIT",
        1 => "BACKUP",
        2 => "MASTER",
        3 => "FAULT",
        _ => "UNKNOWN",
    }
}

/// keepalived `auth_type` codes (vrrp.h), VyOS spellings.
fn auth_name(code: i64) -> &'static str {
    match code {
        0 => "NONE",
        1 => "SIMPLE_PASSWORD",
        2 => "IPSEC_AH",
        _ => "unknown",
    }
}

/// A JSON scalar as VyOS's Jinja would print it: strings bare,
/// numbers as is.
fn scalar(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn int(v: &serde_json::Value) -> i64 {
    match v {
        serde_json::Value::Number(n) => n
            .as_i64()
            .or_else(|| n.as_f64().map(|f| f as i64))
            .unwrap_or(0),
        serde_json::Value::Bool(b) => i64::from(*b),
        _ => 0,
    }
}

/// Python truthiness of a JSON value.
fn truthy(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Null => false,
        serde_json::Value::Bool(b) => *b,
        serde_json::Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        serde_json::Value::String(s) => !s.is_empty(),
        serde_json::Value::Array(a) => !a.is_empty(),
        serde_json::Value::Object(o) => !o.is_empty(),
    }
}

/// `show vrrp` rows for groups carrying `disable` in the last committed
/// model — VyOS appends them to the live table.
fn disabled_rows(model: Option<&VrrpConfig>) -> Vec<Vec<String>> {
    let Some(cfg) = model else {
        return Vec::new();
    };
    cfg.group
        .iter()
        .filter(|g| g.disable)
        .map(|g| {
            vec![
                flex(&g.name).unwrap_or_default(),
                flex(&g.interface).unwrap_or_default(),
                flex(&g.vrid).unwrap_or_default(),
                "DISABLED".to_string(),
                String::new(),
                String::new(),
            ]
        })
        .collect()
}

/// `VRRP.format`: Name, Interface, VRID, State, Priority, Last Transition.
fn summary_text(data: &[serde_json::Value], disabled: &[Vec<String>], now: f64) -> String {
    let mut rows: Vec<Vec<String>> = data
        .iter()
        .map(|rec| {
            let d = &rec["data"];
            let since = (now - d["last_transition"].as_f64().unwrap_or(now)).max(0.0) as u64;
            vec![
                scalar(&d["iname"]),
                scalar(&d["ifp_ifname"]),
                scalar(&d["vrid"]),
                state_name(int(&d["state"])).to_string(),
                scalar(&d["effective_priority"]),
                seconds_to_human(since),
            ]
        })
        .collect();
    rows.extend(disabled.iter().cloned());
    table(
        &[
            "Name",
            "Interface",
            "VRID",
            "State",
            "Priority",
            "Last Transition",
        ],
        &rows,
    )
}

/// `show vrrp statistics` — the `stat_template` of vyos-1x
/// `src/op_mode/vrrp.py`.
fn statistics_text(data: &[serde_json::Value]) -> String {
    let mut out = String::new();
    for rec in data {
        let s = &rec["stats"];
        let d = &rec["data"];
        out.push('\n');
        out.push_str(&format!("VRRP Instance: {}\n", scalar(&d["iname"])));
        out.push_str("  Advertisements:\n");
        out.push_str(&format!("    Received: {}\n", scalar(&s["advert_rcvd"])));
        out.push_str(&format!("    Sent: {}\n", scalar(&s["advert_sent"])));
        out.push_str(&format!(
            "  Became master: {}\n",
            scalar(&s["become_master"])
        ));
        out.push_str(&format!(
            "  Released master: {}\n",
            scalar(&s["release_master"])
        ));
        out.push_str("  Packet Errors:\n");
        out.push_str(&format!("    Length: {}\n", scalar(&s["packet_len_err"])));
        out.push_str(&format!("    TTL: {}\n", scalar(&s["ip_ttl_err"])));
        out.push_str(&format!(
            "    Invalid Type: {}\n",
            scalar(&s["invalid_type_rcvd"])
        ));
        out.push_str(&format!(
            "    Advertisement Interval: {}\n",
            scalar(&s["advert_interval_err"])
        ));
        out.push_str(&format!(
            "    Address List: {}\n",
            scalar(&s["addr_list_err"])
        ));
        out.push_str("  Authentication Errors:\n");
        out.push_str(&format!(
            "    Invalid Type: {}\n",
            scalar(&s["invalid_authtype"])
        ));
        out.push_str(&format!(
            "    Type Mismatch: {}\n",
            scalar(&s["authtype_mismatch"])
        ));
        out.push_str(&format!("    Failure: {}\n", scalar(&s["auth_failure"])));
        out.push_str("  Priority Zero:\n");
        out.push_str(&format!("    Received: {}\n", scalar(&s["pri_zero_rcvd"])));
        out.push_str(&format!("    Sent: {}\n", scalar(&s["pri_zero_sent"])));
    }
    if out.is_empty() {
        out.push('\n');
    }
    out
}

/// `show vrrp detail` — the `detail_template` of vyos-1x
/// `src/op_mode/vrrp.py`, including its boolean spellings.
fn detail_text(data: &[serde_json::Value]) -> String {
    let mut out = String::new();
    let list = |out: &mut String, title: &str, items: &serde_json::Value| {
        if let Some(items) = items.as_array()
            && !items.is_empty()
        {
            out.push_str(&format!("   {title}:\n"));
            for item in items {
                out.push_str(&format!("       {}\n", scalar(item)));
            }
        }
    };
    for (i, rec) in data.iter().enumerate() {
        let d = &rec["data"];
        if i > 0 {
            out.push('\n');
        }
        let version = int(&d["version"]);
        let state = state_name(int(&d["state"]));
        out.push_str(&format!(" VRRP Instance: {}\n", scalar(&d["iname"])));
        out.push_str(&format!("   VRRP Version: {version}\n"));
        out.push_str(&format!("   State: {state}\n"));
        if state == "BACKUP" {
            out.push_str(&format!(
                "   Master priority: {}\n",
                scalar(&d["master_priority"])
            ));
            if version == 3 {
                out.push_str(&format!(
                    "   Master advert interval: {}\n",
                    scalar(&d["master_adver_int"])
                ));
            }
        }
        out.push_str(&format!(
            "   Wantstate: {}\n",
            state_name(int(&d["wantstate"]))
        ));
        out.push_str(&format!(
            "   Last transition: {}\n",
            scalar(&d["last_transition"])
        ));
        out.push_str(&format!("   Interface: {}\n", scalar(&d["ifp_ifname"])));
        if truthy(&d["dont_track_primary"]) {
            out.push_str("   VRRP interface tracking disabled\n");
        }
        if truthy(&d["skip_check_adv_addr"]) {
            out.push_str("   Skip checking advert IP addresses\n");
        }
        if truthy(&d["strict_mode"]) {
            out.push_str("   Enforcing strict VRRP compliance\n");
        }
        out.push_str(&format!(
            "   Gratuitous ARP delay: {}\n",
            scalar(&d["garp_delay"])
        ));
        out.push_str(&format!(
            "   Gratuitous ARP repeat: {}\n",
            scalar(&d["garp_rep"])
        ));
        out.push_str(&format!(
            "   Gratuitous ARP refresh: {}\n",
            scalar(&d["garp_refresh"])
        ));
        out.push_str(&format!(
            "   Gratuitous ARP refresh repeat: {}\n",
            scalar(&d["garp_refresh_rep"])
        ));
        out.push_str(&format!(
            "   Gratuitous ARP lower priority delay: {}\n",
            scalar(&d["garp_lower_prio_delay"])
        ));
        out.push_str(&format!(
            "   Gratuitous ARP lower priority repeat: {}\n",
            scalar(&d["garp_lower_prio_rep"])
        ));
        out.push_str(&format!(
            "   Send advert after receive lower priority advert: {}\n",
            if truthy(&d["lower_prio_no_advert"]) {
                "false"
            } else {
                "true"
            }
        ));
        out.push_str(&format!(
            "   Send advert after receive higher priority advert: {}\n",
            if truthy(&d["higher_prio_send_advert"]) {
                "true"
            } else {
                "false"
            }
        ));
        out.push_str(&format!("   Virtual Router ID: {}\n", scalar(&d["vrid"])));
        out.push_str(&format!("   Priority: {}\n", scalar(&d["base_priority"])));
        out.push_str(&format!(
            "   Effective priority: {}\n",
            scalar(&d["effective_priority"])
        ));
        out.push_str(&format!(
            "   Advert interval: {} sec\n",
            scalar(&d["adver_int"])
        ));
        out.push_str(&format!(
            "   Accept: {}\n",
            if truthy(&d["accept"]) {
                "Enabled"
            } else {
                "Disabled"
            }
        ));
        out.push_str(&format!(
            "   Preempt: {}\n",
            if truthy(&d["nopreempt"]) {
                "Disabled"
            } else {
                "Enabled"
            }
        ));
        if truthy(&d["preempt_delay"]) {
            out.push_str(&format!(
                "   Preempt delay: {}\n",
                scalar(&d["preempt_delay"])
            ));
        }
        out.push_str(&format!(
            "   Promote secondaries: {}\n",
            if truthy(&d["promote_secondaries"]) {
                "Enabled"
            } else {
                "Disabled"
            }
        ));
        out.push_str(&format!(
            "   Authentication type: {}\n",
            auth_name(int(&d["auth_type"]))
        ));
        if let Some(vips) = d["vips"].as_array()
            && !vips.is_empty()
        {
            out.push_str(&format!("   Virtual IP ({}):\n", vips.len()));
            for ip in vips {
                out.push_str(&format!("       {}\n", scalar(ip)));
            }
        }
        list(&mut out, "Virtual IP Excluded", &d["evips"]);
        list(&mut out, "Virtual Routes", &d["vroutes"]);
        list(&mut out, "Virtual Rules", &d["vrules"]);
        list(&mut out, "Tracked interfaces", &d["track_ifp"]);
        list(&mut out, "Tracked scripts", &d["track_script"]);
        out.push_str(&format!(
            "   Using smtp notification: {}\n",
            if truthy(&d["smtp_alert"]) {
                "yes"
            } else {
                "no"
            }
        ));
        out.push_str(&format!(
            "   Notify deleted: {}\n",
            if truthy(&d["notify_deleted"]) {
                "Deleted"
            } else {
                "Fault"
            }
        ));
    }
    if out.is_empty() {
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Presence leaves arrive as `"name": null`; numeric-looking
    /// values arrive as JSON numbers; leaf-lists may be bare scalars.
    /// Both list-key spellings for addresses deserialize.
    #[test]
    fn model_deserializes_config_json_shapes() {
        let json = r#"{
            "disable": null,
            "global-parameters": {"version": 3, "startup-delay": 30, "garp": {"interval": 0.5}},
            "group": [{
                "name": 10, "interface": "eth0", "vrid": 5, "priority": 200,
                "advertise-interval": 0.5, "no-preempt": null, "rfc3768-compatibility": null,
                "v3-checksum-as-v2": null, "version": 3,
                "address": [{"address": "192.0.2.1/24"}, {"ip": "192.0.2.2/24", "interface": "eth1"}],
                "peer-address": "192.0.2.9",
                "track": {"exclude-vrrp-interface": null, "interface": ["eth1"]},
                "authentication": {"password": 12345678, "type": "ah"},
                "health-check": {"ping": "192.0.2.1", "interval": 5}
            }],
            "sync-group": [{"name": "SG", "member": ["10"]}]
        }"#;
        let cfg: VrrpConfig = serde_json::from_str(json).expect("parse");
        assert!(cfg.disable);
        assert_eq!(flex(&cfg.global_parameters.version).as_deref(), Some("3"));
        let g = &cfg.group[0];
        assert_eq!(flex(&g.name).as_deref(), Some("10"));
        assert!(g.no_preempt && g.rfc3768_compatibility && g.v3_checksum_as_v2);
        assert_eq!(flex(&g.advertise_interval).as_deref(), Some("0.5"));
        assert_eq!(g.address.len(), 2);
        assert_eq!(flex(&g.address[1].address).as_deref(), Some("192.0.2.2/24"));
        assert_eq!(flex(&g.address[1].interface).as_deref(), Some("eth1"));
        assert_eq!(g.peer_address.len(), 1);
        assert!(g.track.as_ref().unwrap().exclude_vrrp_interface);
        assert_eq!(
            flex(&g.authentication.as_ref().unwrap().password).as_deref(),
            Some("12345678")
        );
        assert_eq!(cfg.sync_group[0].member[0].to_string(), "10");
        assert!(cfg.is_empty(), "disable makes the tree empty");
    }

    #[test]
    fn empty_and_disabled_render_nothing() {
        assert_eq!(render_str("{}").unwrap(), (String::new(), vec![]));
        assert_eq!(
            render_str(r#"{"disable": null, "group": [{"name": "A", "interface": "eth0", "vrid": 1, "address": [{"address": "10.0.0.1"}]}]}"#).unwrap(),
            (String::new(), vec![])
        );
    }

    const GOLDEN: &str = r#"{
        "global-parameters": {"garp": {"master-delay": 10}, "startup-delay": 30, "version": 2},
        "group": [
            {"name": "WAN", "interface": "eth0", "vrid": 10, "priority": 200, "advertise-interval": 1,
             "description": "uplink pair", "preempt-delay": 5,
             "address": [{"address": "192.0.2.254/24"}, {"address": "192.0.2.253/24", "interface": "eth1"}],
             "excluded-address": [{"address": "198.51.100.1/32"}],
             "track": {"exclude-vrrp-interface": null, "interface": ["eth1", "eth2"]},
             "health-check": {"ping": "192.0.2.1", "interval": 10, "failure-count": 2, "timeout": 5},
             "transition-script": {"master": "/usr/local/bin/on-master", "fault": "/usr/local/bin/on-fault"},
             "garp": {"interval": 0.5, "master-repeat": 3}},
            {"name": "DMZ", "interface": "eth3", "vrid": 20, "no-preempt": null, "rfc3768-compatibility": null,
             "hello-source-address": "10.0.0.2", "peer-address": ["10.0.0.3", "10.0.0.4"],
             "authentication": {"password": "s3cret", "type": "plaintext-password"},
             "address": [{"address": "10.0.0.1/24"}], "version": 3, "v3-checksum-as-v2": null,
             "advertise-interval": 0.5},
            {"name": "V6", "interface": "eth0", "vrid": 10, "address": [{"address": "2001:db8::1/64"}],
             "health-check": {"script": "/usr/local/bin/check", "interval": 5, "failure-count": 3}},
            {"name": "OFF", "interface": "eth9", "vrid": 99, "disable": null,
             "address": [{"address": "10.9.9.9/24"}]}
        ],
        "sync-group": [
            {"name": "PAIR", "member": ["WAN", "DMZ"], "health-check": {"ping": "10.0.0.9"},
             "transition-script": {"backup": "/usr/local/bin/sg-backup"}}
        ]
    }"#;

    #[test]
    fn golden_render() {
        let (out, warnings) = render_str(GOLDEN).unwrap();
        let expected = "\
global_defs {
    dynamic_interfaces
    script_user root
    vrrp_startup_delay 30
    vrrp_garp_interval 0
    vrrp_garp_master_delay 10
    vrrp_garp_master_refresh 5
    vrrp_garp_master_refresh_repeat 1
    vrrp_garp_master_repeat 5
    vrrp_version 2
}

vrrp_script healthcheck_sg_PAIR {
    script \"/usr/bin/ping -c1 10.0.0.9\"
    interval 60
    fall 3
    rise 1
}

vrrp_instance WAN {
    # uplink pair
    state BACKUP
    interface eth0
    virtual_router_id 10
    priority 200
    advert_int 1
    garp_interval 0.5
    garp_master_delay 5
    garp_master_repeat 3
    garp_master_refresh 5
    garp_master_refresh_repeat 1
    dont_track_primary
    preempt_delay 5
    virtual_ipaddress {
        192.0.2.254/24
        192.0.2.253/24 dev eth1
    }
    virtual_ipaddress_excluded {
        198.51.100.1/32
    }
    track_interface {
        eth1
        eth2
    }
    notify_master \"/usr/local/bin/on-master\"
    notify_fault \"/usr/local/bin/on-fault\"
}

vrrp_instance DMZ {
    state BACKUP
    interface eth3
    virtual_router_id 20
    priority 100
    advert_int 0.5
    version 3
    v3_checksum_as_v2
    nopreempt
    unicast_peer {
        10.0.0.3
        10.0.0.4
    }
    unicast_src_ip 10.0.0.2
    use_vmac eth3v20v4
    vmac_xmit_base
    authentication {
        auth_pass \"s3cret\"
        auth_type PASS
    }
    virtual_ipaddress {
        10.0.0.1/24
    }
}

vrrp_script healthcheck_V6 {
    script \"/usr/local/bin/check\"
    interval 5
    fall 3
    rise 1
}

vrrp_instance V6 {
    state BACKUP
    interface eth0
    virtual_router_id 10
    priority 100
    advert_int 1
    preempt_delay 0
    virtual_ipaddress {
        2001:db8::1/64
    }
    track_script {
        healthcheck_V6
    }
}

vrrp_sync_group PAIR {
    group {
        WAN
        DMZ
    }
    track_script {
        healthcheck_sg_PAIR
    }
    notify_backup \"/usr/local/bin/sg-backup\"
}
";
        assert_eq!(out, expected);
        assert_eq!(
            warnings,
            vec![
                "sync-group PAIR: member WAN has its own health-check, which is ignored; only the sync-group health check is used"
            ]
        );
    }

    fn group(extra: &str) -> String {
        format!(
            r#"{{"group": [{{"name": "G", "interface": "eth0", "vrid": 1, "address": [{{"address": "10.0.0.1/24"}}]{extra}}}]}}"#
        )
    }

    /// Every skip rule leaves a valid file (global_defs only) and one
    /// warning naming the group.
    #[test]
    fn skip_rules_warn_and_never_wedge() {
        let cases: Vec<(String, &str)> = vec![
            (
                r#"{"group": [{"name": "G", "interface": "eth0", "address": [{"address": "10.0.0.1"}]}]}"#.to_string(),
                "group G: vrid is required but not set; skipped",
            ),
            (
                r#"{"group": [{"name": "G", "vrid": 1, "address": [{"address": "10.0.0.1"}]}]}"#.to_string(),
                "group G: interface is required but not set; skipped",
            ),
            (
                r#"{"group": [{"name": "G", "interface": "eth0", "vrid": 1}]}"#.to_string(),
                "group G: virtual IP address is required but not set; skipped",
            ),
            (
                r#"{"group": [{"name": "G", "interface": "eth0", "vrid": 1, "address": [{"address": "10.0.0.1"}, {"address": "2001:db8::1"}]}]}"#.to_string(),
                "group G: mixes IPv4 and IPv6 virtual addresses; create separate groups per family; skipped",
            ),
            (
                group(r#", "hello-source-address": "2001:db8::2""#),
                "group G: uses IPv4 but hello-source-address is IPv6; skipped",
            ),
            (
                group(r#", "peer-address": ["2001:db8::3"]"#),
                "group G: uses IPv4 but peer-address 2001:db8::3 is IPv6; skipped",
            ),
            (
                group(r#", "authentication": {"password": "x"}"#),
                "group G: authentication requires both type and password; skipped",
            ),
            (
                r#"{"group": [{"name": "G", "interface": "eth0", "vrid": 1, "address": [{"address": "not-an-ip"}]}]}"#.to_string(),
                "group G: address not-an-ip is not an IP address; skipped",
            ),
            (
                r#"{"group": [{"name": "G", "interface": "eth 0", "vrid": 1, "address": [{"address": "10.0.0.1/24"}]}]}"#.to_string(),
                "group G: interface name is not a plain token; skipped",
            ),
        ];
        for (json, warning) in cases {
            let (out, warnings) = render_str(&json).unwrap();
            assert_eq!(
                out, "global_defs {\n    dynamic_interfaces\n    script_user root\n}\n",
                "output for {warning}"
            );
            assert_eq!(warnings, vec![warning]);
        }
    }

    #[test]
    fn duplicate_vrid_per_interface_and_family() {
        let json = r#"{"group": [
            {"name": "A", "interface": "eth0", "vrid": 1, "address": [{"address": "10.0.0.1"}]},
            {"name": "B", "interface": "eth0", "vrid": 1, "address": [{"address": "10.0.0.2"}]},
            {"name": "C", "interface": "eth0", "vrid": 1, "address": [{"address": "2001:db8::1"}]},
            {"name": "D", "interface": "eth1", "vrid": 1, "address": [{"address": "10.0.0.3"}]}
        ]}"#;
        let (out, warnings) = render_str(json).unwrap();
        assert_eq!(
            warnings,
            vec!["group B: VRID 1 is already used on interface eth0 for IPv4; skipped"]
        );
        for name in ["A", "C", "D"] {
            assert!(out.contains(&format!("vrrp_instance {name} {{")), "{name}");
        }
        assert!(!out.contains("vrrp_instance B"));
    }

    #[test]
    fn health_check_rules() {
        // Neither script nor ping: check omitted, instance kept.
        let (out, warnings) = render_str(&group(r#", "health-check": {"interval": 5}"#)).unwrap();
        assert!(!out.contains("vrrp_script"));
        assert!(!out.contains("track_script"));
        assert_eq!(
            warnings,
            vec!["group G: health-check needs exactly one of script / ping; health check omitted"]
        );
        // Timeout shorter than interval: rendered, warned.
        let (out, warnings) = render_str(&group(
            r#", "health-check": {"ping": "10.0.0.9", "interval": 30, "timeout": 10}"#,
        ))
        .unwrap();
        assert!(out.contains("    script \"/usr/bin/ping -c1 10.0.0.9\"\n    interval 30\n    timeout 10\n    fall 3\n    rise 1\n"));
        assert!(out.contains("    track_script {\n        healthcheck_G\n    }\n"));
        assert_eq!(
            warnings,
            vec![
                "group G: health-check timeout (10s) is less than interval (30s); the script may be killed before completion"
            ]
        );
    }

    #[test]
    fn sync_group_member_rules() {
        let json = r#"{"group": [
            {"name": "A", "interface": "eth0", "vrid": 1, "address": [{"address": "10.0.0.1"}]},
            {"name": "OFF", "interface": "eth1", "vrid": 2, "disable": null, "address": [{"address": "10.0.1.1"}]}
        ], "sync-group": [
            {"name": "SG", "member": ["A", "OFF", "NOPE"]},
            {"name": "SG2", "member": ["A"]},
            {"name": "EMPTY", "member": ["NOPE"]}
        ]}"#;
        let (out, warnings) = render_str(json).unwrap();
        assert_eq!(
            warnings,
            vec![
                "sync-group SG: member OFF does not exist or is disabled; dropped",
                "sync-group SG: member NOPE does not exist or is disabled; dropped",
                "sync-group SG2: member A already belongs to sync-group SG; dropped",
                "sync-group SG2: no valid members; skipped",
                "sync-group EMPTY: member NOPE does not exist or is disabled; dropped",
                "sync-group EMPTY: no valid members; skipped",
            ]
        );
        assert!(out.contains("vrrp_sync_group SG {\n    group {\n        A\n    }\n}\n"));
        assert!(!out.contains("SG2"));
        assert!(!out.contains("EMPTY"));
    }

    #[test]
    fn extension_leaves_and_advert_interval_rules() {
        // VRRPv2 (default for IPv4) rounds a fractional interval up.
        let (out, warnings) = render_str(&group(r#", "advertise-interval": 0.5"#)).unwrap();
        assert!(out.contains("    advert_int 1\n"));
        assert_eq!(
            warnings,
            vec!["group G: advertise-interval 0.5 rounded up to 1s (VRRPv2 uses whole seconds)"]
        );
        // Global version 3 lets the fraction through; per-group version
        // and the checksum knob render as keepalived keywords.
        let json = r#"{"global-parameters": {"version": 3}, "group": [
            {"name": "G", "interface": "eth0", "vrid": 1, "address": [{"address": "10.0.0.1"}], "advertise-interval": 0.25},
            {"name": "H", "interface": "eth0", "vrid": 2, "address": [{"address": "10.0.0.2"}], "version": 2, "advertise-interval": 2.5},
            {"name": "I", "interface": "eth0", "vrid": 3, "address": [{"address": "10.0.0.3"}], "v3-checksum-as-v2": null, "advertise-interval": 100}
        ]}"#;
        let (out, warnings) = render_str(json).unwrap();
        assert!(out.contains("    vrrp_version 3\n"));
        assert!(out.contains("vrrp_instance G {\n    state BACKUP\n    interface eth0\n    virtual_router_id 1\n    priority 100\n    advert_int 0.25\n"));
        assert!(out.contains("    advert_int 3\n    version 2\n"));
        assert!(out.contains("    advert_int 40.95\n    v3_checksum_as_v2\n"));
        assert_eq!(
            warnings,
            vec![
                "group H: advertise-interval 2.5 rounded up to 3s (VRRPv2 uses whole seconds)",
                "group I: advertise-interval 100 clamped to 40.95s (VRRPv3 maximum)",
            ]
        );
        // IPv6 never runs VRRPv2.
        let (out, warnings) = render_str(
            r#"{"group": [{"name": "S", "interface": "eth0", "vrid": 1, "version": 2, "address": [{"address": "2001:db8::1"}]}]}"#,
        )
        .unwrap();
        assert!(out.contains("    version 3\n"));
        assert_eq!(
            warnings,
            vec!["group S: VRRPv2 cannot carry IPv6; using version 3"]
        );
    }

    #[test]
    fn vmac_naming_and_multicast_source() {
        let (out, warnings) = render_str(&group(
            r#", "rfc3768-compatibility": null, "hello-source-address": "10.0.0.5""#,
        ))
        .unwrap();
        assert!(
            out.contains("    mcast_src_ip 10.0.0.5\n    use_vmac eth0v1v4\n    authentication")
                || out.contains(
                    "    mcast_src_ip 10.0.0.5\n    use_vmac eth0v1v4\n    virtual_ipaddress"
                )
        );
        assert!(!out.contains("vmac_xmit_base"));
        assert!(warnings.is_empty());
        let (out, warnings) = render_str(
            r#"{"group": [{"name": "G", "interface": "verylongifname0", "vrid": 1, "rfc3768-compatibility": null, "address": [{"address": "10.0.0.1"}]}]}"#,
        )
        .unwrap();
        assert!(!out.contains("use_vmac"));
        assert_eq!(
            warnings,
            vec![
                "group G: rfc3768-compatibility ignored: VMAC name verylongifname0v1v4 exceeds 15 characters"
            ]
        );
    }

    #[test]
    fn password_and_script_quoting() {
        let (_, warnings) = render_str(&group(
            r#", "authentication": {"password": "longerthan8", "type": "ah"}"#,
        ))
        .unwrap();
        assert_eq!(
            warnings,
            vec!["group G: password is longer than 8 characters; keepalived truncates it"]
        );
        let (out, warnings) = render_str(&group(
            r#", "transition-script": {"master": "/bin/echo \"hi\""}"#,
        ))
        .unwrap();
        assert!(!out.contains("notify_master"));
        assert_eq!(
            warnings,
            vec![
                "group G: transition-script master contains characters keepalived cannot quote; dropped"
            ]
        );
    }

    // ---- show views, from a keepalived 2.2.8 dump captured in the spike ----

    const MASTER: &str = r#"{"data":{"iname":"WAN","dont_track_primary":0,"skip_check_adv_addr":0,"strict_mode":0,"vmac_ifname":"","ifp_ifname":"v1","master_priority":0,"last_transition":1788833808.966043,"garp_delay":5,"garp_refresh":0,"garp_rep":5,"garp_refresh_rep":1,"garp_lower_prio_delay":5,"garp_lower_prio_rep":5,"lower_prio_no_advert":0,"higher_prio_send_advert":0,"vrid":10,"base_priority":200,"effective_priority":200,"vipset":true,"promote_secondaries":false,"adver_int":1,"master_adver_int":1,"accept":1,"nopreempt":false,"preempt_delay":0,"state":2,"wantstate":2,"version":2,"smtp_alert":false,"notify_deleted":false,"vips":["192.0.2.254\/24 dev v1 scope global set"],"auth_type":0},"stats":{"advert_rcvd":0,"advert_sent":6,"become_master":1,"release_master":0,"packet_len_err":0,"advert_interval_err":0,"ip_ttl_err":0,"invalid_type_rcvd":0,"addr_list_err":0,"invalid_authtype":0,"authtype_mismatch":0,"auth_failure":0,"pri_zero_rcvd":0,"pri_zero_sent":0}}"#;
    const BACKUP: &str = r#"{"data":{"iname":"WAN","dont_track_primary":0,"skip_check_adv_addr":0,"strict_mode":0,"vmac_ifname":"","ifp_ifname":"v2","master_priority":200,"last_transition":1788833809.763418,"garp_delay":5,"garp_refresh":0,"garp_rep":5,"garp_refresh_rep":1,"garp_lower_prio_delay":5,"garp_lower_prio_rep":5,"lower_prio_no_advert":0,"higher_prio_send_advert":0,"vrid":10,"base_priority":100,"effective_priority":100,"vipset":false,"promote_secondaries":false,"adver_int":1,"master_adver_int":1,"accept":1,"nopreempt":false,"preempt_delay":0,"state":1,"wantstate":1,"version":2,"smtp_alert":false,"notify_deleted":false,"vips":["192.0.2.254\/24 dev v2 scope global"],"auth_type":0},"stats":{"advert_rcvd":5,"advert_sent":0,"become_master":0,"release_master":0,"packet_len_err":0,"advert_interval_err":0,"ip_ttl_err":0,"invalid_type_rcvd":0,"addr_list_err":0,"invalid_authtype":0,"authtype_mismatch":0,"auth_failure":0,"pri_zero_rcvd":0,"pri_zero_sent":0}}"#;

    fn dump(records: &[&str]) -> Vec<serde_json::Value> {
        records
            .iter()
            .map(|r| serde_json::from_str(r).expect("fixture"))
            .collect()
    }

    #[test]
    fn summary_table_from_dump() {
        let mut backup: serde_json::Value = serde_json::from_str(BACKUP).unwrap();
        backup["data"]["iname"] = serde_json::Value::String("DMZ".into());
        let data = vec![serde_json::from_str(MASTER).unwrap(), backup];
        let model: VrrpConfig = serde_json::from_str(
            r#"{"group": [{"name": "OFF", "interface": "eth9", "vrid": 99, "disable": null}]}"#,
        )
        .unwrap();
        let now = 1788833808.966043 + 93784.0;
        let out = summary_text(&data, &disabled_rows(Some(&model)), now);
        assert_eq!(
            out,
            "\
Name  Interface  VRID  State     Priority  Last Transition
----  ---------  ----  --------  --------  ---------------
WAN   v1         10    MASTER    200       1d2h3m4s
DMZ   v2         10    BACKUP    100       1d2h3m3s
OFF   eth9       99    DISABLED
"
        );
    }

    #[test]
    fn statistics_text_from_dump() {
        let out = statistics_text(&dump(&[BACKUP]));
        assert_eq!(
            out,
            "
VRRP Instance: WAN
  Advertisements:
    Received: 5
    Sent: 0
  Became master: 0
  Released master: 0
  Packet Errors:
    Length: 0
    TTL: 0
    Invalid Type: 0
    Advertisement Interval: 0
    Address List: 0
  Authentication Errors:
    Invalid Type: 0
    Type Mismatch: 0
    Failure: 0
  Priority Zero:
    Received: 0
    Sent: 0
"
        );
    }

    #[test]
    fn detail_text_from_dump() {
        let out = detail_text(&dump(&[MASTER, BACKUP]));
        let expected = " VRRP Instance: WAN
   VRRP Version: 2
   State: MASTER
   Wantstate: MASTER
   Last transition: 1788833808.966043
   Interface: v1
   Gratuitous ARP delay: 5
   Gratuitous ARP repeat: 5
   Gratuitous ARP refresh: 0
   Gratuitous ARP refresh repeat: 1
   Gratuitous ARP lower priority delay: 5
   Gratuitous ARP lower priority repeat: 5
   Send advert after receive lower priority advert: true
   Send advert after receive higher priority advert: false
   Virtual Router ID: 10
   Priority: 200
   Effective priority: 200
   Advert interval: 1 sec
   Accept: Enabled
   Preempt: Enabled
   Promote secondaries: Disabled
   Authentication type: NONE
   Virtual IP (1):
       192.0.2.254/24 dev v1 scope global set
   Using smtp notification: no
   Notify deleted: Fault

 VRRP Instance: WAN
   VRRP Version: 2
   State: BACKUP
   Master priority: 200
   Wantstate: BACKUP
   Last transition: 1788833809.763418
   Interface: v2
   Gratuitous ARP delay: 5
   Gratuitous ARP repeat: 5
   Gratuitous ARP refresh: 0
   Gratuitous ARP refresh repeat: 1
   Gratuitous ARP lower priority delay: 5
   Gratuitous ARP lower priority repeat: 5
   Send advert after receive lower priority advert: true
   Send advert after receive higher priority advert: false
   Virtual Router ID: 10
   Priority: 100
   Effective priority: 100
   Advert interval: 1 sec
   Accept: Enabled
   Preempt: Enabled
   Promote secondaries: Disabled
   Authentication type: NONE
   Virtual IP (1):
       192.0.2.254/24 dev v2 scope global
   Using smtp notification: no
   Notify deleted: Fault
";
        assert_eq!(out, expected);
    }
}
