//! VyOS-derived DHCP server → Kea backend (design/dhcp.md §7, §8, §11).
//!
//! Consumes the `/service/dhcp-server` and `/service/dhcpv6-server`
//! config subtrees as JSON batches, plus the kernel's links and
//! addresses (`crate::links`). Each tree holds one instance per VRF:
//! the default VRF's leaves and every `vrf <name>` entry. Each instance
//! renders into one complete Kea configuration (`dhcp4.rs`,
//! `dhcp6.rs`), applied through `kea.rs`: compare, `config-test`,
//! write, `config-reload`, so a commit never restarts Kea.
//!
//! An instance is re-rendered after every commit to its tree and every
//! link or address change, because Kea's listen set depends on which
//! interfaces carry an address inside a configured subnet (DH8). A
//! render identical to the last one is not applied again, so link churn
//! that does not change the listen set costs nothing.
//!
//! Show views (`show dhcp[v6] server leases|statistics|static-mappings
//! [vrf <name>] [pool <name>]`) read leases and statistics from the
//! instance's control socket (`lease_cmds`, `stat_cmds`) and map subnet
//! ids to shared networks with the last configuration Kea accepted.
//! When Kea refused the latest one, every view starts with Kea's
//! reason.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::{mpsc, watch};

use crate::api::ShowRequest;
use crate::dhcp4::{self, Server4Tree};
use crate::dhcp6::{self, Server6Tree};
use crate::json::Flex;
use crate::kea::{self, Applied, Family, Kea};
use crate::links::{DEFAULT_VRF, Snapshot};
use crate::pd_routes::{self, Ranges};
use crate::text::table;

const V4_PATH: &[&str] = &["service", "dhcp-server"];
const V6_PATH: &[&str] = &["service", "dhcpv6-server"];

// ---------------------------------------------------------------
// Shared render types and helpers
// ---------------------------------------------------------------

/// Everything a render needs besides the config: the instance's VRF,
/// the kernel's interfaces, and the instance's paths.
pub struct Context<'a> {
    pub vrf: &'a str,
    pub links: &'a Snapshot,
    pub socket: String,
    pub lease_file: String,
    pub data_dir: String,
    pub hooks_dir: PathBuf,
    /// The program Kea's `run_script` hook calls for delegated prefixes
    /// (design/dhcp.md §7.5).
    pub notify: String,
    /// A time zone's POSIX TZ string (`/usr/share/zoneinfo`).
    pub tz: fn(&str) -> Option<String>,
}

impl Context<'_> {
    pub fn hook(&self, name: &str) -> String {
        self.hooks_dir.join(name).display().to_string()
    }
}

/// One instance's render.
#[derive(Debug, Default)]
pub struct Render {
    pub text: String,
    /// Something to serve and somewhere to listen. When false, `text`
    /// is the idle configuration (no interfaces, no networks).
    pub serving: bool,
    pub warnings: Vec<String>,
    pub instance: Instance,
    /// DHCPv6: the delegation ranges, and whether their routes are
    /// installed (design/dhcp.md §7.5).
    pub pd: Ranges,
}

/// What the show views need from a configuration Kea accepted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Instance {
    /// Shared network names, in configuration order.
    pub pools: Vec<String>,
    /// subnet-id → (shared network, subnet prefix).
    pub subnets: BTreeMap<u32, (String, String)>,
    pub mappings: Vec<Mapping>,
}

/// One static mapping, for `show … static-mappings`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Mapping {
    pub pool: String,
    pub subnet: String,
    pub hostname: String,
    pub addresses: Vec<String>,
    pub mac: String,
    pub duid: String,
    pub description: String,
}

/// An IPv4 prefix with no host bits set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Net4 {
    pub addr: u32,
    pub len: u8,
}

impl Net4 {
    pub fn parse(s: &str) -> Option<Net4> {
        let (addr, len) = s.split_once('/')?;
        let addr = u32::from(addr.parse::<Ipv4Addr>().ok()?);
        let len: u8 = len.parse().ok().filter(|&l| l <= 32)?;
        let net = Net4 { addr, len };
        (addr & !net.mask() == 0).then_some(net)
    }

    pub fn mask(&self) -> u32 {
        if self.len == 0 {
            0
        } else {
            u32::MAX << (32 - self.len)
        }
    }

    pub fn contains(&self, addr: u32) -> bool {
        addr & self.mask() == self.addr
    }

    pub fn overlaps(&self, other: &Net4) -> bool {
        self.contains(other.addr) || other.contains(self.addr)
    }

    pub fn to_prefix(self) -> String {
        format!("{}/{}", Ipv4Addr::from(self.addr), self.len)
    }
}

/// An IPv6 prefix with no host bits set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Net6 {
    pub addr: u128,
    pub len: u8,
}

impl Net6 {
    pub fn new(addr: Ipv6Addr, len: u8) -> Option<Net6> {
        let net = Net6 {
            addr: u128::from(addr),
            len,
        };
        (len <= 128 && net.addr & !net.mask() == 0).then_some(net)
    }

    pub fn parse(s: &str) -> Option<Net6> {
        let (addr, len) = s.split_once('/')?;
        Net6::new(addr.parse().ok()?, len.parse().ok()?)
    }

    pub fn mask(&self) -> u128 {
        if self.len == 0 {
            0
        } else {
            u128::MAX << (128 - self.len)
        }
    }

    pub fn contains(&self, addr: u128) -> bool {
        addr & self.mask() == self.addr
    }

    /// `other` lies entirely inside `self`.
    pub fn covers(&self, other: &Net6) -> bool {
        other.len >= self.len && self.contains(other.addr)
    }

    pub fn overlaps(&self, other: &Net6) -> bool {
        self.covers(other) || other.covers(self)
    }

    pub fn to_prefix(self) -> String {
        format!("{}/{}", Ipv6Addr::from(self.addr), self.len)
    }
}

/// A client-class test (`kea_build_client_class_test`): each present
/// `(label, kea path, value)` becomes `<path>.hex == 0x…`, joined with
/// `and`. A value is text, sent as its hex encoding (so no quoting can
/// break out of the expression), or `0x`-prefixed hex as given.
pub fn client_class_test(conditions: &[(&str, &str, Option<&Flex>)]) -> Result<String, String> {
    let mut out = Vec::new();
    for (label, path, value) in conditions {
        let Some(value) = value else {
            continue;
        };
        let value = value.to_string();
        let literal = match value.strip_prefix("0x") {
            Some(hex) => {
                if hex.is_empty()
                    || hex.len() % 2 != 0
                    || !hex.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    return Err(format!(
                        "{label} value {value} is not text or 0x-prefixed hex"
                    ));
                }
                format!("0x{}", hex.to_lowercase())
            }
            None if value.is_empty() => {
                return Err(format!("{label} value is empty"));
            }
            None => format!(
                "0x{}",
                value
                    .bytes()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            ),
        };
        out.push(format!("{path}.hex == {literal}"));
    }
    if out.is_empty() {
        return Err("no match condition".to_string());
    }
    Ok(out.join(" and "))
}

/// The `loggers` block: the daemon to stdout (the journal under
/// systemd), at `log-level` (default info).
pub fn loggers(daemon: &str, level: Option<&Flex>) -> Value {
    let severity = level
        .map(|l| l.to_string().to_uppercase())
        .unwrap_or_else(|| "INFO".to_string());
    json!([{
        "name": daemon,
        "output_options": [{ "output": "stdout", "pattern": "%-5p %m\n" }],
        "severity": severity,
        "debuglevel": 0
    }])
}

/// A zone's POSIX TZ string: the last line of its TZif file, as VyOS's
/// `_read_posix_timezone` reads it.
pub fn posix_tz(zone: &str) -> Option<String> {
    if zone.is_empty()
        || zone.starts_with('/')
        || zone.split('/').any(|part| part == ".." || part.is_empty())
    {
        return None;
    }
    let data = std::fs::read(std::path::Path::new("/usr/share/zoneinfo").join(zone)).ok()?;
    if !data.starts_with(b"TZif") {
        return None;
    }
    let text = String::from_utf8_lossy(&data);
    let line = text.trim_end_matches('\n').rsplit('\n').next()?;
    (!line.is_empty() && line.is_ascii()).then(|| line.to_string())
}

// ---------------------------------------------------------------
// Backend task
// ---------------------------------------------------------------

/// Per instance: the last render applied, the configuration Kea runs,
/// and why Kea refused the latest one.
#[derive(Default)]
struct InstanceState {
    /// `(text, serving)` of the last render handed to [`Kea::apply`].
    last: Option<(String, bool)>,
    last_warnings: Vec<String>,
    /// The instance as Kea runs it (for the show views).
    loaded: Instance,
    /// Kea's reason for refusing the latest render.
    stale: Option<String>,
    /// The configuration Kea runs serves something.
    serving: bool,
    /// DHCPv6: the delegation ranges whose routes this instance owns.
    pd: Ranges,
    /// No Kea answered the last apply (socket mode, or a unit that has
    /// not come up yet): retried every [`RETRY`].
    pending: bool,
}

/// How often an instance no Kea answered for is applied again.
const RETRY: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Default)]
struct State {
    v4: Option<Server4Tree>,
    v6: Option<Server6Tree>,
    instances: BTreeMap<(Family, String), InstanceState>,
    /// The `kea-notify` event listeners, per DHCPv6 instance.
    listeners: BTreeMap<String, tokio::task::JoinHandle<()>>,
}

/// kea-notify's events, as `(vrf, datagram)`.
type Events = mpsc::Sender<(String, String)>;

/// Backend task: JSON subscriptions to both server subtrees (snapshot
/// first, then one whole-subtree batch per touching commit), the link
/// watcher, and the show orders the provider routes here. Reconnects
/// with backoff when either stream drops; the fresh snapshots re-render
/// every instance, and Kea is reloaded only for what changed.
pub async fn run(
    host: String,
    kea: Arc<Kea>,
    mut links: watch::Receiver<Arc<Snapshot>>,
    mut show_rx: mpsc::Receiver<ShowRequest>,
) {
    let mut state = State::default();
    let (events, mut events_rx) = mpsc::channel(64);
    let mut sweep = tokio::time::interval(pd_routes::SWEEP);
    let mut retry = tokio::time::interval(RETRY);
    loop {
        let mut v4 = crate::subscribe::subscribe_json(&host, V4_PATH).await;
        let mut v6 = crate::subscribe::subscribe_json(&host, V6_PATH).await;
        state.v4 = None;
        state.v6 = None;
        // A reconnect re-applies everything (Kea::apply finds unchanged
        // instances unchanged).
        for inst in state.instances.values_mut() {
            inst.last = None;
        }
        loop {
            tokio::select! {
                msg = v4.message() => match msg {
                    Ok(Some(event)) => {
                        if let Some(tree) = parse("dhcp-server", &event.json) {
                            state.v4 = Some(tree);
                            let snapshot = links.borrow().clone();
                            apply(&kea, &mut state, &snapshot, Family::V4, &events).await;
                        }
                    }
                    Ok(None) => break,
                    Err(err) => {
                        tracing::warn!("dhcp-server: subscription error: {err}");
                        break;
                    }
                },
                msg = v6.message() => match msg {
                    Ok(Some(event)) => {
                        if let Some(tree) = parse("dhcpv6-server", &event.json) {
                            state.v6 = Some(tree);
                            let snapshot = links.borrow().clone();
                            apply(&kea, &mut state, &snapshot, Family::V6, &events).await;
                        }
                    }
                    Ok(None) => break,
                    Err(err) => {
                        tracing::warn!("dhcpv6-server: subscription error: {err}");
                        break;
                    }
                },
                changed = links.changed() => {
                    if changed.is_err() {
                        // The watcher is gone; keep serving config events.
                        std::future::pending::<()>().await;
                    }
                    let snapshot = links.borrow_and_update().clone();
                    apply(&kea, &mut state, &snapshot, Family::V4, &events).await;
                    apply(&kea, &mut state, &snapshot, Family::V6, &events).await;
                }
                Some((vrf, text)) = events_rx.recv() => {
                    if let Some(inst) = state.instances.get(&(Family::V6, vrf.clone())) {
                        pd_routes::handle(&kea, &vrf, &inst.pd, &text);
                    }
                }
                _ = retry.tick() => {
                    let snapshot = links.borrow().clone();
                    for family in [Family::V4, Family::V6] {
                        if state.instances.iter().any(|((f, _), i)| *f == family && i.pending) {
                            apply(&kea, &mut state, &snapshot, family, &events).await;
                        }
                    }
                }
                _ = sweep.tick() => {
                    for ((family, vrf), inst) in &state.instances {
                        if *family == Family::V6 && !inst.pd.ranges.is_empty() {
                            pd_routes::sweep(&kea, vrf, &inst.pd).await;
                        }
                    }
                }
                Some(req) = show_rx.recv() => process_show(&kea, &state, req).await,
            }
        }
        tracing::warn!("dhcp-server: subscription ended; reconnecting");
        tokio::time::sleep(crate::endpoint::RECONNECT_DELAY).await;
    }
}

/// A subtree that does not deserialize keeps Kea on its current
/// configuration: rendering it as empty would stop serving.
fn parse<T: for<'de> Deserialize<'de>>(tree: &str, json: &str) -> Option<T> {
    match serde_json::from_str(json) {
        Ok(model) => Some(model),
        Err(err) => {
            tracing::error!("{tree}: config parse failed: {err}");
            None
        }
    }
}

/// The render context of instance (`family`, `vrf`).
fn context<'a>(kea: &Kea, family: Family, vrf: &'a str, links: &'a Snapshot) -> Context<'a> {
    Context {
        vrf,
        links,
        socket: kea.socket(family, vrf).display().to_string(),
        lease_file: kea.lease_file(family, vrf).display().to_string(),
        data_dir: kea.data_dir(vrf).display().to_string(),
        hooks_dir: kea.hooks_dir.clone(),
        notify: kea.notify_link(vrf).display().to_string(),
        tz: posix_tz,
    }
}

/// The instances one family's tree asks for, each with its render.
fn render_family(
    kea: &Kea,
    state: &State,
    snapshot: &Snapshot,
    family: Family,
) -> Vec<(String, Render)> {
    let mut out = Vec::new();
    match family {
        Family::V4 => {
            let Some(tree) = &state.v4 else {
                return out;
            };
            for (vrf, server) in dhcp4::instances(tree) {
                let mut render = dhcp4::render(server, &context(kea, family, &vrf, snapshot));
                vrf_gate(kea, family, &vrf, &mut render);
                out.push((vrf, render));
            }
        }
        Family::V6 => {
            let Some(tree) = &state.v6 else {
                return out;
            };
            for (vrf, server) in dhcp6::instances(tree) {
                let mut render = dhcp6::render(server, &context(kea, family, &vrf, snapshot));
                vrf_gate(kea, family, &vrf, &mut render);
                out.push((vrf, render));
            }
        }
    }
    out
}

/// A VRF instance under systemd needs the unit's VRF binding
/// (`BPFProgram=`, design/process.md §4), which is not built yet:
/// without it Kea would run in the default VRF. Until then such an
/// instance is not started. In socket mode whoever starts Kea binds it
/// (the BDD harness uses `ip vrf exec`).
fn vrf_gate(kea: &Kea, family: Family, vrf: &str, render: &mut Render) {
    if vrf != DEFAULT_VRF && kea.control == kea::Control::Systemd && render.serving {
        render.serving = false;
        render.warnings.push(format!(
            "service {} vrf {vrf}: per-VRF Kea under systemd needs the VRF binding of design/process.md §4; not started",
            family.tree()
        ));
    }
}

fn instance_name(family: Family, vrf: &str) -> String {
    format!("{} {vrf}", family.daemon())
}

async fn apply(
    kea: &Arc<Kea>,
    state: &mut State,
    snapshot: &Snapshot,
    family: Family,
    events: &Events,
) {
    let renders = render_family(kea, state, snapshot, family);
    let wanted: BTreeSet<String> = renders.iter().map(|(vrf, _)| vrf.clone()).collect();
    // Instances whose `vrf` entry is gone serve nothing any more.
    let gone: Vec<String> = state
        .instances
        .iter()
        .filter(|((f, vrf), inst)| *f == family && !wanted.contains(vrf) && inst.last.is_some())
        .map(|((_, vrf), _)| vrf.clone())
        .collect();
    let mut work = renders;
    let nothing = Snapshot::default();
    for vrf in gone {
        let ctx = context(kea, family, &vrf, &nothing);
        let idle = match family {
            Family::V4 => dhcp4::render(&Default::default(), &ctx),
            Family::V6 => dhcp6::render(&Default::default(), &ctx),
        };
        work.push((vrf.clone(), idle));
    }
    for (vrf, render) in work {
        let name = instance_name(family, &vrf);
        let inst = state.instances.entry((family, vrf.clone())).or_default();
        if render.warnings != inst.last_warnings {
            for warn in &render.warnings {
                tracing::warn!("{}: {warn}", family.tree());
            }
            inst.last_warnings = render.warnings.clone();
        }
        // Delegation ranges no longer configured, or no longer routed
        // (`disable-route-autoinstall`, `disable`): their routes go now
        // rather than at the next sweep.
        let retired: Vec<Net6> = inst
            .pd
            .ranges
            .iter()
            .filter(|r| !render.pd.ranges.contains(r) || (inst.pd.install && !render.pd.install))
            .copied()
            .collect();
        if !retired.is_empty() {
            let (kea, vrf) = (Arc::clone(kea), vrf.clone());
            tokio::spawn(async move {
                let ranges = Ranges {
                    ranges: retired,
                    install: false,
                };
                pd_routes::sweep(&kea, &vrf, &ranges).await;
            });
        }
        inst.pd = render.pd.clone();
        let key = (render.text.clone(), render.serving);
        if inst.last.as_ref() == Some(&key) {
            continue;
        }
        if render.pd.install && !state.listeners.contains_key(&vrf) {
            match kea
                .prepare_events(&vrf)
                .await
                .and_then(|path| pd_routes::listen(&path, vrf.clone(), events.clone()))
            {
                Ok(handle) => {
                    state.listeners.insert(vrf.clone(), handle);
                }
                Err(err) => tracing::error!("{name}: kea-notify events socket: {err:#}"),
            }
        }
        let inst = state.instances.entry((family, vrf.clone())).or_default();
        // Nothing was ever served here: nothing to stop or idle.
        if inst.last.is_none() && !render.serving && !kea.running(family, &vrf).await {
            inst.last = Some(key);
            continue;
        }
        let interfaces = listen_summary(&render.text, family);
        match kea.apply(family, &vrf, &render.text, render.serving).await {
            Ok(applied) => {
                match &applied {
                    Applied::Loaded if !render.serving => {
                        tracing::info!("{name}: config-reload: idle (nothing to serve)")
                    }
                    Applied::Loaded => tracing::info!(
                        "{name}: config-reload: {} shared networks, {} subnets, interfaces [{interfaces}]",
                        render.instance.pools.len(),
                        render.instance.subnets.len()
                    ),
                    Applied::Started => tracing::info!(
                        "{name}: started: {} shared networks, {} subnets, interfaces [{interfaces}]",
                        render.instance.pools.len(),
                        render.instance.subnets.len()
                    ),
                    Applied::Unchanged => tracing::info!("{name}: configuration unchanged"),
                    Applied::Stopped => tracing::info!("{name}: stopped (nothing to serve)"),
                    Applied::NotRunning if !inst.pending => tracing::warn!(
                        "{name}: not running; configuration written to {}, retrying",
                        kea.conf(family, &vrf).display()
                    ),
                    Applied::NotRunning => {}
                    Applied::Rejected(err) => tracing::error!(
                        "{name}: Kea refused the configuration and keeps running its previous one: {err}"
                    ),
                }
                inst.pending = applied == Applied::NotRunning;
                match applied {
                    Applied::Rejected(err) => inst.stale = Some(err),
                    _ => {
                        inst.stale = None;
                        inst.loaded = render.instance;
                        inst.serving = render.serving;
                    }
                }
                // A pending instance is applied again until a Kea answers.
                inst.last = (!inst.pending).then_some(key);
            }
            Err(err) => {
                tracing::error!("{name}: apply failed: {err:#}");
                inst.last = None;
            }
        }
    }
    // Forget gone instances once they are idle.
    state.instances.retain(|(f, vrf), inst| {
        *f != family || wanted.contains(vrf) || inst.last.as_ref().is_some_and(|(_, s)| *s)
    });
}

/// `lan1 lan2` from a render's `interfaces-config`.
fn listen_summary(text: &str, family: Family) -> String {
    let Ok(config) = serde_json::from_str::<Value>(text) else {
        return String::new();
    };
    config[family.root()]["interfaces-config"]["interfaces"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------
// Show
// ---------------------------------------------------------------

/// One parsed show order.
#[derive(Debug, PartialEq, Eq)]
struct ShowOrder {
    family: Family,
    view: String,
    vrf: String,
    pool: Option<String>,
}

/// `/show/dhcp[v6]/server/<view>[/vrf][/pool]` with the key values in
/// `args`, in order.
fn parse_order(path: &str, args: &[String]) -> Option<ShowOrder> {
    let mut segs = path.trim_start_matches('/').split('/');
    if segs.next()? != "show" {
        return None;
    }
    let family = match segs.next()? {
        "dhcp" => Family::V4,
        "dhcpv6" => Family::V6,
        _ => return None,
    };
    if segs.next()? != "server" {
        return None;
    }
    let view = segs.next()?.to_string();
    let mut args = args.iter();
    let mut order = ShowOrder {
        family,
        view,
        vrf: DEFAULT_VRF.to_string(),
        pool: None,
    };
    for seg in segs {
        match seg {
            "vrf" => order.vrf = args.next()?.clone(),
            "pool" => order.pool = Some(args.next()?.clone()),
            _ => return None,
        }
    }
    Some(order)
}

async fn process_show(kea: &Kea, state: &State, req: ShowRequest) {
    let reply = match parse_order(&req.path, &req.args) {
        Some(order) => show(kea, state, &order, req.json).await,
        None => format!("% unknown DHCP server view {}\n", req.path),
    };
    let _ = req.resp.send(reply);
}

fn configured(state: &State, family: Family, vrf: &str) -> bool {
    match family {
        Family::V4 => state.v4.as_ref().is_some_and(|tree| {
            dhcp4::instances(tree)
                .iter()
                .any(|(v, s)| v == vrf && !s.is_empty())
        }),
        Family::V6 => state.v6.as_ref().is_some_and(|tree| {
            dhcp6::instances(tree)
                .iter()
                .any(|(v, s)| v == vrf && !s.is_empty())
        }),
    }
}

fn disabled(state: &State, family: Family, vrf: &str) -> bool {
    match family {
        Family::V4 => state.v4.as_ref().is_some_and(|tree| {
            dhcp4::instances(tree)
                .iter()
                .any(|(v, s)| v == vrf && s.disable)
        }),
        Family::V6 => state.v6.as_ref().is_some_and(|tree| {
            dhcp6::instances(tree)
                .iter()
                .any(|(v, s)| v == vrf && s.disable)
        }),
    }
}

async fn show(kea: &Kea, state: &State, order: &ShowOrder, json: bool) -> String {
    let v = if order.family == Family::V6 { "v6" } else { "" };
    let in_vrf = if order.vrf == DEFAULT_VRF {
        String::new()
    } else {
        format!(" for VRF {}", order.vrf)
    };
    if !configured(state, order.family, &order.vrf) {
        return format!("DHCP{v} server is not configured{in_vrf}\n");
    }
    let empty = InstanceState::default();
    let inst = state
        .instances
        .get(&(order.family, order.vrf.clone()))
        .unwrap_or(&empty);
    if !inst.serving && inst.stale.is_none() {
        return if disabled(state, order.family, &order.vrf) {
            format!("DHCP{v} server is disabled{in_vrf}\n")
        } else {
            format!(
                "DHCP{v} server is not serving{in_vrf}: no valid shared network, or no interface to listen on\n"
            )
        };
    }
    if let Some(pool) = &order.pool
        && !inst.loaded.pools.contains(pool)
    {
        return format!("DHCP{v} pool \"{pool}\" does not exist{in_vrf}\n");
    }
    let mut out = String::new();
    if let Some(err) = &inst.stale
        && !json
    {
        out.push_str(&format!(
            "DHCP{v} server is running an older configuration: {err}\n\n"
        ));
    }
    let body = match order.view.as_str() {
        "leases" => leases(kea, &inst.loaded, order, json).await,
        "statistics" => statistics(kea, &inst.loaded, order, json).await,
        "static-mappings" => Ok(static_mappings(&inst.loaded, order, json)),
        other => Ok(format!("% unknown DHCP server view {other}\n")),
    };
    match body {
        Ok(body) => out.push_str(&body),
        Err(_) => return format!("DHCP{v} server is not running{in_vrf}\n"),
    }
    out
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `YYYY-MM-DD HH:MM:SS` in UTC.
pub fn utc(ts: i64) -> String {
    let days = ts.div_euclid(86400);
    let secs = ts.rem_euclid(86400);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

/// Python's `str(timedelta)`, which VyOS prints as Remaining:
/// `0:59:58`, `1 day, 0:00:00`.
pub fn remaining(secs: i64) -> String {
    let days = secs / 86400;
    let rest = secs % 86400;
    let hms = format!("{}:{:02}:{:02}", rest / 3600, rest % 3600 / 60, rest % 60);
    match days {
        0 => hms,
        1 => format!("1 day, {hms}"),
        n => format!("{n} days, {hms}"),
    }
}

fn lease_state(state: i64) -> &'static str {
    match state {
        0 => "active",
        1 => "rejected",
        2 => "expired",
        _ => "-",
    }
}

/// Kea's leases that are still valid, in the requested pool, with the
/// pool's name.
fn current_leases(
    reply: &Value,
    loaded: &Instance,
    pool: Option<&str>,
    now: i64,
) -> Vec<(Value, String)> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let leases = reply["arguments"]["leases"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    for lease in leases {
        let cltt = lease["cltt"].as_i64().unwrap_or(0);
        let lft = lease["valid-lft"].as_i64().unwrap_or(0);
        if lft <= 0 || cltt + lft <= now {
            continue;
        }
        let id = lease["subnet-id"].as_u64().unwrap_or(0) as u32;
        let name = loaded
            .subnets
            .get(&id)
            .map(|(p, _)| p.clone())
            .unwrap_or_else(|| "-".to_string());
        if pool.is_some_and(|p| p != name) {
            continue;
        }
        let key = lease["ip-address"].as_str().unwrap_or_default().to_string();
        if !seen.insert(key) {
            continue;
        }
        out.push((lease, name));
    }
    out
}

async fn leases(
    kea: &Kea,
    loaded: &Instance,
    order: &ShowOrder,
    json: bool,
) -> anyhow::Result<String> {
    let command = format!("lease{}-get-all", order.family.digit());
    let reply = kea
        .command(order.family, &order.vrf, &command, None)
        .await?;
    let now = now();
    let leases = current_leases(&reply, loaded, order.pool.as_deref(), now);
    if json {
        let list: Vec<Value> = leases
            .into_iter()
            .map(|(mut lease, pool)| {
                lease["pool"] = Value::String(pool);
                lease
            })
            .collect();
        return Ok(serde_json::to_string_pretty(&json!({ "leases": list }))? + "\n");
    }
    let mut rows = Vec::new();
    for (lease, pool) in &leases {
        let cltt = lease["cltt"].as_i64().unwrap_or(0);
        let end = cltt + lease["valid-lft"].as_i64().unwrap_or(0);
        let str_of = |key: &str| {
            lease[key]
                .as_str()
                .map(|s| s.trim_end_matches('.').to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "-".to_string())
        };
        let state = lease_state(lease["state"].as_i64().unwrap_or(-1)).to_string();
        match order.family {
            Family::V4 => rows.push(vec![
                str_of("ip-address"),
                str_of("hw-address"),
                state,
                utc(cltt),
                utc(end),
                remaining(end - now),
                pool.clone(),
                str_of("hostname"),
                "local".to_string(),
            ]),
            Family::V6 => {
                let mut addr = str_of("ip-address");
                let ty = str_of("type");
                if ty == "IA_PD" {
                    addr = format!("{addr}/{}", lease["prefix-len"].as_u64().unwrap_or(0));
                }
                rows.push(vec![
                    addr,
                    str_of("hw-address"),
                    state,
                    utc(cltt),
                    utc(end),
                    remaining(end - now),
                    pool.clone(),
                    str_of("hostname"),
                    ty,
                    str_of("duid"),
                ]);
            }
        }
    }
    Ok(match order.family {
        Family::V4 => table(
            &[
                "IP Address",
                "MAC address",
                "State",
                "Lease start",
                "Lease expiration",
                "Remaining",
                "Pool",
                "Hostname",
                "Origin",
            ],
            &rows,
        ),
        Family::V6 => table(
            &[
                "IPv6 address",
                "MAC address",
                "State",
                "Last communication",
                "Lease expiration",
                "Remaining",
                "Pool",
                "Hostname",
                "Type",
                "DUID",
            ],
            &rows,
        ),
    })
}

/// A statistics cell: Kea reports big pools (IPv6) as large integers.
fn stat_number(v: &Value) -> u128 {
    v.as_u64()
        .map(u128::from)
        .or_else(|| v.as_f64().map(|f| f as u128))
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        .unwrap_or(0)
}

/// Per shared network: (size, leases), summed over its subnets from
/// `stat-lease{4,6}-get`. Size is Kea's count of addresses (and, for
/// DHCPv6, delegated prefixes) in the pools; leases are those assigned.
pub fn pool_stats(reply: &Value, loaded: &Instance) -> BTreeMap<String, (u128, u128)> {
    let set = &reply["arguments"]["result-set"];
    let columns: Vec<&str> = set["columns"]
        .as_array()
        .map(|c| c.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let col = |name: &str| columns.iter().position(|c| *c == name);
    let id = col("subnet-id");
    let totals = [col("total-addresses"), col("total-nas"), col("total-pds")];
    let assigned = [
        col("assigned-addresses"),
        col("assigned-nas"),
        col("assigned-pds"),
    ];
    let mut out: BTreeMap<String, (u128, u128)> = BTreeMap::new();
    for row in set["rows"].as_array().cloned().unwrap_or_default() {
        let Some(sid) = id.and_then(|i| row[i].as_u64()) else {
            continue;
        };
        let Some((pool, _)) = loaded.subnets.get(&(sid as u32)) else {
            continue;
        };
        let sum = |cols: &[Option<usize>]| -> u128 {
            cols.iter().flatten().map(|&i| stat_number(&row[i])).sum()
        };
        let entry = out.entry(pool.clone()).or_default();
        entry.0 += sum(&totals);
        entry.1 += sum(&assigned);
    }
    out
}

async fn statistics(
    kea: &Kea,
    loaded: &Instance,
    order: &ShowOrder,
    json: bool,
) -> anyhow::Result<String> {
    let command = format!("stat-lease{}-get", order.family.digit());
    let reply = kea
        .command(order.family, &order.vrf, &command, None)
        .await?;
    let stats = pool_stats(&reply, loaded);
    let mut rows = Vec::new();
    let mut list = Vec::new();
    for pool in &loaded.pools {
        if order.pool.as_ref().is_some_and(|p| p != pool) {
            continue;
        }
        let (size, leases) = stats.get(pool).copied().unwrap_or_default();
        // Rounded to the nearest percent, as VyOS's round(); 0 for an
        // empty pool.
        let usage = (leases * 100 + size / 2).checked_div(size).unwrap_or(0);
        let available = size.saturating_sub(leases);
        rows.push(vec![
            pool.clone(),
            size.to_string(),
            leases.to_string(),
            available.to_string(),
            format!("{usage}%"),
        ]);
        list.push(json!({
            "pool": pool,
            "size": size.to_string(),
            "leases": leases.to_string(),
            "available": available.to_string(),
            "use_percentage": usage.to_string(),
        }));
    }
    if json {
        return Ok(serde_json::to_string_pretty(&Value::Array(list))? + "\n");
    }
    Ok(table(
        &["Pool", "Size", "Leases", "Available", "Usage"],
        &rows,
    ))
}

fn static_mappings(loaded: &Instance, order: &ShowOrder, json: bool) -> String {
    let na = |s: &str| {
        if s.is_empty() {
            "N/A".to_string()
        } else {
            s.to_string()
        }
    };
    let mappings: Vec<&Mapping> = loaded
        .mappings
        .iter()
        .filter(|m| order.pool.as_ref().is_none_or(|p| *p == m.pool))
        .collect();
    if json {
        let list: Vec<Value> = mappings
            .iter()
            .map(|m| {
                json!({
                    "pool": m.pool,
                    "subnet": m.subnet,
                    "hostname": m.hostname,
                    "ip": m.addresses,
                    "mac": m.mac,
                    "duid": m.duid,
                    "description": m.description,
                })
            })
            .collect();
        return serde_json::to_string_pretty(&Value::Array(list)).unwrap_or_default() + "\n";
    }
    let rows: Vec<Vec<String>> = mappings
        .iter()
        .map(|m| {
            vec![
                m.pool.clone(),
                m.subnet.clone(),
                m.hostname.clone(),
                na(&m.addresses.join(", ")),
                na(&m.mac),
                na(&m.duid),
                na(&m.description),
            ]
        })
        .collect();
    table(
        &[
            "Pool",
            "Subnet",
            "Hostname",
            "IP Address",
            "MAC Address",
            "DUID",
            "Description",
        ],
        &rows,
    )
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::links::{Addr, Link};

    pub fn link(index: u32, name: &str, kind: Option<&str>, addrs: &[&str]) -> (Link, Vec<Addr>) {
        let link = Link {
            index,
            name: name.to_string(),
            kind: kind.map(str::to_string),
            master: None,
            up: true,
        };
        let addrs = addrs
            .iter()
            .map(|a| {
                let (addr, len) = a.split_once('/').unwrap();
                Addr {
                    index,
                    addr: addr.parse().unwrap(),
                    prefix_len: len.parse().unwrap(),
                    tentative: false,
                }
            })
            .collect();
        (link, addrs)
    }

    pub fn snapshot(links: &[(Link, Vec<Addr>)]) -> Snapshot {
        let mut snapshot = Snapshot::default();
        for (link, addrs) in links {
            snapshot.links.insert(link.index, link.clone());
            snapshot.addrs.extend(addrs.iter().cloned());
        }
        snapshot
    }

    fn tz(zone: &str) -> Option<String> {
        match zone {
            "Asia/Tokyo" => Some("JST-9".to_string()),
            "America/New_York" => Some("EST5EDT,M3.2.0,M11.1.0".to_string()),
            _ => None,
        }
    }

    pub fn context<'a>(vrf: &'a str, links: &'a Snapshot) -> Context<'a> {
        Context {
            vrf,
            links,
            socket: format!("/run/insomnia/kea/{vrf}/kea4-ctrl-socket"),
            lease_file: format!("/var/lib/insomnia/kea/{vrf}/kea-leases4.csv"),
            data_dir: format!("/var/lib/insomnia/kea/{vrf}"),
            hooks_dir: "/usr/lib/kea/hooks".into(),
            notify: format!("/run/insomnia/kea/{vrf}/kea-notify"),
            tz,
        }
    }

    #[test]
    fn nets() {
        let n = Net4::parse("10.1.0.0/24").unwrap();
        assert!(n.contains(u32::from(Ipv4Addr::new(10, 1, 0, 200))));
        assert!(!n.contains(u32::from(Ipv4Addr::new(10, 1, 1, 0))));
        assert!(Net4::parse("10.1.0.1/24").is_none());
        assert!(n.overlaps(&Net4::parse("10.1.0.128/25").unwrap()));
        assert!(!n.overlaps(&Net4::parse("10.2.0.0/24").unwrap()));
        assert_eq!(Net4::parse("0.0.0.0/0").unwrap().mask(), 0);
        let p = Net6::parse("2001:db8:8000::/48").unwrap();
        assert!(p.covers(&Net6::parse("2001:db8:8000:100::/56").unwrap()));
        assert!(!p.covers(&Net6::parse("2001:db8::/32").unwrap()));
        assert!(p.overlaps(&Net6::parse("2001:db8::/32").unwrap()));
        assert!(Net6::parse("2001:db8::1/64").is_none());
    }

    #[test]
    fn class_tests() {
        let s = |v: &str| Flex::Str(v.to_string());
        let circuit = s("lan1");
        let vendor = s("0x6869");
        assert_eq!(
            client_class_test(&[
                ("circuit-id", "relay4[1]", Some(&circuit)),
                ("remote-id", "relay4[2]", None),
                ("vendor-class-id", "option[60]", Some(&vendor)),
            ])
            .unwrap(),
            "relay4[1].hex == 0x6c616e31 and option[60].hex == 0x6869"
        );
        // Text that looks like an expression is only ever hex data.
        let quote = s("x' or 'a' == 'a");
        assert_eq!(
            client_class_test(&[("hostname", "option[12]", Some(&quote))]).unwrap(),
            "option[12].hex == 0x7827206f7220276127203d3d202761"
        );
        assert!(client_class_test(&[("hostname", "option[12]", None)]).is_err());
        let odd = s("0x123");
        assert!(client_class_test(&[("hostname", "option[12]", Some(&odd))]).is_err());
    }

    #[test]
    fn show_paths() {
        let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            parse_order("/show/dhcp/server/leases", &[]),
            Some(ShowOrder {
                family: Family::V4,
                view: "leases".into(),
                vrf: "default".into(),
                pool: None
            })
        );
        assert_eq!(
            parse_order(
                "/show/dhcpv6/server/statistics/vrf/pool",
                &args(&["red", "LAN"])
            ),
            Some(ShowOrder {
                family: Family::V6,
                view: "statistics".into(),
                vrf: "red".into(),
                pool: Some("LAN".into())
            })
        );
        assert_eq!(parse_order("/show/dhcp/relay/statistics", &[]), None);
        assert_eq!(parse_order("/show/dhcp/server/leases/pool", &[]), None);
    }

    #[test]
    fn times() {
        assert_eq!(utc(0), "1970-01-01 00:00:00");
        assert_eq!(utc(1_794_212_255), "2026-11-09 08:17:35");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00:00");
        assert_eq!(remaining(3598), "0:59:58");
        assert_eq!(remaining(86400), "1 day, 0:00:00");
        assert_eq!(remaining(2 * 86400 + 61), "2 days, 0:01:01");
    }

    /// `lease4-get-all` and `stat-lease4-get` replies captured from Kea
    /// 2.4.1, mapped to pools with the loaded instance.
    #[test]
    fn leases_and_stats_from_kea() {
        let loaded = Instance {
            pools: vec!["LAN".into(), "LAN2".into()],
            subnets: [
                (1, ("LAN".to_string(), "10.1.0.0/24".to_string())),
                (2, ("LAN2".to_string(), "10.2.0.0/24".to_string())),
            ]
            .into_iter()
            .collect(),
            mappings: vec![],
        };
        let reply: Value = serde_json::from_str(
            r#"{ "arguments": { "leases": [
                { "cltt": 1794212255, "fqdn-fwd": false, "fqdn-rev": false, "hostname": "h1", "hw-address": "02:00:00:00:00:01", "ip-address": "10.1.0.150", "state": 0, "subnet-id": 1, "valid-lft": 7200 },
                { "cltt": 1794212255, "fqdn-fwd": false, "fqdn-rev": false, "hostname": "", "hw-address": "02:00:00:00:00:02", "ip-address": "10.2.0.50", "state": 0, "subnet-id": 2, "valid-lft": 7200 },
                { "cltt": 1794200000, "fqdn-fwd": false, "fqdn-rev": false, "hostname": "old", "hw-address": "02:00:00:00:00:03", "ip-address": "10.1.0.151", "state": 0, "subnet-id": 1, "valid-lft": 60 }
            ] }, "result": 0, "text": "3 IPv4 lease(s) found." }"#,
        )
        .unwrap();
        let now = 1_794_212_255 + 1;
        let all = current_leases(&reply, &loaded, None, now);
        assert_eq!(all.len(), 2);
        assert_eq!(all[1].1, "LAN2");
        let lan = current_leases(&reply, &loaded, Some("LAN"), now);
        assert_eq!(lan.len(), 1);
        assert_eq!(lan[0].0["ip-address"], "10.1.0.150");

        let stats: Value = serde_json::from_str(
            r#"{ "arguments": { "result-set": { "columns": [ "subnet-id", "total-addresses", "cumulative-assigned-addresses", "assigned-addresses", "declined-addresses" ], "rows": [ [ 1, 99, 2, 2, 0 ], [ 2, 10, 1, 1, 0 ] ], "timestamp": "2026-11-09 08:17:35.371264" } }, "result": 0, "text": "stat-lease4-get[all subnets]: 2 rows found" }"#,
        )
        .unwrap();
        let per_pool = pool_stats(&stats, &loaded);
        assert_eq!(per_pool.get("LAN"), Some(&(99, 2)));
        assert_eq!(per_pool.get("LAN2"), Some(&(10, 1)));
    }

    #[test]
    fn mappings_view() {
        let loaded = Instance {
            pools: vec!["LAN".into()],
            subnets: BTreeMap::new(),
            mappings: vec![Mapping {
                pool: "LAN".into(),
                subnet: "10.1.0.0/24".into(),
                hostname: "printer".into(),
                addresses: vec!["10.1.0.10".into()],
                mac: "02:00:00:00:00:01".into(),
                duid: String::new(),
                description: String::new(),
            }],
        };
        let order = ShowOrder {
            family: Family::V4,
            view: "static-mappings".into(),
            vrf: "default".into(),
            pool: None,
        };
        assert_eq!(
            static_mappings(&loaded, &order, false),
            "Pool  Subnet       Hostname  IP Address  MAC Address        DUID  Description\n\
             ----  -----------  --------  ----------  -----------------  ----  -----------\n\
             LAN   10.1.0.0/24  printer   10.1.0.10   02:00:00:00:00:01  N/A   N/A\n"
        );
    }

    #[test]
    fn tz_names_cannot_escape() {
        assert_eq!(posix_tz("../../etc/passwd"), None);
        assert_eq!(posix_tz("/etc/passwd"), None);
        assert_eq!(posix_tz(""), None);
    }
}
