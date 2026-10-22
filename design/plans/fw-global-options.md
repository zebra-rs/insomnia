# Firewall global options and the sysctl writer — implementation plan

Status: plan, 2026-10-21. Covers: §4.4 (the sysctl writer), FW4, FW5, FW6, D4
([vyos-gap](../vyos-gap.md) §4.4, §5, §6.4, §11).
Priority: P2 · Effort: M · Owner: insomnia (zebra-rs: help text only)
Depends on: [fw-load-safety](fw-load-safety.md) (the restructured `process()` and the
`insomnia_node.sh` BDD script), [nft-common](nft-common.md) (`Script` for the FW4 chain) ·
Unblocks: [conntrack](conntrack.md) (`system conntrack` sizes and tcp knobs; the link
watcher for VRF zones), [fw-bridge](fw-bridge.md) (`apply-to-bridged-traffic`,
`br_netfilter`, `absent_baseline`; bridge ports), [fw-flowtable](fw-flowtable.md) (the link
watcher), [fw-zones](fw-zones.md) (VRF members), [vrrp-vrf](vrrp-vrf.md) (VRF membership;
A3/B4 wait for M3), [pbr](pbr.md) (`Link.vrf_table`),
[wan-load-balancing](wan-load-balancing.md) (link snapshot), [ipsec-vti](ipsec-vti.md)
(optional host warning)

This plan **owns two APIs**, and nobody else re-implements either:
- **`crate::sysctl`.** Other backends add an `Owner` and call it; nobody else writes
  `/proc/sys`.
- **`crate::links`**, the kernel link watcher. Every backend that needs to know which
  devices exist subscribes to it.

Assumes D4: write only what is configured.

## 1. Goal

- `firewall global-options` toggles (FW5) and conntrack `timeout`s (FW6) take effect. Today
  they are dropped without a log line.
- Per-interface toggles reach every device, including devices created after the commit.
- `source-validation` and `ipv6-source-validation` (FW4) work as nft `fib` rules at
  prerouting `raw`, as VyOS rolling does. zebra-rs's forced `rp_filter=0` cannot interfere.
- D4: a host with no `global-options` keeps its kernel/distro values. Deleting a leaf puts
  back the value the host had before insomnia first touched it.
- One shared, owner-scoped sysctl writer. It compares before writing, never touches a key
  zebra-rs owns, and is reused by `system conntrack` and the bridge firewall.
- One shared kernel link watcher (name, kind, master, VRF table) for the sysctl writer,
  flowtables and every consumer of VRF membership: fw-zones `member vrf`, conntrack VRF
  zones, vrrp-vrf and PBR's VRF table IDs.

## 2. Current state

**insomnia:**
- `GlobalOptions` deserializes only `state-policy`; the other leaves are ignored by serde
  (`src/firewall.rs:1052-1059`). The module doc says so (`firewall.rs:22-25`). insomnia
  writes no sysctls, and has no netlink code (`Cargo.toml` deps: no netlink crate; `libc`
  is present).
- There is no `source-validation` rendering.
- The book is wrong: ch-01-06 lines 69-72 say a commit touching the timeouts logs a
  warning.

**zebra-rs** (`141da2fc`):
- `firewall.yang` global-options `1087-1350`:
  - the eleven toggles are enums `enable|disable`;
  - `source-validation` and `ipv6-source-validation` are `strict|loose|disable`
    (`1124`, `1160`);
  - `timeout` holds `icmp`, `other`, `tcp {close close-wait established fin-wait last-ack syn-recv syn-sent time-wait}`
    and `udp {other stream}` (`1269-1350`).
- No leaf has a YANG `default`. Help texts only mention "(VyOS default: …)". The
  `source-validation` help still says "rp_filter" (`1160-1161`).
- `src/fib/netlink/sysctl.rs` writes these keys:
  - `ip_forward`, `conf.{all,default}.rp_filter=0` (`14-15`), `ipv6.conf.all.forwarding`,
    `seg6_enabled`, `keep_addr_on_down`, `vrf.strict_mode`, `tcp_l3mdev_accept`,
    `mpls.platform_labels` (`3-34`);
  - per link: `mpls.conf.<if>.input`, `ipv6.conf.<if>.seg6_enabled`, `keep_addr_on_down`
    (`83-109`, called from `rib/link.rs:969-971`).
- Per-interface writes go through `/proc/sys/<tree>/<ifname>/<leaf>`, because dotted
  names would split `eth0.100` (`sysctl.rs:66-81`). The rationale for `rp_filter=0` is
  SRv6 End.DT46 decapsulation on `sr0`, which strict RPF would drop (`sysctl.rs:5-13`).

**VyOS** (`7f2c893`):
- `data/templates/firewall/sysctl-firewall.conf.j2` holds the toggles (`4-14`), the
  bridge keys (`16-22`) and the timeouts (`24-36`). It is rendered to
  `/run/sysctl/10-vyos-firewall.conf` (`src/conf_mode/firewall.py:54`, `722`) and applied
  with `sysctl -f` after the nft load (`784-785`). It always writes every value, using the
  XML defaults:

  | Leaf | `include/firewall/global-options.xml.i` line | VyOS default |
  |:--|:--|:--|
  | all-ping | 25 | enable |
  | broadcast-ping | 45 | disable |
  | directed-broadcast | 131 | enable |
  | ip-src-route | 196 | disable |
  | log-martians | 216 | enable |
  | receive-redirects | 236 | disable |
  | send-redirects | 275 | enable |
  | source-validation | 299 | disable |
  | syn-cookies | 364 | enable |
  | twa-hazards-protection | 392 | disable |
  | ipv6-receive-redirects | 412 | disable |
  | ipv6-source-validation | 436 | disable |
  | ipv6-src-route | 456 | disable |

  Timeouts come from `timeout-common-protocols.xml.i`:

  | Key | VyOS default (s) |
  |:--|:--|
  | icmp | 30 |
  | other | 600 |
  | tcp close-wait | 60 |
  | tcp close | 10 |
  | tcp established | 432000 |
  | tcp fin-wait | 120 |
  | tcp last-ack | 30 |
  | tcp syn-recv | 60 |
  | tcp syn-sent | 120 |
  | tcp time-wait | 120 |
  | udp other | 30 |
  | udp stream | 180 |

- `conf.*` keys use a glob. `bc_forwarding` and `log_martians` are written to `all` only.
  `bc_forwarding` also needs the per-interface value, which VyOS sets from
  `interfaces … ip enable-directed-broadcast` (`python/vyos/ifconfig/interface.py:193-196`,
  `2013-2015`). The VyOS boot baseline is `src/etc/sysctl.d/30-vyos-router.conf:34-80`.
- Source validation is nft: `table raw` chain `vyos_global_rpfilter` holds
  `fib saddr [. iif] oif 0 counter drop` (`data/templates/firewall/nftables.j2:8-31`). It
  is jumped from `vyos_rpfilter` at prerouting -300 (`data/vyos-firewall-init.conf:29-35`).

**This host** (Ubuntu, Linux 6.8). The values below show why "the default" is
host-specific:
- `conf.all.accept_source_route=0` but `conf.default=1`;
- `conf.all.accept_redirects=0` but `conf.default=1`;
- `log_martians=0`;
- `nf_conntrack` not loaded, so every `net/netfilter/nf_conntrack_*_timeout` is absent.

## 3. Design

### 3.1 D4 defaults policy

- Write only what is configured.
- Before insomnia first writes a path, record its current value in a baseline.
- When the leaf disappears, the whole `global-options`, or the firewall tree, write the
  baseline back and forget it.
- The baseline lives in `/run/insomnia/sysctl-baseline.json` (tmpfs). A reboot resets the
  kernel and the file together, and an insomnia restart does not mistake insomnia's own
  values for the originals.
- Stopping insomnia leaves the values in place, just as it leaves the nft tables loaded.
- **Deviation** (`firewall.rs` module doc and book). VyOS writes its defaults on every
  commit, so a migrated VyOS config with no `global-options` behaves differently here.
  For example, VyOS sets `log_martians=1`, `accept_redirects=0` and `send_redirects=1`.
- *Rejected:* adding YANG `default`s (VyOS parity). An empty insomnia config would rewrite
  the host's network stack and silently undo what the distro chose.

### 3.2 The writer (`crate::sysctl`, proposed)

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Owner { Firewall, Conntrack }            // fw-bridge settings ride Owner::Firewall

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Af { V4, V6 }                            // net.ipv4.conf | net.ipv6.conf

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ConfScope {
    All,         // conf/all only                     (VyOS: conf.all.X)
    Each,        // conf/all + conf/default + every device, now and later (VyOS: conf.*.X)
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Key {
    Global(&'static str),                         // dotted, no device part: "net.ipv4.tcp_syncookies"
    Conf { af: Af, leaf: &'static str, scope: ConfScope },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Setting {
    pub key: Key,
    pub value: String,
    pub module: Option<&'static str>,             // modprobe once if the node is absent (nf_conntrack, br_netfilter)
    pub absent_baseline: Option<&'static str>,    // baseline for a node that only our own modprobe created (fw-bridge: "0")
}

#[derive(Debug, Default)]
pub struct Report {
    pub written: Vec<String>,                     // "/proc/sys/... = v (was w)"
    pub unchanged: usize,
    pub restored: Vec<String>,
    pub errors: Vec<String>,                      // never fatal; the caller logs them as warnings
}

pub struct Options { pub root: PathBuf /* /proc/sys */, pub baseline: PathBuf, pub links: Option<Links> /* None in unit tests */ }

#[derive(Clone)]
pub struct Sysctl { /* mpsc::Sender to the writer task */ }
impl Sysctl {
    pub fn spawn(opts: Options) -> Sysctl;
    /// Declarative and idempotent: `settings` replaces everything `owner` set before.
    /// Writes only what differs; restores the baseline for paths the owner dropped.
    pub async fn apply(&self, owner: Owner, settings: Vec<Setting>) -> Report;
    /// Desired vs live per expanded path, for show (fw-opmode).
    pub async fn status(&self, owner: Owner) -> Vec<(String, String, Option<String>)>;
}
```

Semantics:
- **Expansion.**
  - `Global` maps to `<root>/<dots→slashes>`.
  - `Conf{scope: All}` maps to `<root>/net/<af>/conf/all/<leaf>`.
  - `Conf{scope: Each}` maps to `all`, `default`, and every directory under
    `<root>/net/<af>/conf/` that exists right now (`lo` included, the same set the VyOS
    glob matches). Device names are joined as path components (zebra-rs pattern,
    `sysctl.rs:66-81`), so `eth0.100` works.
- **Compare before write.** Read, trim, compare, then write only on difference. A
  resubscribe snapshot, or an unrelated commit, therefore writes nothing.
- **Guards.** These are programming errors, returned in `Report.errors`; nothing is
  written:
  - a fixed deny-list of zebra-rs keys: `net.ipv4.ip_forward`, any `conf.*.rp_filter`,
    `conf.*.forwarding`, `seg6_enabled`, `keep_addr_on_down`, `net.vrf.*`,
    `tcp_l3mdev_accept`, `net.mpls.*` (from `sysctl.rs:3-34`, `83-109`);
  - a path that another `Owner` already holds.
- **Missing nodes.**
  - If `module` is set, run `modprobe <module>` once per apply and re-read.
  - A node that appears only after that `modprobe` has no host value to record. Its
    baseline is `absent_baseline` when set, so restore writes that value; with `None`,
    the baseline is the value read just after loading (the module default). This is
    what [fw-bridge](fw-bridge.md) §3.5 needs: loading `br_netfilter` turns
    `bridge-nf-call-ip(6)tables` on, and restoring that default would keep bridged
    traffic in the ip hooks after the option is removed.
  - A node that is still missing gives an error, for example
    `net.netfilter.nf_conntrack_tcp_timeout_established: no such sysctl (module nf_conntrack not loaded)`.
  - A device that vanished between expansion and write is ignored, at debug level.
- **Restore.** A path the owner no longer sets is written back to its baseline value. A
  device created after the baseline was taken has no entry of its own, so it gets the
  baseline of `conf/default/<leaf>`. The baseline file is rewritten atomically (the
  `keepalived.rs:229-241` pattern), with mode 0644.
- **New devices.**
  - New devices copy `conf/default` when they are created (*unverified* per key, from
    kernel `devinet`/`addrconf`), so writing `default` covers most cases. But udev's
    `systemd-sysctl --prefix=/net/ipv4/conf/<dev>` run, in the init netns, can re-apply
    distro `conf.*` entries afterwards (*unverified* per distro).
  - So the writer subscribes to the shared link watcher (§3.2a). On a link `Added` or
    `Changed` event it waits 1 s per device (debounce), then compare-writes every `Each`
    setting for that device. On `Resync` it rescans `conf/`. On `Removed` it forgets the
    device.
  - Because `RTM_NEWLINK` also fires on link up, an override by udev after creation is
    corrected on the next link event. Without such an event it is not, which is a known
    gap (§8).
  - *Rejected:*
    - zebra-rs interface events: there is no API, and it would cover only configured
      interfaces, not ppp, tunnels or VRF slaves created by others;
    - a `/run/sysctl.d` drop-in: systemd and init-netns only, and the precedence of globs
      against explicit keys is *unverified*;
    - polling `conf/`: latency and wakeups;
    - the `rtnetlink` crate: four new dependencies to read five attributes.
- **Netns.** Every `net.*` path is per network namespace, and insomnia writes its own. In
  BDD that is the router's netns.
- **Per-key errors.** `EPERM`, `ENOENT` and `EINVAL` are reported per expanded path, and
  the rest of the batch continues. That is what [conntrack](conntrack.md) needs for
  `nf_conntrack_buckets` in a child netns.

### 3.2a The link watcher (`crate::links`, proposed; shared)

[fw-flowtable](fw-flowtable.md), [fw-zones](fw-zones.md) (`member vrf`),
[conntrack](conntrack.md) (VRF zones), [vrrp-vrf](vrrp-vrf.md) (membership findings),
[pbr](pbr.md) (VRF table IDs), [fw-bridge](fw-bridge.md) (bridge ports),
[wan-load-balancing](wan-load-balancing.md) and [ipsec-vti](ipsec-vti.md) (host checks)
need the same kernel signal as `Each` sysctls, with more fields. It is the one source of
VRF membership in insomnia. There is one watcher per process:

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    pub ifindex: u32,
    pub name: String,                // IFLA_IFNAME
    pub kind: Option<String>,        // IFLA_LINKINFO / IFLA_INFO_KIND ("vrf", "bridge", "ppp", …)
    pub master: Option<String>,      // IFLA_MASTER, resolved to a name
    pub vrf_table: Option<u32>,      // IFLA_INFO_DATA / IFLA_VRF_TABLE when kind == "vrf"
}
#[derive(Clone, Debug)]
pub enum LinkEvent { Added(Link), Changed(Link), Removed(String), Resync }
#[derive(Clone)]
pub struct Links { /* Arc<RwLock<BTreeMap<String, Link>>> + broadcast::Sender<LinkEvent> */ }
impl Links {
    pub fn spawn() -> Links;                                // one per process, from main.rs
    pub fn snapshot(&self) -> BTreeMap<String, Link>;       // current devices in insomnia's netns
    pub fn subscribe(&self) -> broadcast::Receiver<LinkEvent>;
}
```

- **Implementation.**
  - A `NETLINK_ROUTE` socket through `libc`, bound to `RTMGRP_LINK` and read with
    `tokio::io::unix::AsyncFd`.
  - At start it sends an `RTM_GETLINK` dump, which builds the first snapshot.
  - It parses `nlmsghdr`, `ifinfomsg` and the attributes listed above by hand, about 150
    lines. This is the same minimal-client approach as `vici.rs`. The attribute numbers
    come from `linux/if_link.h` and are pinned by tests.
  - `ENOBUFS`, or a lagged broadcast receiver, gives a fresh dump followed by `Resync`.
- **`Changed`** fires on any `RTM_NEWLINK` for a known index: flags, master or rename.
  Subscribers filter for the fields they care about.
- **Rejected:**
  - one watcher per backend: N sockets and diverging parsers;
  - zebra-rs config as the source: it misses kernel-only devices and slaves enslaved
    outside zebra-rs, which flowtables, zones, conntrack and vrrp-vrf need. All of them
    read VRF membership from here.

### 3.3 FW5 and FW6 mapping (VyOS `sysctl-firewall.conf.j2` line for line)

| Leaf | `enable` | `disable` | Key | Scope |
|:--|:--|:--|:--|:--|
| all-ping | 0 | 1 | `net.ipv4.icmp_echo_ignore_all` | Global |
| broadcast-ping | 0 | 1 | `net.ipv4.icmp_echo_ignore_broadcasts` | Global |
| directed-broadcast | 1 | 0 | `bc_forwarding` (v4) | All |
| ip-src-route | 1 | 0 | `accept_source_route` (v4) | Each |
| ipv6-receive-redirects | 1 | 0 | `accept_redirects` (v6) | Each |
| ipv6-src-route | 0 | -1 | `accept_source_route` (v6) | Each |
| log-martians | 1 | 0 | `log_martians` (v4) | All |
| receive-redirects | 1 | 0 | `accept_redirects` (v4) | Each |
| send-redirects | 1 | 0 | `send_redirects` (v4) | Each |
| syn-cookies | 1 | 0 | `net.ipv4.tcp_syncookies` | Global |
| twa-hazards-protection | 1 | 0 | `net.ipv4.tcp_rfc1337` | Global |

Timeouts map to `Global("net.netfilter.nf_conntrack_<x>")` with `module: Some("nf_conntrack")`.
The value is the configured number:

| Leaf | `<x>` |
|:--|:--|
| `icmp` | `icmp_timeout` |
| `other` | `generic_timeout` |
| `tcp close-wait` | `tcp_timeout_close_wait` |
| `tcp close` | `tcp_timeout_close` |
| `tcp established` | `tcp_timeout_established` |
| `tcp fin-wait` | `tcp_timeout_fin_wait` |
| `tcp last-ack` | `tcp_timeout_last_ack` |
| `tcp syn-recv` | `tcp_timeout_syn_recv` |
| `tcp syn-sent` | `tcp_timeout_syn_sent` |
| `tcp time-wait` | `tcp_timeout_time_wait` |
| `udp other` | `udp_timeout` |
| `udp stream` | `udp_timeout_stream` |

- **Ordering.** The firewall `process()` applies nft first, then
  `sysctl.apply(Owner::Firewall, global_sysctls(&opts))`, which is VyOS's order. A ruleset
  that uses `ct` loads `nf_conntrack` by itself; `module` covers configs without one. The
  sysctls are applied even when the nft apply was `Kept`, because the two are independent
  and the commit has already happened.
- **Notes for the module doc:**
  - `directed-broadcast enable` writes `conf.all.bc_forwarding` only, as VyOS does. It has
    no effect until the per-interface value is also 1, and zebra-rs has no
    `ip enable-directed-broadcast` knob (open question).
  - The ICMPv6 conntrack timeout is not covered, which is VyOS parity.

### 3.4 FW4 source validation (nft only)

- Base chain `ZEBRA_GLOBAL_RPFILTER` in each `zebra_firewall` table,
  `type filter hook prerouting priority raw; policy accept;`. Priority `raw` is -300,
  VyOS's `vyos_rpfilter` priority.
- One rule:
  - strict: `fib saddr . iif oif 0 counter drop`;
  - loose: `fib saddr oif 0 counter drop`;
  - with comment `source-validation <mode>` or `ipv6-source-validation <mode>`, for
    [fw-opmode](fw-opmode.md) counters.
- `disable`, or no leaf, emits nothing. The chain is rendered after the custom chains and
  before the frag chains.
- **Deviation.** VyOS uses a shared `table raw` from `vyos-firewall-init.conf` and a jump.
  insomnia owns no shared table, so it uses its own base chain at the same priority.
  Ordering against `ZEBRA_PREROUTING_raw` is unspecified, as in VyOS, and does not matter:
  a `drop` in either chain is final.
- **Never `rp_filter`.** zebra-rs forces `rp_filter=0` (`sysctl.rs:14-15`), and the kernel
  takes the max of `all` and the interface. The deny-list in §3.2 keeps insomnia from
  fighting it.

## 4. Changes

### zebra-rs

Help text only, `firewall.yang`:
- the toggles and timeouts: "(VyOS default: X; unset leaves the host value)";
- `source-validation` (`1160-1161`): "Reverse-path source validation via nft fib (strict |
  loose)", without "rp_filter".

No new nodes. No `exec.yang` change.

### insomnia

- **New `src/links.rs`** (§3.2a) and **new `src/sysctl.rs`** (§3.2). `main.rs` does
  this before the backends:
  - spawns `Links`;
  - spawns the writer with
    `Options { root: "/proc/sys", baseline: "/run/insomnia/sysctl-baseline.json", links: Some(links.clone()) }`;
  - passes a `Sysctl` clone and a `Links` clone to `firewall::run`. The firewall's
    `links.subscribe()` `select!` arm is added by [fw-zones](fw-zones.md) (VRF milestone)
    and shared with [fw-flowtable](fw-flowtable.md)'s hot-plug; until then the firewall
    task only holds the handle;
  - keeps `links` for the other subscribers (conntrack, `vrrp::run` for vrrp-vrf,
    `pbr::run`, wan-load-balancing), each taking a clone.

  It adds no CLI flag.
- **`src/firewall.rs`:**
  - `GlobalOptions` gains the eleven toggles as `Option<Flex>`,
    `source_validation: Option<Flex>`, `ipv6_source_validation: Option<Flex>`, and
    `timeout: Option<Timeouts>` (`icmp`, `other`, `tcp: Option<TcpTimeouts>`,
    `udp: Option<UdpTimeouts>`, all `Option<Flex>`);
  - new pure `fn global_sysctls(g: Option<&GlobalOptions>) -> (Vec<Setting>, Vec<String>)`.
    An unknown enum value or a non-numeric timeout gives a warning and no setting;
  - `render_table` emits `ZEBRA_GLOBAL_RPFILTER` (§3.4);
  - `process()` calls the writer after the nft apply and logs `Report.errors` as warnings,
    and `written`/`restored` at info;
  - `run(host, sysctl, links, show_rx)` gains two parameters;
  - module doc lines 22-25 are replaced by the §3.1 deviation and §3.3 notes.

**Worked example.** Config:

```json
{"global-options": {"all-ping": "disable", "receive-redirects": "disable",
  "timeout": {"tcp": {"established": 3600}},
  "source-validation": "strict", "ipv6-source-validation": "loose"}}
```

`global_sysctls` returns, in this order:

```
Global("net.ipv4.icmp_echo_ignore_all") = "1"
Conf{V4, "accept_redirects", Each} = "0"
Global("net.netfilter.nf_conntrack_tcp_timeout_established") = "3600"   module nf_conntrack
```

On a host with devices `lo` and `eth0`, the writer then touches
`ipv4/icmp_echo_ignore_all`, `ipv4/conf/{all,default,lo,eth0}/accept_redirects` and
`netfilter/nf_conntrack_tcp_timeout_established`. Deleting `receive-redirects` restores
each of the four paths to its recorded value.

nft. This passes `nft -c`, nftables 1.0.9:

```
table ip zebra_firewall {
    chain ZEBRA_GLOBAL_RPFILTER {
        type filter hook prerouting priority raw; policy accept;
        fib saddr . iif oif 0 counter drop comment "source-validation strict"
    }
}
table ip6 zebra_firewall {
    chain ZEBRA_GLOBAL_RPFILTER {
        type filter hook prerouting priority raw; policy accept;
        fib saddr oif 0 counter drop comment "ipv6-source-validation loose"
    }
}
```

Show: no new view in this plan. `Sysctl::status` is the hook for a later
`show firewall global-options` ([fw-opmode](fw-opmode.md)).

## 5. Tests

Unit tests, with no root:
- `global_sysctls_mapping`: table-driven over every leaf × value in §3.3, asserting the
  exact `Setting`.
- `global_sysctls_empty`: `None` and `{}` → `[]` (D4).
- `global_sysctls_bad_value`: timeout `"abc"` → a warning and no setting.
- `golden_fw4_source_validation`: the worked-example script (full text), plus `disable`
  rendering nothing.
- Writer tests against a scratch root, as the keepalived tests use scratch dirs:
  - `writes_each_scope_including_dotted_device` (`conf/eth0.100/`);
  - `compare_before_write_counts_unchanged`;
  - `restore_on_removal` and `restore_device_created_later_uses_default_baseline`;
  - `baseline_persists_across_writer_restart`;
  - `guard_refuses_zebra_keys` (`conf.all.rp_filter`);
  - `owner_collision_is_an_error`;
  - `missing_node_runs_module_hook_once` (injectable modprobe command);
  - `restore_absent_baseline`: a node created by the module hook, with
    `absent_baseline: Some("0")`, is restored to `0`, not to its post-load value.
- `links::parse`: hand-built `RTM_NEWLINK`/`RTM_DELLINK` byte fixtures give name, kind,
  master index and `IFLA_VRF_TABLE` (for a `vrf` kind); a dump reply builds the snapshot;
  an unknown attribute is skipped; truncated input yields nothing.
- `links_resync_on_lag`: a lagged subscriber receives `Resync`, followed by the current
  snapshot.
- The existing firewall goldens are unchanged: no `global-options` toggles in them.

BDD `@fw_global_options`:
- Topology: router `r1` (`insomnia_node.sh`, from [fw-load-safety](fw-load-safety.md)) and host
  `h1` on a bridge.
- Scenarios:
  1. **Setup.** Apply `all-ping disable` → `ping from "h1" to "192.0.2.1" should fail`;
     `command "sysctl -n net.ipv4.icmp_echo_ignore_all" in namespace "r1" should contain "1"`.
  2. **Restore.** Delete `all-ping` → the value is back to the recorded baseline, and the
     ping succeeds.
  3. **New device.** With `receive-redirects disable`,
     `I execute "ip link add dummy9 type dummy" in namespace "r1"` →
     `sysctl -n net.ipv4.conf.dummy9.accept_redirects` eventually contains `0`.
  4. **Timeout in a netns.** `timeout tcp established 3600` → the sysctl reads 3600. This
     also settles whether the timeouts are per-netns writable (*unverified* today).
  5. **Strict source validation.** `h1` adds 198.51.100.1 and pings `r1` from it; `r1` has
     no route back via that link. The `ZEBRA_GLOBAL_RPFILTER` counter moves and the ping
     fails. Then a VRF variant: `r1`'s link in a zebra-rs VRF, a legitimate ping succeeds
     (the fib/VRF interplay §4.4 asks to test).
  6. **Teardown topology.**

## 6. Docs

- **ch-01-06 connection tracking:** replace "not applied yet … logs a warning" with how
  the timeouts work, the `nf_conntrack` module note, and D4.
- **ch-01-00:** the `global-options` line of the tree (line 37) gets "state policy,
  sysctl toggles (applied), source validation (nft fib)".
- **New book section "Global options"** (in ch-01-06, or a short new chapter), covering:
  - the §3.3 table;
  - D4, with a "VyOS default vs. unset here" table;
  - per-interface semantics: `Each` reaches new devices;
  - `directed-broadcast` needs a per-interface knob;
  - strict-mode caveats (§8).
- **`firewall.rs` module doc:** the §3.1 deviation, the §3.3 notes and the §3.4
  deviation.
- **`src/sysctl.rs` module doc:** the owner model, the deny-list and its source
  (`zebra-rs/src/fib/netlink/sysctl.rs`), the baseline file, `absent_baseline`. A
  `src/links.rs` module doc: events, snapshot, `Resync` semantics, and the subscribers
  (sysctl, firewall zones and flowtables, conntrack, vrrp, pbr).

## 7. Milestones

| # | Scope | Repo | Effort | Done when |
|:--|:--|:--|:--|:--|
| 1 | `crate::sysctl` core: expansion, compare, baseline/restore, guards, modules | insomnia | S | writer unit tests green |
| 2 | FW5 + FW6: model, `global_sysctls`, call from `process()`, docs | insomnia | S | mapping tests; ch-01-06 fixed |
| 3 | `crate::links` (dump + `RTMGRP_LINK`, kind/master/VRF table, broadcast) and the writer's `Each` re-apply | insomnia | S | `links::parse` + new-device writer test; fw-flowtable and conntrack can subscribe |
| 4 | FW4 `ZEBRA_GLOBAL_RPFILTER` + golden | insomnia | S | `golden_fw4_source_validation` |
| 5 | `@fw_global_options` BDD | insomnia | S | feature green locally |
| 6 | Help-text update (D4 wording, source-validation) | zebra-rs | XS | merged with a CHANGELOG line |

Ordering: milestone 3 (`crate::links`) gates [vrrp-vrf](vrrp-vrf.md) A3/B4,
[fw-zones](fw-zones.md) milestone 6, [fw-flowtable](fw-flowtable.md) milestone 5,
[conntrack](conntrack.md) M4 and [pbr](pbr.md) I1. It depends only on milestone 1, so
land it early; those plans wait for it rather than add a second netlink reader.

## 8. Risks and open questions

- **udev after link-up.** A distro `conf.*` entry re-applied by udev after the last
  `RTM_NEWLINK` stays in effect until the next link event or commit. If BDD or field
  reports show this, add one delayed second pass (+5 s) per new device.
- **Strict source validation breaks some legitimate traffic.** The same rules exist in
  VyOS, so document them rather than add exceptions:
  - SRv6 End.DT4/DT46 egress, where decapsulated packets re-enter on `sr0` (the reason
    zebra-rs disabled `rp_filter`, `sysctl.rs:5-13`);
  - DHCP requests from `0.0.0.0`;
  - IPv6 DAD from `::` (*unverified*).
- **fib inside VRFs** relies on kernel l3mdev handling in `nft_fib` (*unverified* per
  kernel version). BDD scenario 5 decides whether to document "loose only with VRFs".
- **Timeouts in a non-init netns.** Writability is *unverified*; scenario 4 settles it.
  Loading `nf_conntrack` should not start tracking by itself (hooks register on demand,
  *unverified* per kernel). If it does, document that `timeout` implies tracking.
- **directed-broadcast:** parity means a no-op without a per-interface value. Propose a
  zebra-rs `interface … ip enable-directed-broadcast` later, rather than writing
  `conf.*.bc_forwarding` here, which would be a deviation.
- **Shared with [fw-bridge](fw-bridge.md).** VyOS writes `bridge-nf-call-ip(6)tables = 0`
  when `apply-to-bridged-traffic` is unset (`sysctl-firewall.conf.j2:19-22`). Under D4,
  insomnia does not touch them. fw-bridge records that, and uses
  `module: Some("br_netfilter")` and `absent_baseline: Some("0")` with
  `Owner::Firewall` (§3.2 "Missing nodes").

## 9. Acceptance criteria

- [ ] `crate::sysctl` exists with the §3.2 API, and is the only `/proc/sys` writer in
      insomnia. It refuses the zebra-rs keys and cross-owner paths.
- [ ] Every FW5 leaf and FW6 timeout maps exactly as in §3.3, with nothing written for
      unset leaves; deleting a leaf restores the baseline.
- [ ] `Each` settings reach devices created after the commit (BDD scenario 3).
- [ ] `crate::links` gives a snapshot plus an event stream with name, kind, master and VRF
      table. It is the only netlink link socket in insomnia and the only source of VRF
      membership; the firewall task (zones, flowtables), conntrack, vrrp and pbr take a
      `Links` clone from `main.rs`.
- [ ] `source-validation` and `ipv6-source-validation` render the §4 chains (passing
      `nft -c`) and drop spoofed sources in BDD; `rp_filter` is never written.
- [ ] A resubscribe or an unrelated commit writes no sysctl (`Report.unchanged` only).
- [ ] Book, module docs and zebra-rs help texts updated; ch-01-06's false "logs a
      warning" sentence is gone.
