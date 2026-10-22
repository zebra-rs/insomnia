# `system conntrack` and per-VRF conntrack zones — implementation plan

Status: plan, 2026-10-21. Covers: §6.4 rows `table-size | hash-size |
expect-table-size`, `modules`, `tcp loose | max-retrans | half-open`,
`flow-accounting`, `log timestamp`, `timeout custom`, `ignore`, `log event`,
per-VRF ct zones (FW13), `show conntrack table | statistics`,
`reset conntrack`, D6 ([vyos-gap](../vyos-gap.md) §6.4, §5 FW13, §6.1, §4.2).
Priority: P2 (sizes, helpers, VRF zones, show) · P3 (tcp knobs, custom
timeouts, ignore, event log) · Effort: L (sum of S/M items) · Owner: both
Depends on: [fw-global-options](fw-global-options.md) (`crate::sysctl` with
`Owner::Conntrack`; `crate::links`), [nft-common](nft-common.md)
(`crate::nft`, including `apply_if_changed`), [exec-verbs](exec-verbs.md)
(`reset conntrack`, the shared `show log` container),
[commit-validation](commit-validation.md) (`crate::findings`),
[multi-path-subscribe](multi-path-subscribe.md) (only for `ignore` group
references), [ebpf-netfilter](ebpf-netfilter.md) (behaviour on eBPF ports);
soft: [conntrack-sync](conntrack-sync.md) (only for `modules nfs|sqlnet`,
whose userspace helpers conntrackd registers) ·
Unblocks: [nat](nat.md) (this plan owns the conntrack reader behind
`show nat … translations`, and VRF zones for NAT across overlapping VRFs),
[conntrack-sync](conntrack-sync.md), [fw-matchers](fw-matchers.md) (FW15
`conntrack-helper` matches only once helpers are assigned),
[nat-cgnat-nat64](nat-cgnat-nat64.md) (`ctread::delete` by source prefix),
[wan-load-balancing](wan-load-balancing.md) (`ctread::delete` by mark,
`ctread::dump`)

Global conntrack timeouts (FW6) and the `global-options` toggles (FW5) stay in
[fw-global-options](fw-global-options.md). This plan does not touch them.

## 1. Goal

- `set system conntrack table-size | hash-size | expect-table-size`,
  `tcp …`, `flow-accounting` and `log timestamp` reach the kernel. A key that
  cannot be written, because it is read-only in a non-init netns, produces a
  warning that names the key.
- `set system conntrack modules ftp|h323|nfs|pptp|rtsp|sip|sqlnet|tftp`
  loads the helper modules and assigns them with nft `ct helper` objects. A
  helper the host cannot provide is skipped with a warning and does not stop
  the rest of the ruleset from loading.
- `timeout custom` and `ignore` rules render into `ip/ip6 zebra_conntrack`.
  Nothing is notracked by default (D6).
- Hosts with VRFs get a conntrack zone per VRF (`inet zebra_vrf_zones`) and a
  NAT anchor, so a stateful firewall or NAT across VRFs with overlapping
  addresses keeps separate flows.
- `show conntrack table ipv4|ipv6 [vrf <name>]`, `show conntrack statistics`
  and `reset conntrack` work from the zebra-rs CLI.

## 2. Current state

**insomnia @ `ee4dfaa`:**
- There is no conntrack backend: `main.rs:101-111` spawns firewall, ipsec,
  vrrp and the provider only.
- The firewall's `GlobalOptions` keeps only `state-policy`
  (`firewall.rs:1054-1059`), and the module doc says the rest is dropped
  (`firewall.rs:22-25`).
- `notrack` already works as a raw-chain action (`firewall.rs:1903`), which is
  why VyOS's own advice for `ignore` rules ("use firewall … prerouting raw")
  is already available.
- No code writes a sysctl or runs `modprobe`. The unit runs as root
  (`packaging/systemd/insomnia.service`, `User=root`).
- Provider routing is a bare prefix test (`provider.rs:91-100`).
  `/show/conntrack` would therefore also capture `/show/conntrack-sync`.

**zebra-rs @ `141da2fc`:**
- `container system` (`config.yang:605`) has no `conntrack` child.
- VRF membership is config (`interface … vrf`, `config.yang:5720`), but table
  IDs are internal. They are allocated smallest-free from 1, skipping 253-255
  (`src/rib/vrf/alloc.rs:13-15`, `MIN_TABLE_ID = 1`).
- There is no `show conntrack` grammar. The predicates in `SHOW_PROTOS`
  (`manager.rs:2078-2092`) test `paths.iter().any(|x| x.name == …)`, and key
  values are path elements too (`paths.rs:30-41` reads the VRF name from one).
  So `show conntrack table ipv4 vrf bgp` would route to BGP. A new predicate
  must be anchored at `paths[1]`.
- `vrf_redirect_split` finds no per-VRF client for an external provider and
  falls through with the original paths (`paths.rs:30-41`,
  `manager.rs:1795-1817`). insomnia therefore receives
  `/show/conntrack/table/ipv4/vrf` with the name in `args`.

**VyOS `7f2c893`:**
- `src/conf_mode/system_conntrack.py`:
  - `module_map` (`:41-77`);
  - `apply()` runs `modprobe -a`, then `nft --file`, then `rmmod` of the
    unused modules, then `sysctl -f` (`:212-257`).
- `data/templates/conntrack/sysctl.conf.j2:4-11` always writes every key.
  The defaults (`system_conntrack.xml.in`) are:

  | Leaf | Default |
  |:--|:--|
  | `expect-table-size` | 2048 (`:29`) |
  | `hash-size` | 65536 (`:42`) |
  | `table-size` | 262144 (`:334`) |
  | `tcp half-open-connections` | 512 (`:352`) |
  | `tcp loose` | enable (`:372`) |
  | `tcp max-retrans` | 3 (`:385`) |
- `data/templates/conntrack/nftables-ct.j2`:
  - `VYOS_CT_IGNORE`, then `VYOS_CT_TIMEOUT` with `ct timeout` objects and
    hooks at -199 (`:19-49`);
  - PREROUTING/OUTPUT at -300, ending in `notrack` unless
    FW/NAT/WLB_CONNTRACK accepts (`:51-76`);
  - helper chains at -5, rendered only when the firewall or NAT needs state
    (`:60-83`);
  - the ip6 table renders `l3proto ip` (`:127`).
- `nftables-helpers.j2:1-76` holds the helper objects and `VYOS_CT_HELPER`.
- `python/vyos/template.py:782-881` holds `conntrack_rule` and
  `conntrack_ct_policy`.
- **VRF zones:**
  - `data/vyos-firewall-init.conf:76-91` creates `inet vrf_zones` with the
    map `ct_iface_map` (`typeof iifname : ct zone`).
  - `src/conf_mode/vrf.py:48-86` gives the rationale: original direction
    only (T3655/T6097), and an `inet vrf_zones_nat` anchor at postrouting 99,
    which costs about 200 ns per new connection.
  - `vrf.py:394-417` adds the rules only when `conntrack_required()`
    (`python/vyos/firewall.py:32-49`). The map elements are VRF device →
    table ID (`vrf.py:394-397`) and member → table ID
    (`python/vyos/ifconfig/interface.py:470-478`).
- **Op mode:**
  - `src/op_mode/conntrack.py:29-37` runs `conntrack --dump --family F
    --output xml [--orig-zone <vrf table id>]`; headers at `:77-96` and
    `:171-186`.
  - `src/op_mode/clear_conntrack.py` runs `conntrack -F` and
    `conntrack -F expect` after a yes/no prompt.

**Kernel facts, tested for this plan** (Ubuntu 6.8.0-147, nftables 1.0.9,
throwaway netns via `unshare -n`):

1. **Read-only in a child netns.** `nf_conntrack_max`, `nf_conntrack_buckets`
   and `nf_conntrack_expect_max` are mode 0444 there, and a write fails with
   EPERM. `nf_conntrack_tcp_loose`, `_tcp_max_retrans`, `_acct`,
   `_timestamp` and `net.ipv4.tcp_max_syn_backlog` are writable. This
   resolves the *unverified* note in gap §6.4.
2. **No helper auto-assignment.** `net.netfilter.nf_conntrack_helper` does
   not exist, so a loaded but unassigned helper module is inert.
3. **No procfs.** `CONFIG_NF_CONNTRACK_PROCFS` is not set, so
   `/proc/net/nf_conntrack` is absent. Any reader must use ctnetlink.
4. **No rtsp helper.** `nf_conntrack_rtsp` is not shipped (it is out of
   tree).
5. **Missing helpers fail the whole script.** A `ct helper` object of type
   `"rtsp"`, `"rpc"` (nfs) or `"tns"` (sqlnet), with no registered
   kernel/userspace helper, fails with `Could not process rule: No such file
   or directory`, and `nft -c` fails the whole script. `rpc` and `tns` exist
   only as conntrackd userspace helpers (VyOS `conntrackd.conf.j2:56-78`),
   which run only with conntrack-sync. VyOS's `modules nfs` alone therefore
   probably fails to load (*unverified* on VyOS).
6. **`l3proto ip` in an ip6 table** is accepted and listed back unchanged.
7. **Example scripts pass.** The scripts in §4.2 pass `nft -c` and apply.

## 3. Design

**3.1 Backend shape.** `src/conntrack.rs` follows AGENTS.md "Backend shape".
- It subscribes to `["system", "conntrack"]` and `select!`s stream events,
  `crate::links` events (`Links::subscribe`) and show/exec requests.
- It owns two independent transactions. Each is applied with
  `nft::apply::apply_if_changed` ([nft-common](nft-common.md)), not with a
  local compare:
  - **`ip/ip6 zebra_conntrack`**, commit-driven.
  - **`inet zebra_vrf_zones`**, link-driven.
- **Why they are separate.** Deleting the table destroys its `ct timeout`
  objects. The kernel then detaches them from live flows
  (`nft_ct_timeout_obj_destroy` → `nf_ct_untimeout`; kernel source, not
  tested), which drops those flows back to default timeouts. Link churn
  (an interface enslaved to a VRF) must never touch `zebra_conntrack`, and
  an unchanged commit must not re-apply it.
- The zones table holds no stateful objects, so replacing it is harmless.

**3.2 Apply order** (from VyOS `apply()`):
1. `modprobe -a nf_conntrack <helper kos>`. Loading `nf_conntrack`
   registers no hooks, and without the module the sysctls do not exist.
2. Sysctls: `Sysctl::apply(Owner::Conntrack, settings)` (§3.3).
3. The `zebra_conntrack` script.

Every external call (`modprobe`, the helper probe, nft, conntrack-tools) runs
under a timeout (5 s; 10 s for `conntrack -F` on a large table), as
[exec-verbs](exec-verbs.md) D-8 requires of every handler.

**Deviation: never `rmmod`.** Unassigned helpers are inert (fact 2), and
`rmmod` would also hit modules that something else loaded.

**3.3 Sysctls.** These go through `crate::sysctl`
([fw-global-options](fw-global-options.md) §3.2) as `Owner::Conntrack`. The
writer's owner guard keeps these keys apart from `Owner::Firewall`'s
`nf_conntrack_*_timeout` keys. Each row is a
`Setting { key: Key::Global(<key>), value, module: Some("nf_conntrack"),
absent_baseline: None }`, so a key that only appears after the writer's
`modprobe` restores to the module default. The exception is
`tcp_max_syn_backlog`, which has `module: None`.

| Leaf | Key | Value |
|:--|:--|:--|
| `table-size` | `net.netfilter.nf_conntrack_max` | n |
| `hash-size` | `net.netfilter.nf_conntrack_buckets` | n |
| `expect-table-size` | `net.netfilter.nf_conntrack_expect_max` | n |
| `tcp half-open-connections` | `net.ipv4.tcp_max_syn_backlog` | n |
| `tcp loose enable\|disable` | `net.netfilter.nf_conntrack_tcp_loose` | 1/0 |
| `tcp max-retrans` | `net.netfilter.nf_conntrack_tcp_max_retrans` | n |
| `flow-accounting` | `net.netfilter.nf_conntrack_acct` | 1 |
| `log timestamp` | `net.netfilter.nf_conntrack_timestamp` | 1 |

- **Only configured keys are written** (assumes D4). `apply` is
  declarative: a key that leaves the list gets its baseline back. That is the
  writer's restore.
- **`Report.errors`** carries the per-key errors. EPERM or 0444 becomes the
  warning `system conntrack table-size: read-only in
  this network namespace; set it in the host namespace`, once per key and
  value.

**3.4 ALG helpers.**
- Port `module_map` verbatim, with `pptp` and `rtsp` IPv4-only.
- **Helper chains are rendered whenever at least one helper is available.**
  VyOS gates them on the firewall or NAT needing state. Under D6, insomnia
  always tracks.
- **Availability** comes from two checks:
  - `modprobe` succeeding for every `ko` of that module;
  - for kos-less (`nfs`, `sqlnet`) and out-of-tree (`rtsp`) helpers, a probe:
    `nft -c -f -` of `table ip zebra_ct_probe { ct helper p { type "<t>"
    protocol <p>; } }`.
- The result is a pure input to `render` (`HelperAvail`), so golden tests stay
  deterministic. Probing is host state, so it lives in `host_findings`, per
  the [commit-validation](commit-validation.md) rule (`render()` stays pure).
  `validate()` uses the last cached `HelperAvail`. An unavailable module is skipped with
  `system conntrack modules rtsp: kernel helper not available (module nf_conntrack_rtsp not found); skipped`.
- `nfs` and `sqlnet` become available once conntrackd registers its
  userspace helpers ([conntrack-sync](conntrack-sync.md)). The conntrack task
  re-probes when that task signals that conntrackd has started (an in-process
  `watch`).

**3.5 Custom timeouts.**
- `ct timeout ct-timeout-<N>` objects, with rules in `ZEBRA_CT_TIMEOUT`
  jumped from PREROUTING/OUTPUT at -199, after conntrack (-200) creates the
  entry and before confirm. That is VyOS's priority.
- **Exactly one of `tcp` or `udp`** under `protocol`. Otherwise the rule is
  skipped with a warning (VyOS rejects the commit,
  `system_conntrack.py:173-179`).
- **The ip6 table renders `l3proto ip6`.** Deviation: VyOS renders `ip`
  (`nftables-ct.j2:127`). The kernel accepts both (fact 6). The kernel's
  eval path appears to key only on l4proto, so both probably behave the same
  (*unverified*), but `ip6` is what an operator reading `nft list` expects.
- Policy keys are VyOS leaf names with `-` → `_` (`close-wait` →
  `close_wait`), in schema order.
- **`inbound-interface`** is quoted (the existing firewall deviation). `any`
  renders no `iifname` match.

**3.6 `ignore`.**
- Rendered as `ZEBRA_CT_IGNORE` (`… counter notrack comment "ignore-N"`) plus
  PREROUTING/OUTPUT chains at -300 that only `jump` to it. There is no
  trailing `notrack` (D6).
- Groups need `firewall group` sets in this table, and therefore the
  two-subtree subscription from
  [multi-path-subscribe](multi-path-subscribe.md) (`subscribe_json_multi`,
  `Fallback::Refuse`). That makes `ignore` the last milestone. Until then,
  an `ignore` rule with a group reference is skipped with a warning.
- Sets come from `nft::group::render_sets`, and references are checked with
  the `GroupIndex` it returns. An undefined group skips the rule. This
  table is not a [fw-dynamic-sources](fw-dynamic-sources.md) consumer, so a
  `domain-group` or `remote-group` reference also skips the rule with a
  warning. The table has no custom chains, so the
  [fw-load-safety](fw-load-safety.md) chain graph is not involved.
- The docs steer users to `firewall … prerouting raw` (VyOS warns the same,
  `system_conntrack.py:171`).

**3.7 VRF zones (FW13).**

*Source of membership: the kernel.* The input is `crate::links`
([fw-global-options](fw-global-options.md) §3.2a): `Links::snapshot()` gives
`Link { name, kind, master, vrf_table }`, and `Links::subscribe()` gives
`Added`/`Changed`/`Removed`/`Resync`. The task re-renders on events that
change `kind`, `master` or `vrf_table`, after a 250 ms debounce. A `Resync`
re-reads the snapshot.
- Map elements: each VRF device → its table, and each enslaved device → its
  master's table (the VyOS pairs).
- **Zone = VRF table ID**, as in VyOS, so `show conntrack table … vrf X`
  filters with `--orig-zone <table>` the same way. zebra-rs IDs start at 1
  today and at 1000 once [pbr](pbr.md) Z2 lands (2047 is never allocated),
  so they never collide with zone 0.
- A table ID above 65535 is skipped with a warning (`ct zone` is 16-bit).
- **Rejected:** membership from config via
  [multi-path-subscribe](multi-path-subscribe.md) (`interface` + `vrf`).
  [fw-zones](fw-zones.md) D-Z5 rejects it too, and also reads `crate::links`.
  Here:
  - The zone number must stay stable while flows exist. The only stable
    per-VRF number is the kernel table ID, and that exists only in the
    kernel (`config.yang:5843` says it is internal).
  - Devices that exist outside `interface … vrf` also carry VRF traffic:
    keepalived's VMAC macvlans, which keepalived itself enslaves to the
    parent's VRF (`design/vrrp.md` §13), and devices created by zebra-rs
    internally. They must be zoned too, and a zone that misses them breaks
    flows.
  - So this plan needs no `interface` subscription.
    [multi-path-subscribe](multi-path-subscribe.md) §3 lists conntrack with
    `system conntrack` and `firewall group` only, the latter for `ignore`
    (M7), and records VRF zones under "Not consumers".

*Rules:*
- Original direction only: `ct original zone set iifname|oifname map
  @ct_iface_map`. VyOS's reasoning (`vrf.py:49-60`) is kept: zoning the reply
  direction breaks route-leaked NAT.
- A `type nat hook postrouting priority 99` chain `anchor` registers nf_nat
  for both families, so clashing reply tuples in zone 0 get reallocated.
  An empty nat chain does not stop later nat chains: nf_nat iterates them
  until one binds.

*When:*
- Whenever at least one VRF device exists, unless the zebra-rs extension leaf
  `system conntrack vrf-zones disable` is set.
- **Deviation:** VyOS enables zones only when `conntrack_required()` (nat,
  nat66, WLB, or a stateful firewall rule). Deriving that here would couple
  this table to three subtrees, which is what D6 rejected.
- The cost is the nf_nat registration measured by VyOS (+19% on IPv4
  connection setup, established traffic unaffected, `vrf.py:75-79`). The
  extension leaf opts out.

**3.8 Show, reset, event log.**
- **The reader is owned by this plan.** It is `src/ctread.rs` (proposed),
  and [nat](nat.md) M7 consumes it for `show nat … translations`. It shells
  out to conntrack-tools: no procfs exists (fact 3), and a native ctnetlink
  client would be a new netlink dependency for what VyOS also does with the
  CLI. It parses `-o extended,id`, which is `key=value` text, so no XML
  crate is needed. VyOS parses `-o xml`. The exact text format must be
  pinned by a captured fixture, because conntrack-tools is not installed on
  the dev host (*unverified*).

  ```rust
  pub struct Flow { pub family: Fam, pub proto: String, pub timeout: u64, pub state: Option<String>,
                    pub orig: Tuple, pub reply: Tuple, pub mark: u32, pub zone: Option<u16>,
                    pub helper: Option<String>, pub snat: bool, pub dnat: bool }
  pub struct Tuple { pub src: String, pub dst: String, pub sport: Option<u16>, pub dport: Option<u16>,
                     pub packets: Option<u64>, pub bytes: Option<u64> }
  pub struct Filter { pub family: Fam, pub orig_zone: Option<u16>, pub src_nat: bool, pub dst_nat: bool,
                      pub address: Option<String> }
  pub async fn dump(f: &Filter) -> Result<Vec<Flow>, CtError>;        // conntrack -L -f F [--orig-zone Z] [--src-nat|--dst-nat] -o extended,id
  pub async fn stats() -> Result<Vec<Vec<(String, u64)>>, CtError>;    // conntrack -S, one row per cpu
  pub async fn flush() -> Result<(), CtError>;                         // conntrack -F; conntrack -F expect
  pub struct DeleteFilter { pub family: Fam, pub src: Option<String>, pub mark: Option<u32> }
  pub async fn delete(f: &DeleteFilter) -> Result<(), CtError>;       // conntrack -D -f F [-s P] [--mark M]
  pub fn events(filter: &EventFilter) -> tokio::process::Child;        // conntrack -E … (M8)
  pub enum CtError { NotInstalled, Failed(String) }                    // NotInstalled → "% conntrack not available"
  ```

  `NotInstalled` produces the `% conntrack not available` answer that
  [nat](nat.md) §8 expects. `delete` serves two callers:
  [nat-cgnat-nat64](nat-cgnat-nat64.md) C-3 (`src`, a host or prefix whose
  CGNAT allocation changed) and [wan-load-balancing](wan-load-balancing.md)
  W-2/W-6 (`mark`, a WAN's mark). A delete that matches nothing is success,
  not `Failed`; conntrack-tools' exit status for "0 flow entries" is
  *unverified*, so the fixture pins it. Packaging adds `conntrack` to `recommends`,
  which is also nat's change. Whichever lands first adds it.
- **`show conntrack table ipv4|ipv6`** uses VyOS's columns: Original
  src/dst/packets/bytes, Reply src/dst/packets/bytes, Protocol, State,
  Timeout, Mark, Zone. `-j` returns the flows as JSON.
- **`vrf <name>`** resolves through the same link snapshot. An unknown VRF
  answers `% VRF <name> not found or has no table ID` (VyOS text).
- **`show conntrack statistics`** has one row per CPU. The two columns VyOS
  leaves unnamed are named here (`Clash resolve`, `Chain too long`), a minor
  deviation.
- **`reset conntrack`**, through [exec-verbs](exec-verbs.md), flushes the
  table and the expectations.
  - zebra-rs: the `EXEC_ROUTES` row `reset conntrack` → key `conntrack`, and
    `container conntrack` under the `reset` verb container.
  - insomnia: `"conntrack"` in `EXEC_TREES`, and the `ROUTES` rows
    `(Show, "/show/conntrack", Backend::Conntrack)` and
    `(Exec, "/reset/conntrack", Backend::Conntrack)`.
  - The handler runs `ctread::flush()` in a spawned task with the timeout
    above. It answers `Answer { text: "Connection tracking table flushed\n",
    error: false }`, or `error: true` with the conntrack-tools message.
  - There is no confirmation prompt (VyOS asks yes/no). EXEC orders are
    admin-only, and the audit log line from exec-verbs D-9 records who
    flushed.
- **`log event new|update|destroy <proto>`** spawns one `conntrack -E`
  child, which needs conntrack-tools, with `-e`/`-p` filters,
  `--buffer-size` from `queue-size`, and `-o timestamp`. Lines are logged
  with tracing target `conntrack_event`. `show log conntrack` is a
  `conntrack` child of the shared `show log` container
  ([exec-verbs](exec-verbs.md)). Its exact-segment predicate goes ahead of
  the any-segment tests. It reads the journal for that target, bounded by
  [fw-opmode](fw-opmode.md)'s `show log` limits.
- **eBPF ports.** Traffic that cradle forwards in XDP/TC never reaches
  conntrack. It gets no entry, no zone, no helper and no custom timeout, and
  `show conntrack table` does not list it. See
  [ebpf-netfilter](ebpf-netfilter.md). Under its default outcome (B), zebra-rs
  refuses forwarding firewall trees on eBPF ports. This plan adds the
  `system conntrack modules` / `timeout custom` row to that check's
  `EBPF_BYPASSED_TREES` with M1. VRF zones alone are harmless there (that
  plan lists them as allowed).
- **Findings.** `render()` returns `(String, Findings)`
  ([commit-validation](commit-validation.md) `crate::findings`).
  - The skip cases above are `Warning`s with `Effect::Skipped("rule
    skipped")` or `Skipped("helper skipped")`.
  - Read-only sysctls are `Effect::NotApplied`.
  - `conntrack::validate(parts)` joins the validator `UNITS` as
    `"conntrack"`.

**3.9 Deviations to record in the `src/conntrack.rs` module doc:**
- `zebra_conntrack` and `zebra_vrf_zones` replace `vyos_conntrack`,
  `vrf_zones` and `vrf_zones_nat`. The NAT anchor lives inside
  `zebra_vrf_zones` (single owner, atomic).
- No trailing `notrack` and no FW/NAT/WLB_CONNTRACK chains (D6). Helper
  chains are unconditional.
- Sysctls are written only when configured (D4). VyOS always writes its
  defaults.
- Helper modules are never `rmmod`ed.
- The ip6 `ct timeout` uses `l3proto ip6`.
- `nfs`, `sqlnet` and `rtsp` render only when the helper probes as
  available.
- VRF membership is read from the kernel. Zones are enabled whenever a VRF
  exists, and the `vrf-zones disable` extension leaf opts out.
- Statistics column names are added.

## 4. Changes

### zebra-rs

`yang/config.yang`, inside `container system`, shown here as a sketch. The
ranges and enums are VyOS's (`system_conntrack.xml.in`).
`if-feature` on a non-top-level node has no precedent in the tree
(`zebra-features.yang:8-13` says any node may carry it). Confirm with a
schema test.

```yang
container conntrack {
  if-feature feat:insomnia;
  ext:help "Connection tracking";
  leaf table-size { ext:help "Maximum tracked connections (VyOS default: 262144)";
    type uint32 { range "1..50000000"; } }
  leaf hash-size { ext:help "Hash buckets (VyOS default: 65536)";
    type uint32 { range "1024..50000000"; } }
  leaf expect-table-size { ext:help "Maximum expectations (VyOS default: 2048)";
    type uint32 { range "1..50000000"; } }
  leaf flow-accounting { ext:help "Per-flow packet/byte accounting"; type empty; }
  leaf vrf-zones {                       // zebra-rs extension (deviation, §3.7)
    ext:help "Per-VRF conntrack zones (default: enable when VRFs exist)";
    type enumeration { enum enable; enum disable; } }
  container tcp {
    leaf half-open-connections { type uint32 { range "1..2147483647"; } }
    leaf loose { type enumeration { enum enable; enum disable; } }
    leaf max-retrans { type uint8 { range "1..255"; } }
  }
  container modules {
    leaf ftp { type empty; }  leaf h323 { type empty; }  leaf nfs { type empty; }
    leaf pptp { type empty; } leaf rtsp { type empty; }  leaf sip { type empty; }
    leaf sqlnet { type empty; } leaf tftp { type empty; }
  }
  container log {
    leaf timestamp { type empty; }
    container event {
      container new { leaf icmp {type empty;} leaf other {type empty;}
                      leaf tcp {type empty;} leaf udp {type empty;} }
      container update  { /* same four */ }
      container destroy { /* same four */ }
    }
    leaf queue-size { type uint32 { range "1..2147483647"; } }
    leaf log-level { type enumeration { enum info; enum debug; } }
  }
  container timeout { container custom {
    container ipv4 { list rule { key number; uses ct-timeout-rule-v4; } }
    container ipv6 { list rule { key number; uses ct-timeout-rule-v6; } } } }
  container ignore {
    container ipv4 { list rule { key number; uses ct-ignore-rule-v4; } }
    container ipv6 { list rule { key number; uses ct-ignore-rule-v6; } } }
}
```

- **The rule groupings:**
  - `number` (1..999999), `description`, `inbound-interface` (string,
    `ext:dynamic "rib:interface"`);
  - `source`/`destination` `address` and `port`, using the `string` union
    arms the way `firewall.yang`'s `l3-match-*` do;
  - `protocol`: for timeouts, `container tcp { close close-wait established
    fin-wait last-ack syn-recv syn-sent time-wait }` and
    `container udp { replied unreplied }`, all `uint32 1..21474836`; for
    ignore, a string;
  - ignore only: `tcp flags` (reuse `fw:rule-base`'s `tcp` container) and
    `group` (reuse `l3-match-v4/v6`'s `group`).
- **Layer-1 checks** (§4.1, [commit-validation](commit-validation.md)):
  - the ranges above;
  - `mandatory` on `protocol` for timeout rules;
  - the "exactly one of tcp or udp" rule as a `choice` if the zebra-rs
    engine supports it (*unverified*), otherwise a render warning.
- **`yang/exec.yang`:**

  ```yang
  container conntrack { if-feature feat:insomnia; ext:help "Connection tracking";
    container statistics { presence "Per-CPU conntrack statistics"; }
    container table {
      container ipv4 { presence "IPv4 flows"; list vrf { key name; leaf name {
        ext:dynamic "rib:vrf"; type string; } } }
      container ipv6 { presence "IPv6 flows"; list vrf { … } } } }
  ```

- **`reset conntrack`:** the verb grammar comes from
  [exec-verbs](exec-verbs.md).
- **`src/config/manager.rs`:**
  - `fn is_conntrack(paths) -> bool { paths.get(1).is_some_and(|p| p.name ==
    "conntrack") }`;
  - a `SHOW_PROTOS` entry `(is_conntrack, "conntrack", "Conntrack")`, placed
    **first**, so the unanchored predicates further down never see a VRF key
    named like a protocol.

### insomnia

- **`src/conntrack.rs` (new):**
  - `ConntrackConfig` and its children, all `Flex`, `de_presence` and
    `de_flex_vec` per `json.rs`;
  - `render_sysctls(&ConntrackConfig) -> Vec<(&'static str, String)>`;
  - `render(&ConntrackConfig, &HelperAvail) -> (String, Findings)`, built on
    `nft::Script` (`reset_tables(&["ip", "ip6"], "zebra_conntrack")`);
  - `render_zones(&BTreeMap<String, links::Link>, enabled: bool) -> String`;
  - `host_findings(&ConntrackConfig, &HelperAvail) -> Findings` and
    `validate(parts) -> Findings`;
  - `#[cfg(test)] render_str(json, avail)`;
  - `run(host, links: Links, sysctl: Sysctl, rx, sizes_tx)`. `rx` is the
    backend's request channel, carrying both show and exec orders
    ([exec-verbs](exec-verbs.md) `ShowRequest { kind, .. }`).
  - It keeps `Applied` state for the two tables, for `apply_if_changed`.
- **`src/ctread.rs` (new, §3.8):** the conntrack-tools wrapper and its
  `key=value` parser, a pure `parse_extended(&str) -> Vec<Flow>` with fixture
  tests, and a pure `delete_argv(&DeleteFilter) -> Vec<String>`.
  [nat](nat.md), [nat-cgnat-nat64](nat-cgnat-nat64.md),
  [wan-load-balancing](wan-load-balancing.md) and
  [conntrack-sync](conntrack-sync.md) consume it.
- **`sizes_tx`** is a `watch::Sender<CtSizes { buckets, max }>`. It publishes
  the live values after each sysctl apply, for
  [conntrack-sync](conntrack-sync.md).
- **`src/main.rs`:**
  - a `conntrack` field in exec-verbs' `Backends`;
  - spawning `conntrack::run` with the shared `Links` and `Sysctl` handles;
  - handing the `sizes` and `helpers-changed` watches to the conntrack-sync
    task.
- **`src/provider.rs`:**
  - `"conntrack"` goes in the registered show names and in `EXEC_TREES`;
  - the two `ROUTES` rows from §3.8;
  - [exec-verbs](exec-verbs.md) D-8 `route()` matches a prefix only on a
    segment boundary (`path == p || path.starts_with(p + "/")`), so
    `/show/conntrack` and `/show/conntrack-sync` cannot capture each
    other.
- **`packaging`:** add `conntrack` (conntrack-tools) to `recommends` in
  `Cargo.toml` `[package.metadata.deb]`, which today lists
  `strongswan-swanctl, charon-systemd, keepalived`. [nat](nat.md) makes the
  same change; whichever lands first adds it.

**Worked example.**

```text
set system conntrack table-size 1048576
set system conntrack hash-size 262144
set system conntrack modules ftp
set system conntrack modules sip
set system conntrack timeout custom ipv4 rule 10 inbound-interface eth0
set system conntrack timeout custom ipv4 rule 10 destination address 192.0.2.10
set system conntrack timeout custom ipv4 rule 10 destination port 22
set system conntrack timeout custom ipv4 rule 10 protocol tcp established 7200
```

The subtree JSON:

```json
{"table-size":1048576,"hash-size":262144,"modules":{"ftp":null,"sip":null},
 "timeout":{"custom":{"ipv4":{"rule":[{"number":10,"inbound-interface":"eth0",
   "destination":{"address":"192.0.2.10","port":22},
   "protocol":{"tcp":{"established":7200}}}]}}}}
```

`render_sysctls` returns:

```
[("net.netfilter.nf_conntrack_max", "1048576"),
 ("net.netfilter.nf_conntrack_buckets", "262144")]
```

`render` returns the following script, with ftp and sip available. It was
checked with `nft -c` and applied in a scratch netns:

```nft
add table ip zebra_conntrack
delete table ip zebra_conntrack
add table ip6 zebra_conntrack
delete table ip6 zebra_conntrack
table ip zebra_conntrack {
    chain ZEBRA_CT_TIMEOUT {
        iifname "eth0" meta l4proto tcp ip daddr 192.0.2.10 th dport { 22 } counter ct timeout set "ct-timeout-10" comment "timeout-10"
        return
    }
    ct timeout ct-timeout-10 {
        protocol tcp;
        l3proto ip;
        policy = { established: 7200 }
    }
    chain PREROUTING_CT_TIMEOUT {
        type filter hook prerouting priority -199; policy accept;
        counter jump ZEBRA_CT_TIMEOUT
    }
    chain OUTPUT_CT_TIMEOUT {
        type filter hook output priority -199; policy accept;
        counter jump ZEBRA_CT_TIMEOUT
    }
    chain PREROUTING_HELPER {
        type filter hook prerouting priority -5; policy accept;
        counter jump ZEBRA_CT_HELPER
    }
    chain OUTPUT_HELPER {
        type filter hook output priority -5; policy accept;
        counter jump ZEBRA_CT_HELPER
    }
    ct helper ftp_tcp {
        type "ftp" protocol tcp;
    }
    ct helper sip_tcp {
        type "sip" protocol tcp;
    }
    ct helper sip_udp {
        type "sip" protocol udp;
    }
    chain ZEBRA_CT_HELPER {
        tcp dport { 21 } ct helper set "ftp_tcp" return
        tcp dport { 5060, 5061 } ct helper set "sip_tcp" return
        udp dport { 5060, 5061 } ct helper set "sip_udp" return
        return
    }
}
table ip6 zebra_conntrack {
    chain PREROUTING_HELPER { … same as ip … }
    chain OUTPUT_HELPER { … }
    ct helper ftp_tcp { … }  ct helper sip_tcp { … }  ct helper sip_udp { … }
    chain ZEBRA_CT_HELPER { … same three rules … }
}
```

An ipv6 rule 20 with `protocol udp unreplied 15 replied 120` adds
`ct timeout ct-timeout-20 { protocol udp; l3proto ip6; policy = { unreplied: 15, replied: 120 } }`
to the ip6 table. That was also checked with `nft -c`.

`render_zones`, for VRF `blue` (table 1, slave `eth1`) and VRF `red`
(table 2, slaves `eth2`, `eth3`), with elements sorted by name. It passed
`nft -c`:

```nft
add table inet zebra_vrf_zones
delete table inet zebra_vrf_zones
table inet zebra_vrf_zones {
    map ct_iface_map {
        typeof iifname : ct zone
        elements = { "blue" : 1, "eth1" : 1, "eth2" : 2, "eth3" : 2, "red" : 2 }
    }
    chain vrf_zones_ct_in {
        type filter hook prerouting priority raw; policy accept;
        counter ct original zone set iifname map @ct_iface_map
    }
    chain vrf_zones_ct_out {
        type filter hook output priority raw; policy accept;
        counter ct original zone set oifname map @ct_iface_map
    }
    chain anchor {
        type nat hook postrouting priority 99; policy accept;
    }
}
```

With no VRFs, or with `vrf-zones disable`, only the two add/delete lines are
rendered.

`show conntrack statistics`, through `text::table`:

```
CPU  Found  Invalid  Insert  Insert fail  Drop  Early drop  Errors  Search restart  Clash resolve  Chain too long
---  -----  -------  ------  -----------  ----  ----------  ------  --------------  -------------  --------------
0    0      12       0       0            0     0           0       3               0              0
```

## 5. Tests

**Golden and unit tests** (`conntrack::tests`; none needs nft, modprobe or
conntrack):

| Test | Asserts |
|:--|:--|
| `golden_render` | The §4.2 config and script byte for byte, plus the sysctl list |
| `empty_renders_teardown` | `{}` → four add/delete lines; no sysctls |
| `ipv6_timeout_uses_l3proto_ip6` | The ip6 table renders `l3proto ip6` |
| `timeout_rule_needs_one_protocol` | Both or neither of tcp/udp → rule skipped, warning names the rule |
| `helper_unavailable_skipped` | `HelperAvail` without rtsp/nfs → no object or chain line; one warning each |
| `pptp_rtsp_ipv4_only` | Neither appears in the ip6 table |
| `sysctls_only_configured` | Unset leaves produce no key (D4) |
| `tcp_loose_maps_enable_disable` | `enable`/`disable` → 1/0 |
| `zones_from_links` | The example above; a slave of a missing master is ignored |
| `zones_disabled_or_no_vrf` | Teardown only |
| `zone_over_u16_skipped` | Table 70000 → skipped with a warning |
| `ignore_without_groups_until_multipath` | A group ref → rule skipped with a warning (removed in M7) |
| `show_table_from_fixture` / `show_statistics_from_fixture` | Captured reader output → the tables above; `vrf` filter → `orig_zone` passed |
| `provider_routes_by_segment` | In `provider.rs`: `/show/conntrack-sync` does not route to conntrack, and vice versa |
| `ctread::tests::parse_extended_fixture` | A `conntrack -L -o extended,id` capture (tcp, udp, icmp, a zoned flow, a SNAT flow, a helper flow) parses into `Flow`s; unknown keys are ignored |
| `ctread::tests::not_installed_maps_to_error` | ENOENT on spawn → `CtError::NotInstalled` |
| `ctread::tests::delete_argv` | `src` → `-D -f ipv4 -s 100.64.0.0/29`; `mark` → `--mark 2147483446`; both; a "0 flow entries" capture → `Ok` |

**BDD feature `@conntrack`** (needs conntrack-tools on the host for the
reader; the Makefile target checks for it, as the VRRP target does for
keepalived):
- **Topology:** `h1` — `r1` — `h2`, linked with "I connect namespace …".
  `r1` uses the generic node script (`insomnia_node.sh` from
  [fw-load-safety](fw-load-safety.md); `insomnia_node.sh` in
  [nat](nat.md)/[commit-validation](commit-validation.md), one script).
  `r1` runs zebra-rs and insomnia, plus VRFs `blue` and `red`. Each VRF has
  one interface towards its own host, and both hosts use 10.0.0.2/24
  (overlapping).
- **Scenarios:**
  1. Setup, then apply `r1.conf` (VRFs, firewall state-policy, custom
     timeout `established 77777` for tcp/5001, `modules ftp`).
  2. `command "nft list table inet zebra_vrf_zones" in namespace "r1"`
     eventually contains `"blue" : `.
  3. Open TCP connections to 5001 from both hosts (`nc`, through `I
     spawn`). `show conntrack table ipv4 vrf blue` contains `10.0.0.2` and
     `7777`. The two flows show different `Zone` values.
  4. `nft list table ip zebra_conntrack` contains `ct helper ftp_tcp`.
  5. A `table-size` commit puts `read-only in this network namespace` in the
     insomnia log, and the rest still loads.
  6. Once [exec-verbs](exec-verbs.md) lands: `reset conntrack`, then `show
     conntrack table ipv4` eventually does not contain `10.0.0.2`.
  7. Teardown topology.

Configs go in `bdd/tests/configs/conntrack/`.

## 6. Docs

- **Book:**
  - `ch-01-06-connection-tracking.md`: rewrite the Timeouts section to link
    the [fw-global-options](fw-global-options.md) chapter, and add a "System
    conntrack" section, or move it to a new `ch-01-13-system-conntrack.md`
    covering sizes, helpers, custom timeouts, ignore and VRF zones.
    The two factual errors in §3 of the gap analysis are fixed by
    [docs-corrections](docs-corrections.md) first.
  - New `ch-03-05-show-conntrack.md`.
  - `SUMMARY.md` entries.
  - `ch-00-01-install.md`: the optional conntrack-tools dependency.
- **Module doc:** the §3.9 deviation list in `src/conntrack.rs`.
- **`firewall.rs:22-25`:** no change from this plan. The timeouts belong to
  fw-global-options.

## 7. Milestones

| # | Scope | Repo | Effort | Done when |
|:--|:--|:--|:--|:--|
| M1 | `system conntrack` YANG (all of §4.1 except `ignore`), the `vrf-zones` leaf, `show conntrack` grammar, anchored `is_conntrack` | zebra-rs | S | Schema tests pass, `--feature insomnia` only; `show conntrack …` routes to an external provider named `conntrack` |
| M2 | Backend skeleton: subscription, model, `render_sysctls` → `Sysctl::apply(Owner::Conntrack, …)`, helper modprobe, `Findings`/`validate`, provider registration and `ROUTES` rows | insomnia | S | Sysctl goldens; a BDD smoke shows the table-size warning in a child netns |
| M3 | `zebra_conntrack`: helpers with availability probe, custom timeouts, compare-before-apply | insomnia | M | §5 goldens; `nft -c` of every golden in a dev netns; unchanged commits do not re-apply |
| M4 | VRF zones from `crate::links` (debounced 250 ms), a separate `apply_if_changed` transaction | insomnia | M | `zones_*` tests; BDD scenario 2 |
| M5 | `src/ctread.rs` (`dump`, `stats`, `flush`, `delete`) and `show conntrack table\|statistics` (zone filter, stats); [nat](nat.md) M7, [nat-cgnat-nat64](nat-cgnat-nat64.md) M-C4 and [wan-load-balancing](wan-load-balancing.md) W4 build on it | both | S | Fixture parser tests; `delete_argv`; BDD scenario 3; JSON output |
| M6 | `reset conntrack`: the `EXEC_ROUTES` row, `EXEC_TREES`, the `Answer` handler with timeout, via [exec-verbs](exec-verbs.md) | both | S | BDD scenario 6 |
| M7 | `ignore` rules: `subscribe_json_multi` with `Fallback::Refuse`, `nft::group::render_sets` and `nft::matcher::endpoint` ([multi-path-subscribe](multi-path-subscribe.md), [nft-common](nft-common.md)) | both | S | Goldens with `@A_`/`@N_`/`@P_` refs; no trailing notrack |
| M8 | `log event` listener (`conntrack -E`), `queue-size`, `log-level`; `show log conntrack` as a child of exec-verbs' shared `show log` container | insomnia | M | A unit test for the argument builder; manual check |
| M9 | Book chapters, module doc, CHANGELOG | insomnia | S | `mdbook build` clean |

M3 and M4 are independent. M5 depends only on M1-M2, so it can be pulled ahead
when a consumer ([nat](nat.md) M7 first) needs the reader.

## 8. Risks and open questions

- **Assumptions on [fw-global-options](fw-global-options.md)** (all are in
  its §3.2 and §3.2a):
  - `Owner::Conntrack`;
  - errors per key without aborting the batch;
  - `module: Some("nf_conntrack")` handling;
  - baseline restore;
  - `Link.vrf_table`.
  This plan adds no writer and no watcher.
- **Requirement on [nft-common](nft-common.md):** `apply_if_changed` must
  accept the inet table key `("inet", "zebra_vrf_zones")` in `tables`. Its
  terse listing is per `(family, table)`, so nothing new is needed beyond
  that.
- **[exec-verbs](exec-verbs.md)** already carries what this plan needs:
  segment-boundary prefix matching in `route()` (D-8) and the
  `EXEC_ROUTES` row `reset conntrack`.
- **[ebpf-netfilter](ebpf-netfilter.md)** lists the `system conntrack
  modules` / `timeout custom` row in its B-class table; this plan adds it
  to `EBPF_BYPASSED_TREES` (§3.8).
- **[multi-path-subscribe](multi-path-subscribe.md) §3** carries the
  conntrack row as this plan needs it: VRF zones use `crate::links`
  (§3.7), and `ignore` needs only
  `[["system", "conntrack"], ["firewall", "group"]]` with
  `Fallback::Refuse`, each part going through `json::parse_subtree`.
- **Promise to [nat](nat.md):** `ctread` keeps the `Filter` fields nat M7
  needs (`src_nat`, `dst_nat`, `address`). A change to them is coordinated
  with nat.
- **Promise to [nat-cgnat-nat64](nat-cgnat-nat64.md) and
  [wan-load-balancing](wan-load-balancing.md):** `delete` keeps the
  `DeleteFilter { family, src, mark }` shape that C-3 requested and W-6
  uses. Whether conntrack-tools 1.4.8 accepts a CIDR after `-s` is
  nat-cgnat-nat64's open question; its per-host fallback needs nothing
  new here.
- **Timeout objects reset on change.** Any change to `zebra_conntrack`
  re-creates the timeout objects, so existing flows lose their custom
  timeouts (VyOS has the same behaviour). Document it.
  Compare-before-apply keeps unchanged commits and resubscribes from doing
  it.
- **Userspace helpers.** `nfs`/`sqlnet` without conntrack-sync stay
  unavailable. Open: run a helper-only conntrackd (a `Helper` section with
  no `Sync`) from this backend? conntrackd may require a `Sync` section
  (*unverified*).
- **Zones on by default.** Zoning whenever a VRF exists adds the nf_nat cost
  on VRF hosts that never need it. The alternative default (off unless
  enabled) leaves overlapping-VRF NAT silently broken. Recommendation: on by
  default, with `vrf-zones disable` as the opt-out.
- **conntrackd and zones.** Whether conntrackd preserves `ct zone` when it
  syncs flows is *unverified*; see [conntrack-sync](conntrack-sync.md) §8.
- **Bridges.** ct zones are not applied to bridged traffic (the inet family
  does not see bridge hooks). That is the same as VyOS.
- **The routing bug.** The `SHOW_PROTOS` problem with keys that are named
  like protocols is a pre-existing zebra-rs bug for every provider. Anchoring
  only `is_conntrack` fixes this tree. File it for the others.

## 9. Acceptance criteria

- [ ] `system conntrack` exists only with `--feature insomnia`; ranges
      enforced at commit.
- [ ] Every configured sysctl key is written; unset keys are untouched; a
      read-only key produces a warning naming it.
- [ ] Helper modules load; unavailable helpers are skipped with a warning;
      the script always loads.
- [ ] Custom timeouts apply to new flows; the ip6 table uses `l3proto ip6`.
- [ ] No `notrack` is rendered except by explicit `ignore` rules.
- [ ] VRF zone map follows kernel VRF membership within 1 s of a link
      change; the NAT anchor exists while zoning is on; the zones table
      updates never re-apply `zebra_conntrack`.
- [ ] `show conntrack table ipv4|ipv6 [vrf X]`, `show conntrack statistics`
      (text and `-j`) and `reset conntrack` work.
- [ ] Golden tests and the `@conntrack` BDD feature pass; `cargo clippy -D
      warnings` and `cargo fmt --check` clean.
- [ ] Module-doc deviations and book chapters are updated.
