# Zone-based firewall — implementation plan

Status: plan, 2026-10-21. Covers: FW1 and the `show firewall zone-policy`
op-mode row ([vyos-gap](../vyos-gap.md) §5, §4.3; assumes §11 D1).
Priority: P1 · Effort: M (interface members), L with VRF members · Owner: both
Depends on: [nft-common](nft-common.md) (`crate::nft`), [fw-load-safety](fw-load-safety.md)
(`RefIndex`, `ChainGraph`, X12 compare-before-apply), [commit-validation](commit-validation.md)
(`findings.rs`), [fw-global-options](fw-global-options.md) (`crate::links`; VRF
milestone only), [ebpf-netfilter](ebpf-netfilter.md) (behaviour on eBPF ports) ·
Unblocks: [fw-flowtable](fw-flowtable.md) (zone jump
edges in the reachability check), [fw-opmode](fw-opmode.md) (zone default
labels in `show log firewall`)

The zone verify rules this plan resolves (D-Z4) are what
[commit-validation](commit-validation.md) layer 2 refuses for zones (its row 29); that
plan is a dependency here, not a dependent.

## 1. Goal

- `firewall zone <z>` with `member interface`, `from <z> firewall name|ipv6-name`,
  `default-firewall`, `intra-zone-filtering action|firewall`, `local-zone`,
  `default-action drop|reject`, `default-log` and `description` is accepted by
  zebra-rs and enforced by insomnia, rendered as VyOS `nftables-zone.j2` renders it.
- `member vrf <v>` works from the kernel's VRF membership, read through
  `crate::links`. Enslaving or releasing an interface re-renders.
- A zone config that VyOS would reject at commit never fails the whole `nft -f`
  transaction. Each inconsistency is resolved toward the more restrictive result
  and reported as a finding naming the zone. With insomnia connected, commit
  validation refuses the commit.
- On ports with `ebpf enabled`, the behaviour is the one
  [ebpf-netfilter](ebpf-netfilter.md) fixes for every netfilter feature (D-Z2).
- `show firewall zone-policy [zone <z>]` prints the VyOS table, and `-j` returns
  the same data structured.
- Book ch-01-05 describes the shipped feature instead of a "planned" sketch.

## 2. Current state

**zebra-rs @ 141da2fc.**
- `firewall.yang` has no `zone` node; its module description lists zones as
  deferred (`yang/firewall.yang:29-35`).
- `grouping firewall` (`firewall.yang:970-1351`) holds `group`, `ipv4`, `ipv6`
  and `global-options`, and is instantiated insomnia-gated at
  `yang/config.yang:5686-5690`.
- `show firewall` grammar (`yang/exec.yang:310-408`) has no `zone-policy`.
- Interface VRF membership is the config leaf `interface <if> vrf <v>`, a leafref
  to `/vrf/name` (`config.yang:5720-5735`). The VRF master device is named after
  the VRF (`src/fib/netlink/handle.rs:3789-3802`, `vrf_add(name, …)`).
- `check.rs` has no firewall rules, so nothing can veto a zone config (§4.1).

**insomnia @ ee4dfaa.**
- `FirewallConfig` is `group`, `ipv4`, `ipv6`, `global_options`
  (`src/firewall.rs:764-769`). Unknown keys are ignored, so a `zone` key today
  is dropped silently (`golden_render` pins that, `firewall.rs:2119-2128`).
- `render_table` (`firewall.rs:1193-1316`) emits sets, base chains under
  `if let Some(f) = family` (`1212-1254`), the frag-mark chain, the state-policy
  chain (`1270-1299`, outside the family guard), then RECENT sets.
- `render_default_rule(r, chain, fam, label, base)` (`1518-1551`) takes a
  `&Chain`; `CustomChain::as_chain` (`853-863`) is the existing adapter pattern.
- One subscription, `CONFIG_PATH = ["firewall"]` (`firewall.rs:40`, `56-82`).
- `text::table` (`src/text.rs:6-31`) is the VyOS-tabulate look used by the IPsec
  and VRRP shows. It has no multi-line cells.
- The firewall show is fixed-width code of its own (`firewall.rs:288-363`).

**VyOS @ 7f2c893.**
- Schema: `interface-definitions/firewall.xml.in:415-580`.
  - `default-action` is drop|reject with `defaultValue drop`.
  - `member interface` allows wildcards
    (`include/generic-interface-multi-wildcard.xml.i`).
  - `member vrf` is a multi leaf.
  - `local-zone` is valueless.
- Template: `data/templates/firewall/nftables-zone.j2:1-148`.
  - `VYOS_ZONE_FORWARD|LOCAL|OUTPUT` at priority 1; each jumps the state-policy
    chain first when one is configured (`6-8`, `27-29`, `38-40`).
  - Forward dispatch is on `oifname` into `VZONE_<z>` (`9-23`).
  - The local zone gets `VZONE_<z>_IN` / `_OUT` (`49-109`).
  - Inside `VZONE_<z>` (`111-145`):
    - intra-zone first (`nft_intra_zone_action`);
    - then `iifname {from members} jump NAME_<chain>` + `return` per from zone;
    - then default-firewall;
    - then `nft_default_rule('zone_<z>')`.
  - Included from `nftables.j2:199-201` (ip) and `395-397` (ip6), after the
    groups and before the state-policy chains.
- `python/vyos/template.py`:
  - `nft_intra_zone_action` (`712-726`): no filtering → `return`; `accept` →
    `return`; `drop` → `drop`; a firewall → `jump NAME[6]_<n>`.
  - `nft_default_rule` (`667-685`): prefix `[<fam>-<label[:19]>-default-<A>]`,
    comment `"<label> default-action <a>"`.
- `src/conf_mode/firewall.py`:
  - `get_config` (`154-176`) derives `vrf_interfaces` from the kernel
    (`get_vrf_members`), and `from_local` / `default_local` for the local zone.
  - `verify` zone rules: `624-716`.
- Op-mode: `op-mode-definitions/firewall.xml.in:754-770` and
  `src/op_mode/zone.py:122-210`. The columns are Zone, Members, From Zone,
  Firewall IPv4, Firewall IPv6. Members of the local zone read `LOCAL`.
- VyOS bug (code reading): `nftables-zone.j2:103` reads
  `from_conf.firewall[fw_name]` in the `default_local` + VRF branch, where
  `from_conf` is a `default-firewall` dict with no `firewall` key. Fix it; do
  not copy it.

## 3. Design

**D-Z1. Follow `nftables-zone.j2` line for line.** Chains are
`ZEBRA_ZONE_FORWARD|LOCAL|OUTPUT` (the `VYOS_` → `ZEBRA_` rename already used for
every base chain). `VZONE_<z>`, `VZONE_<z>_IN` and `VZONE_<z>_OUT` and the
`zone_<z>` default label are kept verbatim, so VyOS log greps and docs carry
over. The zone chains live in the existing `zebra_firewall` tables, rendered
after the custom chains and frag-mark chain and before `ZEBRA_STATE_POLICY`, in
both families whenever any zone exists, independent of `ipv4`/`ipv6` presence
(VyOS does the same).

**D-Z2. Semantics recorded, not changed.**
- Zone chains are base chains at priority 1, beside `ZEBRA_FORWARD_filter` etc.
  at priority 0. A packet must pass both; `accept` in one base chain does not
  skip the other.
- Interfaces in no zone are not zone-filtered.
- A zone pair with only `name` (no `ipv6-name`) drops all IPv6 between those
  zones. For the local zone that includes ICMPv6 ND: the book must say so.
- **eBPF ports** ([ebpf-netfilter](ebpf-netfilter.md)).
  - Traffic that cradle forwards in XDP/TC on an `ebpf enabled` port never
    reaches `ZEBRA_ZONE_FORWARD`, so zone policy does not apply to it.
  - Local-zone traffic (input and output) is still filtered.
  - Under that plan's default outcome B, zebra-rs refuses a commit that
    combines `firewall zone` with an eBPF-forwarding port. Milestone 1 adds
    `firewall zone` to that check's tree list, if the check has landed.
  - Until then, the book states the constraint.

**D-Z3. Deterministic order.** Zones render sorted by name. `from` entries
render sorted by from-zone name. Members render in config order. VyOS uses
config-dict order; with no interface allowed in two zones, order has no
semantic effect.

**D-Z4. Render-time resolution of VyOS `verify()` rules, as findings.**
- Every row is a `Finding` from `findings.rs`
  ([commit-validation](commit-validation.md)), with the `Effect` shown.
- Error rows mirror a VyOS ConfigError. With insomnia connected, layer 2
  refuses the commit (assumes D1). At apply time the effect is taken, and the
  choice is fail-closed wherever the zone model allows it.
- Host-state rows depend on `crate::links` and are Warnings, per
  commit-validation's host-findings rule.

| VyOS rule (`firewall.py`) | Sev | insomnia render (`Effect`) | Net effect |
|:--|:--|:--|:--|
| zone with no member and not local (`630-631`) | Error | zone skipped; `from` entries naming it skipped (`Skipped`) | no interfaces affected |
| more than one local zone (`634-635`) | Error | first by name wins; the others are treated as memberless → skipped | the winner governs local traffic |
| local zone with members (`636-637`) | Error | `local-zone` wins, members dropped (`Dropped`), finding names them as not zone-filtered | fail-open for those interfaces' forwarded traffic (no restrictive choice exists) |
| local zone with intra-zone-filtering (`638-639`) | Error | ignored (`Dropped`) | none |
| interface in two zones (`646-647`), VRF in two zones (`656-657`) | Error | kept in the first zone by name, dropped from later ones | still filtered |
| `from` names an undefined zone (`686-687`) | Error | entry skipped | nothing to match |
| `from`/default-firewall/intra-zone names an undefined chain (`673-682`, `690-711`) | Error | the jump+return pair is skipped | traffic falls to `default-action` (fail-closed) |
| intra-zone with both `action` and `firewall` (`669-670`) | Error | `action` wins (`Adjusted`, `nft_intra_zone_action` order) | as VyOS would render |
| local zone `from` itself (insomnia-only) | Error | entry skipped | — |
| VRF member with no slave interfaces (`660-664`) | Warning (host) | VRF dispatch rendered without slave list (`Kept`) | ingress still matched |
| interface member enslaved to a VRF (`648-651`, a VyOS warning) | Warning (host) | rendered as configured (`Kept`) | as VyOS |
| offload chain in local zone / default-firewall (`697-700`, `714-716`) | — | not a zone check: [fw-flowtable](fw-flowtable.md) skips offload rules in chains reachable from input/output, using the zone entries and edges this plan registers | — |

"Undefined chain" uses the X2 `RefIndex` from [fw-load-safety](fw-load-safety.md).
This plan adds no second index.

**D-Z5. VRF membership comes from the kernel, through `crate::links`** (VRF
milestone).
- Source: [fw-global-options](fw-global-options.md) owns the one link watcher,
  with `Links::snapshot()`, `Links::subscribe()` and
  `Link { name, kind, master, vrf_table }`. The slaves of VRF `v` are the links
  with `master == v`, where link `v` has `kind == "vrf"`. This is what VyOS
  does (`get_vrf_members`, `firewall.py:154-165`).
- Re-render: the firewall task holds a `subscribe()` receiver. It re-renders
  from the retained model with a fresh snapshot on any of these:
  - `Added`, `Changed` or `Removed` for a VRF that a zone names;
  - the same for a device whose master is, or was, such a VRF;
  - `Resync`.

  X12 compare-before-apply reloads only when the text changes. VyOS
  re-renders only on a firewall commit.
- Rejected: zebra-rs `interface … vrf` config through
  [multi-path-subscribe](multi-path-subscribe.md).
  - It misses slaves enslaved outside zebra-rs config.
  - It would add a second subtree to the firewall stream.
  - fw-global-options already rejected config as the link source.
  - multi-path-subscribe §3 lists fw-zones under "Not consumers" for this
    reason.
- The enslave-to-re-render window is one event round trip. During it, forwarded
  traffic leaving through a newly enslaved slave is not dispatched to the VRF's
  zone (§8).

**D-Z6. Kernel facts the VRF rendering relies on** (from the VyOS template and
kernel `vrf_ip_rcv`, which re-runs PREROUTING with the VRF master as indev):
- In the forward hook, traffic received on a VRF slave has `iifname` = the VRF
  device, while `oifname` is the real egress slave.
- Hence VyOS matches ingress with `iifname {vrf names}`, and egress with
  `oifname {slaves}` plus `oifname {vrf names}`.
- An interface member enslaved to a VRF therefore never matches on ingress
  (VyOS warns).
- These facts are *unverified* here; the VRF BDD scenario asserts them.

**D-Z7. Host facts reach the renderer through a context.**
- Proposed: `RenderCtx { links: Option<BTreeMap<String, links::Link>> }`,
  holding a `Links::snapshot()`. It is passed as `render(&cfg, &ctx)`;
  `render_str` uses `RenderCtx::default()` (`links: None`).
- This plan owns the type. [fw-flowtable](fw-flowtable.md) uses `links` for
  device gating and adds `hw_tc_offload`.
- `render` stays a pure function of `(cfg, ctx)`. `validate()`
  ([commit-validation](commit-validation.md)) builds its ctx from the same
  `crate::links` snapshot, so render and validate agree.
- With `links: None`, a VRF member renders only its `iifname`/`oifname {vrf}`
  lines, and the no-slaves Warning is not raised, because the host state is
  unknown.

**D-Z8. `member vrf` YANG ships with the VRF milestone, not before.** Shipping
the leaf earlier would render ingress-only dispatch, which leaves traffic *to*
the VRF zone unfiltered (fail-open).

**Deviations to record in the `firewall.rs` module doc:**
- `ZEBRA_ZONE_*` chain names;
- zones and from-entries sorted by name;
- render-time skip with fail-closed resolution when no validator refused the
  commit (table above);
- VRF membership re-read on every relevant link event;
- the VyOS `nftables-zone.j2:103` bug fixed.

## 4. Changes

### zebra-rs

`yang/firewall.yang`, inside `grouping firewall` (sketch; plain strings for
references, no `pattern`, per the module's conventions at `firewall.yang:37-45`):

```yang
grouping zone-chain-ref {
  leaf name      { ext:help "IPv4 firewall ruleset (firewall ipv4 name)"; type string; }
  leaf ipv6-name { ext:help "IPv6 firewall ruleset (firewall ipv6 name)"; type string; }
}
list zone {
  ext:help "Zone-policy";
  key "name";
  leaf name { ext:help "Zone name"; type string; }
  leaf description { ext:help "Description"; type string { pattern '.*'; } }
  leaf default-action {
    ext:help "Default action for traffic into this zone (VyOS default: drop)";
    type enumeration { enum drop; enum reject; }
  }
  leaf default-log { ext:help "Log packets hitting the default action"; type empty; }
  container default-firewall { ext:help "Default rule sets into this zone"; uses zone-chain-ref; }
  list from {
    ext:help "Zone from which to filter traffic";
    key "zone";
    leaf zone { ext:help "Source zone name"; type string; }
    container firewall { ext:help "Rule sets"; uses zone-chain-ref; }
  }
  container member {
    ext:help "Interfaces associated with the zone";
    leaf-list interface { ext:help "Interface name; wildcard eth3* allowed";
                          ext:dynamic "rib:interface"; type string; }
    // VRF milestone:
    // leaf-list vrf { ext:help "VRF associated with zone"; ext:dynamic "rib:vrf"; type string; }
  }
  container intra-zone-filtering {
    ext:help "Intra-zone filtering";
    leaf action { ext:help "Action for intra-zone traffic"; type enumeration { enum accept; enum drop; } }
    container firewall { ext:help "Use the specified rule set"; uses zone-chain-ref; }
  }
  leaf local-zone { ext:help "This zone is the router itself"; type empty; }
}
```

- Drop "zone" from the deferred list in the module description.
- `yang/exec.yang`, under `show firewall` (`exec.yang:310`):

  ```yang
  container zone-policy {
    ext:help "Zone policy information";
    presence "All zones";
    list zone {
      ext:help "One zone"; ext:presence "One zone"; key "name";
      leaf name { ext:help "Zone name"; type string; }
    }
  }
  ```

  Paths: `/show/firewall/zone-policy` and `/show/firewall/zone-policy/zone`,
  args `[<z>]`. They route through `is_firewall` (`manager.rs:2016-2021`). Known
  issue until [fw-opmode](fw-opmode.md) milestone 1 fixes the any-segment routing
  (X15 in [vyos-gap](../vyos-gap.md) §3): a zone named `bgp`, `evpn`, `ospf` and so
  on routes to that protocol.
- If [ebpf-netfilter](ebpf-netfilter.md)'s outcome-B check exists, add
  `firewall zone` to its trees (D-Z2).
- Extend `show_firewall_grammar_gated_on_insomnia` (`manager.rs:7600-…`) with
  both paths.
- Layer-1 constraints come for free from the enums. No `check.rs` rule.

### insomnia

**Model** (`src/firewall.rs`):

```rust
pub struct FirewallConfig { …, pub zone: Vec<Zone> }      // is_empty() also checks zone
pub struct Zone {
    pub name: Option<Flex>, pub description: Option<Flex>,
    pub default_action: Option<Flex>,
    #[serde(deserialize_with = "de_presence")] pub default_log: bool,
    pub default_firewall: Option<ZoneChainRef>,
    pub from: Vec<ZoneFrom>,
    pub member: Option<ZoneMember>,
    pub intra_zone_filtering: Option<IntraZone>,
    #[serde(deserialize_with = "de_presence")] pub local_zone: bool,
}
pub struct ZoneChainRef { pub name: Option<Flex>, pub ipv6_name: Option<Flex> }
pub struct ZoneFrom { pub zone: Option<Flex>, pub firewall: Option<ZoneChainRef> }
pub struct ZoneMember {
    #[serde(deserialize_with = "de_flex_vec")] pub interface: Vec<Flex>,
    #[serde(deserialize_with = "de_flex_vec")] pub vrf: Vec<Flex>,   // VRF milestone
}
pub struct IntraZone { pub action: Option<Flex>, pub firewall: Option<ZoneChainRef> }
```

**Renderer:** new `render_zones(r, cfg, fam, ctx)`, called from `render_table`
after the custom chains and frag-mark chain.
1. `resolve_zones(cfg, ctx) -> ZonePlan`. It applies the D-Z4 table once,
   sorted, and is shared by both families and by show. `ZonePlan` holds
   `local: Option<name>` and per zone the effective members, slaves, from list,
   default-firewall, intra action and default action.
2. Emit `ZEBRA_ZONE_FORWARD` / `_LOCAL` / `_OUTPUT`, each with
   `jump ZEBRA_STATE_POLICY` when state-policy is set (`firewall.rs:1235-1237`
   is the existing pattern), then the `VZONE_*` chains.
3. Interface names pass `safe_token` and render quoted, comma-joined
   (`{ "eth1","eth2" }`), matching the I_ set element style at
   `firewall.rs:1461-1465`. Zone names must pass `safe_name`. Chain references
   render `NAME{fam.suffix()}_<n>`.
4. Default rule: `render_default_rule(r, &zone.as_chain(), fam, &format!("zone_{z}"), true)`,
   with `default_action` defaulting to `drop`.
5. Join fw-load-safety's jump graph through its extension points
   ([fw-load-safety](fw-load-safety.md) §3.2 step 4), so that loop, depth and
   `reaching_hooks` cover the zones:
   - `ChainGraph::add_entry("VZONE_<z>", forward)`, `(…_IN, input)` and
     `(…_OUT, output)`;
   - `ChainGraph::add_edge(VZONE_*, NAME[6]_*, origin)` for every from,
     default-firewall and intra-zone jump. Its origin is the zone line's key,
     for example `zone_LAN-from-WAN`.

   A zone jump removed as a loop edge is treated like an undefined chain: the
   pair is skipped, and traffic falls to `default-action`.

**Worked example** (golden `zone_golden_interfaces`). Config:

```json
{"ipv4": {"name": [
   {"name": "LAN-LOCAL", "default-action": "accept"},
   {"name": "LAN-WAN", "default-action": "accept"},
   {"name": "LOCAL-ANY", "default-action": "accept"},
   {"name": "WAN-LAN", "rule": [{"number": 10, "action": "accept", "state": ["established", "related"]}]}]},
 "zone": [
   {"name": "LAN", "member": {"interface": ["eth1", "eth2"]},
    "from": [{"zone": "WAN", "firewall": {"name": "WAN-LAN"}}]},
   {"name": "LOCAL", "local-zone": null,
    "from": [{"zone": "LAN", "firewall": {"name": "LAN-LOCAL"}}]},
   {"name": "WAN", "member": {"interface": ["eth0", "ppp*"]},
    "default-action": "reject", "default-log": null,
    "from": [{"zone": "LAN", "firewall": {"name": "LAN-WAN"}},
             {"zone": "LOCAL", "firewall": {"name": "LOCAL-ANY"}}]}]}
```

Expected `table ip zebra_firewall` zone section. This was checked with
`nft -f` inside a throwaway netns (nftables 1.0.9, kernel 6.8), together with
the custom chains:

```
    chain ZEBRA_ZONE_FORWARD {
        type filter hook forward priority 1; policy accept;
        oifname { "eth1","eth2" } counter jump VZONE_LAN
        oifname { "eth0","ppp*" } counter jump VZONE_WAN
    }
    chain ZEBRA_ZONE_LOCAL {
        type filter hook input priority 1; policy accept;
        counter jump VZONE_LOCAL_IN
    }
    chain ZEBRA_ZONE_OUTPUT {
        type filter hook output priority 1; policy accept;
        counter jump VZONE_LOCAL_OUT
    }
    chain VZONE_LAN {
        iifname { "eth1","eth2" } counter return
        iifname { "eth0","ppp*" } counter jump NAME_WAN-LAN
        iifname { "eth0","ppp*" } counter return
        counter drop comment "zone_LAN default-action drop"
    }
    chain VZONE_LOCAL_IN {
        iifname lo counter return
        iifname { "eth1","eth2" } counter jump NAME_LAN-LOCAL
        iifname { "eth1","eth2" } counter return
        counter drop comment "zone_LOCAL default-action drop"
    }
    chain VZONE_LOCAL_OUT {
        oifname lo counter return
        oifname { "eth0","ppp*" } counter jump NAME_LOCAL-ANY
        oifname { "eth0","ppp*" } counter return
        counter drop comment "zone_LOCAL default-action drop"
    }
    chain VZONE_WAN {
        iifname { "eth0","ppp*" } counter return
        iifname { "eth1","eth2" } counter jump NAME_LAN-WAN
        iifname { "eth1","eth2" } counter return
        counter log prefix "[ipv4-zone_WAN-default-R]" reject comment "zone_WAN default-action reject"
    }
```

- `VZONE_LOCAL_OUT` lists only WAN, because only `WAN from LOCAL` exists
  (VyOS `from_local`). LAN has neither `from LOCAL` nor `default-firewall`, so
  router-originated traffic to LAN hits the local default.
- The `ip6` table renders the same three base chains and the `VZONE_*` chains,
  with only the intra-zone `return` lines and default rules, because no
  `ipv6-name` is set.

**VRF example** (golden `zone_vrf_members`). The `ctx.links` fixture holds
`blue` (`kind: vrf`) and `eth5` (`master: blue`); zone WAN is `member vrf blue`
with no intra-zone filtering. The ip6 table lines are:

```
        oifname { "eth5" } counter jump VZONE_WAN          # in ZEBRA_ZONE_FORWARD
        oifname { "blue" } counter jump VZONE_WAN
        iifname { "blue" } counter return                  # in VZONE_WAN: intra-zone
```

**Link events (VRF milestone).**
- The config subscription is unchanged (`["firewall"]`, `firewall.rs:59`).
- `firewall::run` already receives the `Links` handle from `main.rs`
  ([fw-global-options](fw-global-options.md) §4).
- `run` gains one `select!` arm on `links.subscribe()`; this plan adds it. It is shared with
  [fw-flowtable](fw-flowtable.md)'s hot-plug: one arm, and each feature filters
  for the events it cares about (D-Z5).
- `process()` and the link arm both build `RenderCtx` from `links.snapshot()`.
- Findings are logged through `Findings::log("firewall")`.

**Show** (`process_show`, `firewall.rs:218-279`):
- `/show/firewall/zone-policy` and `…/zone-policy/zone` (args `[z]`) render from
  `resolve_zones(model)`, so what is shown is what was programmed.
- Text uses `text::table`, which gains multi-line cells (split on `\n`, pad the
  continuation rows). This plan owns that change; [fw-opmode](fw-opmode.md)
  reuses it.
- No counters are fetched for this view.

```
Zone   Members  From Zone  Firewall IPv4  Firewall IPv6
-----  -------  ---------  -------------  -------------
LAN    eth1     WAN        WAN-LAN
       eth2
LOCAL  LOCAL    LAN        LAN-LOCAL
WAN    eth0     LAN        LAN-WAN
       ppp*     LOCAL      LOCAL-ANY
```

- Intra-zone filtering with a firewall adds the zone itself as a From Zone row,
  as in `zone.py:139-151`.
- An unknown zone returns `% Zone <z> is not configured`.
- JSON keeps the existing camelCase convention (`defaultAction` in `chain_json`,
  `firewall.rs:700-707`):
  `{"zones":[{"name":"WAN","type":"zone|local","members":["eth0","ppp*"],"vrfs":[],"defaultAction":"reject","defaultLog":true,"from":[{"zone":"LAN","ipv4Name":"LAN-WAN","ipv6Name":null}],"intraZone":null,"defaultFirewall":null,"findings":[…this zone's findings…]}]}`.

## 5. Tests

**Golden render** (`render_str` / a new `render_str_ctx`):
- `zone_golden_interfaces`: the example above, both tables, full text.
- `zone_state_policy_jump`: the three base chains begin with
  `jump ZEBRA_STATE_POLICY`.
- `zone_intra_zone_variants`: none / `action accept` / `action drop` /
  `firewall name X` produce `return` / `return` / `drop` / `jump NAME_X` plus the
  trailing `return`.
- `zone_default_firewall`: the jump+return pair before the default rule, and its
  use in `VZONE_<local>_OUT` through `default_local`.
- `zone_ipv6_name_only_v6`: `name` renders only in ip and `ipv6-name` only in
  ip6.
- `zone_verify_resolution`: one case per row of the D-Z4 table. Each asserts
  the finding's severity, effect and text through `findings.errors()` /
  `findings.warnings()`, plus the fail-closed output. For example, an undefined
  chain gives no jump, and the default drop remains.
- `zone_only_no_family`: zones with no `ipv4`/`ipv6` key still render both
  tables' zone chains.
- `zone_vrf_members` (VRF milestone): slaves from the `ctx.links` fixture. An
  empty slave list gives a Warning and only the `{vrf}` lines; `links: None`
  gives no Warning.
- `zone_names_unsafe`: a zone or interface name failing `safe_name`/`safe_token`
  is skipped with an Error finding.

**Unit tests:**
- `model_deserializes_zone_json` (`local-zone: null`; `from` keyed by `zone`;
  `member.interface` given as a bare scalar).
- `resolve_zones_sorted`.
- `vrf_slaves_from_links`: `master` matching, a master that is not a VRF is
  ignored.
- `link_event_relevance`: which `LinkEvent`s trigger a zone re-render.
- `zone_policy_text` and `zone_policy_json`.
- `text_table_multiline`.

**zebra-rs:** grammar test cases for both `zone-policy` paths; a config parse
test for `set firewall zone LAN from WAN firewall name WAN-LAN`.

**BDD** `@fw_zone` (new; no firewall feature exists yet):
- Topology: one router r1 with two legs, `lan` (h1 192.0.2.0/24) and `wan`
  (h2 198.51.100.0/24).
- The harness's `I create namespace … on bridge …` creates a namespace per call
  (`bdd/tests/cucumber.rs:292-321`). A second leg needs a new generic step,
  `I connect namespace {string} to bridge {string} as {string} with IP {string}`.
  This plan adds it in `bdd/tests/cucumber.rs`, generic and zone-agnostic;
  [fw-flowtable](fw-flowtable.md) reuses it.
- Node launcher: `bdd/tests/scripts/insomnia_node.sh` from
  [fw-load-safety](fw-load-safety.md). It is `vrrp_node.sh` minus keepalived:
  a private `/run`, so this insomnia's VRRP/IPsec backends cannot touch host
  services.
- Scenarios:
  1. LAN→WAN ping succeeds and WAN→LAN new ping fails.
  2. Return traffic is allowed by `WAN-LAN` established.
  3. LAN→LOCAL ping to r1 succeeds and WAN→LOCAL fails.
  4. `show firewall zone-policy` lists the zones.
  5. A `default-log` drop appears in `journalctl -k`, if host logging from a
     netns is enabled (`nf_log_all_netns`); skip otherwise.
  6. `delete firewall zone` restores open forwarding.
  7. VRF milestone: both legs in `vrf blue` and one zone `member vrf blue`.
     `intra-zone-filtering action drop` blocks h1↔h2; `accept` allows it.
     `delete interface <wan> vrf` triggers a link `Changed` event, the zone
     re-renders, and `nft list chain ip zebra_firewall ZEBRA_ZONE_FORWARD` no
     longer lists that leg.
  8. Teardown.

## 6. Docs

- Rewrite `book/src/ch-01-05-zone-based-firewall.md`:
  - Drop the "planned" banner and the "(planned)" markers.
  - Correct "the router itself as the built-in `local` zone": VyOS requires
    `local-zone` on a named zone.
  - Cover the model (to-zone chains dispatched on `oifname`, from-zone on
    `iifname`), the local zone, intra-zone defaults (accepted unless
    `intra-zone-filtering`), and `default-firewall`.
  - Call out the IPv4/IPv6 split and the ICMPv6 ND warning, and coexistence
    with hook chains (both must accept).
  - Explain VRF members (VRF milestone), the eBPF-port constraint, and the
    findings: refused at commit while insomnia is connected, logged at apply
    time otherwise.
  - Keep the interim-pattern section as "without zones".
- `ch-03-00-show-firewall.md`: a `zone-policy` section.
- `ch-01-11-firewall-logging.md`: the `[ipv4-zone_<z>-default-<A>]` prefix.
- Module doc of `src/firewall.rs`: the deviations in §3.

## 7. Milestones

| # | Scope | Repo | Effort | Done when |
|:--|:--|:--|:--|:--|
| 1 | `list zone` YANG (no `member vrf`) + `zone-policy` exec grammar + grammar/parse tests | zebra-rs | S | `set firewall zone …` commits; `show firewall zone-policy` parses and routes to `firewall` |
| 2 | Model, `resolve_zones`, `render_zones`, chain-graph edges, goldens incl. `zone_verify_resolution`; module doc | insomnia | M | goldens pass; script loads in a netns (`nft -f`) |
| 3 | `text::table` multi-line cells; zone-policy text/JSON | insomnia | S | unit tests pass |
| 4 | BDD `@fw_zone` (interfaces) + two-leg step; book ch-01-05 rewrite | insomnia | S | feature green; `make -C bdd docs` regenerated |
| 5 | `member vrf` YANG | zebra-rs | S | parses; `ext:dynamic "rib:vrf"` completes |
| 6 | `crate::links` arm, `RenderCtx.links`, VRF rendering + goldens, VRF BDD scenario, D-Z6 facts confirmed | insomnia | M | VRF scenario green; X12 shows no reload on unrelated link events |

Milestones 1–4 ship on their own. Milestone 6 waits for fw-global-options'
`crate::links` (its milestone 3). Milestone 2's findings need
commit-validation C1 (`findings.rs`). If C1 has not landed, use today's
`warnings: Vec<String>` and convert later.

## 8. Risks and open questions

- **Fail-open cases.**
  - Two remain when no validator refuses the commit (insomnia not connected,
    or before layer 2): a local zone with members, and a skipped VRF slave
    list.
  - A third is the D-Z5 enslave-to-re-render window.
  - Zones make forwarding default-deny only for interfaces in zones.
    Operators migrating from VyOS expect commit errors, so the book must say
    where the findings appear.
- **Kernel VRF hook semantics** (D-Z6) are *unverified*. If `iifname` in the
  forward hook is the slave, not the master, on the shipped kernel, the VRF
  ingress lines must switch to slave lists. BDD milestone 6 decides.
- **Overlapping addresses across VRF zones** need per-VRF conntrack zones (FW13,
  [conntrack](conntrack.md)), or state matches in shared chains can cross VRFs.
  Document; not blocking.
- **eBPF.** Covered by D-Z2. If [ebpf-netfilter](ebpf-netfilter.md) ends at
  outcome A (documentation only), zone policy silently misses fast-pathed
  traffic, and only the book warns.
- **Show routing (X15).** A zone named after a protocol keyword (`bgp`, `pim`, …)
  misroutes `show firewall zone-policy zone <z>` until the
  [fw-opmode](fw-opmode.md) milestone 1 routing fix lands. That fix should ship
  before or with milestone 1.
- **Open:** should zone jump rules get comments (`"zone_LAN-from-WAN"`), so that
  per-pair counters can be shown? VyOS has none. Deferred; it would change
  goldens.

## 9. Acceptance criteria

- [ ] `firewall zone` YANG (milestone 1) and `member vrf` (milestone 5) in zebra-rs, insomnia-gated
- [ ] Renders match `nftables-zone.j2` for every branch, except the documented deviations
- [ ] Every D-Z4 row has a golden test; no zone config can make `nft -f` fail
- [ ] `show firewall zone-policy [zone <z>]` text and `-j`
- [ ] VRF members from `crate::links`; re-render on enslave or release; no reload when the render is unchanged
- [ ] Every D-Z4 row emits a `Finding` with the listed severity; eBPF-port behaviour documented (and checked, if ebpf-netfilter's outcome B is in place)
- [ ] BDD `@fw_zone` green, including the VRF scenario; ends with `Teardown topology`
- [ ] ch-01-05 rewritten; module-doc deviations recorded
