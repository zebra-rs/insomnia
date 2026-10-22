# Policy-based routing — implementation plan

Status: plan, 2026-10-21. Covers: `policy route`, `policy route6`,
`policy local-route`, `policy local-route6`, `show policy route`
([vyos-gap](../vyos-gap.md) §6.6, decision D5).
Priority: P2 · Effort: L (zebra-rs M + insomnia M + local-route S) · Owner: both
Depends on: [nft-common](nft-common.md) (the X10 bit-31 fragment mark, the
mark-matcher mask, the extracted rule matcher),
[multi-path-subscribe](multi-path-subscribe.md),
[fw-packet-modification](fw-packet-modification.md) (`set` statements and
their YANG body), [fw-global-options](fw-global-options.md) (`crate::links`,
the VRF table IDs), [commit-validation](commit-validation.md) (`findings.rs`),
[ebpf-netfilter](ebpf-netfilter.md) (cradle's reserved fwmark, pref and
table); soft: [fw-matchers](fw-matchers.md) (the `ipsec` matcher),
[exec-verbs](exec-verbs.md) (provider `ROUTES`/`Backends`),
[fw-opmode](fw-opmode.md) (the group-use registry PBR publishes into),
[fw-dynamic-sources](fw-dynamic-sources.md) (only for the deferred geoip /
domain-group, §8) ·
Unblocks: [wan-load-balancing](wan-load-balancing.md) (the ip-rule
southbound, numbered tables, table-ID bands),
[vrrp-virtual-server](vrrp-virtual-server.md) (a config-driven fwmark
source, which retires its fwmark warning); also zebra-rs BGP flowspec
redirect (outside this plan set)

## 1. Goal

- Operators classify forwarded and inbound traffic with firewall-style
  rules bound to ingress interfaces. Each rule either steers the traffic
  into a numbered table or a VRF, or rewrites marks, DSCP, TTL or MSS.
  The CLI spelling stays mechanically convertible from VyOS: `policy
  route` becomes `policy-route`.
- **zebra-rs** owns everything in the routing layer:
  - the `fwmark → table` `ip rule`s;
  - numbered static tables (`router static table N`);
  - `policy-local-route(6)`;
  - a published contract for table IDs and rule prefs, which includes
    cradle's reserved resources.

  zebra-rs stays the only netlink route and rule writer.
- **insomnia** owns the nft half: `ip/ip6 zebra_mangle` at prerouting
  -150, using the VyOS mark encoding with the frag bit preserved.
- `show policy-route [NAME [rule N]]` (and `…6`) is answered by
  insomnia. A new `show ip rule` / `show ipv6 rule` is answered by
  zebra-rs.
- PBR is documented, and warned about at runtime, as requiring insomnia
  on the zebra-rs host and in the same netns.

## 2. Current state

**zebra-rs @ `141da2fc`:**
- **Name collision.**
  - Top-level `list policy` is the route-map list, keyed by name
    (`yang/config.yang:5897`). `policy route FOO …` would therefore parse
    as the route-map `route`.
  - `is_policy` routes any show path containing an element named
    `policy` to the route-map module (`src/config/manager.rs:2047-2061`).
    It is listed in `SHOW_PROTOS` at `:2091`.
- **No `ip rule` code.**
  - `src/` has no `RTM_NEWRULE` or fwmark use. The only mention is a
    comment in `src/bgp/transparent.rs:12`.
  - The pinned rtnetlink fork (`Cargo.toml:216`, rev `2d7b183`) already
    has `src/rule/{add,del,get}.rs`, with `fw_mark`, `table_id`,
    `priority` and `input_interface`.
  - netlink-packet-route has `RuleAttribute::{FwMark, FwMask,
    SuppressPrefixLen, Protocol, IpProtocol, SourcePortRange}`
    (`src/rule/attribute.rs:56-70`). No crate work is needed.
- **No numbered tables.** `config-static.yang` routes have no `table`.
  The only `table` leaf is the SRv6 End.DT decap table (`:215-218`).
- **VRF table IDs.**
  - They are allocated smallest-free from 1, skipping 0/253/254/255
    (`src/rib/vrf/alloc.rs:13-48`), by `RibInst.vrf_id_alloc`
    (`src/rib/inst.rs:1299`).
  - They are documented as not user-configurable (`config.yang:5838-5843`).
  - The kernel's l3mdev rule sits at pref 1000.
  - Every `cradle serve` installs `pref 100 fwmark 0x4c37 lookup 2047`
    for its L7 proxy, as recorded in [ebpf-netfilter](ebpf-netfilter.md).
    It owns that fwmark, that pref and that table.
- **Foreign tables.** OSPF `redistribute table N` imports routes from
  foreign kernel tables (`config.yang:991-1000`).
- **Flowspec.** The flowspec design notes that FRR uses `ip rule` plus
  reserved tables for redirect (`docs/design/bgp-flowspec-plan.md:144`).

**insomnia @ `ee4dfaa`:**
- No mangle table.
- **Fragment mark.** The firewall *overwrites* the mark with `0xffff1` at
  -450 and matches that value exactly (`src/firewall.rs:1266`, `:1795`,
  `:1799`) — X10. A PBR `meta mark set` at -150 would erase the frag
  flag, and the flag would erase any PBR mark.
- The `mark` matcher is unmasked (`:1849`).

**VyOS @ `7f2c893`:**
- **Schema.**
  - `policy_route.xml.in` and `include/policy/route-common.xml.i`.
  - Set-level leaves: `interface` (multi, wildcard), `default-log` and
    `description`.
  - Rules take the firewall matcher set plus `action
    accept|reject|return|drop` and `set
    connection-mark|dscp|mark|table|vrf|tcp-mss|ttl|hop-limit`.
  - `set table` accepts `1-200` or `main`
    (`include/firewall/set-packet-modifications-table-and-vrf.xml.i`).
- **Render** (`data/templates/firewall/nftables-policy.j2`):
  - `ip/ip6 vyos_mangle` with `VYOS_PBR[6]_PREROUTING` (filter,
    prerouting, priority -150), holding
    `iifname { … } counter jump VYOS_PBR[6]_UD_<name>`;
  - an empty POSTROUTING -150 chain;
  - one `VYOS_PBR[6]_UD_<name>` chain per set, whose rules are rendered
    by the firewall's `parse_rule` (`python/vyos/firewall.py:107-674`).
  - **Order:** matchers, `log`, `counter`, `set`, then the action, or
    an implicit `return` after `set table|vrf` (`:670-671`), then
    `comment "ipv4-route-<name>-<n>"`.
  - **Encoding** (`:611-629`): `set table T` and `set vrf X` both become
    `meta mark set meta mark & 0x80000000 | (0x7FFFFFFF - T)`; `set mark`
    uses the same mask. `main` and `vrf default` mean table 254
    (`python/vyos/defaults.py:83-97`).
- **ip rules** (`src/conf_mode/policy_route.py:243-289`):
  - one per distinct target table:
    `ip rule add pref T fwmark (0x7FFFFFFF-T)/0x7fffffff table T`;
  - cleanup deletes every rule whose mark equals `0x7FFFFFFF - table`;
  - a `set vrf` table ID is read from the kernel VRF device
    (`get_vrf_tableid`).
- **`local-route(6) rule N`** (`policy_local-route.xml.in`): N is the
  ip-rule pref, 1–32765.
  - Selectors: `fwmark`, `protocol`, `source/destination address
    (multi)/port` and `inbound-interface`. Target: exactly one of
    `set table|vrf`.
  - Rendered as `ip rule add prio N from … to … ipproto … sport …
    dport … fwmark M/0x7fffffff iif … lookup T`
    (`policy_local-route.py:296-334`), with diff-driven deletes.
- **verify** (`policy_route.py:110-198`):
  - icmp type and type-name rules;
  - `tcp-mss` needs the SYN flag;
  - `table` and `vrf` are exclusive, and the VRF must exist;
  - tcp flags need tcp;
  - group and port rules as in NAT.
- **Op mode** (`src/op_mode/policy_route.py:34-100`). It reads
  `nft list chain ip mangle VYOS_PBR_<name>`, a table and chain the
  template never creates, so its counter and condition columns are
  empty. This is from code reading, *unverified* at runtime.

## 3. Design

**D-1. Spelling (assumes D5).**
- New top-level nodes, each `if-feature feat:insomnia`, keep VyOS's
  inner shape: `policy-route <name>`, `policy-route6 <name>`,
  `policy-local-route` and `policy-local-route6`.
- Why:
  - The conversion from VyOS is one character (`policy route` →
    `policy-route`).
  - The names sit alongside `prefix-set` and `as-path-set`.
  - `is_policy` compares names exactly, so `policy-route` never routes
    to the route-map module.
- Rejected:
  - special-casing `policy route` in the parser: it forbids route-maps
    named `route`, `route6` or `local-route`, and needs parser and
    `is_policy` hacks;
  - one `pbr { route …; local-route … }` container: it is equally clean,
    but further from VyOS text.
- `local-route` is not insomnia-shaped. Gate it with `feat:insomnia`
  anyway, so the whole PBR surface appears together. Open: un-gate it
  once it is useful without insomnia.

**D-2. Table-ID and rule-pref contract.** It is published in `alloc.rs`'s
doc and in the book. It includes the resources
[ebpf-netfilter](ebpf-netfilter.md) reserves for cradle.

| Table ID | Owner |
|:--|:--|
| 1–200 | numbered static tables (`router static table N`), the VyOS `set table` range |
| 201–599 | [wan-load-balancing](wan-load-balancing.md) (VyOS uses 201+) |
| 600–999 | reserved for future zebra-rs users (flowspec redirect) |
| ≥ 1000 | VRF tables: `MIN_TABLE_ID` goes from 1 to 1000 |
| 253, 254, 255 | kernel |
| 2047 | cradle's L7-proxy table (`local 0.0.0.0/0 dev lo`); added to `RESERVED_TABLE_IDS`, so no VRF ever gets it |

| Rule pref | Owner |
|:--|:--|
| 100 | cradle (`fwmark 0x4c37 lookup 2047`) |
| 900 | every `policy-route(6)` fwmark rule |
| 910, 920 | [wan-load-balancing](wan-load-balancing.md) |
| 1000 | the kernel l3mdev rule |

- `policy-local-route rule N` with N ∈ {100, 900, 910, 920, 1000} is
  refused by a zebra-rs value check (`check.rs`, the hook at
  `manager.rs:849-878`).
- VRF masters that already exist in the kernel are still adopted with
  their own ID (`reserve`, `alloc.rs:55-61`).
- Rejected alternatives:
  - **User-configured VRF table IDs** (`vrf X table N`, the VyOS way): it
    contradicts the current model and is a larger zebra-rs change.
  - **zebra-rs publishing marks over gRPC:** a new API, with no gain over
    reading the kernel.

**D-3. Mark encoding and rule placement.**
- **insomnia** marks with `nft::frag::set_mark(0x7FFFFFFF − T)`, i.e.
  `meta mark set meta mark & 0x80000000 | (0x7FFFFFFF − T)`. This is
  VyOS's encoding, and it keeps bit 31 per the nft-common mark contract.
- **zebra-rs** installs `pref 900 fwmark (0x7FFFFFFF−T)/0x7fffffff lookup T`
  for every distinct target: tables 1–200, `main` (254) and VRFs.
  - The marks are distinct, so one shared pref is unambiguous.
  - The `/0x7fffffff` mask is required by the nft-common contract.
- This deviates from VyOS's pref = T:
  - pref 100 belongs to cradle;
  - a VRF table ID ≥ 1000 would land after the kernel's l3mdev rule
    (pref 1000), which catches packets on VRF slaves first.
- **Generated marks never collide with cradle's `0x4c37`.** A collision
  would need T = `0x7FFFB3C8`; real table IDs stay far below that (VRFs
  allocate upward from 1000). A
  user `set mark 0x4c37` (19511), from PBR or the firewall, would be
  steered by cradle's pref-100 rule into table 2047, i.e. delivered
  locally.
  - PBR emits an `Error` finding, `Effect::Skipped("rule")`, through
    [nft-common](nft-common.md)'s `frag::check_user_mark`, which also
    refuses 0 and values above `0x7fffffff`.
  - [fw-packet-modification](fw-packet-modification.md) applies the same
    check to firewall `set mark`, through the same function.
- **Both sides compute T without exchanging messages.**
  - zebra-rs knows its own VRF IDs.
  - insomnia reads `Link.vrf_table` from
    [fw-global-options](fw-global-options.md)'s shared kernel link
    watcher, `crate::links`. This is the same kernel attribute VyOS's
    `get_vrf_tableid` reads.
- **A VRF not present yet.** The rule gets a `Warning` finding,
  `Effect::NotApplied`, and is left out. The `LinkEvent` for that VRF
  (`Added`, `Changed`, `Removed`, `Resync`) re-renders. There is no
  polling.

**D-4. zebra-rs derives the fwmark rules in-process from `policy-route`
and `policy-route6`.**
- The set of distinct targets maps to rules. The new rule southbound
  reconciles them against the kernel.
- Every zebra-rs rule carries `FRA_PROTOCOL = RouteProtocol::Zebra`, the
  same tag zebra-rs gives the routes it installs
  (`src/fib/netlink/handle.rs:330`, `:365`).
- On startup, zebra-rs deletes rules with that tag that its config does
  not want. Foreign rules are never touched; that covers cradle's pref
  100 rule, which is not tagged `zebra` (*unverified*: cradle's rule
  protocol). VyOS's cleanup matches on mark arithmetic instead.
- When a VRF is re-created with a new ID, zebra-rs re-issues the rule,
  and insomnia re-renders on the `LinkEvent` (D-3).

**D-5. The insomnia `pbr` backend.**
- `src/pbr.rs` makes one multi-path subscription:
  `subscribe_json_multi(&host, &[&["policy-route"], &["policy-route6"], &["firewall","group"]], Fallback::Refuse)`
  (assumes D3). It decodes each part with `json::parse_subtree`.
- The run loop `select!`s on that stream, on `links.subscribe()`
  (filtered to `kind == "vrf"`), and on show requests.
- It renders `ip zebra_mangle` and `ip6 zebra_mangle` in one transaction,
  using `nft::apply::apply_if_changed`:
  - chains `ZEBRA_PBR[6]_PREROUTING` (filter, prerouting, -150) and
    `ZEBRA_PBR[6]_UD_<name>`;
  - the group sets, from `nft::group::render_sets`;
  - a table where a rule uses `fragment` emits its own `nft::frag::chains`
    (idempotent, per nft-common);
  - VyOS's empty POSTROUTING chain is dropped (a deviation).
- Rules use `nft::rule::render_matchers(&rule, &RuleCtx { hook: "route" | "route6", label: name, … })`
  (nft-common), then:
  1. `log`;
  2. `counter`;
  3. fw-packet-modification's `render_set(&SetActions, fam)`;
  4. the PBR-only `set table|vrf` mark, through `frag::set_mark`;
  5. the action, or VyOS's implicit `return` after `table|vrf`;
  6. `comment "ipv4-route-<name>-<n>"`.
- Agreed with [fw-packet-modification](fw-packet-modification.md) (its
  model sketch carries it):
  - `SetActions` carries `table` and `vrf` as two extra
    `Option<Flex>` fields. `render_set` ignores them, and the firewall
    YANG never sets them.
  - PBR reads them, so the `set` object deserializes once into
    `nft::Rule`.
  - PBR's YANG uses `set-packet-modifications-body` (v4) and `-body6`
    (v6) inside its own `container set`, adding `table` and `vrf`.
- **Verify rules are [commit-validation](commit-validation.md)
  `Findings`.**
  - The `findings.rs` severity and effect apply.
  - `pbr::validate` serves the unit
    `pbr → [policy-route], [policy-route6], [firewall group]`.
  - Dangling group references follow fw-load-safety's reference pass,
    through `GroupIndex::reference`.

**D-6. Locality.**
- insomnia applies nft on its own host; zebra-rs installs rules on its
  own. Unless both run on the same host and in the same netns, PBR
  silently does nothing.
- When `--host` is `tcp:` and PBR is configured, insomnia emits a
  `Warning` finding on every apply:
  `pbr: --host is not a unix: socket; policy-route needs insomnia on the zebra-rs host`.
- Abstract `unix:` sockets are per-netns, so a `unix:` connection
  guarantees co-location.
- The same constraint applies to
  [wan-load-balancing](wan-load-balancing.md).

**Deviations for the module doc:**
- spelling (D-1);
- the single pref 900, plus the cradle and l3mdev avoidance (D-2, D-3);
- rule ownership by protocol tag (D-4);
- no POSTROUTING chain (D-5);
- `show policy-route` reads live counters by comment, which works where
  VyOS's op-mode cannot;
- interface names are quoted.

**Constraints:**
- Traffic that enters an `ebpf enabled` port bypasses netfilter, so PBR
  marks never apply to it. [ebpf-netfilter](ebpf-netfilter.md) decides
  the outcome (documentation, refusal or punt), and the PBR chapter
  links to it. Under its default outcome B, zebra-rs refuses
  `policy-route` and `policy-route6` together with eBPF ports; this plan
  adds that row to its `EBPF_BYPASSED_TREES` with Z4.
  `policy-local-route*` stays allowed.
- Prerouting only (VyOS parity), so router-originated traffic is not
  policy-routed. Use `policy-local-route` for that.

## 4. Changes

### zebra-rs

**`firewall.yang`.** A structural refactor, with no data-tree change:
- move `connection-mark`, `connection-status`, `mark`,
  `packet-length(-exclude)`, `packet-type` and `state` out of
  `rule-common` (`:395-478`) into a new `grouping rule-ct-match`;
- `rule-common` then `uses rule-base; uses rule-ct-match;` plus the
  action leaves.

**New `yang/pbr.yang`** (prefix `pbr`, imports `fw`). Sketch:

```yang
grouping pbr-rule { uses fw:rule-key; uses fw:rule-base; uses fw:rule-ct-match;
  leaf action { type enumeration { enum accept; enum drop; enum reject; enum return; } }
  container set { uses fw:set-packet-modifications-body;           // from fw-packet-modification
    leaf table { type union { type uint8 { range "1..200"; } type enumeration { enum main; } } }
    leaf vrf { type string; } } }                                   // name | default
grouping policy-route { list policy-route { key "name"; leaf name { type string; }
  leaf description { type string { pattern '.*'; } }  leaf default-log { type empty; }
  leaf-list interface { type string; }                              // wildcard eth*
  list rule { key "number"; uses pbr-rule; uses fw:rule-match-v4; } } }
// policy-route6: the same with fw:rule-match-v6 and fw:set-packet-modifications-body6
grouping policy-local-route { container policy-local-route { list rule { key "pref";
  leaf pref { type uint16 { range "1..32765"; } }
  leaf fwmark { type uint32 { range "1..2147483647"; } }
  leaf protocol { type string; }  leaf inbound-interface { type string; }
  container source { leaf-list address { type inet:ipv4-prefix; } leaf port { type string; } }
  container destination { leaf-list address { type inet:ipv4-prefix; } leaf port { type string; } }
  container set { leaf table { type union { type uint8 { range "1..200"; }
                                            type enumeration { enum main; } } }
                  leaf vrf { type string; } } } } }
```

- The VyOS key leaf is `rule N`; the sketch names it `pref`. Keep VyOS's
  `rule <N>` spelling and treat N as the pref.
- `config.yang`: `uses pbr:policy-route;`, `…6`, `policy-local-route(6)`,
  all `if-feature feat:insomnia`.
- `config-static.yang` / `config.yang` `router static`: add
  `list table { key "id"; leaf id { type uint8 { range "1..200"; } } uses
  static:static-routes; }` beside `list vrf` (`config.yang:5362-5391`).
  The RIB models a numbered table as a table-only instance (no VRF
  device) keyed by table ID; the FIB installs with `RTA_TABLE = id`.

**Rule southbound (new `src/fib/netlink/rule.rs`, proposed):**

```rust
pub struct RuleSpec { pub v6: bool, pub pref: u32, pub fwmark: Option<(u32, u32)>, pub table: u32,
    pub iif: Option<String>, pub src: Option<IpNet>, pub dst: Option<IpNet>,
    pub ipproto: Option<u8>, pub sport: Option<(u16,u16)>, pub dport: Option<(u16,u16)>,
    pub suppress_prefixlen: Option<u32> }
pub async fn rule_add(h: &Handle, r: &RuleSpec) -> anyhow::Result<()>;    // FRA_PROTOCOL=Zebra
pub async fn rule_del(h: &Handle, r: &RuleSpec) -> anyhow::Result<()>;
pub async fn rule_dump_owned(h: &Handle) -> anyhow::Result<Vec<RuleSpec>>;
pub struct RuleTable { want: BTreeSet<RuleSpec> }    // reconcile(want) -> adds/dels
```

- Callers:
  - a policy-route subscriber (D-4);
  - `policy-local-route(6)` (one rule per source × destination address
    pair, as VyOS expands it);
  - later, WLB.
- `alloc.rs`:
  - `MIN_TABLE_ID = 1000`;
  - `RESERVED_TABLE_IDS` gains `2047` (cradle);
  - a doc table of the D-2 bands and prefs.
- `check.rs` (value check): refuse a `policy-local-route rule N` whose N
  is a reserved pref (D-2).
- `exec.yang`:
  - `show policy-route [name [rule N]]` and `show policy-route6 …`;
  - `show ip rule` and `show ipv6 rule`, under the existing `container
    ip` (`:776`) and `ipv6`.
- `manager.rs`:
  - `(is_pbr, "pbr", "Policy routing")`, where `is_pbr` matches
    `"policy-route" | "policy-route6"`, before `is_policy`;
  - `show ip rule` is answered by the RIB/FIB task.

### insomnia

- New `src/pbr.rs`:
  - `PolicyRoute { name, description, default_log, interface: Vec<Flex>, rule: Vec<fw::Rule> }`,
    where `fw::Rule` is extended with `set` by fw-packet-modification;
  - `render(&PbrInputs, &BTreeMap<String, Link>, &nft::Exclusions) -> (String, Findings)`,
    with VRF tables taken from the `crate::links` snapshot;
  - `validate(parts) -> Findings`;
  - show handlers that answer `Answer`.
- `main.rs`: pass the shared `Links` handle (fw-global-options) into
  `pbr::run`.
- `provider.rs`:
  - `"pbr"` in `Register.name`;
  - a `pbr` field in [exec-verbs](exec-verbs.md)' `Backends`;
  - `ROUTES` rows `(Show, "/show/policy-route6", Backend::Pbr)` and
    `(Show, "/show/policy-route", Backend::Pbr)`.
- [fw-opmode](fw-opmode.md)'s `GroupUseRegistry` (O5) is passed to
  `pbr::run`, once that plan's milestone 5 has landed. After each apply
  PBR replaces its `"pbr"` entry with one
  `GroupUse` per (rule, group) reference, with paths such as
  `route-ISP2-10` and `route6-ISP2-10`, so `show firewall group` counts
  PBR references.

**Worked example.**

Config:
```
set firewall group network-group GUEST network 192.168.50.0/24
set router static table 100 ipv4 route 0.0.0.0/0 nexthop 198.51.100.9
set vrf RED                                   # zebra-rs allocated table 1001 (band ≥ 1000)
set policy-route ISP2 interface lan0
set policy-route ISP2 interface lan1
set policy-route ISP2 default-log
set policy-route ISP2 rule 10 source group network-group GUEST
set policy-route ISP2 rule 10 set table 100
set policy-route ISP2 rule 20 protocol tcp
set policy-route ISP2 rule 20 destination port 25
set policy-route ISP2 rule 20 action drop
set policy-route ISP2 rule 30 source address 192.168.60.0/24
set policy-route ISP2 rule 30 set vrf RED
```

insomnia renders the script below. It passed `nft -c` (1.0.9).
`0x7fffff9b = 0x7FFFFFFF − 100`; `0x7ffffc16 = 0x7FFFFFFF − 1001`.

```
add table ip zebra_mangle
delete table ip zebra_mangle
add table ip6 zebra_mangle
delete table ip6 zebra_mangle
table ip zebra_mangle {
    set N_GUEST {
        type ipv4_addr
        flags interval
        auto-merge
        elements = { 192.168.50.0/24 }
    }
    chain ZEBRA_PBR_PREROUTING {
        type filter hook prerouting priority -150; policy accept;
        iifname { "lan0", "lan1" } counter jump ZEBRA_PBR_UD_ISP2
    }
    chain ZEBRA_PBR_UD_ISP2 {
        ip saddr @N_GUEST counter meta mark set meta mark & 0x80000000 | 0x7fffff9b return comment "ipv4-route-ISP2-10"
        meta l4proto tcp tcp dport {25} counter drop comment "ipv4-route-ISP2-20"
        ip saddr 192.168.60.0/24 counter meta mark set meta mark & 0x80000000 | 0x7ffffc16 return comment "ipv4-route-ISP2-30"
        counter log prefix "[ipv4-ISP2-default]"
    }
}
table ip6 zebra_mangle {
    chain ZEBRA_PBR6_PREROUTING {
        type filter hook prerouting priority -150; policy accept;
    }
}
```

zebra-rs installs:

```
100:  from all fwmark 0x4c37 lookup 2047                (cradle, when it runs)
900:  from all fwmark 0x7fffff9b/0x7fffffff lookup 100 proto zebra
900:  from all fwmark 0x7ffffc16/0x7fffffff lookup 1001 proto zebra
1000: from all lookup [l3mdev-table]                    (kernel)
```

plus `default via 198.51.100.9 table 100 proto zebra`.

`show policy-route ISP2` keeps VyOS's layout (`policy_route.py:59-100`),
with the counters joined by comment:

```
---------------------------------
IPv4 Policy Route "ISP2"

Active on: lan0 lan1

Rule    Action    Protocol    Packets    Bytes    Conditions
------  --------  ----------  ---------  -------  -----------------------------
10      set       all         120        10080    ip saddr @N_GUEST
20      drop      tcp         3          180      meta l4proto tcp tcp dport {25}
30      set       all         0          0        ip saddr 192.168.60.0/24
```

## 5. Tests

**insomnia, `pbr::tests` (`render_str`, with VRF tables injected):**
- `empty_renders_teardown`;
- `golden_render` (the worked example);
- `set_table_main_is_254`;
- `set_vrf_default_is_254`;
- `set_vrf_unresolved_not_applied_then_link_event_rerenders`;
- `set_mark_masks_bit31` (with fw-packet-modification);
- `implicit_return_only_after_table_or_vrf`;
- `interface_wildcard_quoted`;
- `ipv6_route6_comments`;
- `findings` (each one asserts severity and effect): `table` together
  with `vrf`; `tcp-mss` without SYN; an undefined group; a port without
  tcp/udp; an unsafe set name; `set mark 0x4c37`;
- `tcp_host_warns_locality`;
- `show_policy_route_text` and `show_json`.

**zebra-rs:**
- `alloc.rs`:
  - the first VRF ID is 1000;
  - 2047 is never allocated;
  - `reserve` keeps adopting kernel IDs.
- `rule.rs`: reconcile produces minimal add/del sets, and ignores
  foreign rules.
- Policy-route → rule derivation: distinct targets; `main`;
  every target at pref 900; deleting a target removes its rule;
  `policy-local-route rule 100` is refused.
- `local-route` expansion and validation (at least one selector; exactly
  one of table/vrf).
- Manager routing: `show policy-route` → `"pbr"`, `show policy` still
  goes to `"policy"`, and a route-map named `route` still works.
- Static table N installs into kernel table N; `show ip route table N`
  (if added).

**BDD `pbr_dual_wan`:**
- Topology:
  - `lan` hosts `.10` and `.200` (two addresses on one netns);
  - `r1` (zebra-rs + insomnia under `insomnia_node.sh` from [nat](nat.md));
  - `isp1` and `isp2`, each with a route back to 10.0.0.0/24.
- `198.51.100.1/32` lives on a dummy in `isp2` only. `r1`'s main default
  is via `isp1`, which has no route to it; table 100's default is via
  `isp2`.
- Scenarios:
  1. **Setup.** Apply the config.
  2. **PBR steers the matched source.** A ping from `10.0.0.10`
     (matched) to 198.51.100.1 succeeds. A ping from `10.0.0.200`
     (unmatched) fails.
  3. **Counters and rules are visible.** `show policy-route ISP2`
     counter > 0, and `show ip rule` contains
     `fwmark 0x7fffff9b/0x7fffffff lookup 100`.
  4. **Fragments follow the policy too.** A large ping (`-s 3000`) from
     `.10` succeeds with a firewall rule using `fragment match-frag`
     present. This proves bit 31 and the PBR mark coexist.
  5. **VRF target.** `set vrf` steers into a VRF whose table holds the
     route.
  6. **Delete.** `delete policy-route` removes the rule
     (`ip rule` lacks it), and insomnia's table is gone.
  7. **Teardown topology.**

## 6. Docs

- **New book part "Policy Routing"** (`book/src/ch-06-00-policy-routing.md`,
  `ch-06-01-local-route.md`). Cover:
  - the spelling map from VyOS;
  - the table bands (D-2);
  - the mark encoding (D-3);
  - the locality rule (D-6);
  - forwarded/inbound-only (use `policy-local-route` for local
    traffic);
  - the eBPF constraint.
- **`ch-03-06-show-policy-route.md`.**
- **SUMMARY.md, ch-00-00 and AGENTS.md:** the fifth backend, and the
  `/show/policy-route` route.
- **zebra-rs docs:** `router static table`, `show ip rule`, and the VRF
  table-ID band in the VRF chapter.
- **`src/pbr.rs` module doc:** the deviations in §3.
- **`design/vyos-gap.md` §6.6:** status, plus a note that D5 is decided.

## 7. Milestones

| # | Scope | Repo | Effort | Done when |
|:--|:--|:--|:--|:--|
| Z1 | Rule southbound `rule.rs` + `RuleTable` reconcile, `FRA_PROTOCOL` ownership, startup cleanup; `show ip rule` | zebra-rs | M | unit tests; a netns test adds and removes rules and leaves foreign rules intact |
| Z2 | Table-ID bands and prefs: `MIN_TABLE_ID = 1000`, 2047 reserved, reserved-pref check, doc table | zebra-rs | S | VRF BDD suite still passes; first VRF gets 1000; pref 100 refused |
| Z3 | `router static table N` (1–200): RIB table-only instance + FIB `RTA_TABLE` | zebra-rs | M | `ip route show table 100` holds the route; `show ip route table 100` |
| Z4 | Schema: `firewall.yang` `rule-ct-match` split; `pbr.yang` (`policy-route(6)`, `policy-local-route(6)`); exec grammar; `is_pbr` | zebra-rs | S | parses only with the feature; routing tests green; route-map `route` still parses |
| Z5 | fwmark rules derived from `policy-route(6)` `set table\|vrf` (D-3/D-4) | zebra-rs | S | rules follow commits and VRF re-creation |
| I1 | `src/pbr.rs`: render, multi-path, VRF resolution via `crate::links`, `Findings`, `apply_if_changed`, goldens. Needs nft-common (bit 31, `render_matchers`) and fw-global-options' `links` | insomnia | M | goldens green; the worked example loads |
| I2 | `set` statements via [fw-packet-modification](fw-packet-modification.md); `show policy-route(6)` | insomnia | S | show tests green |
| I3 | BDD `pbr_dual_wan` scenarios 1–4, 6, 7 | both | S | passes twice in a row |
| Z6 | `policy-local-route(6)` on the southbound | zebra-rs | S | unit tests; BDD scenario: a locally originated ping with `fwmark` steered |
| I4 | VRF target scenario 5; docs (§6) | both | S | BDD green; `mdbook build` clean |

- Ordering: Z1 → Z2 → Z3 gate usefulness, so build them first.
- Z4 and I1 can run in parallel with them, against fixtures.
- Z5 needs Z1 and Z4. I3 needs Z3, Z5, I1 and I2.

## 8. Risks and open questions

- **`MIN_TABLE_ID` change.**
  - Existing deployments get new VRF IDs on the next restart. IDs are
    internal and adopted from the kernel when the device survives, so
    only VRFs created after the upgrade move.
  - Check `rib/client.rs:215` consumers (FPM, cradle) for an assumption
    that IDs are small.
- **`redistribute table N` overlap.** OSPF importing kernel table N could
  now see zebra-rs's own numbered-table routes. Decide whether
  `router static table N` routes are excluded from that import, or
  documented as visible.
- **VRF-ID read in insomnia.** It comes from the shared kernel link
  watcher, so it is only as fresh as `RTM_NEWLINK`. A VRF re-created with
  a new ID leaves a short window between zebra-rs re-issuing the rule
  and insomnia's re-render. During it, new flows to that VRF follow
  main. This is acceptable; document it.
- **Equal priority with WAN-LB.** [wan-load-balancing](wan-load-balancing.md)
  takes -149, so PBR at -150 runs first and wins. Both claim the low 31
  mark bits; their table bands are disjoint by D-2.
- **`policy-local-route` gating.** It is useful without insomnia. Open:
  un-gate it in a later release.
- **Dynamic sources** (vyos-gap §6.6 "geoip / domain-group in PBR", P3)
  are deferred. [fw-dynamic-sources](fw-dynamic-sources.md) adds `fqdn`,
  `geoip`, `domain-group` and `remote-group` to the shared `l3-match`
  groupings, so `policy-route` rules inherit the leaves. Until PBR sends
  its own `Demand` (consumer `"pbr"`) and appends the `fill` for
  `ip/ip6 zebra_mangle` (fw-dynamic-sources §3.3, after its M3 and M7),
  such a rule is skipped with a `Warning` finding naming the leaf.
- **Kernel rule protocol support.** `FRA_PROTOCOL` needs Linux ≥ 4.17.
  On older kernels the fallback is matching on (pref, mark, table),
  *unverified* whether needed for supported targets.

## 9. Acceptance criteria

- [ ] `policy-route(6)` and `policy-local-route(6)` exist only with
      `--feature insomnia`. A route-map named `route` still works, and
      `show policy` is unchanged.
- [ ] zebra-rs installs exactly the fwmark rules implied by the config,
      tagged `proto zebra` at pref 900. It never deletes foreign rules,
      including cradle's pref 100. It never allocates table 2047.
- [ ] `router static table N` routes land in kernel table N.
- [ ] VRF tables are allocated from 1000, and the bands are documented.
- [ ] The insomnia render matches the worked example and preserves bit
      31. A fragment-matching firewall rule and PBR coexist (BDD
      scenario 4).
- [ ] `show policy-route` shows live counters, and `show ip rule` lists
      the zebra-owned rules.
- [ ] insomnia warns when PBR is configured over a `tcp:` host.
- [ ] `pbr_dual_wan` passes and ends with a clean teardown.
