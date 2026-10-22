# Shared nftables module (`crate::nft`) — implementation plan

Status: plan, 2026-10-21. Covers: the shared nft helper extraction
([vyos-gap](../vyos-gap.md) §6.2 "Shared code", §10 Phase 1), X10 (§3), and the `mark`
matcher mask that goes with X10 (§6.1, §6.6; FW7's "`mark` uses the bit-31 mask").
Priority: P2 (X10 blocks PBR / WAN-LB marking) · Effort: S · Owner: insomnia
Depends on: [fw-load-safety](fw-load-safety.md) (lands first; its loop and group index
move here) · Unblocks: [nat](nat.md), [pbr](pbr.md), [conntrack](conntrack.md),
[fw-zones](fw-zones.md), [fw-matchers](fw-matchers.md),
[fw-packet-modification](fw-packet-modification.md), [fw-bridge](fw-bridge.md),
[wan-load-balancing](wan-load-balancing.md), [fw-global-options](fw-global-options.md),
[fw-flowtable](fw-flowtable.md), [fw-opmode](fw-opmode.md),
[fw-dynamic-sources](fw-dynamic-sources.md), [nat-cgnat-nat64](nat-cgnat-nat64.md),
[ipsec-dmvpn-l2tp](ipsec-dmvpn-l2tp.md)

This plan **owns the `crate::nft` API**. Consumers use it and must not re-implement set
rendering, token checks, frag-mark chains, counters or the apply loop. Assumes D3: how a
consumer receives `firewall group` (multi-path subscribe) is outside this module, which
takes a `&Groups`.

## 1. Goal

- `src/nft.rs` + `src/nft/*.rs` hold everything a second nft backend needs:
  - family helpers and token checks;
  - a script builder that records line origins;
  - running nft and parsing its diagnostics, and the exclude-and-retry apply loop;
  - comment-keyed counters;
  - the group model, its set rendering and its index;
  - the endpoint, interface, protocol and mark matchers;
  - numbered-rule ordering;
  - the VyOS `parse_rule` core shared by the firewall and PBR;
  - the bit-31 fragment scheme.
- `src/firewall.rs` keeps only what is firewall-specific: the model above `Rule`, the hooks
  and chain layout, state-policy, the chain graph, and show.
- Milestone 1 is a pure move: every existing golden stays byte-identical.
- X10: fragments are flagged by OR-ing bit 31 at prerouting -450 and unflagged at
  forward/input `filter + 10`. Any mark set by tc, policy routing or a future
  `zebra_mangle` survives.
- `rule … mark N` matches with `meta mark & 0x7fffffff`, so the fragment bit never hides a
  user mark.

## 2. Current state

**insomnia** (`src/firewall.rs` @ `ee4dfaa`). The candidates for extraction, all private
today:

| Piece | Lines |
|:--|:--|
| `TABLE`, `enum Fam` (`ip`/`label`/`suffix`) | 1082-1109 |
| `safe_token`, `safe_name` | 1111-1127 |
| `Render` (`out`, `warnings`, `line`, `warn`) + table-specific `recent_sets`, `need_frag_mark` | 1129-1160 |
| add+delete table preamble | 1176-1182 |
| `nft_apply` (`nft -f -`) | 107-134 |
| `Counters`, `nft_counters`, `parse_counters` | 145-193 |
| group model `Groups`, `Group` | 780-811 |
| rule model `Rule`, `Endpoint`, `GroupRef`, `IfMatch`, `Icmp`, `Cmp`, `Tcp`, `TcpFlags`, `TcpFlagsNot`, `Fragment`, `Limit`, `LogOptions`, `ConnStatus`, `Recent`, `TimeMatch` | 865-1050 |
| `render_group_sets` + `collect_members` | 1318-1482 |
| rule sort, three copies | 312-318, 676-682, 1485-1491 |
| `render_rule` (VyOS `parse_rule` order), `render_tcp_flags`, `render_time` | 1556-2013 |
| frag chain emission / frag matcher / mark matcher | 1256-1268 / 1793-1802 / 1842-1850 |

[fw-load-safety](fw-load-safety.md) adds `RefIndex`, line `Origin`s, `parse_diags`,
`apply_loop`, `NftRunner` and the X12 `Applied` check to the same file. This plan moves
them as they are, and makes the X12 check generic (`apply_if_changed`).

**X10 today:**
- `ZEBRA_FRAG_MARK` at prerouting -450 runs
  `ip frag-off & 0x3fff != 0 meta mark set 0xffff1 return`. The v6 form is
  `exthdr frag exists …` (`firewall.rs:1256-1268`). This overwrites the whole mark.
- The matcher is `meta mark 0xffff1` / `meta mark != 0xffff1` (`1793-1802`).
- `mark` matches the full 32 bits: `meta mark [!= ]{N}` (`1842-1850`).
- The chain is emitted only when a rule in that family uses `fragment`. That is a
  documented deviation (`firewall.rs:18-19`) and stays.

**VyOS** (`7f2c893`):
- `python/vyos/defaults.py:96-97`: `fragment_mark_bit = 0x80000000`,
  `user_mark_mask = 0x7fffffff`.
- `data/templates/firewall/nftables.j2:122-138` (ip) and `:321-335` (ip6):
  `VYOS_FRAG[6]_MARK` ORs the bit at -450. `VYOS_FRAG[6]_UNMARK_FWD|INP` at
  `filter + 10` clears it. These are always emitted.
- `python/vyos/firewall.py:465-471`: the fragment matcher is
  `meta mark & 0x80000000 ==|!= 0x80000000`.
- `:535-541`: the mark matcher is `meta mark & 0x7fffffff [!=] {N}`.
- `:613`, `:629`: `set mark` / `set table` write `meta mark set meta mark & 0x80000000 | N`.
- PBR installs `ip rule … fwmark M/0x7fffffff` (`src/conf_mode/policy_route.py:243-289`).
  `parse_rule` is shared by the firewall and `policy route`, and every nft template
  re-renders groups through one macro (`nftables-defines.j2`).

Verified with `nft -c` (nftables 1.0.9, Linux 6.8):
- the six chains and both matchers below;
- `meta mark & 0x7fffffff {5}`, `… != {5-10}`, `… {0x10,0x20}`;
- `meta mark set meta mark & 0x80000000 | 100` at priority -150.

## 3. Design

### 3.1 Module layout and API (proposed; this plan is its owner)

```rust
// src/nft.rs — module root; doc lists the VyOS sources and deviations (§3.4)
pub mod apply; pub mod counters; pub mod fam; pub mod frag;
pub mod group; pub mod matcher; pub mod rule; pub mod script; pub mod token;
// Root re-exports: consumers write `nft::Groups`, `nft::IfMatch` (as nat.md does).
pub use fam::Fam; pub use script::{Script, Origin, Rendered};
pub use group::{Group, Groups, GroupIndex, GroupKind};
pub use matcher::{Dir, Endpoint, GroupRef, IfMatch};
pub use rule::{Rule, RuleCtx, RenderedRule};
pub use apply::{Applied, ApplyReport, Exclusions, NftCli, NftRunner};

// fam.rs
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Fam { V4, V6 }                  // fw-bridge adds Bridge: ip() "bridge", label() "bri"
impl Fam {
    pub const BOTH: [Fam; 2] = [Fam::V4, Fam::V6];   // stays ip/ip6; Bridge is opt-in
    pub fn ip(self) -> &'static str;      // "ip" | "ip6"
    pub fn label(self) -> &'static str;   // "ipv4" | "ipv6"
    pub fn suffix(self) -> &'static str;  // "" | "6"
}

// token.rs — the only gate between config strings and nft text
pub fn safe_token(s: &str) -> bool;                          // firewall.rs:1115
pub fn safe_name(s: &str) -> bool;                           // firewall.rs:1122
pub fn tok(v: &Flex, what: &str) -> Result<String, String>;  // the closure at 1572-1579
pub fn strip_neg(s: &str) -> (bool, &str);                   // one leading '!'

// script.rs
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Origin { Fixed, Set { fam: Fam, name: String }, Rule(String), Default(String),
                  Flowtable { fam: Fam, name: String } }               // fw-flowtable F4
pub struct Script { /* out, warnings, origins (one per output line) */ }
impl Script {
    pub fn new() -> Self;
    pub fn line(&mut self, indent: usize, s: &str);                 // Origin::Fixed
    pub fn line_from(&mut self, indent: usize, s: &str, o: Origin);
    pub fn warn(&mut self, msg: String);
    pub fn reset_tables(&mut self, families: &[&str], table: &str); // "add table F T\ndelete table F T"
    pub fn origin(&self, line: usize) -> Option<&Origin>;            // 1-based, as nft reports
    pub fn finish(self) -> Rendered;
}
pub struct Rendered { pub script: String, pub warnings: Vec<String>, pub origins: Vec<Origin>,
                      /// fw-dynamic-sources §3.3: `add element` lines appended after `script`
                      /// in the same transaction, never compared by X12. Empty for other consumers.
                      pub fill: String, pub fill_origins: Vec<Origin> /* Origin::Set only */ }

// apply.rs
pub struct Diag { pub line: Option<usize>, pub cols: Option<(usize, usize)>, pub msg: String }
pub enum NftError { Spawn(std::io::Error), Rejected { stderr: String, diags: Vec<Diag> } }
pub fn parse_diags(stderr: &str) -> Vec<Diag>;
pub trait NftRunner {
    async fn run(&self, script: &str) -> Result<(), NftError>;       // nft -f -
    async fn check(&self, script: &str) -> Result<(), NftError>;     // nft -c -f -
    async fn list_terse(&self, family: &str, table: &str) -> String; // nft -s -t list table; "<absent>"
}
pub struct NftCli;                                                   // the real runner
#[derive(Default, Clone)]
pub struct Exclusions { pub rules: HashSet<String>, pub sets: HashSet<(Fam, String)>, pub defaults: HashSet<String>,
                        // fw-flowtable F4: first rejection downgrades to software, the second excludes
                        pub flowtables_soft: HashSet<(Fam, String)>, pub flowtables: HashSet<(Fam, String)> }
pub struct ApplyReport { pub applied: Option<String>, pub excluded: Exclusions,
                         pub warnings: Vec<String>, pub error: Option<String>, pub attempts: usize }
/// Sends `script ‖ fill` as one `nft -f -`. A diagnostic on a fill line maps through
/// `fill_origins` (line − script lines) to an `Origin::Set` exclusion.
pub async fn apply_loop<R: NftRunner>(
    runner: &R, max_attempts: usize, render: impl FnMut(&Exclusions) -> Rendered,
) -> ApplyReport;
/// X12, generic: skip when the first-attempt render and the terse listing of `tables`
/// both match the last apply ([fw-load-safety](fw-load-safety.md) §3.5). NAT, PBR and
/// conntrack get compare-before-apply from this, not from their own copies. `tables` may
/// name any family (`inet` for conntrack's `zebra_vrf_zones`, `bridge` for fw-bridge).
/// `Applied.rendered` is `Rendered.script` only: `fill` never counts as a change.
pub struct Applied { pub rendered: String, pub live: String }
pub async fn apply_if_changed<R: NftRunner>(
    runner: &R, last: Option<&Applied>, tables: &[(&str, &str)], max_attempts: usize,
    render: impl FnMut(&Exclusions) -> Rendered,
) -> (Option<Applied>, Option<ApplyReport> /* None = unchanged, not applied */);

// counters.rs
pub type Counters = HashMap<String, (u64, u64)>;
pub async fn fetch(family: &str, table: &str) -> Counters;  // firewall.rs:147-163, table now a parameter
pub fn parse(v: &serde_json::Value) -> Counters;             // 168-193
pub fn strip_tail(line: &str) -> String;                      // Conditions column (rule_conditions 369-387)
// fw-packet-modification PM10 adds `parse_live(&Value) -> Live { counters, sets }` here;
// `parse` then becomes `parse_live(v).counters`. It is not a second module.

// group.rs — mirrors firewall.yang `container group`, which nat/pbr/conntrack YANG reuse
pub struct Groups { … }  pub struct Group { … }               // moved verbatim (780-811)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GroupKind { Address, Network, Port, Mac, Interface,
                     Dynamic,   // fw-packet-modification PM5: DA_/DA6_, per family, `flags dynamic, timeout`, not interval
                     Domain,    // fw-dynamic-sources: D_ in ip and ip6, interval, rendered empty (filled out of band)
                     Remote }   // fw-dynamic-sources: R_/R6_, per family, interval, rendered empty
impl GroupKind {
    pub fn config_name(self, fam: Fam) -> &'static str;      // "address-group" | "ipv6-address-group" …
    pub fn set_prefix(self, fam: Fam) -> &'static str;       // A_ A6_ N_ N6_ P_ M_ I_ DA_ DA6_ D_ R_ R6_
    pub fn set_type(self, fam: Fam) -> &'static str;         // ipv4_addr ipv6_addr inet_service ether_addr ifname
    pub fn interval(self) -> bool;                           // all but Mac and Dynamic → also `auto-merge`
    pub fn per_family(self) -> bool;                         // Address, Network, Dynamic, Remote
}
pub fn set_name(kind: GroupKind, fam: Fam, name: &str) -> String;
pub fn flatten(groups: &Groups, kind: GroupKind, fam: Fam, g: &Group, s: &mut Script) -> Vec<String>;
/// `Fam::Bridge` (fw-bridge): A_/A6_/N_/N6_ for both families, P_/M_/I_ once, and never
/// the Dynamic/Domain/Remote kinds (VyOS `is_l3=False`).
pub fn render_sets(s: &mut Script, groups: &Groups, fam: Fam, ex: &Exclusions) -> GroupIndex;
pub struct GroupIndex { /* nft set names defined in this table */ }
impl GroupIndex {
    pub fn has(&self, kind: GroupKind, fam: Fam, name: &str) -> bool;
    /// `!NAME` aware; Err("address-group \"X\" is not defined") when absent.
    pub fn reference(&self, kind: GroupKind, fam: Fam, raw: &str) -> Result<(bool, String), String>;
}

// matcher.rs — one function per VyOS matcher family, each returning nft expression strings
pub enum Dir { Src, Dst }                                    // 's' | 'd'
pub struct Endpoint { … } pub struct GroupRef { … } pub struct IfMatch { … }   // 911-935
pub fn protocol(p: Option<&Flex>) -> Result<(Option<String>, String), String>;  // (expr, proto_for_port) 1596-1614
pub fn endpoint(e: &Endpoint, d: Dir, fam: Fam, proto_for_port: &str, idx: &GroupIndex)
    -> Result<Vec<String>, String>;                                             // 1617-1700
    // later arms, in parse_rule order: dynamic-address-group (fw-packet-modification),
    // fqdn and geoip (fw-dynamic-sources), per-matcher ip/ip6 choice for Fam::Bridge (fw-bridge)
pub fn interface(m: &IfMatch, kw: &str /* iifname|oifname */, idx: &GroupIndex)
    -> Result<Option<String>, String>;                                          // 1716-1741
pub fn mark(v: &Flex) -> Result<String, String>;                                // X10 mask, §3.3

// frag.rs — the bit-31 scheme (X10)
pub const FRAG_MARK_BIT: &str = "0x80000000";
pub const USER_MARK_MASK: &str = "0x7fffffff";
pub fn matcher(frag: bool) -> &'static str;   // "meta mark & 0x80000000 == 0x80000000" | "… != …"
pub fn chains(s: &mut Script, fam: Fam);      // MARK at -450, UNMARK_FWD/INP at filter + 10
pub fn set_mark(value: &str) -> String;       // "meta mark set meta mark & 0x80000000 | V" (FW7, PBR)
pub const CRADLE_FWMARK: u32 = 0x4c37;        // reserved by cradle (ebpf-netfilter); §3.3
pub fn check_user_mark(v: u32) -> Result<(), String>; // Err for 0 or > 0x7fffffff, and for CRADLE_FWMARK

// rule.rs — VyOS `parse_rule` (python/vyos/firewall.py:107-674), shared by firewall and PBR
pub struct Rule { … }  /* + Icmp, Cmp, Tcp, TcpFlags, TcpFlagsNot, Fragment, Limit,
                          LogOptions, ConnStatus, Recent, TimeMatch: moved verbatim (865-1050) */
pub trait Numbered { fn number(&self) -> Option<&Flex>; fn disabled(&self) -> bool; }
pub fn sorted<R: Numbered>(rules: &[R]) -> Vec<&R>;   // enabled rules by number; replaces 3 copies
pub fn number_str(n: Option<&Flex>) -> String;
pub struct RuleCtx<'a> {
    pub fam: Fam,
    pub hook: &'a str,     // comment/log code: FWD INP OUT PRE NAM (PBR: route|route6)
    pub label: &'a str,    // filter | raw | chain or policy name
    pub groups: &'a GroupIndex,
    pub jump: &'a dyn Fn(&str) -> Result<String, String>,  // jump-target → nft chain; the X2 check
    pub offload: &'a dyn Fn(&str) -> Result<String, String>, // offload-target → ZEBRA_FLOWTABLE_<t> (fw-flowtable F5);
                                                             // PBR and NAT pass one that always errs
}
/// `set` statements (FW7). Owned and implemented by fw-packet-modification (PM4); `table`
/// and `vrf` are PBR's extra fields, which `render_set` ignores.
pub struct SetActions { /* dscp, connection_mark, mark, tcp_mss, ttl, hop_limit, table, vrf: Option<Flex> */ }
pub fn render_set(set: &SetActions, fam: Fam) -> Result<Vec<String>, String>;
/// Field names as fw-packet-modification PM9 proposes. nft-common defines the type in
/// M1 with `statements` always empty; fw-packet-modification fills `statements` (set,
/// add-address-to-group) and owns how show prints them.
pub struct RenderedRule {
    pub line: String,            // the full nft rule line
    pub matchers: Vec<String>,   // match expressions only, in parse_rule order
    pub statements: Vec<String>, // non-terminal statements after `counter`
    pub recent: Option<String>,  // RECENT set to declare
    pub frag: bool,              // table needs frag::chains
}
/// The matcher half (state … mark), for PBR, which appends its own `set` statements and
/// verdict (the requirement pbr.md lists as `render_matchers`).
pub fn render_matchers(rule: &Rule, ctx: &RuleCtx) -> Result<RenderedRule, String>;
/// render_matchers + log + `last` + counter + statements + verdict + comment.
pub fn render_rule(rule: &Rule, ctx: &RuleCtx) -> Result<RenderedRule, String>;   // 1556-1916
```

Rules for consumers:
- Every value that reaches nft text goes through `tok`/`safe_name`.
- Every table re-renders the groups it references with `group::render_sets`. Sets are
  table-scoped, so NAT, mangle and conntrack each carry their own copy, as VyOS does.
- The `jump` and `offload` callbacks keep chain and flowtable naming (`NAME[6]_`, zone
  `VZONE_`, `ZEBRA_FLOWTABLE_`) and the X2 existence check with the caller. `render_rule`
  never invents object names.
- New matchers ([fw-matchers](fw-matchers.md)), `set` statements
  ([fw-packet-modification](fw-packet-modification.md)) and the bridge-mode `vlan` /
  `ether type` matchers ([fw-bridge](fw-bridge.md)) are added inside `rule.rs`, in
  VyOS `parse_rule` order. They are not added in the backends.
- **Extensions owned here, implemented by the plan that needs them** (each lands as a
  change to these modules, never as a copy): `Fam::Bridge` and bridge mode
  ([fw-bridge](fw-bridge.md)); `GroupKind::Dynamic` and `render_set`
  ([fw-packet-modification](fw-packet-modification.md)); `GroupKind::Domain`/`Remote`,
  the fqdn/geoip endpoint arms and `Rendered.fill`
  ([fw-dynamic-sources](fw-dynamic-sources.md)); `Origin::Flowtable` and
  `RuleCtx.offload` ([fw-flowtable](fw-flowtable.md)). Until a plan lands, its variant or
  field does not exist.

### 3.2 What stays in `firewall.rs`

- `FirewallConfig`, `Family`, `Hook`, `Chain`, `CustomChain`, `GlobalOptions`,
  `StatePolicy*`;
- `render_table` (hook layout, `ZEBRA_<HOOK>_<prio>` naming, state-policy chain,
  `RECENT_` declarations);
- `render_default_rule`;
- the [fw-load-safety](fw-load-safety.md) chain graph (`TablePlan`, `reaching_hooks`);
- all show code;
- the `run`/`process` loop.

The firewall's `jump` callback resolves `NAME[6]_<target>` against its chain index.

### 3.3 X10 and the `mark` mask

- Fragment matcher: `meta mark & 0x80000000 == 0x80000000` (match-frag) and `… !=` (match-non-frag).
- Chains, emitted once per table whose rules use `fragment` (deviation kept; §3.4):

| Chain | Hook / priority | Body |
|:--|:--|:--|
| `ZEBRA_FRAG_MARK` / `ZEBRA_FRAG6_MARK` | prerouting -450 | `ip frag-off & 0x3fff != 0` / `exthdr frag exists`, then ` meta mark set meta mark \| 0x80000000 return` |
| `ZEBRA_FRAG[6]_UNMARK_FWD` | forward `filter + 10` | `meta mark & 0x80000000 == 0x80000000 meta mark set meta mark & 0x7fffffff` |
| `ZEBRA_FRAG[6]_UNMARK_INP` | input `filter + 10` | same |

- `mark` matcher: `meta mark & 0x7fffffff {N}` or `meta mark & 0x7fffffff != {N}`, with a
  single space. VyOS emits two spaces when there is no operator. A value above
  `0x7fffffff` in the string arm (ranges, hex) skips the rule with a warning. The YANG
  `uint32` arm is already capped at 2147483647 (`firewall.yang:429-437`).
- **Contract** for every consumer of `meta mark` (record it in the `nft::frag` doc):
  - Bit 31 belongs to the fragment flag from prerouting -450 until forward/input
    `filter + 10`. Routing runs inside that window.
  - So:
    - fwmark `ip rule`s must use mask `0x7fffffff`. This is a requirement on
      [pbr](pbr.md) and [wan-load-balancing](wan-load-balancing.md), on the zebra-rs side;
    - mark writers must use `frag::set_mark`, which keeps bit 31
      ([fw-packet-modification](fw-packet-modification.md), [pbr](pbr.md));
    - `ct mark set meta mark` copies must mask with `& 0x7fffffff`.
  - Locally generated packets never pass prerouting, so output-hook marks are unaffected.
  - **cradle's reservations** ([ebpf-netfilter](ebpf-netfilter.md)): fwmark `0x4c37`,
    `ip rule` pref `100` and table `2047`. No helper here produces them: a user-supplied
    mark (`set mark`, PBR) goes through `frag::check_user_mark`, which refuses
    `0x4c37` (the caller skips the rule with an Error finding), and nothing in
    `crate::nft` writes `ip rule`s or routing tables. PBR's generated
    `0x7FFFFFFF − T` cannot reach it for real table IDs ([pbr](pbr.md) D-3).
- **Several tables.** If a future table (say `zebra_mangle`) also uses `fragment`, it emits
  its own `frag::chains`. OR-ing and clearing are idempotent, so duplicate chains in two
  tables are harmless. This is what lets each table keep the "emit on use" deviation.

### 3.4 Deviations to record in the `nft` module doc

- Frag mark and unmark chains are emitted only in a table where some rule uses
  `fragment`. VyOS always emits them in `vyos_filter`.
- Single spaces where VyOS's f-strings produce two (`iifname  {…}`,
  `meta mark & 0x7fffffff  {N}`).
- Names use `ZEBRA_*`; `NAME_` and the set prefixes keep VyOS's names.
- `auto-merge` on every interval set and member de-duplication: the VyOS behaviour, as
  restored by [fw-load-safety](fw-load-safety.md).

Rejected:
- **A crate, or a trait-heavy rule AST.** Strings in, strings out matches VyOS's template
  filters line for line. An AST would make "follow `parse_rule` line for line" harder to
  review.
- **Per-backend copies of the group renderer.** Copies would drift, and X1 showed that a
  one-line difference (`auto-merge`) decides whether the whole ruleset loads.
- **Keeping the 0xffff1 scheme for configs without marks.** One scheme is simpler, and
  PBR needs bit 31.

## 4. Changes

### zebra-rs

None.

### insomnia

- New `src/nft.rs` + `src/nft/{apply,counters,fam,frag,group,matcher,rule,script,token}.rs`
  with the API in §3.1. `main.rs` gains `mod nft;`.
- `src/firewall.rs`:
  - deletes the moved items and adds `use crate::nft::{…}`;
  - `render_table` calls `group::render_sets`, `rule::sorted` and `rule::render_rule` with
    a `RuleCtx` whose `jump` resolves `NAME[6]_x` through the fw-load-safety chain index;
  - the show code calls `counters::fetch(fam.ip(), TABLE)` and `counters::strip_tail`.
- `src/json.rs` is unchanged. The models keep `Flex`, `de_presence` and `de_flex_vec`.
- `AGENTS.md` "Architecture": add `src/nft.rs` under "Backend shape" ("nft backends render
  through `crate::nft`; do not copy set or matcher code").

**Worked example (X10 + mark).** Config:

```json
{"ipv4": {"forward": {"filter": {"rule": [
    {"number": 10, "action": "drop", "fragment": {"match-frag": null}},
    {"number": 20, "action": "accept", "mark": "!100-200"}]}}},
 "ipv6": {"input": {"filter": {"rule": [
    {"number": 10, "action": "accept", "fragment": {"match-non-frag": null}}]}}}}
```

Expected render (passes `nft -c`):

```
add table ip zebra_firewall
delete table ip zebra_firewall
add table ip6 zebra_firewall
delete table ip6 zebra_firewall
table ip zebra_firewall {
    chain ZEBRA_FORWARD_filter {
        type filter hook forward priority filter; policy accept;
        meta mark & 0x80000000 == 0x80000000 counter drop comment "ipv4-FWD-filter-10"
        meta mark & 0x7fffffff != {100-200} counter accept comment "ipv4-FWD-filter-20"
        counter accept comment "FWD-filter default-action accept"
    }
    chain ZEBRA_FRAG_MARK {
        type filter hook prerouting priority -450; policy accept;
        ip frag-off & 0x3fff != 0 meta mark set meta mark | 0x80000000 return
    }
    chain ZEBRA_FRAG_UNMARK_FWD {
        type filter hook forward priority filter + 10; policy accept;
        meta mark & 0x80000000 == 0x80000000 meta mark set meta mark & 0x7fffffff
    }
    chain ZEBRA_FRAG_UNMARK_INP {
        type filter hook input priority filter + 10; policy accept;
        meta mark & 0x80000000 == 0x80000000 meta mark set meta mark & 0x7fffffff
    }
}
table ip6 zebra_firewall {
    chain ZEBRA_INPUT_filter {
        type filter hook input priority filter; policy accept;
        meta mark & 0x80000000 != 0x80000000 counter accept comment "ipv6-INP-filter-10"
        counter accept comment "INP-filter default-action accept"
    }
    chain ZEBRA_FRAG6_MARK {
        type filter hook prerouting priority -450; policy accept;
        exthdr frag exists meta mark set meta mark | 0x80000000 return
    }
    chain ZEBRA_FRAG6_UNMARK_FWD {
        type filter hook forward priority filter + 10; policy accept;
        meta mark & 0x80000000 == 0x80000000 meta mark set meta mark & 0x7fffffff
    }
    chain ZEBRA_FRAG6_UNMARK_INP {
        type filter hook input priority filter + 10; policy accept;
        meta mark & 0x80000000 == 0x80000000 meta mark set meta mark & 0x7fffffff
    }
}
```

**Consumer sketch** (for [nat](nat.md), illustrative only; static and CGNAT rules live
in the same `zebra_nat` tables, nat D-1):

```rust
let mut s = Script::new();
s.reset_tables(&["ip", "ip6"], "zebra_nat");
s.line(0, "table ip zebra_nat {");
let idx = nft::group::render_sets(&mut s, groups, Fam::V4, &ex);
// … chains, using nft::matcher::{protocol, endpoint, interface} with &idx …
s.line(0, "}");
// … `table ip6 zebra_nat` the same way, with Fam::V6 …
let (applied, report) = nft::apply::apply_if_changed(
    &NftCli, state.applied.as_ref(), &[("ip", "zebra_nat"), ("ip6", "zebra_nat")], 8,
    |ex| render_nat(cfg, groups, ex)).await;
```

## 5. Tests

- **M1 (move).**
  - The existing tests pass with no expected-text edits: `golden_render`,
    `raw_hooks_and_fragment`, `unsafe_rule_skipped_with_warning`,
    `parse_counters_from_nft_json`, the show tests, and the fw-load-safety goldens.
  - `git diff` of `src/firewall.rs` `mod tests` contains only `use` lines. This is the
    byte-identical check.
  - Unit tests move with their code:
    - `nft::token`: accept and reject tables for `safe_token`/`safe_name`;
    - `nft::group`: `flatten` order and de-dup; cycle warning;
    - `nft::apply`: `parse_diags` fixtures from fw-load-safety;
    - `nft::rule::sorted`: number order, unnumbered last, disabled dropped.
- **M2 (X10).** A deliberate golden change, explained in the commit.
  - `raw_hooks_and_fragment` (2198-2235): assertions 2222 and 2227-2228 change to
    `meta mark & 0x80000000 == 0x80000000 counter drop comment "ipv4-PRE-raw-20"` and
    `ip frag-off & 0x3fff != 0 meta mark set meta mark | 0x80000000 return`. It also
    asserts both UNMARK chains.
  - New `golden_fragment_bit31`: the worked example, full script.
  - New `frag_chains_once_per_table`: two fragment rules in one family produce one set of
    three chains, and a family without fragment rules gets none.
- **M3 (mark).**
  - `mark_matcher_masks_bit31`: `5`, `!5`, `5-10`, `0x10`.
  - `mark_above_mask_skipped`: `0x80000000` gives a warning and the rule is skipped.
  - `check_user_mark_reserved`: `0x4c37`, `0` and `0x80000000` are refused; `0x4c36` passes.
- Opt-in `nft_check_goldens` ([fw-load-safety](fw-load-safety.md)) covers the new goldens.
- **BDD:** none new. The move is behaviour-neutral, and X10's effect (a tc/PBR mark that
  survives fragmentation) cannot be observed until [pbr](pbr.md). pbr's feature must
  include a fragmented packet carrying a policy mark.

## 6. Docs

- `src/nft.rs` module doc: purpose, the VyOS sources (`nftables-defines.j2`,
  `python/vyos/firewall.py`, `template.py`, `defaults.py`), the §3.3 mark contract, and
  the §3.4 deviations.
- `src/firewall.rs` header (lines 15-25): the frag deviation becomes "frag mark/unmark
  chains only when a rule uses `fragment`", and it points to `crate::nft`.
- Book ch-01-02 (match criteria):
  - `fragment` no longer clobbers marks;
  - `mark` compares the low 31 bits;
  - one sentence saying that bit 31 is reserved.
- `AGENTS.md`: the `src/nft.rs` line from §4.

## 7. Milestones

| # | Scope | Repo | Effort | Done when |
|:--|:--|:--|:--|:--|
| 1 | Pure extraction to `crate::nft` (API §3.1), firewall rewired | insomnia | S | all tests green with only `use` changes in `firewall::tests`; clippy `-D warnings` clean |
| 2 | X10: `nft::frag`, fragment matcher, six chains; golden updates | insomnia | S | `golden_fragment_bit31` passes; `raw_hooks_and_fragment` updated; module docs |
| 3 | `mark` mask + over-range skip, `frag::check_user_mark`; book ch-01-02 | insomnia | XS | M3 tests pass |

## 8. Risks and open questions

- **Generic `async fn` in `NftRunner`** is not object-safe. Callers are generic over `R`,
  which is fine for one real runner plus test fakes. Fall back to `Box<dyn Future>` only if
  a backend needs `dyn`.
- **`RuleCtx.jump` as `&dyn Fn`** adds one indirect call per jump rule, which is
  negligible. The alternative is a `ChainResolver` trait.
- **Two tables both using `fragment`** emit duplicate MARK/UNMARK chains at the same
  priority. That is harmless (idempotent), but `nft list ruleset` shows them twice. The
  alternative is to make the firewall table always own the frag chains: that couples PBR
  to the firewall config. Revisit with [pbr](pbr.md).
- **Interaction with third-party bit-31 users** (some IPVS or tc setups): VyOS reserves
  the bit too. Document it, and do not add a knob.
- **Visibility churn.** Model structs become `pub` in `crate::nft`. They are already `pub`
  in `firewall.rs`; only the paths change.
- **Map-only incremental apply** (`add element` / `delete element` without recreating the
  table) is requested as a later option by [nat-cgnat-nat64](nat-cgnat-nat64.md) for large
  CGNAT maps. It is not in this API. If measured need appears, add
  `apply::update_elements(runner, family, table, set, add, del)` next to `apply_loop`.

## 9. Acceptance criteria

- [ ] `crate::nft` exposes the §3.1 API, with root re-exports, `render_matchers`,
      `RenderedRule` and `apply_if_changed`. `firewall.rs` has no copies of the moved
      code (one rule sort, one group renderer, one `nft` runner, one compare-before-apply).
- [ ] Milestone 1 merges with every pre-existing golden byte-identical.
- [ ] Fragment rules render the bit-31 matcher. The six chains appear only when used, and
      the worked example passes `nft -c`.
- [ ] `mark` matches with `& 0x7fffffff`; out-of-range values skip with a warning.
- [ ] The mark contract (§3.3), including cradle's reserved `0x4c37` / pref 100 / table
      2047, is written in the `nft::frag` doc, and the pbr, fw-packet-modification and
      wan-load-balancing plans link to it.
