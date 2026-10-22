# NAT44 and NAT66 — implementation plan

Status: plan, 2026-10-21. Covers: `nat source|destination|static`, NAT66,
`show nat …`, `show nat66 …` ([vyos-gap](../vyos-gap.md) §6.1, §6.2, and
the `nat66` row of §6.3).
Priority: P1 (source, destination, `exclude`, `show … rules|statistics`) ·
P2 (static, NAT66, `log`, `redirect`, translations) · P3 (options,
`load-balance`, `packet-type`). Effort: L (the P1 core is M) · Owner: both
Depends on: [multi-path-subscribe](multi-path-subscribe.md),
[nft-common](nft-common.md), [fw-load-safety](fw-load-safety.md) (the X1,
X2 and X12 patterns), [commit-validation](commit-validation.md)
(`findings.rs` C1; the validator for M9), [conntrack](conntrack.md) (the
translations reader only); soft: [exec-verbs](exec-verbs.md) (provider
`ROUTES`/`Backends`/`Answer`), [ebpf-netfilter](ebpf-netfilter.md),
[fw-opmode](fw-opmode.md) (the group-use registry NAT publishes into),
[fw-dynamic-sources](fw-dynamic-sources.md) (only for the deferred `fqdn` /
`domain-group`, §8) ·
Unblocks: [nat-cgnat-nat64](nat-cgnat-nat64.md),
[wan-load-balancing](wan-load-balancing.md)

## 1. Goal

- `set nat source|destination|static …` and `set nat66 source|destination
  …` exist with `--feature insomnia`, in VyOS spelling.
- insomnia renders them into `ip zebra_nat` and `ip6 zebra_nat` in one
  atomic `nft -f -` transaction. An unchanged render is not re-applied.
- All of these work, including with `firewall group` sets and interface
  groups: masquerade; SNAT and DNAT to an address, range or prefix (with
  ports); `exclude`; port forwarding; 1:1 static NAT.
- insomnia answers these views:
  - `show nat source|destination rules|statistics|translations`;
  - the same views under `nat66`;
  - `show nat static rules|statistics`.
- A rule the renderer cannot express is skipped with a finding that names
  it, and the rest still loads.

## 2. Current state

**insomnia @ `ee4dfaa`.**
- There is no NAT code. The only related piece is the firewall
  `connection-status nat` → `ct status snat|dnat` matcher
  (`src/firewall.rs:1586-1594`).
- What NAT needs is private to `firewall.rs`. [nft-common](nft-common.md)
  extracts it:
  - `safe_token`/`safe_name` (`:1115-1127`) and `Render` (`:1129-1160`);
  - the add+delete prologue (`:1173-1191`);
  - `render_group_sets` and `collect_members` (`:1322-1482`);
  - the rule sort (`:1484-1491`);
  - the protocol, address, port, group and interface matchers inside
    `render_rule` (`:1596-1745`);
  - `nft_apply` (`:110-138`), plus `nft_counters` and `parse_counters`
    (`:147-193`).
- Subscriptions take one path each (`src/subscribe.rs:11`,
  `proto/config.proto:31-36`).
- The provider registers `firewall`, `ipsec` and `vrrp`
  (`src/provider.rs:17-27`) and routes orders by path prefix (`:91-101`).
- `main.rs:86-111` spawns the backends.

**zebra-rs @ `141da2fc`.**
- There is no `nat` node. `config.yang:5684-5709` gates `firewall`, `vpn`
  and `vrrp` behind `if-feature feat:insomnia`.
- `firewall.yang` has groupings NAT can reuse:
  - `match-interface-in/out` (`:129-155`);
  - `rule-key` (`:721-728`);
  - `l3-match-v4/v6` (`:498-598`): `address`, `address-mask`,
    `mac-address`, `port`, and `group {address,network,port,mac}-group`.
- `SHOW_PROTOS` (`src/config/manager.rs:2078-2092`) matches a path element
  by exact name. No existing entry matches `nat`, `nat66`, `source`,
  `destination` or `static`.
- Provider names are free-form (`src/config/show_provider.rs:68-76`).

**VyOS @ `7f2c893`.**
- **Schema.** `nat.xml.in` with the includes `nat-rule`, `nat-address`,
  `nat-port`, `nat-exclude`, `nat-translation-{port,options}` and
  `firewall/nat-balance`.
  - `protocol` defaults to `all`.
  - The options are `address-mapping persistent|random` (default
    `random`) and `port-mapping random|none` (default `none`).
  - `nat66.xml.in` has name-only interfaces. Source rules match on
    `prefix`; destination rules match on `address`.
- **Render.** `nat.py` fills `firewall/nftables-nat.j2` into `ip vyos_nat`:
  PREROUTING at -100 and POSTROUTING at 100, each opened by
  `counter jump VYOS_PRE_{D,S}NAT_HOOK`.
  - `nftables-static-nat.j2` builds a separate `ip vyos_static_nat` at
    the same priorities. `nftables-nat66.j2` builds `ip6 vyos_nat`.
  - Every group is copied into every table.
  - Rules come from `python/vyos/nat.py:20-274`; static rules from
    `:276-336`.
  - Token order: interface, protocol, `packet-type`, then **source before
    destination**, `counter`, `log`, translation, `comment`.
  - Comments are `SRC-NAT-n`, `DST-NAT-n`, `SRC-NAT66-n` and
    `STATIC-{SRC,DST}-NAT-n`; log suffixes are `-MASQ` and `-EXCL`.
- **verify** (`nat.py:82-215`):
  - Any port (match, translation, redirect, port-group) needs protocol
    `tcp|udp|tcp_udp`.
  - At most one of address and fqdn, and at most one group type; a group
    excludes an address.
  - A referenced group must exist (an error); an empty group is only a
    warning.
  - Interface name and group are mutually exclusive.
  - A translation is required unless the rule uses `exclude`,
    `load-balance` or (destination only) `redirect`.
  - Static rules need `inbound-interface`.
- **Op mode** (`src/op_mode/nat.py`):
  - `rules` and `statistics` parse `nft --json list chain`.
  - `translations` parses
    `conntrack --dump --src-nat|--dst-nat -o xml`.
  - There is no `show nat static`, and no reset or clear command.

## 3. Design

**D-1. One backend and one table per family, with static NAT folded in.**
- `src/nat.rs` renders `ip zebra_nat` (from `nat`) and `ip6 zebra_nat`
  (from `nat66`) in one transaction.
- Static DNAT rules head PREROUTING and static SNAT rules head
  POSTROUTING, ahead of the dynamic rules.
- Why: VyOS hooks `vyos_static_nat` at the same priority as `vyos_nat`.
  Whether a 1:1 host's outbound traffic hits its static SNAT or a broader
  masquerade first is then unspecified. One chain fixes the order.
- Rejected alternatives:
  - a second table at the same priority: nondeterministic;
  - a second table at 99: already used by WLB SNAT and the VRF-zones
    anchor (vyos-gap §6.1).
- Caveat to document: `nat source … exclude` cannot exempt a static host,
  because static SNAT runs first. For such a host, write an ordered
  destination + source rule pair instead.

**D-2. VyOS chain names.**
- `PREROUTING` and `POSTROUTING` at numeric priorities `-100` and `100`.
  VyOS's NAT chains have no `VYOS_` prefix, and the table name already
  separates the stacks.
- The never-filled `VYOS_PRE_{D,S}NAT_HOOK` and `VYOS_{D,S}NPT_HOOK`
  chains are dropped.
- No NAT OUTPUT chain, so router-originated traffic is never DNATed (as
  in VyOS).

**D-3. One multi-path subscription** (assumes D3).
- Paths: `["nat"]`, `["nat66"]` and `["firewall","group"]`.
- Requirement on [multi-path-subscribe](multi-path-subscribe.md). That
  plan's `MultiUpdate` contract already provides it:
  - a snapshot of all paths first;
  - then one event per commit that touches any path, carrying **every
    path's current document**, with `"{}"` for an absent path.
- The backend calls `subscribe_json_multi(&host, PATHS, Fallback::Refuse)`
  and decodes each part with `json::parse_subtree`.
- There is no single-stream interim, for two reasons:
  - multi-path-subscribe rejects merging skewed streams;
  - its `Fallback::Refuse` makes a zebra-rs without `SubscribeMulti` log
    and retry.

  M2's renderer and goldens need neither; only the live loop does.

**D-4. No copies of shared code.**
- Requirement on [nft-common](nft-common.md), using the `crate::nft` API
  proposed there:
  - `Fam`, `Script` (`reset_tables`, `line`, `warn`), `tok`, `safe_name`;
  - `Groups`, `GroupRef`, `IfMatch` and `Endpoint`;
  - `group::render_sets` (X1 `auto-merge` and de-duplication), which
    returns the X2 `GroupIndex`;
  - `matcher::{protocol, endpoint, interface}`;
  - `rule::sorted`;
  - `apply::apply_if_changed` (the X12 shape, over
    `[("ip","zebra_nat"),("ip6","zebra_nat")]`);
  - `counters::fetch`.
- `NatSide` (`address`, `port`, `group`) is mapped onto `nft::Endpoint`,
  which has no mask or MAC. NAT calls `matcher::endpoint` for `Src`, then
  `Dst`, in VyOS NAT order. For prefix-map translations it skips the
  same-side address, as `ignore_type_addr` does.
- nft-common's consumer sketch follows D-1: static (and later CGNAT)
  rules live in the same `zebra_nat` tables.
- All groups are rendered into each NAT table, as VyOS does.

**D-5. `parse_nat_rule`, token for token, except:**
- interface names are quoted, as in the firewall (VyOS writes
  `oifname {eth0}`);
- ports use the shared spelling (`tcp dport {443}`, `!= {22}`);
- doubled spaces are normalized;
- translation values are *parsed* into masquerade, address, range `a-b`
  or prefix `a/n`, plus an optional port or range. Anything else skips
  the rule.

**D-6. Verify rules are findings (assumes D1).**
- Every VyOS `verify()` rule becomes a `Finding` in
  [commit-validation](commit-validation.md)'s `src/findings.rs`:
  - `ConfigError` rules are `Severity::Error` with
    `Effect::Skipped("rule")`;
  - `Warning()` rules (an empty group, for example) are
    `Severity::Warning` with `Effect::Kept`.
- `render()` returns `(String, Findings)`, so the rendered script never
  contains a rule that a finding skipped.
- Dangling group and interface-group references follow
  [fw-load-safety](fw-load-safety.md)'s reference pass, through
  nft-common's `GroupIndex::reference`.
- `pub fn validate(parts: &[JsonConfigUpdate]) -> Findings` returns
  `render(..).1`. The validator task's `UNITS` gains
  `nat → [nat], [nat66], [firewall group]`.
  - Once layer 2 is live, an Error refuses the commit while insomnia is
    connected.
  - Until then, it is a skip that is logged.
- Structural rules go into YANG (§4).

**D-7. Show reads the retained model plus live counters**, like
`show firewall`.
- Counters are joined by comment, which is unique per table.
- Rows are single-line: `addr port P`, not VyOS's second line.
- A rule that was skipped shows `(not applied)` as its translation, and
  its finding is printed under the table.

**Deviations for the module doc:**
- D-1, D-2, D-5 and D-7;
- `show nat static` exists only in insomnia;
- defaults are filled by the renderer;
- hairpin is a documented rule pattern, not a knob (VyOS has none).

**Constraints to document:**
- Traffic that enters an `ebpf enabled` port bypasses netfilter, so NAT
  does not apply to it. [ebpf-netfilter](ebpf-netfilter.md) decides what
  happens there: documentation only, a zebra-rs refusal, or a cradle
  punt. The NAT chapters link to its outcome.
  - Under its default outcome B, zebra-rs refuses `nat` and `nat66`
    together with eBPF ports. This plan adds that row (`nat`, `nat66`,
    including `nat cgnat`) to its `EBPF_BYPASSED_TREES` with M1.
  - On such a port, SNAT/DNAT to router-owned addresses would still
    work, because the replies are local and punted. Pools that are routed
    but not local would break. The NAT chapters say so.
- NAT across overlapping VRFs needs [conntrack](conntrack.md)'s VRF
  conntrack zones.

## 4. Changes

### zebra-rs

**`firewall.yang`.** A structural split; the data tree does not change.
`l3-match-core-v4` holds `address`, `port` and
`group {address,network,port,mac}-group`. `l3-match-v4` becomes
`uses l3-match-core-v4` plus `address-mask` and `mac-address`. Do the same
for v6. The VyOS NAT sides carry exactly the core set.

**New `yang/nat.yang`** (prefix `nat`, imports `firewall` as `fw`).
Sketch:

```yang
grouping nat-rule-base {
  uses fw:rule-key;                                    // number 1..999999
  leaf description { type string { pattern '.*'; } }
  leaf disable { type empty; }  leaf exclude { type empty; }  leaf log { type empty; }
  leaf packet-type { type enumeration { enum broadcast; enum host; enum multicast; enum other; } }
  leaf protocol { type union { type uint8; type string; } }         // all, tcp_udp
  container load-balance {
    leaf-list hash { type enumeration { enum source-address; enum destination-address;
                                        enum source-port; enum destination-port; enum random; } }
    list backend { key "address"; leaf address { type inet:ipv4-address; }
                   leaf weight { type uint8 { range "1..100"; } } } }
  container source      { uses fw:l3-match-core-v4; }
  container destination { uses fw:l3-match-core-v4; }
}
grouping nat-translation-v4 {
  leaf address { type union { type inet:ipv4-address; type inet:ipv4-prefix; type string; } }
  leaf port { type union { type uint16; type string; } }                      // range
  container options {
    leaf address-mapping { type enumeration { enum persistent; enum random; } }
    leaf port-mapping    { type enumeration { enum random; enum none; } } }
}
grouping nat {
  container source { list rule { key "number"; uses nat-rule-base; uses fw:match-interface-out;
    container translation { uses nat-translation-v4; } } }           // address: + masquerade
  container destination { list rule { key "number"; uses nat-rule-base; uses fw:match-interface-in;
    container translation { uses nat-translation-v4;
      container redirect { presence "Redirect to local host"; leaf port { type string; } } } } }
  container static { list rule { key "number"; uses fw:rule-key;
    leaf description { type string { pattern '.*'; } }
    leaf inbound-interface { type string; mandatory true; }         // plain leaf; `any`
    leaf log { type empty; }
    container destination { leaf address { type union { type inet:ipv4-address; type inet:ipv4-prefix; } } }
    container translation { leaf address { type union { type inet:ipv4-address; type inet:ipv4-prefix; } } } } }
}
grouping nat66 { /* source: outbound-interface { name }, source|destination { prefix, port,
  group (v6 core) }; destination: inbound-interface { name }, source|destination { address,
  port, group }; translation { address = masquerade|v6 addr|v6 prefix; port }; exclude, log,
  disable, description, protocol. No static, options or load-balance (VyOS parity). */ }
```

Still to settle:
- `mandatory` (`src/config/configs.rs:552-571`) needs a test on a leaf
  inside a keyed list entry.
- How a childless presence container (`redirect`) is serialized is
  *unverified*: `null` or `{}`. insomnia accepts both.

**`config.yang`.**
- Add `import nat { prefix nat; }`.
- Beside `container vrrp` (`:5703-5709`), add:
  - `container nat { if-feature feat:insomnia; uses "nat:nat"; }`
  - `container nat66 { if-feature feat:insomnia; uses "nat:nat66"; }`

  Each gets an `ext:help`.
- [nat-cgnat-nat64](nat-cgnat-nat64.md) later adds `cgnat` inside
  `grouping nat`.
- Extend the `feature insomnia` description in `zebra-features.yang`.

**`exec.yang`**, after `container vrrp` (`:434-439`):

```yang
grouping nat-show-direction {
  container rules      { ext:help "NAT rules";         presence "NAT rules"; }
  container statistics { ext:help "NAT rule counters"; presence "NAT rule counters"; }
  container translations { ext:help "Active translations (conntrack)"; presence "Active translations";
    list address { ext:presence "One address"; key "ip"; leaf ip { type string; } } }
}
container nat   { if-feature feat:insomnia; ext:help "NAT information";
  container source { uses nat-show-direction; }  container destination { uses nat-show-direction; }
  container static { container rules { presence "Static NAT rules"; }
                     container statistics { presence "Static NAT counters"; } } }
container nat66 { if-feature feat:insomnia; ext:help "NAT66 information";
  container source { uses nat-show-direction; }  container destination { uses nat-show-direction; } }
```

**`manager.rs`.**
- `is_nat` matches `"nat" | "nat66"`. Add `(is_nat, "nat", "NAT")` to
  `SHOW_PROTOS` before `is_policy`.
- Add tests in the style of `:7600-7700`:
  - `show nat source rules` and `show nat66 destination translations`
    route to `"nat"`;
  - the schema is absent without the feature.

**`check.rs`.** No change: reference checks live in insomnia's validator
(D-6).

### insomnia

**New `src/nat.rs`** (the API below is proposed):

```rust
const PATHS: &[&[&str]] = &[&["nat"], &["nat66"], &["firewall", "group"]];
const TABLE: &str = "zebra_nat";
#[derive(Default)] struct NatInputs { nat: NatConfig, nat66: Nat66Config, groups: nft::Groups }
#[derive(Default)] struct ShowState { inputs: Option<Arc<NatInputs>>, findings: Findings, applied: Option<nft::apply::Applied> }
pub struct NatConfig { source: Option<RuleSet>, destination: Option<RuleSet>,
                       #[serde(rename = "static")] static_: Option<StaticSet> }   // kebab-case, default
pub struct NatRule { number, description, protocol, packet_type: Option<Flex>,
    disable, exclude, log: bool /* de_presence */, source, destination: Option<NatSide>,
    inbound_interface, outbound_interface: Option<nft::IfMatch>,
    translation: Option<Translation>, load_balance: Option<LoadBalance> }
pub struct NatSide { address, prefix /* nat66 source */, port: Option<Flex>, group: Option<nft::GroupRef> }
pub struct Translation { address, port: Option<Flex>, options: Option<TranslationOptions>,
                         redirect: Option<Redirect> /* de_presence_obj */ }
pub fn render(inp: &NatInputs, ex: &nft::Exclusions) -> (String, Findings);       // commit-validation shape
pub fn validate(parts: &[JsonConfigUpdate]) -> Findings;                           // = render(..).1
#[cfg(test)] pub fn render_str(nat: &str, nat66: &str, groups: &str) -> anyhow::Result<(String, Findings)>;
fn render_rule(rule: &NatRule, kind: Kind /* Src|Dst */, fam: nft::Fam) -> Result<String, String>;
fn render_static(rule: &StaticRule, kind: Kind) -> Result<String, String>;
enum Xlat { Masq, Addr(String), Range(String), Prefix(String) }       // + Option<port>
```

- `process(update: MultiUpdate)`:
  1. Decode each part with `json::parse_subtree`. A part that fails to
     parse is an Error finding, and that path keeps its previous value.
  2. Render, through `nft::apply::apply_if_changed(&NftCli, last, &[("ip","zebra_nat"),("ip6","zebra_nat")], …)`.
  3. Retain the inputs, the findings and `Applied` for show.
- Logs: `nat: nftables ruleset applied`; `Findings::log("nat")` for the
  rest.
- `src/json.rs` gains `de_presence_obj`, which returns `Some` for either
  `null` or an object.

**Wiring.**
- `main.rs`: `mod nat;`, a fourth show channel, and the spawn.
- `provider.rs`:
  - add `"nat"` to `Register.name`;
  - add a `nat` field to [exec-verbs](exec-verbs.md)' `Backends` struct;
  - add rows `(Show, "/show/nat66", Backend::Nat)` and
    `(Show, "/show/nat", Backend::Nat)` to its `ROUTES` table. NAT has
    no exec verbs, so `EXEC_TREES` is unchanged.
  - exec-verbs D-8 `route` matches at a segment boundary, so a later
    `/show/nat64` row ([nat-cgnat-nat64](nat-cgnat-nat64.md) M-N4) cannot
    be swallowed by `/show/nat`.
  - Before exec-verbs lands, the same rows go into the current if-chain
    (`provider.rs:91-101`) as segment matches.
- Show handlers answer `Answer` (`text.into()`), per exec-verbs.
- `nat::run` also receives [fw-opmode](fw-opmode.md)'s `GroupUseRegistry`
  (O5), once that plan's milestone 5 has landed. After each apply it
  replaces its `"nat"` entry with one `GroupUse` per (rule, group)
  reference, with paths such as `nat-source-100`, `nat-destination-10`
  and `nat66-source-10`, so `show firewall group` counts NAT references.
  Skipped rules publish nothing.
- `Cargo.toml`:
  - mention NAT in the extended description;
  - add `conntrack` to `recommends`. Ubuntu noble ships 1:1.4.8, and it
    is not installed by default.

**Worked example.** Config (set-format; also set
`firewall group network-group LAN network 192.168.0.0/24` and
`… 192.168.1.0/24`):

```
set nat source rule 50 outbound-interface name eth0
set nat source rule 50 source address 192.168.0.0/24
set nat source rule 50 destination address 10.0.2.0/24
set nat source rule 50 exclude
set nat source rule 100 outbound-interface name eth0
set nat source rule 100 source group network-group LAN
set nat source rule 100 translation address masquerade
set nat destination rule 10 inbound-interface name eth0
set nat destination rule 10 protocol tcp
set nat destination rule 10 destination port 443
set nat destination rule 10 translation address 192.168.0.5
set nat destination rule 10 translation port 8443
set nat destination rule 10 log
set nat static rule 10 inbound-interface eth0
set nat static rule 10 destination address 203.0.113.7
set nat static rule 10 translation address 192.168.1.7
set nat66 source rule 10 outbound-interface name eth0
set nat66 source rule 10 source prefix fd00:1::/64
set nat66 source rule 10 translation address 2001:db8:1::/64
```

It renders exactly this. The output passed `nft -c` (1.0.9) and was loaded
twice in a scratch netns.

```
add table ip zebra_nat
delete table ip zebra_nat
add table ip6 zebra_nat
delete table ip6 zebra_nat
table ip zebra_nat {
    set N_LAN {
        type ipv4_addr
        flags interval
        auto-merge
        elements = { 192.168.0.0/24,192.168.1.0/24 }
    }
    chain PREROUTING {
        type nat hook prerouting priority -100; policy accept;
        iifname "eth0" ip daddr 203.0.113.7 counter dnat to 192.168.1.7 comment "STATIC-DST-NAT-10"
        iifname "eth0" meta l4proto tcp tcp dport {443} counter log prefix "[DST-NAT-10]" dnat to 192.168.0.5:8443 comment "DST-NAT-10"
    }
    chain POSTROUTING {
        type nat hook postrouting priority 100; policy accept;
        oifname "eth0" ip saddr 192.168.1.7 counter snat to 203.0.113.7 comment "STATIC-SRC-NAT-10"
        oifname "eth0" ip saddr 192.168.0.0/24 ip daddr 10.0.2.0/24 counter return comment "SRC-NAT-50"
        oifname "eth0" ip saddr @N_LAN counter masquerade comment "SRC-NAT-100"
    }
}
table ip6 zebra_nat {
    chain PREROUTING {
        type nat hook prerouting priority -100; policy accept;
    }
    chain POSTROUTING {
        type nat hook postrouting priority 100; policy accept;
        oifname "eth0" ip6 saddr fd00:1::/64 counter snat prefix to 2001:db8:1::/64 comment "SRC-NAT66-10"
    }
}
```

The other translation forms, each also checked with `nft -c` (the column
shows what follows `counter`):

| Config | Rendered |
|:--|:--|
| range, `persistent`, `port-mapping random` | `snat to 203.0.113.8-203.0.113.15 persistent,random` |
| `source address 10.20.0.0/24` + prefix | `snat ip prefix to ip saddr map { 10.20.0.0/24 : 198.51.100.0/24 }` (the `ip saddr` match is dropped, as in VyOS) |
| prefix, no source address | `snat prefix to 198.51.100.0/24` |
| `tcp_udp`, address, `port 2000-3000` | `meta l4proto {tcp, udp} …` then `snat to 203.0.113.20:2000-3000` |
| masquerade, port, `log` | `log prefix "[SRC-NAT-210-MASQ]" masquerade to :1024-65535` |
| `redirect port 3128` | `redirect to :3128` |
| `load-balance hash source-address`, weights 1 and 2 | `dnat to jhash ip saddr mod 3 map { 0-0 : 10.0.0.1, 1-2 : 10.0.0.2 }` |
| the same with `port 8080` and `hash source-port` | `dnat ip to jhash ip saddr . tcp sport mod 3 map { 0-0 : 10.0.0.1 . 8080, 1-2 : 10.0.0.2 . 8080 }` |
| NAT66 address + port | `snat to [2001:db8::5]:4000-5000` |
| static prefix | `dnat ip prefix to ip daddr map { 203.0.113.64/28 : 10.0.64.0/28 }`, plus the mirrored `snat … map` |

`nft` itself rejects `snat to A:port` when no transport-protocol match
precedes it: "transport protocol mapping is only valid after transport
protocol match" (reproduced). So the port-needs-protocol rule is a hard
skip.

**Show output.** VyOS headers (`src/op_mode/nat.py:255-275`), printed with
`text::table`:

```
show nat source rules
Rule    Source            Destination    Proto    Out-Int    Translation
------  ----------------  -------------  -------  ---------  -----------
50      192.168.0.0/24    10.0.2.0/24    any      eth0       exclude
100     @N_LAN            0.0.0.0/0      any      eth0       masquerade

show nat source statistics
Rule    Packets    Bytes    Interface
------  ---------  -------  -----------
50      0          0        eth0
100     1834       146720   eth0
```

- `-j` returns
  `[{"rule":100,"interface":"eth0","translation":"masquerade","packets":…,"bytes":…,"applied":true}]`.
- `translations` uses VyOS's columns: `Pre-NAT Post-NAT Proto Timeout
  Mark Zone`.
  - Source rows show the original source and the reply destination;
    destination rows show the original destination and the reply source.
  - `address X` filters on the original source, like VyOS's `--src`.

## 5. Tests

**Golden-render tests** (`nat::tests`, via `render_str`):
- `empty_renders_teardown`
- `groups_without_nat_render_teardown`
- `model_deserializes_config_json_shapes`: numeric values; `null`
  presence leaves; `redirect` as both `null` and `{}`; the `static` key;
  unknown keys ignored
- `golden_render`: the worked example, byte for byte
- `golden_translation_forms`: every row of the table above
- `golden_static_first`: `inbound-interface any` adds no interface match
- `golden_nat66`: no `ip` table when only `nat66` is set
- `golden_load_balance`: the modulus equals the weight sum
- `log_prefixes`
- `findings_skip_rule`. Each case asserts the `Finding` (severity and effect) and that the other
  rules still render:
  - a port with `icmp`, or a translation port with no protocol;
  - an undefined network-group or interface-group;
  - an interface name together with an interface group;
  - no translation and no `exclude`;
  - a translation that does not classify, or an IPv4 translation in
    `nat66`;
  - hash ports without tcp or udp;
  - an unsafe token.

**Show tests.** `show_rules_text`; `show_statistics_counters` (fixture
JSON captured from the netns load); `show_skipped_rule_marked`;
`show_json`. Also an optional `#[ignore]` `nft_check_golden` that pipes
every golden through `nft -c -f -`. CI never runs it, because the unit
tests must not need `nft` (AGENTS.md).

**zebra-rs.**
- The schema exists only with the feature.
- Routing goes to `"nat"`, and the not-running fallback names "NAT".
- A `nat static rule 1` without `inbound-interface` fails commit with
  "missing mandatory node".

**BDD `nat_edge`** (`bdd/tests/features/nat_edge.feature`, configs in
`bdd/tests/configs/nat_edge/`):

```
  lan  e0 10.0.0.2/24, default via 10.0.0.1
   |
  r1   lan0 10.0.0.1/24 | wan0 192.0.2.1/24        zebra-rs + insomnia
   |
  wan  e0 192.0.2.9/24; NO route to 10.0.0.0/24; 198.51.100.0/24 via 192.0.2.1
```

r1 runs under the generic `tests/scripts/insomnia_node.sh` (created by [fw-load-safety](fw-load-safety.md)) (with a
`_stop.sh`). It is `vrrp_node.sh` without keepalived. The private mount
namespace with tmpfs over `/run` and `/etc/swanctl` stays, because the
IPsec backend writes `swanctl.conf` on every snapshot
(`vrrp_node.sh:14-17`).

Scenarios:
1. **Setup.** Apply `r1.conf`. The insomnia log contains
   `nat: nftables ruleset applied`.
2. **Masquerade.** `ping -c 2 192.0.2.9` from `lan` eventually gets
   `2 received`. `wan` has no route back, so a reply proves SNAT. `show
   nat source rules` contains `masquerade`, and the counter moves.
3. **Port forward.** Run `python3 -m http.server 80 --bind 10.0.0.2` in
   `lan`. A `wan0` tcp 8080 → 10.0.0.2:80 rule makes
   `curl -s -m 2 http://192.0.2.1:8080/` from `wan` contain
   `Directory listing`.
4. **Exclude.** An `exclude` rule for `192.0.2.9/32` makes the ping show
   `100% packet loss`. Deleting the rule restores it.
5. **Static before masquerade.** Add a static rule mapping 198.51.100.10
   to 10.0.0.2 on `wan0`. In `wan`, a raw `nft` rule drops echo requests
   from 192.0.2.1. The ping from `lan` then succeeds only through static
   SNAT. `ping 198.51.100.10` from `wan` also succeeds.
6. **Translations** (after M7). `show nat source translations` contains
   `10.0.0.2`.
7. **Delete.** After `delete nat`, `nft list tables` in `r1` eventually
   lacks `zebra_nat`.
8. **Teardown topology.** Asserts a clean environment.

The Makefile gets a `nat_edge` target. The host needs `python3`, `curl`,
and `conntrack` (for scenario 6).

## 6. Docs

- **`ch-01-08-source-nat.md`.** Rewrite it as shipped: masquerade;
  address, range and prefix; ports and why they need a protocol;
  options; `exclude` with the IPsec-exemption example (link ch-02-02);
  groups; log prefixes; the D-1 order; the eBPF and VRF constraints.
- **`ch-01-09-destination-nat.md`.** Port forwarding, `redirect` and
  `load-balance`. Add a **Hairpin NAT** section: a destination rule on
  the inside interface plus a masquerade toward the inside.
- **`ch-01-10-static-nat.md`.** `inbound-interface eth0` is a plain,
  mandatory leaf, and `any` is allowed. Phase 0
  [docs-corrections](docs-corrections.md) already fixes the `name`
  spelling. Add the D-1 caveat.
- **New `ch-01-12-nat66.md`.** Stateful prefix translation, which is not
  RFC 6296 NPTv6.
- **New `ch-03-04-show-nat.md`.**
- **`SUMMARY.md`.** List the new pages; keep the existing file names.
- **`ch-04-00`.** Add `nat_edge`.
- **`ch-00-00` and AGENTS.md** (what insomnia is, process layout, show
  commands): the `nat`/`nat66` trees, the fourth backend task, and
  `/show/nat`.
- **`src/nat.rs` module doc.** The deviations listed in §3.
- **`design/vyos-gap.md`.** Update the §6.2/§6.3 status columns as the
  milestones ship. The §6.1 engine map already shows the D-1 layout.

## 7. Milestones

| # | Scope | Repo | Effort | Done when |
|:--|:--|:--|:--|:--|
| M1 | `firewall.yang` core split; `nat.yang` (`nat` incl. static, `nat66`); `config.yang`; `exec.yang`; `is_nat`; manager tests | zebra-rs | M | `set nat …` parses only with `--feature insomnia`; `show nat source rules` routes to `"nat"` |
| M2 | `src/nat.rs` core: model; source and destination render (masquerade, address/range/prefix, ports, `exclude`, matchers, groups, interfaces, `log`, `disable`); `Findings`; apply via `apply_if_changed`; wiring (`Backends`, `ROUTES`); goldens | insomnia | M | goldens green; worked example loads in a netns; no helper duplicated from `firewall.rs` |
| M3 | `show nat source\|destination rules\|statistics` (+ `-j`) | insomnia | S | show tests green |
| M4 | `insomnia_node.sh`; `nat_edge` scenarios 1–4, 7, 8 | insomnia | S | `make -C bdd nat_edge` passes twice in a row |
| M5 | Static (+ `show nat static`), `redirect`, options, `packet-type`, `load-balance`; scenario 5 | insomnia | S | goldens and scenario 5 green |
| M6 | NAT66 render + `show nat66 … rules\|statistics`; a NAT66 BDD scenario | insomnia | S | `golden_nat66` and the scenario green |
| M7 | `… translations [address X]` on the [conntrack](conntrack.md) reader; scenario 6; deb `recommends` | insomnia | S | scenario passes |
| M8 | Book (§6) and AGENTS.md, shipped alongside M3, M5 and M6 | insomnia | S | `mdbook build` clean; no "planned" banner left |
| M9 | `nat` unit in [commit-validation](commit-validation.md)'s validator (`UNITS`, `nat::validate`) | both | S | a commit referencing an undefined group is refused while insomnia is connected |

M1 and M2 can proceed in parallel against JSON fixtures. M2's renderer
needs [nft-common](nft-common.md) and `findings.rs`
([commit-validation](commit-validation.md) C1). Its live loop also needs
[multi-path-subscribe](multi-path-subscribe.md). The provider rows ride
[exec-verbs](exec-verbs.md) E5 if that has landed.

## 8. Risks and open questions

- **zebra-rs without `SubscribeMulti`.** With `Fallback::Refuse`, NAT
  logs an error and retries. Running a newer insomnia against an older
  zebra-rs therefore means no NAT, never a NAT that drifts from its
  groups.
- **Apply cost.** Replacing the table does not disturb established flows:
  their bindings live in conntrack.
  - Every `firewall group` commit re-applies NAT.
  - With CGNAT maps that takes about 1 s for 65536 hosts, measured on
    the dev VM ([nat-cgnat-nat64](nat-cgnat-nat64.md)).
- **NAT references in `show firewall group`.** They live in another
  task. Settled: NAT publishes them into [fw-opmode](fw-opmode.md)'s
  `GroupUseRegistry` (§4 wiring); there is no query channel.
- **`fqdn` / `domain-group` in NAT** (vyos-gap §6.2, P3) are deferred
  until [fw-dynamic-sources](fw-dynamic-sources.md) M3. Then
  `l3-match-core-v4` gains `fqdn`, and the nat backend sends its own
  `Demand` (consumer `"nat"`) and appends the `fill` for `ip zebra_nat`
  (fw-dynamic-sources §3.3). Until then a rule that references a
  `domain-group` or `remote-group`, if the shared group container carries
  them, is skipped with a finding.
- **`outbound-interface name <vrf>`.** VyOS's validator accepts it. What
  `oifname` sees for VRF-slave egress is *unverified*; add a BDD case
  before documenting it.
- **`any` outside static rules.** VyOS renders `oifname {any}` literally;
  parity is kept. Open: should it be refused instead?
- **No conntrack-tools.** `translations` answers
  `% conntrack not available` rather than an error chunk.

## 9. Acceptance criteria

- [ ] `nat` and `nat66` exist only with `--feature insomnia`.
- [ ] A static rule without `inbound-interface` is refused at commit.
- [ ] The worked example renders byte for byte and loads with `nft -f`.
- [ ] Every rule in `nat.py:82-215` and `nat66.py:63-127` has a
      `Findings` test, checking severity and effect.
- [ ] Static rules come before dynamic ones (golden test and BDD
      scenario 5).
- [ ] An unchanged render is not re-applied, so a zebra-rs restart keeps
      the counters.
- [ ] All `show nat`, `show nat static` and `show nat66` views answer,
      including `-j`.
- [ ] `nat_edge` passes and ends with a clean-environment teardown.
- [ ] No nft-common helper is copied; clippy `-D warnings` and fmt are
      clean.
- [ ] ch-01-08, -09, -10 and -12 and ch-03-04 describe the shipped
      behaviour, and the module doc lists every deviation in §3.
