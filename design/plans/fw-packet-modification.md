# Packet modification and dynamic groups — implementation plan

Status: plan, 2026-10-21. Covers: FW7, FW8 ([vyos-gap](../vyos-gap.md) §5;
the `show firewall group` live-member item of the §5 op-mode table).
Priority: P2 · Effort: M (FW7 S + FW8 S) · Owner: both
Depends on: [nft-common](nft-common.md) (`frag::set_mark`, `FRAG_MARK_BIT`,
`GroupKind`/`GroupIndex`, `rule.rs` and `RenderedRule`), [fw-load-safety](fw-load-safety.md)
(X2 skip path, `insomnia_node.sh`), [commit-validation](commit-validation.md) (`findings.rs`)
· Unblocks: [pbr](pbr.md) (reuses the `set` statement renderer),
[vrrp-virtual-server](vrrp-virtual-server.md) (first config-driven fwmark
source), [fw-opmode](fw-opmode.md) (live set reader, statement-aware
Conditions), [fw-dynamic-sources](fw-dynamic-sources.md) (live-member display),
[fw-bridge](fw-bridge.md) (`set …` in bridge forward/output rules; soft)

## 1. Goal

- Rules take `set dscp|connection-mark|mark|ttl|hop-limit|tcp-mss` in exactly
  the hooks where VyOS offers them, rendered as VyOS `parse_rule` renders them.
  The common case, TCP MSS clamping on PPPoE and tunnel links, is one rule.
- `set mark` never touches bit 31, the fragment bit that
  [nft-common](nft-common.md) owns.
- `firewall group dynamic-group address-group|ipv6-address-group <g>` plus rule
  `add-address-to-group source-address|destination-address address-group <g>
  [timeout <N>s|m|h|d]` and the matcher `source|destination group
  dynamic-address-group <g>` work, which covers port knocking and brute-force
  block lists.
- `show firewall group` lists the live members of dynamic groups, with timeout
  and expiry, read from nftables.
- Nothing in either feature can make `nft -f` reject the script.

## 2. Current state

**insomnia @ ee4dfaa (`src/firewall.rs`).**
- `Rule` (`867-909`) has no `set` and no `add_address_to_group`. `GroupRef`
  (`923-928`) has address, network, port and mac only. `Groups` (`782-790`) has
  no dynamic groups. Unknown keys are ignored, so such config is dropped
  silently.
- `render_rule` (`1556-1916`):
  - It pushes `counter` (`1878`), then the verdict (`1880-1908`), then the
    comment (`1910-1913`). There is no statement slot between counter and
    verdict.
  - The `group_ref` closure (`1667-1699`) renders address, network, mac, then
    port.
  - `rule mark` matches the whole mark (`1842-1850`). The bit-31 mask is X10,
    owned by [nft-common](nft-common.md).
- The only dynamic sets are the RECENT ones: `flags dynamic`, `size 65535`
  (`1301-1313`).
- Show:
  - `rule_conditions` cuts the rendered line at ` counter` (`369-387`), so any
    statement after the counter would be invisible.
  - `parse_counters` reads only `rule` objects from `nft --json list table`
    (`168-193`); set elements are ignored.
  - `show_groups_text` (`606-643`) prints members from config only.

**zebra-rs @ 141da2fc.**
- `firewall.yang` has no `set` container, no `add-address-to-group`, no
  `dynamic-group` and no `dynamic-address-group` reference. Its module
  description lists "dynamic groups and add-address-to-group" as deferred
  (`yang/firewall.yang:33-35`).
- `rule-base` (`163-391`) is shared by every filter and raw rule body.
  `l3-match-v4` / `l3-match-v6` (`498-597`) are shared by filter and raw rules.

**VyOS @ 7f2c893.**
- Renderer: `python/vyos/firewall.py:590-639`.
  - After `counter` it emits `set update ip[6] daddr|saddr [timeout T]
    @DA[6]_<g>` (destination first), then `ct mark set N`, `ip[6] dscp set N`,
    `meta mark set meta mark & 0x80000000 | N` (`fragment_mark_bit`,
    `python/vyos/defaults.py:96`), `tcp option maxseg size set N`,
    `ip ttl set N` and `ip6 hoplimit set N`, then the verdict.
  - Dynamic references render at `332-338`, after the network group.
- Sets: `data/templates/firewall/nftables-defines.j2:120-138`, as
  `set DA_<g> { type ipv4_addr; flags dynamic, timeout }` (DA6_ for IPv6),
  with no size.
- Schema: `interface-definitions/firewall.xml.in:111-140` (`dynamic-group`) and
  `include/firewall/`:
  - `set-packet-modifications-*.xml.i`: dscp 0-63, connection-mark
    0-2147483647, mark 1-2147483647, tcp-mss 500-1460, ttl and hop-limit 0-255;
  - `add-addr-to-group-ipv4.xml.i` / `add-dynamic-address-groups.xml.i`:
    timeout regex `\d+(s|m|h|d)`;
  - `source-destination-dynamic-group[-ipv6].xml.i`.
- Verify:
  - `src/conf_mode/firewall.py:471-481` checks that the add-target dynamic
    group exists for the family.
  - The `dynamic-address-group` matcher reference is *not* verified, so a
    typo fails the nft load.
- Op-mode: `src/op_mode/firewall.py:607-655` (dynamic rows with Timeout and
  Expires columns) and `131-157` (`nft -j list set` member read).

**Per-hook availability**, from the VyOS hook includes (`ipv4-hook-forward.xml.i:29-39`,
`ipv4-hook-input.xml.i:29-31`, `ipv4-hook-output.xml.i:29-36` and `62-69`,
`ipv4-hook-prerouting.xml.i:35-41`, `ipv4-custom-name.xml.i:34-43`, the ipv6
twins, `common-rule-ipv4[-raw].xml.i`, `common-rule-ipv6[-raw].xml.i`):

| Hook | dscp | connection-mark | mark | tcp-mss | ttl (v4) / hop-limit (v6) | add-address-to-group | `group dynamic-address-group` |
|:--|:--|:--|:--|:--|:--|:--|:--|
| forward filter | yes | yes | yes | yes | yes | yes | yes |
| input filter | — | — | — | — | — | yes | yes |
| output filter | yes | yes | yes | yes | yes | yes | yes |
| output raw | yes | yes | yes | yes | yes | yes | IPv6 only in VyOS |
| prerouting raw | yes | — | yes | yes | yes | yes | IPv6 only in VyOS |
| name (custom) | yes | yes | yes | yes | yes | yes | yes |

## 3. Design

**PM1. Statement slot and order: exactly `parse_rule`.** The rule line is laid
out as follows:
- matchers, then `log …`, then `counter`;
- then the add-to-group statements, destination first;
- then the `set` statements in the order connection-mark, dscp, mark, tcp-mss,
  ttl, hop-limit;
- then the verdict and the comment.

A rule with `set` and no `action` renders no verdict, so evaluation continues.
That matches today's verdict-less behaviour; "action required" is
[commit-validation](commit-validation.md)'s rule.

**PM2. `set mark` preserves bit 31:** `meta mark set meta mark & 0x80000000 | N`.
It is produced by [nft-common](nft-common.md)'s `frag::set_mark(value)`, which
is built on `FRAG_MARK_BIT`. The YANG range 1..2147483647 keeps user marks off
bit 31. No second constant or helper is defined here.
- `set mark 0x4c37` (19511) is refused. That fwmark belongs to cradle
  ([ebpf-netfilter](ebpf-netfilter.md)), whose pref-100 `ip rule` would steer the
  packet into table 2047, i.e. local delivery. The value goes through nft-common's
  `frag::check_user_mark`; its `Err` skips the rule as an Error finding,
  `Effect::Skipped("rule")`, the same check [pbr](pbr.md) D-3 applies to its own
  `set mark`. `set connection-mark` is not checked: cradle's rule reads the packet
  mark only.

**PM3. `set connection-mark` is unmasked** (`ct mark set N`), as in VyOS. In
`output raw` (priority -300, before conntrack at -200) it most likely has no
effect (*unverified*). It is kept for parity and documented.

**PM4. One statement renderer, shared.**
- Proposed: `fn render_set(set: &SetActions, fam: Fam) -> Result<Vec<String>, String>`,
  with `SetActions` beside it. Both live in nft-common's `rule.rs`, since
  nft-common §3.1 says `set` statements are added there in `parse_rule` order.
  This plan owns them.
- This is the function [pbr](pbr.md) asks for (`render_set`, bit-31-masked). It
  returns `Result`, because values pass `tok` like every other scalar. PBR adds
  `set table|vrf` and VyOS's implicit `return` itself.
- `SetActions` also carries PBR's `table` and `vrf` as two `Option<Flex>`
  fields, so a PBR rule's `set` object deserializes once into `nft::Rule`.
  `render_set` ignores them, and the firewall YANG never sets them.
- YANG gives PBR the leaves without a container: `set-packet-modifications-body`
  (IPv4: dscp, mark, tcp-mss, connection-mark, ttl) and
  `set-packet-modifications-body6` (hop-limit instead of ttl). PBR can then
  build one `container set` with `table` and `vrf` added (pbr's request).
  PBR's request names a single body grouping; the family split is needed
  because ttl and hop-limit differ.

**PM5. Dynamic sets follow `nftables-defines.j2`:** `type ipv4_addr|ipv6_addr;
flags dynamic, timeout`, no `size` line, rendered after the static groups in the
family's table only.
- They are rendered by extending nft-common's group model: a new
  `GroupKind::Dynamic` (prefix `DA_`/`DA6_`, per-family, not interval, flags
  `dynamic, timeout`) in `render_sets`.
- `GroupIndex` then knows the names, so `GroupIndex::reference` resolves and
  rejects them like any other group.
- nft gives a dynamic set a default size of 65535; `nft -j list set` reports
  `"size": 65535` on 1.0.9.
- `flags timeout` is required: `set update … timeout 30s` against a set without
  it fails the load (checked in a scratch netns).

**PM6. `add-address-to-group` renders `set update ip[6] saddr|daddr [timeout T]
@DA[6]_<g>`.**
- `timeout` is a YANG string (the module avoids `pattern`). At render time it
  must be `<digits><s|m|h|d>`; anything else skips the rule as an Error finding,
  which mirrors VyOS's constraint regex.
- An add-target or matcher reference to an undefined dynamic group skips the
  rule as an Error finding. VyOS checks only the add-target.
- The check goes through `GroupIndex` (PM5) and the X2 skip path
  ([fw-load-safety](fw-load-safety.md)). No separate index is built here.

**PM7. `group dynamic-address-group` (with `!`)** renders `ip[6] saddr|daddr
[!= ]@DA[6]_<g>` immediately after the network-group reference, in VyOS order.
In zebra-rs the leaf goes into the shared `l3-match-v4/v6` group containers, so
IPv4 raw rules get it too. That is a superset deviation; VyOS has it only in
IPv6 raw.

**PM8. Behaviour to document, not change:**
- Dynamic members are lost on every apply, because each apply recreates the
  table, exactly as RECENT sets and VyOS do. X12 already avoids reapplying on a
  resubscribe.
- When a set is full, the kernel cannot insert. `nft_dynset_eval` then breaks
  the rule (NFT_BREAK), so its verdict is not applied: a `drop` +
  add-address-to-group rule stops dropping new sources. This is from kernel
  source reading, *unverified* by test, and identical in VyOS. A `size` override
  would only move the threshold, so none is added.
- `set mark` in `output` filter/raw chains does not re-route locally generated
  packets. Only `type route` chains do, and VyOS's output chains are
  `type filter`. Policy routing belongs to [pbr](pbr.md).
- `set tcp-mss` rewrites the option only where it is present (SYN, SYN-ACK).
  Pair it with `tcp flags syn`. There is no `rt mtu` form; VyOS has that only
  under interfaces.
- A `set mark` value can coincide with a [pbr](pbr.md) `set table` mark
  (`0x7FFFFFFF - T`), as in VyOS.

**PM9. Show what was programmed.**
- nft-common defines `RenderedRule { line, matchers, statements, recent, frag }`,
  with `statements` always empty in its M1 (nft-common §3.1). This plan fills
  `statements` with the add-to-group and `set` statements, in emission order.
- `rule_conditions` prints `matchers` followed by `statements`. VyOS op-mode's
  Conditions column likewise keeps everything except counter, verdict and
  comment (`op_mode/firewall.py:97`). The string slicing at
  `firewall.rs:372-378` goes away.
- This plan owns how show prints `statements`; [fw-opmode](fw-opmode.md)
  consumes it.

**PM10. Live members come from the JSON already fetched.** `nft_counters`
(`firewall.rs:147-163`) already runs `nft --json list table`, and that output
carries `set` objects with
`elem: [{"elem": {"val": "192.0.2.7", "timeout": 3600, "expires": 3599}}]`
(observed on 1.0.9).
- Proposed: `fn parse_live(&Value) -> Live { counters: Counters, sets: HashMap<String, Vec<SetElem>> }`.
  `parse_counters` becomes `parse_live(..).counters`. No extra nft call.
- This plan owns `parse_live` and `SetElem`. [fw-opmode](fw-opmode.md) and
  [fw-dynamic-sources](fw-dynamic-sources.md) reuse them.
- `SetElem { val: String, timeout: Option<u64>, expires: Option<u64> }`. `val` also
  covers interval elements, which the `D_`/`R_`/`FQDN_`/`GEOIP_` sets of
  fw-dynamic-sources hold: a `{"prefix": {"addr", "len"}}` element becomes `a/n`
  and a `{"range": [a, b]}` element becomes `a-b`, bare or inside `{"elem": …}`.
  The JSON shapes are those of nftables 1.0.9 (*unverified* until the fixture
  below is captured).

**Rejected:**
- Per-hook renderer checks for `set` availability. The schema is the gate,
  because each hook's rule list has its own `set` container; the renderer
  trusts it.
- A `size` on DA sets (PM8).
- A separate `nft -j list set` call per group, which costs N extra subprocesses
  per show.

**Deviations to record in the module doc:** `dynamic-address-group` refs in
IPv4 raw rules; and, if milestone 7 lands, dynamic members carried across
applies.

## 4. Changes

### zebra-rs (`yang/firewall.yang`)

```yang
grouping set-dscp-mark-mss {
  leaf dscp    { ext:help "Set DSCP <0-63>"; type uint8 { range "0..63"; } }
  leaf mark    { ext:help "Set packet mark <1-2147483647> (bit 31 is reserved)";
                 type uint32 { range "1..2147483647"; } }
  leaf tcp-mss { ext:help "Set TCP MSS <500-1460>"; type uint16 { range "500..1460"; } }
}
grouping set-connection-mark {
  leaf connection-mark { ext:help "Set connection mark"; type uint32 { range "0..2147483647"; } }
}
grouping set-ttl       { leaf ttl       { ext:help "Set TTL <0-255>"; type uint8; } }
grouping set-hop-limit { leaf hop-limit { ext:help "Set hop limit <0-255>"; type uint8; } }
```

```yang
grouping set-packet-modifications-body  { uses set-dscp-mark-mss; uses set-connection-mark; uses set-ttl; }
grouping set-packet-modifications-body6 { uses set-dscp-mark-mss; uses set-connection-mark; uses set-hop-limit; }
```

Per-hook `container set { ext:help "Packet modifications"; … }`, following the
table in §2:
- ipv4 forward filter, output filter, output raw and `name`:
  `uses set-packet-modifications-body;`
- ipv4 prerouting raw: `uses set-dscp-mark-mss; uses set-ttl;`
- ipv6: the same, with `-body6` and `set-hop-limit`. Input filter gets none.
- [pbr](pbr.md) reuses the body groupings.

The hook rule lists are `firewall.yang:736-845` (ipv4) and `854-963` (ipv6).

Dynamic groups and add-to-group:

```yang
// under container group (firewall.yang:971)
container dynamic-group {
  ext:help "Firewall dynamic group";
  list address-group      { key "name"; leaf name { type string; } leaf description { type string { pattern '.*'; } } }
  list ipv6-address-group { key "name"; leaf name { type string; } leaf description { type string { pattern '.*'; } } }
}
// in rule-base (all filter + raw rule bodies, both families — VyOS includes it everywhere)
grouping add-to-group-target {
  leaf address-group { ext:help "Dynamic address-group name"; type string; }
  leaf timeout       { ext:help "Entry lifetime <N>s|m|h|d"; type string; }
}
container add-address-to-group {
  ext:help "Add the packet's address to a dynamic address-group";
  container source-address      { uses add-to-group-target; }
  container destination-address { uses add-to-group-target; }
}
// in l3-match-v4 and l3-match-v6 `container group`
leaf dynamic-address-group { ext:help "dynamic-group name; negate with !"; type string; }
```

- Drop both items from the deferred list in the module description.
- No exec grammar: live members ride the existing `show firewall group`.
- Config parse tests: `set firewall ipv4 forward filter rule 10 set tcp-mss 1360`
  parses. These must fail to parse, since the schema is the per-hook gate (the
  renderer trusts it, PM rejected-list):
  - `set … input filter rule 10 set dscp 1`;
  - `set … prerouting raw rule 10 set connection-mark 1`;
  - `set … forward filter rule 10 set mark 2147483648`.

### insomnia (`src/firewall.rs`, or the shared nft module where noted)

Model:

```rust
pub struct Groups { …, pub dynamic_group: Option<DynamicGroups> }
pub struct DynamicGroups { pub address_group: Vec<Group>, pub ipv6_address_group: Vec<Group> }
pub struct GroupRef { …, pub dynamic_address_group: Option<Flex> }
pub struct Rule { …, pub set: Option<SetActions>, pub add_address_to_group: Option<AddToGroup> }
pub struct SetActions { pub dscp: Option<Flex>, pub connection_mark: Option<Flex>, pub mark: Option<Flex>,
                        pub tcp_mss: Option<Flex>, pub ttl: Option<Flex>, pub hop_limit: Option<Flex>,
                        pub table: Option<Flex>, pub vrf: Option<Flex> }   // PBR only; ignored by render_set
pub struct AddToGroup { pub source_address: Option<AddTarget>, pub destination_address: Option<AddTarget> }
pub struct AddTarget { pub address_group: Option<Flex>, pub timeout: Option<Flex> }
```

Renderer. Line numbers are today's `firewall.rs`; after
[nft-common](nft-common.md) the same code lives in `group.rs`, `matcher.rs` and
`rule.rs`.
- Group sets (`render_group_sets`, `1322-1442`, then `group::render_sets`):
  `GroupKind::Dynamic` appends the `DA_` sets (Fam::V4) or `DA6_` sets
  (Fam::V6).
- The endpoint matcher (the `group_ref` closure, `1667-1699`, then
  `matcher::endpoint`) gains the dynamic arm after network.
- In `render_rule`:
  - after `out.push("counter")` (`1878`): first the add-to-group statements
    (destination, then source), then `render_set(set, fam)?`;
  - `ttl` on V6 or `hop-limit` on V4 returns `Err` (defensive; the schema
    prevents it);
  - `RenderedRule.statements` is filled (PM9).

**Worked example** (golden `set_and_dynamic_golden`). Config:

```json
{"group": {"dynamic-group": {"address-group": [{"name": "KNOCK"}],
                             "ipv6-address-group": [{"name": "SCAN"}]}},
 "ipv4": {
   "forward": {"filter": {"rule": [
     {"number": 10, "action": "accept", "protocol": "tcp",
      "tcp": {"flags": {"syn": null, "not": {"rst": null}}}, "set": {"tcp-mss": 1360}},
     {"number": 20, "action": "accept", "protocol": "udp",
      "set": {"dscp": 46, "mark": 16, "connection-mark": 7, "ttl": 64}}]}},
   "input": {"filter": {"rule": [
     {"number": 10, "action": "drop", "protocol": "tcp", "destination": {"port": 7000},
      "add-address-to-group": {"source-address": {"address-group": "KNOCK", "timeout": "30s"}}},
     {"number": 20, "action": "accept", "protocol": "tcp", "destination": {"port": 22},
      "source": {"group": {"dynamic-address-group": "KNOCK"}}}]}},
   "prerouting": {"raw": {"rule": [{"number": 10, "action": "accept", "protocol": "udp", "set": {"dscp": 0}}]}}},
 "ipv6": {"forward": {"filter": {"rule": [
     {"number": 10, "action": "continue", "set": {"hop-limit": 32},
      "add-address-to-group": {"source-address": {"address-group": "SCAN", "timeout": "1h"}}}]}}}}
```

Expected, with the default rules, matching the existing goldens (checked with
`nft -f` in a throwaway netns, nftables 1.0.9 / kernel 6.8):

```
table ip zebra_firewall {
    set DA_KNOCK {
        type ipv4_addr
        flags dynamic, timeout
    }
    chain ZEBRA_FORWARD_filter {
        type filter hook forward priority filter; policy accept;
        meta l4proto tcp tcp flags & (syn|rst) == syn counter tcp option maxseg size set 1360 accept comment "ipv4-FWD-filter-10"
        meta l4proto udp counter ct mark set 7 ip dscp set 46 meta mark set meta mark & 0x80000000 | 16 ip ttl set 64 accept comment "ipv4-FWD-filter-20"
        counter accept comment "FWD-filter default-action accept"
    }
    chain ZEBRA_INPUT_filter {
        type filter hook input priority filter; policy accept;
        meta l4proto tcp tcp dport {7000} counter set update ip saddr timeout 30s @DA_KNOCK drop comment "ipv4-INP-filter-10"
        meta l4proto tcp tcp dport {22} ip saddr @DA_KNOCK counter accept comment "ipv4-INP-filter-20"
        counter accept comment "INP-filter default-action accept"
    }
    chain ZEBRA_PREROUTING_raw {
        type filter hook prerouting priority raw; policy accept;
        meta l4proto udp counter ip dscp set 0 accept comment "ipv4-PRE-raw-10"
        counter accept comment "PRE-raw default-action accept"
    }
}
table ip6 zebra_firewall {
    set DA6_SCAN {
        type ipv6_addr
        flags dynamic, timeout
    }
    chain ZEBRA_FORWARD_filter {
        type filter hook forward priority filter; policy accept;
        counter set update ip6 saddr timeout 1h @DA6_SCAN ip6 hoplimit set 32 continue comment "ipv6-FWD-filter-10"
        counter accept comment "FWD-filter default-action accept"
    }
}
```

`nft list` prints rule 20's mark statement folded as
`meta mark & 0x80000010 | 0x00000010`, which is the same function.

**Show** (`show_groups_text`, `show_json_groups`, `group_references`):
- Dynamic groups are listed after the static kinds, with Type
  `address-group (dynamic)` or `ipv6-address-group (dynamic)`.
- Members come from `Live.sets["DA_<g>"]`, one per line in the VyOS
  detail-row format `192.0.2.7 (timeout: 30, expires: 12)`, with raw seconds as
  VyOS prints them. An empty set prints `N/D`.
- References count rules naming the group through `dynamic-address-group` or
  `add-address-to-group`, in the matching family only.
- JSON:
  `{"name":"KNOCK","type":"address-group","dynamic":true,"references":2,"members":[],"liveMembers":[{"address":"192.0.2.7","timeout":30,"expires":12}]}`.
- `process_show` passes the `Live` value it already fetched (`205-216`) into the
  group view. Today `/show/firewall/group` fetches counters but does not use
  them.
- Conditions in the chain tables show the statements (PM9). For example, rule
  20's Conditions read `meta l4proto udp ct mark set 7 ip dscp set 46 …`.

## 5. Tests

**Golden render:**
- `set_and_dynamic_golden`: the example above, full text.
- `set_statement_order`: all six `set` leaves and both add-to-group sides in
  one rule; asserts the VyOS order.
- `set_mark_keeps_frag_bit`: uses the [nft-common](nft-common.md) constant,
  not a literal.
- `set_mark_cradle_reserved_skipped`: `set mark 19511` (`0x4c37`) skips the rule
  with an Error finding; `19510` renders.
- `set_ipv6_hop_limit`, and `set_ttl_on_ipv6_rejected` (rule skipped, Error
  finding).
- `dynamic_sets_per_family`: DA_ only in ip, DA6_ only in ip6.
- `add_to_group_no_timeout`, and `add_to_group_bad_timeout_skipped` (`30x`,
  `s30`, empty).
- `dynamic_ref_negated`: `!KNOCK` → `ip saddr != @DA_KNOCK`.
- `dynamic_undefined_skipped`, for both the matcher and the add-target
  (`GroupIndex` from nft-common).
- Existing `golden_render` and `raw_hooks_and_fragment` unchanged: no churn
  without the new keys.

**Unit tests:**
- `model_deserializes_set_and_dynamic`.
- `parse_live_sets_from_nft_json`: fixture is the observed `nft -j list set`
  output with a `{"elem": {"val", "timeout", "expires"}}` element, plus a bare
  string element, a `prefix` element and a `range` element from an interval set.
- `show_groups_dynamic_members` (text and JSON).
- `rule_conditions_include_statements`.

**BDD** `@fw_dyn_group`:
- Topology: h1 and r1 on one bridge. It uses `insomnia_node.sh` from
  [fw-load-safety](fw-load-safety.md).
- Config: input rule 10 adds the source to `KNOCK` with `timeout 10s` on UDP
  7000 and drops; rule 20 accepts ICMP echo from `@DA_KNOCK`; rule 30 drops ICMP.
- Scenarios:
  1. Ping h1→r1 fails.
  2. After `I execute "bash -c 'echo > /dev/udp/<r1>/7000'" in namespace "h1"`,
     `show firewall group` on r1 eventually contains h1's address and the ping
     succeeds.
  3. After 12 s the ping fails again.
  4. A commit that adds an unrelated rule empties the group, documenting PM8.
  5. `set tcp-mss` and `set dscp` load (insomnia log "nftables ruleset applied")
     and their rule counters move under traffic. Packet rewriting itself is not
     asserted, because there is no capture step.
  6. Teardown.

## 6. Docs

- `ch-01-03-actions.md`: a new section "Packet modification (`set`)":
  - the §2 per-hook table;
  - the bit-31 reservation for `mark`;
  - an MSS clamp example (`forward filter`, `protocol tcp`, `tcp flags syn`,
    `set tcp-mss 1360`);
  - the output-hook no-reroute note and the `connection-mark` in `output raw`
    caveat.
- `ch-01-04-groups.md`: replace "Dynamic groups … not implemented yet"
  (`ch-01-04-groups.md:70-71`) with a dynamic-groups section covering `DA_`
  sets, `add-address-to-group`, timeouts, members lost on commit, the full-set
  behaviour and a port-knock example. Domain and remote groups stay "not
  implemented".
- `ch-03-00-show-firewall.md`: dynamic rows in the group view; statements in
  Conditions.
- Module doc: the PM7 deviation, plus the PM8 notes as known behaviour.

## 7. Milestones

| # | Scope | Repo | Effort | Done when |
|:--|:--|:--|:--|:--|
| 1 | `set` containers per hook (§2 table) + parse tests | zebra-rs | S | input-filter `set` refused; the others commit |
| 2 | FW7 renderer: `SetActions` + `render_set` in nft-common `rule.rs`, `RenderedRule.statements` + Conditions, body groupings for PBR, goldens | insomnia | S | goldens pass; script loads in a netns |
| 3 | `dynamic-group`, `add-address-to-group`, `dynamic-address-group` YANG | zebra-rs | S | parse tests |
| 4 | FW8 renderer: `GroupKind::Dynamic`, `set update`, refs, goldens | insomnia | S | goldens pass, including undefined-group skips |
| 5 | `parse_live` + dynamic rows in `show firewall group` (text/JSON) | insomnia | S | unit tests |
| 6 | BDD `@fw_dyn_group`; book ch-01-03 / ch-01-04 / ch-03-00 | insomnia | S | feature green; docs regenerated |
| 7 | Optional (P3): carry dynamic members across applies by appending `add element … { <addr> timeout <expires>s }` from the pre-apply `Live` to the same `nft -f` transaction; X12 compares only the pure render | insomnia | S | members survive an unrelated commit; module doc deviation |

FW7 (1–2) and FW8 (3–5) are independent. Order follows vyos-gap §5: FW7 with
X10 first.

## 8. Risks and open questions

- **Ordering with [nft-common](nft-common.md).** This plan must not land
  before nft-common's `rule.rs` split and its bit-31 work. Otherwise
  `render_set` has no home, and `set mark` would mix two schemes.
- **The full-set NFT_BREAK** (PM8) is *unverified* by test. A BDD that fills a
  set would need 65535 sources; leave it to a kernel-source citation in the
  docs.
- **Milestone 7** makes `process()` read live state before every apply. The
  carried elements are trusted data from our own table, but a member list
  that is huge (up to 65535) inflates the transaction. Cap it, or skip the
  carry-over above a threshold.
- **The `ct mark set` in `output raw`** effect is *unverified* (PM3).
- **Open:** should `show firewall group` also show live RECENT sets? VyOS does
  not. Not planned.

## 9. Acceptance criteria

- [ ] `set` leaves exist exactly where the §2 table says, with VyOS ranges
- [ ] Statement order and spelling match `parse_rule`; `set mark` uses the nft-common bit-31 constant and refuses cradle's `0x4c37`
- [ ] `SetActions` carries PBR's `table`/`vrf`, ignored by `render_set`; `parse_live` reads interval elements
- [ ] DA/DA6 sets, `set update` with and without timeout, `dynamic-address-group` refs (incl. `!`)
- [ ] Undefined dynamic groups and bad timeouts skip the rule with an Error finding (refused at commit while insomnia is connected); `nft -f` never fails on them
- [ ] Conditions show statements; `show firewall group` shows live members (text and `-j`)
- [ ] BDD `@fw_dyn_group` green; books updated; module doc deviations recorded
