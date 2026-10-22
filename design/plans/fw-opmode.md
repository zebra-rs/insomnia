# Firewall op-mode — implementation plan

Status: plan, 2026-10-21. Covers: every row of the [vyos-gap](../vyos-gap.md)
§5 op-mode table except `zone-policy` (owned by [fw-zones](fw-zones.md)), plus
X11 and X15 (§3) and FW19 (§5). X15 is the zebra-rs show-routing defect;
milestone 1 fixes it.
Priority: P2 (rows range P2–P3) · Effort: M · Owner: both
Depends on: [fw-packet-modification](fw-packet-modification.md) (`RenderedRule.statements`,
`parse_live`), [fw-zones](fw-zones.md) (`text::table` multi-line cells, zone
default labels), [fw-load-safety](fw-load-safety.md) (`ChainGraph` for summary
references), [exec-verbs](exec-verbs.md) (shared `show log` container, insomnia
`ROUTES`, `generate` root and `EXEC_LOCAL`), [nft-common](nft-common.md) (`RenderedRule`);
soft: [fw-matchers](fw-matchers.md) (FW16 `last-used`) · Unblocks:
[fw-flowtable](fw-flowtable.md) (state-policy comment convention),
[nat](nat.md) and [pbr](pbr.md) (the group-use registry they publish into; soft),
[fw-bridge](fw-bridge.md) (bridge show/log slots),
[fw-dynamic-sources](fw-dynamic-sources.md) (the group view it adds rows to; soft)

## 1. Goal

- Every VyOS `show firewall …` command has a zebra-rs grammar path that insomnia
  answers. The text is VyOS-shaped and `-j` gives a structured equivalent.
- The X11 show bugs are gone:
  - group references are counted once per rule and only in the right family;
  - `-j` on a chain returns that chain, not the whole family.
- Custom-chain default rules carry VyOS's `NAM-<name>` label (FW19), so log
  prefixes and counters line up with VyOS.
- `show log firewall [ipv4|ipv6 [<hook> <prio> [rule N]] | name <c> [rule N]]`
  returns the matching kernel-log entries.
- zebra-rs show routing no longer depends on user-chosen names (X15). Today a
  chain named `bgp` sends `show firewall ipv4 name bgp` to BGP.
- `generate firewall rule-resequence` exists on the zebra-rs side. It is P3 and
  optional.

## 2. Current state

**Command inventory**

| VyOS command | zebra-rs path (proposed where new) | exec.yang change | insomnia work | Pri | M# |
|:--|:--|:--|:--|:--|:--|
| `show firewall`, `show firewall ipv4\|ipv6` | `/show/firewall`, `/show/firewall/<fam>` (exist) | no | state-policy section; JSON `statePolicy` and default rows | P2 | 3 |
| `show firewall <fam> <hook> <prio>`, `… name <c>` | exist | no | `-j` returns that chain (X11) | P2 | 2 |
| `… rule <N>` | `…/<prio>/rule` args `[N]`; `…/name/rule` args `[c, N]` | yes | single row, no default row | P2 | 5 |
| `… detail`, `… rule <N> detail` | `…/detail`, `…/rule/detail` | yes | vertical view with Description and Last Used | P3 | 5 |
| `show firewall group` | exists | no | references as rule paths; X11; dynamic rows (from fw-packet-modification) | P2 | 2, 5 |
| `show firewall group <g> [detail]`, `group detail` | `/show/firewall/group/name` `[g]`, `…/group/name/detail`, `…/group/detail` | yes | filter and vertical view | P3 | 5 |
| `show firewall summary` | `/show/firewall/summary` | yes | ruleset table, groups, flowtables | P3 | 5 |
| `show firewall statistics [detail]` | `/show/firewall/statistics[/detail]` | yes | per-rule source, destination and interfaces | P3 | 5 |
| `show log firewall [ipv4\|ipv6 …]` | `/show/log/firewall/…` | yes, plus provider prefix | journal reader and filter | P2 | 6 |
| `show firewall bridge …`, `show log firewall bridge …` | — | with [fw-bridge](fw-bridge.md) | — | P2 | — |
| `show firewall zone-policy [zone <z>]` | owned by [fw-zones](fw-zones.md) | | | P1 | — |
| `generate firewall rule-resequence [start N [step M]]` | zebra-rs only | yes (`generate` root) | none | P3 | 7 |

**zebra-rs @ 141da2fc.**
- Grammar:
  - `show firewall` is at `yang/exec.yang:310-408`: `group` and every hook
    container are `presence`, and `list name` is keyed `chain`.
  - There is no `rule`, `detail`, `summary`, `statistics` or `show log`.
  - zebra-rs's own named objects already use the `… name <n>` spelling
    (`show as-path-set name <n>`, `exec.yang:265-276`).
- Routing:
  - `SHOW_PROTOS` (`src/config/manager.rs:2077-2092`) checks predicates like
    `paths.iter().any(|x| x.name == "bgp")` (`is_bgp`, `1979-1981`) and
    `== "firewall"` (`is_firewall`, `2016-2021`).
  - `CommandPath.name` also carries matched values. KeyMatched entries hold the
    user's token (`src/config/paths.rs:80-100`; test `114-128` uses
    `cp("vrf1", 3)`).
  - So any chain, group, zone or VRRP group named `bgp`, `evpn`, `ospf`,
    `isis`, `pim` and so on routes to that protocol, because `is_bgp` is
    checked first. This is X15 in [vyos-gap](../vyos-gap.md) §3.
- `path_from_command` pushes Dir, Key and Leaf names into the path and
  *Matched values into args (`paths.rs:84-97`). A `type empty` leaf therefore
  lands in the path, as `received-routes ipv6` does (`exec.yang:584-590`); pin
  this with tests.

**insomnia @ ee4dfaa (`src/firewall.rs`).**
- `process_show` (`195-281`) is called inline in the task's `select!` (`76`),
  so a slow handler delays config processing.
- X11:
  - `group_references` (`537-584`) checks interface groups inside the
    `for side in [source, destination]` loop (`556-573`), counting them twice;
  - it iterates both families for every kind (`552`);
  - `show_hook` and `show_custom` return the whole family for `-j`
    (`480-482`, `498-500`).
- `chain_json` (`666-708`) has no default-rule row.
- State-policy rules carry no comment (`1279-1295`), so their counters cannot
  be joined.
- FW19: a custom chain's default rule is labelled with the bare chain name
  (`1251`). Its log prefix is `[ipv4-<name>-default-X]` (`1526-1531`) and its
  comment `"<name> default-action X"` (`1549`); the show mirrors this
  (`350-355`).
- `provider.rs:91-101` routes only `/show/firewall`, `/show/vpn/ipsec` and
  `/show/vrrp`. A `/show/log/…` order gets "% Unknown show command".
- Show replies are one eof chunk per order (`provider.rs:29-37`, `128-133`).

**VyOS @ 7f2c893.**
- `src/op_mode/firewall.py`:
  - `output_firewall_name` (`199-250`): table columns Rule, Action, Protocol,
    Packets, Bytes, Conditions. Detail is vertical with Description and Last
    Used; `rule N` drops the default row.
  - `output_firewall_state_policy` (`252-278`) reads only `VYOS_STATE_POLICY`
    (`101-129`). Since rolling split out `VYOS_STATE_POLICY_FORWARD`
    (`nftables.j2:216-230`), forward-path state-policy counters are missing
    from VyOS's show.
  - `output_firewall_name_statistics` (`280-405`).
  - `show_firewall_group` (`460-728`): `find_references` (`470-600`) is
    family-scoped (`473-482`), lists rule paths `{fam}-{hook}-{prio}-{rule}`
    (it skips prerouting, `486`) and adds NAT and policy-route paths; dynamic
    rows are at `607-655`.
  - `show_summary` (`730-774`): the References header is printed but never
    filled; IPv6 prints before IPv4.
- Grammar: `op-mode-definitions/firewall.xml.in`:
  - `group` with a `virtualTagNode` plus a `detail` leaf (`10-58`);
  - `rule` and `detail` under every chain;
  - statistics (`731-746`), summary (`747-753`).
- Logs: `op-mode-definitions/show-log.xml.in:183-…`.
  - The top level runs
    `journalctl --no-hostname --boot -k --grep='(ipv[46]|bri)-(FWD|INP|OUT|NAM)|STATE-POLICY'`
    (`187`), which misses PRE and zone defaults.
  - Rule level greps `\[ipv4-FWD-filter-$8-[ADRJCO]\]`.
  - `grep ipv4-NAM-$6` also matches chain `X-Y` when asked for `X`.
- Defaults: `nft_default_rule('NAM-' + name)` (`nftables.j2:151`,
  `template.py:667-685`), with the label truncated to 19 characters in the
  prefix.
- Resequence: `src/op_mode/generate_service_rule-resequence.py` prints
  renumbered `set` commands from the running config. It never commits.

## 3. Design

**O1. Grammar.**
- VyOS keywords everywhere, with one deviation: `show firewall group name <g>
  [detail]` instead of `show firewall group <g>`. This grammar cannot hold a
  list key beside the `detail` keyword without ambiguity, and zebra-rs's own
  sets already use `… name <n>`. Record it in the module doc and the book.
- Every chain view takes `detail` and `rule <N> [detail]` through one grouping.

**O2. Routing fix (zebra-rs, X15).**
- Protocol predicates look only at non-value segments: skip the KeyMatched,
  LeafMatched and LeafListMatched entries.
- Proposed helper: `fn keywords(paths: &[CommandPath]) -> impl Iterator<Item = &str>`,
  used by every `is_*` in `SHOW_PROTOS`.
- This lands first and stands alone. It also protects
  [fw-zones](fw-zones.md)' `zone-policy zone <z>`.
- It complements [exec-verbs](exec-verbs.md)' rule that new routes use exact
  leading-segment predicates. The old any-segment tests stay for existing
  roots, but no longer look at user-typed values.

**O3. JSON scope (X11).**
- A chain view returns that chain's `chain_json`; `name` without a key returns
  the custom chains only; `rule N` returns one rule object.
- `chain_json` gains `default: {action, log, packets, bytes}` and a per-rule
  `description`.
- JSON always carries the detail fields, so the `detail` keyword changes text
  only.

**O4. State policy section.**
- The renderer stamps `comment "STATE-POLICY-<state>"` on each
  `ZEBRA_STATE_POLICY` rule. This is a deliberate golden change: it makes the
  counters joinable, where VyOS text-parses `nft list chain`.
- The forward copy that [fw-flowtable](fw-flowtable.md) adds uses
  `STATE-POLICY-FWD-<state>` and `STATE-POLICY-FWD-offload`. The show sums
  `<state>` and `FWD-<state>`, which fixes the VyOS gap rather than copying it.
- Text: `<fam> State Policy` with columns State, Action, Packets, Bytes and
  Conditions, printed before the family's chains (VyOS order).

**O5. Group view.**
- References are counted once per (rule, group) match. The family scope
  follows `find_references`: address and network groups are IPv4,
  `ipv6-*` groups IPv6, and port, mac and interface groups both.
- The References column lists rule paths in VyOS format: `ipv4-forward-filter-20`,
  `ipv4-name-WEB-IN-10`, and also `ipv4-prerouting-raw-5` (VyOS skips
  prerouting; this is a superset). `N/D` when there are none.
- JSON keeps `references`, now a correct count, and adds `referencedBy`. The
  change is non-breaking.
- Description appears in the detail view only (VyOS).
- Cross-tree references go through a registry. This plan owns it; it is
  proposed:

  ```rust
  pub struct GroupUse { pub path: String, pub kind: GroupKind, pub name: String }
  pub type GroupUseRegistry = Arc<std::sync::RwLock<BTreeMap<&'static str, Vec<GroupUse>>>>;
  ```

  `main.rs` creates it and hands it to every nft backend. The firewall writes
  its `"firewall"` entry after each apply. [nat](nat.md) and [pbr](pbr.md)
  publish `nat-source-100` and `route-PBR-10` style paths after their own
  applies, so no query channel to the NAT task is needed (nat §8 agrees).
  Whichever of this plan's milestone 5 and the publisher lands second wires the
  publish; until then the view lists firewall paths only.
- Rows for `domain-group` and `remote-group` (members and freshness) come from
  [fw-dynamic-sources](fw-dynamic-sources.md) §3.7; this plan only lays the view
  out.

**O6. New views follow VyOS columns** and use `text::table` with multi-line
cells ([fw-zones](fw-zones.md)). The existing fixed-width chain tables stay
unchanged, so there is no churn.
- **`rule <N>`:** the chain header and that rule only. `% Rule N is disabled`
  or `% Rule N is not configured` otherwise.
- **`detail`:** one vertical block per rule: Rule, Description, Action,
  Protocol, Packets, Bytes, Last Used, Conditions.
  - Last Used is `N/A` until [fw-matchers](fw-matchers.md) ships `last-used`.
  - After that it is read from the rule's `last` expression in the nft JSON;
    the key name is *unverified*.
  - Conditions come from `RenderedRule.matchers` plus `.statements`
    ([fw-packet-modification](fw-packet-modification.md)).
- **`statistics [detail]`:** Rule, Packets, Bytes, Action, Source, Destination,
  Inbound-Interface, Outbound-interface. Source is the address, else the group
  name, else `any`. Later plans add domain, remote, fqdn and geoip.
- **`summary`:**
  - Per family: Ruleset Hook, Ruleset Priority, Description, References.
  - References are filled for custom chains from the chain graph
    ([fw-load-safety](fw-load-safety.md)): jumping rule paths,
    `default-jump-target` holders, and zone uses such as `zone-LAN-from-WAN`.
    VyOS never fills the column; this is a deviation.
  - Then the groups, then the flowtables ([fw-flowtable](fw-flowtable.md)).
  - IPv4 prints before IPv6 (deviation: VyOS prints IPv6 first).

**O7. FW19.**
- The custom-chain default label becomes `NAM-<name>`: prefix
  `[ipv4-NAM-WEB-IN-default-D]` (label truncated to 19 characters, as VyOS
  does) and comment `"NAM-WEB-IN default-action drop"`.
- One proposed function, `default_label(code, label, base) -> String`, is
  shared by the renderer (`1251`), the show's counter join (`350-355`) and the
  log filter (O8). [fw-bridge](fw-bridge.md) uses it for bridge custom chains
  (`[bri-NAM-<n>-default-<A>]`).

**O8. `show log firewall`: the log source.**
- Source: `journalctl -k -b -r -o json --no-pager`. Reading newest first lets
  the reader stop after N matches and kill the child, so a long uptime costs
  nothing. Parse `MESSAGE`; non-UTF-8 byte arrays are decoded lossily. Filter
  in Rust.
- Not `--grep`: it depends on a PCRE2-built journald, and a chain name would be
  spliced into a regex.
- Rejected:
  - `dmesg`: the ring buffer wraps and has no wall-clock time.
  - An nflog listener: it only sees `log-options group` rules and needs a
    long-lived socket.
  - Reading `/dev/kmsg`: it reimplements journald.
- If `journalctl` is absent, answer `% journalctl not available`.

**O8. `show log firewall`: the filter.**
- Parse the prefix token `[<fam>-<CODE>-<label>-<rule|default>-<A>]`, anchored
  on the known tail (`-<digits>-<A>]` or `-default-<A>]`), because chain names
  contain `-`. A request for `name X` matches label `X` exactly, and the
  default entry with label `default_label("NAM", X)`.
- Top level: everything that parses (FWD, INP, OUT, PRE, NAM and `zone_*`),
  plus `[STATE-POLICY-…]`. This is a superset of VyOS's grep, which misses PRE
  and zones. `<fam>` is `ipv4`, `ipv6` or, once [fw-bridge](fw-bridge.md) lands,
  `bri`.
- Rule-level filters accept any action letter (`[ADRJCO]` in VyOS).

**O8. `show log firewall`: the output.**
- At most the newest 1000 matching entries. Replies are a single chunk today.
- Text: `<ISO-8601 time> <MESSAGE>`, oldest first.
- JSON: `{"entries":[{"time","family","hook","chain","rule","action","message"}],"truncated":bool}`.
- The handler runs in a spawned task that owns the oneshot, with a 5 s time
  bound. This is the [exec-verbs](exec-verbs.md) D-8 rule that `show log vrrp`
  also follows, so the firewall `select!` loop is never blocked. It needs only
  the model's chain names, which are cloned in.
- A remote insomnia reads its own journal. That is the host whose nftables
  logged, so it is correct.
- Documented limits:
  - nflog (`log-options group`) entries never reach the kernel log;
  - netns logging needs `net.netfilter.nf_log_all_netns=1`;
  - `monitor log firewall` (streaming) does not fit the one-answer-per-order
    contract and is out of scope.

**O8a. Grammar placement and routing for `show log firewall`.**
- [exec-verbs](exec-verbs.md) D-6 owns the empty, insomnia-gated
  `container log` under `show`. This plan adds only the `firewall` child.
  [ipsec-opmode](ipsec-opmode.md) and [vrrp-hardening](vrrp-hardening.md) add
  `ipsec` and `vrrp` beside it.
- The `bridge` child of `show log firewall` (forward/input/output/prerouting
  `filter` and `name <c>`, each with `rule N`) is part of this plan's grammar,
  added in the same commit as [fw-bridge](fw-bridge.md)'s `firewall bridge`
  YANG (its M1) so it never appears without a bridge firewall.
- If this plan lands first, it creates the container with exec-verbs' text.
- Routing uses an exact predicate, `is_log_firewall` (leading segments
  `show log firewall`). It sits in `SHOW_PROTOS` ahead of the any-segment
  tests, as exec-verbs D-6 requires.
- insomnia: one row `(Show, "/show/log/firewall", Firewall)` in exec-verbs' D-8
  `ROUTES` table, or a prefix arm in today's `provider.rs` if-chain if `ROUTES`
  has not landed.

**O9. Resequence.**
- zebra-rs only, in-process: renumber the rule lists of the running `firewall`
  tree with start and step (defaults 100 and 10, VyOS) and print the `set`
  commands, never committing.
- It is the first user of [exec-verbs](exec-verbs.md)' `EXEC_LOCAL` table under
  its `generate` root (exec-verbs D-5/D-6). This plan adds only the
  `generate firewall rule-resequence [start N [step M]]` grammar and the
  handler; it never reaches insomnia.

**Deviations to record** (module doc and book): `group name <g>`; prerouting
and raw in references; summary References filled and IPv4 first; the log
top-level superset, the anchored chain match and the 1000-entry cap;
state-policy comments; forward state-policy counters summed.

## 4. Changes

### zebra-rs

`yang/exec.yang` (sketch):

```yang
grouping fw-chain-views {
  leaf detail { ext:help "List view with description and last-used"; type empty; }
  list rule {
    ext:help "One rule"; ext:presence "One rule"; key "number";
    leaf number { ext:help "Rule number"; type uint32 { range "1..999999"; } }
    leaf detail { ext:help "List view"; type empty; }
  }
}
// every `container filter|raw { presence …; }` under show firewall ipv4/ipv6, and `list name`:
//   uses fw-chain-views;
container group {                                  // replaces the bare presence container
  ext:help "Firewall groups and their members"; presence "All firewall groups";
  leaf detail { ext:help "List view"; type empty; }
  list name {
    ext:help "One group"; ext:presence "One group"; key "group";
    leaf group { ext:help "Group name"; type string; }
    leaf detail { ext:help "List view"; type empty; }
  }
}
leaf summary { ext:help "Ruleset and group summary"; type empty; }
container statistics {
  ext:help "Per-rule statistics"; presence "Per-rule statistics";
  leaf detail { ext:help "List view"; type empty; }
}
// child of exec-verbs' shared `container log` under `show` (exec-verbs D-6):
container firewall {
  ext:help "Firewall log entries (kernel log)"; presence "All firewall log entries";
  container ipv4 { ext:help "IPv4"; presence "IPv4 entries"; uses fw-log-hooks; }
  container ipv6 { ext:help "IPv6"; presence "IPv6 entries"; uses fw-log-hooks; }
}
grouping fw-log-rule { list rule { ext:presence "One rule"; key "number"; leaf number { type uint32 { range "1..999999"; } } } }
grouping fw-log-hooks {
  container forward    { presence "Forward hook";    container filter { presence "Forward filter";    uses fw-log-rule; } }
  container input      { presence "Input hook";      container filter { presence "Input filter";      uses fw-log-rule; } }
  container output     { presence "Output hook";     container filter { presence "Output filter";     uses fw-log-rule; }
                                                     container raw    { presence "Output raw";        uses fw-log-rule; } }
  container prerouting { presence "Prerouting hook"; container raw    { presence "Prerouting raw";    uses fw-log-rule; } }
  list name { ext:presence "One custom chain"; key "chain"; leaf chain { type string; } uses fw-log-rule; }
}
```

`src/config/manager.rs`:
- The O2 `keywords()` helper is used by all `is_*` predicates.
- `is_log_firewall` (O8a) goes into `SHOW_PROTOS` ahead of the any-segment
  tests, beside exec-verbs' other `show log` predicates.
- `show_firewall_grammar_gated_on_insomnia` (`7600-…`) gains cases:
  - `show firewall ipv4 forward filter rule 10 detail` →
    `/show/firewall/ipv4/forward/filter/rule/detail`, args `[10]`;
  - `show firewall ipv6 name WEB-IN rule 5` → `/show/firewall/ipv6/name/rule`,
    args `[WEB-IN, 5]`;
  - `show firewall group name SERVERS detail`, `show firewall summary`,
    `show firewall statistics detail`;
  - `show log firewall ipv4 name X rule 3` → `/show/log/firewall/ipv4/name/rule`,
    args `[X, 3]`.
- New routing test: `show firewall ipv4 name bgp`, `show vrrp detail group ospf`
  and `show log firewall` route to `firewall`, `vrrp` and `firewall`; existing
  BGP/OSPF cases are unchanged.
- Milestone 7: the `generate firewall rule-resequence [start N [step M]]`
  grammar under exec-verbs' `generate` root, and an `EXEC_LOCAL` row with its
  handler.

### insomnia

- Routing: the `(Show, "/show/log/firewall", Firewall)` row in exec-verbs'
  `ROUTES` table. Before that table lands, it is a prefix arm in
  `src/provider.rs` `dispatch` (`91-101`).
- `src/firewall.rs` (or the show submodule, if [nft-common](nft-common.md)
  splits the file):
  - `process_show`: a dispatch arm per new path, keyed on the path suffix
    (`/rule`, `/detail`, `/rule/detail`) over the existing hook and name arms.
  - New functions, all proposed: `show_rule`, `show_chain_detail`,
    `show_state_policy`, `show_group_filtered(name, detail)`, `show_summary`,
    `show_statistics(detail)`, and `fw_log::show(req, chains)` in a new
    `src/fw_log.rs`.
  - `group_references` → `group_uses(cfg) -> Vec<GroupUse>` (X11 fixed). It
    feeds the counts, the paths and the registry.
  - `default_label` (O7); state-policy comments (O4).
- `src/main.rs` creates the `GroupUseRegistry` and passes it to
  `firewall::run`, and later to `nat::run` and `pbr::run`.

**Worked examples.** With the existing `show_fixture` (`firewall.rs:2284-2306`):

`show firewall group`:

```
Firewall Groups

Name     Type           References              Members
-------  -------------  ----------------------  -----------------
SERVERS  address-group  ipv4-forward-filter-20  10.0.0.1
                                                10.0.0.2-10.0.0.5
```

`show firewall ipv4 forward filter rule 20` keeps the existing table format,
one row, no default row:

```
ipv4 Firewall "forward filter"

 Rule     Action     Protocol      Packets        Bytes  Conditions
 ----     ------     --------      -------        -----  ----------
 20       drop       tcp                 5          500  meta l4proto tcp ip daddr @A_SERVERS
```

The state-policy section, with
`global-options state-policy established action accept` and
`invalid action drop log`:

```
ipv4 State Policy

State        Action  Packets  Bytes   Conditions
-----------  ------  -------  ------  ------------------------------------------------
established  accept  4210     612000  ct state established
invalid      drop    12       720     ct state invalid log prefix "[STATE-POLICY-INV-D]"
```

The rendered state-policy chain becomes the following, which updates
`golden_render` deliberately (`firewall.rs:2162-2166`, `2185-2189`):

```
    chain ZEBRA_STATE_POLICY {
        ct state established counter accept comment "STATE-POLICY-established"
        ct state invalid log prefix "[STATE-POLICY-INV-D]" counter drop comment "STATE-POLICY-invalid"
        return
    }
```

FW19, for `ipv4 name WEB-IN default-action drop default-log`:

```
        counter log prefix "[ipv4-NAM-WEB-IN-default-D]" drop comment "NAM-WEB-IN default-action drop"
```

`show log firewall ipv4 input filter rule 10` (text):

```
2026-10-21T10:02:11+09:00 [ipv4-INP-filter-10-D] IN=eth0 OUT= MAC=… SRC=198.51.100.7 DST=192.0.2.1 … PROTO=TCP SPT=51515 DPT=22 …
```

## 5. Tests

**insomnia unit and golden tests:**
- X11: `group_uses_interface_group_once`, `group_uses_family_scoped`
  (same-named v4/v6 groups), `show_hook_json_single_chain`,
  `show_custom_json_single_chain`, `chain_json_default_row`.
- O4: `golden_render` updated, `state_policy_section_text`,
  `state_policy_sums_forward_copy` (fixture with `FWD-` comments).
- O7: `custom_chain_default_label_golden`, `custom_default_counter_join`,
  `default_label_truncates_19`.
- O6: `rule_view_single_row`, `rule_view_disabled`, `rule_view_missing`,
  `chain_detail_vertical`, `statistics_columns`, `summary_references`
  (jump, default-jump-target and zone sources), `group_name_filter`,
  `group_detail_vertical`, `registry_merges_foreign_uses` (fake `nat` entries).
- O8: `log_parse_prefix_*`, covering each hook, `zone_*`, `STATE-POLICY`,
  truncated defaults, and chain `X` versus `X-Y`.
  - `log_filter_by_path` uses a fixture of captured `journalctl -k -o json`
    lines plus synthetic messages.
  - `log_cap_newest_1000`, `log_missing_journalctl`, `log_non_utf8_message`.
- Provider: `dispatch_routes_show_log_firewall`.

**zebra-rs:** the grammar and routing tests in §4.

**BDD** (scenarios added to the first firewall feature; [fw-zones](fw-zones.md)'
`@fw_zone` is the likely host, or a small `@fw_show` on one router):
- `rule 10` shows only rule 10.
- `show firewall group` contains `ipv4-input-filter-10`.
- `summary` and `statistics` render.
- `-j` on a chain contains no other chain.
- `show log firewall` needs `nf_log_all_netns=1`, a host-global sysctl with no
  harness step and outside the clean-environment check. It stays a documented
  manual check; the filter logic is unit-tested.

## 6. Docs

- `book/src/ch-03-00-show-firewall.md`: sections for the state policy,
  `rule <N>`, `detail`, the group view (paths in References; `group name <g>`),
  `summary`, `statistics`, and per-chain `-j`. Replace the group example.
- `ch-01-04-groups.md`: the References example (`ch-01-04-groups.md:55-66`).
- `ch-01-11-firewall-logging.md`:
  - the custom-chain default prefix `[ipv4-NAM-<chain>-default-<A>]`;
  - zone and state-policy prefixes;
  - `show log firewall` usage, the 1000-entry cap, nflog and netns caveats.
- Module doc: the §3 deviation list.

## 7. Milestones

| # | Scope | Repo | Effort | Done when |
|:--|:--|:--|:--|:--|
| 1 | O2 routing fix (X15) + tests | zebra-rs | S | `show firewall ipv4 name bgp` reaches insomnia |
| 2 | X11 fixes, per-chain/rule JSON scope, `chain_json` default row | insomnia | S | X11 unit tests pass |
| 3 | FW19 + state-policy comments + state-policy section (goldens updated deliberately) | insomnia | S | goldens; commit message explains the golden change |
| 4 | Grammar: `fw-chain-views`, `group detail/name`, `summary`, `statistics` | zebra-rs | S | grammar tests |
| 5 | `rule`, `detail`, group paths + registry + `group name`, `statistics`, `summary` | insomnia | M | unit tests; BDD scenarios |
| 6 | `show log firewall` child + `is_log_firewall` (zebra-rs, on exec-verbs' container) + `ROUTES` row + `fw_log.rs` (insomnia) | both | S | unit tests; manual check on a host |
| 7 | Optional (P3): `generate firewall rule-resequence` as an exec-verbs `EXEC_LOCAL` row | zebra-rs | S | prints renumbered `set` commands; never commits |
| 8 | Book ch-03-00, ch-01-04, ch-01-11; module doc | insomnia | S | `mdbook build` clean |

Ordering:
- Milestone 1 should land before [fw-zones](fw-zones.md) milestone 1.
- Milestone 3 must precede [fw-flowtable](fw-flowtable.md) milestone 2, which
  uses the comment convention.
- Milestone 6 uses [exec-verbs](exec-verbs.md) E4 (the `show log` container)
  and E5 (`ROUTES`), or creates the container itself per O8a.
- Milestone 7 needs E3–E4 (`op_verb`, `EXEC_LOCAL`, the `generate` root).

## 8. Risks and open questions

- **The `group` text changes** (References become paths) break screen
  scrapers. JSON stays compatible.
- **`type empty` leaves as path segments** are assumed from
  `path_from_command`. If the parser does not end on Leaf for an empty leaf,
  switch to `container detail { presence …; }`; the paths are identical.
- **`last-used` JSON key** is *unverified* until fw-matchers lands; the column
  degrades to `N/A`.
- **The 1000-entry log cap** is arbitrary. Chunked replies would need backend
  streaming, which the `ShowRequest` oneshot (`src/api.rs:27-37`) does not
  have.
- **The registry only sees backends in this process**, which is by design: NAT
  and PBR are insomnia backends.
- **Open:** should `show firewall group <g>` (the VyOS spelling) also parse,
  through a zebra-rs alias? It is ambiguous with `detail`, so not planned.

## 9. Acceptance criteria

- [ ] Routing ignores matched values (X15); the regression tests pass
- [ ] X11 fixed; `-j` scoped per chain and per rule
- [ ] FW19 label everywhere: renderer, counter join, log filter
- [ ] State-policy section with counters, summing the forward copy when present
- [ ] `rule <N> [detail]`, chain `detail`, `group [detail]`, `group name <g> [detail]`, `summary`, `statistics [detail]` (text and `-j`)
- [ ] `show log firewall …` with an anchored filter, a cap, and a non-blocking handler
- [ ] `GroupUseRegistry` defined; firewall publishes; NAT/PBR can publish
- [ ] Book and module-doc deviations updated
