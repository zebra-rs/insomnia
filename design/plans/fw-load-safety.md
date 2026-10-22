# Firewall load safety — implementation plan

Status: plan, 2026-10-21. Covers: X1, X2, X9, X12 ([vyos-gap](../vyos-gap.md) §3),
and §4.1 layer 3 (render-time skip-with-warning).
Priority: P1 (X1, X2) · P2 (X9) · P3 (X12) · Effort: M (four S items plus the
apply/exclude loop) · Owner: insomnia
Depends on: none · Unblocks: [nft-common](nft-common.md), [fw-matchers](fw-matchers.md),
[fw-zones](fw-zones.md), [fw-flowtable](fw-flowtable.md) (graph, index, X12),
[fw-opmode](fw-opmode.md) (chain graph), [commit-validation](commit-validation.md),
[nat](nat.md) (same apply loop), [fw-global-options](fw-global-options.md) (`process()`,
`insomnia_node.sh`), [fw-packet-modification](fw-packet-modification.md) (X2 skip path),
[fw-dynamic-sources](fw-dynamic-sources.md) (`RefIndex`, `plan_table`),
[fw-bridge](fw-bridge.md) (`plan_table` for the bridge table)

Assumes D1: until the validation RPC exists, every VyOS `verify()` rule is a render-time
skip. This plan's pre-pass is the code that RPC will call.

## 1. Goal

- Overlapping group members load: `10.0.0.0/8` + `10.1.0.0/16`, `80` + `80-90`, `eth0` +
  `eth*`, or an `include` that overlaps its parent. Today any of these fails the whole
  `nft -f -` and keeps the old ruleset.
- A reference to an undefined group, interface-group, jump target or default jump target
  skips only the rule that makes it, with a warning that names the rule. The same goes for
  a jump that closes a loop or goes too deep. A default action that cannot jump falls back
  to `drop`.
- When nft still rejects a script, the rules or groups it names are dropped and the apply
  is retried. When nothing can be applied, `show firewall` says so. The operator never
  depends on one log line to learn that the ruleset was not loaded.
- A `state-policy` entry with no `action` renders log + counter and no verdict, as VyOS
  does.
- A zebra-rs restart, or a commit that leaves the nft script unchanged, does not reload
  the tables. Counters and `RECENT_*` sets survive.

## 2. Current state

**insomnia** (`src/firewall.rs` @ `ee4dfaa`):
- `process()` parses, renders, sets `state.model`, then always runs `nft_apply`. On
  failure it logs `error!` plus the script at `debug` (`firewall.rs:84-105`). Every event
  is applied, including the snapshot that follows each resubscribe (`firewall.rs:56-82`).
- Group sets get `flags interval` and nothing more (`firewall.rs:1431-1439`).
  `collect_members` flattens includes. It cuts cycles silently through `seen` and does not
  de-duplicate members (`firewall.rs:1446-1482`).
- References are only syntax-checked with `safe_name`: group refs (`firewall.rs:1677`),
  interface-group (`1736`), jump-target (`1887`), default-jump-target (`1536`). A missing
  default target, or one that fails `safe_name`, already falls back to `drop` with a
  warning (`1534-1548`). An undefined but well-formed name is emitted as is.
- `render_rule` returns `Err` for a rule it cannot express, and `render_rules` warns
  `"{fam} {hook}-{label} rule {num}: {err} — rule skipped"` (`firewall.rs:1501-1511`). This
  plan reuses that path and that format.
- A state-policy entry with no action defaults to `accept` (`firewall.rs:1280-1284`).
- The module doc claims "a rendered script is always syntactically valid nft"
  (`firewall.rs:27-29`). The book makes the same claim (ch-01-00 "one bad rule never
  blocks the rest"). Both are false today.

**nft behaviour.** Re-checked for this plan with `nft -c` (nftables 1.0.9, Linux 6.8) in a
throwaway netns:

| Script fragment | `nft -c` |
|:--|:--|
| interval set `10.0.0.0/8,10.1.0.0/16` | `conflicting intervals specified` |
| same, plus `auto-merge` | ok |
| `inet_service` `80,80-90`; `ipv4_addr` `10.0.0.1,10.0.0.0-10.0.0.5` | conflict; ok with `auto-merge` |
| `ifname` `"eth0","eth*"` | conflict; ok with `auto-merge` |
| exact duplicates (`443,443`, `http,80`, a MAC twice) | ok without `auto-merge` |
| anonymous sets in rules: `tcp dport {80,80-90}`, `ip dscp {10,8-12}`, `meta mark {5,1-10}` | ok (nft merges anonymous sets itself) |
| `ip saddr @A_MISSING`, `iifname != @I_NOPE` | `No such file or directory`. Userspace phase: every such line is reported, and kernel-phase errors are hidden until this phase is clean |
| `jump NAME_GHOST` | `Could not process rule: No such file or directory` (kernel phase; all such lines reported) |
| jump to a base chain | `Could not process rule: Operation not supported` |
| `NAME_A` ↔ `NAME_B` loop, self-jump, base → loop | **rc 0** |
| `meta ipsec == 1` in an output-hook chain, or in a chain jumped from one | **rc 0** |
| `day {"Mon"}`, the book's own example (ch-01-02 line 95, `weekdays Mon,Tue,…`) | `Could not parse Day of week …; did you you mean 'Monday'?` |
| `ct state established log prefix "…" counter` (no verdict) | ok |

Diagnostics look like `/dev/stdin:13:18-27: Error: <msg>` when the script is piped in
(`<file>:` when it comes from a file), followed by the source line and a caret line. `-c`
does not run the kernel's commit-time validation: loops, jump depth, and per-hook
expression limits such as `meta ipsec`/`synproxy`. Whether the real commit rejects these,
and whether it then reports a line, is *unverified*: no non-check apply was run. Kernel
source reading says it does (ELOOP / EOPNOTSUPP).

**VyOS** (vyos-1x @ `7f2c893`):
- Every interval group set gets `auto-merge`: `data/templates/firewall/nftables-defines.j2`
  lines 10, 23, 73, 86, 99, 112. `nft_nested_group` appends included members, skipping any
  already present (`python/vyos/template.py:728-746`).
- `verify()` rejects these at commit:
  - missing jump target, plus loop detection and a warning at 8 levels
    (`src/conf_mode/firewall.py:182-213`, `261-271`);
  - missing or self default-jump-target (`600-613`);
  - missing or circular include (`507-521`);
  - missing group or interface-group (`verify_rule`, after line 420).
- `apply()` runs `nft -c`, and on failure maps the `comment "…"` in nft's error output to
  a ConfigError. Only then does it run `nft --file` (`firewall.py:734-782`).
- `nft_state_policy` emits no verdict when there is no action
  (`python/vyos/template.py:687-710`).
- VyOS reloads only on commit.

**zebra-rs:** `event_loop` runs `load_config()` (the startup commit) before it processes
any message, `ConfigSubscribe` included (`zebra-rs/src/config/manager.rs:2128-2136`). The
first snapshot after a zebra-rs restart therefore already holds the startup config, so
compare-before-apply sees "unchanged" and not a transient `{}`.

## 3. Design

### 3.1 X1: `auto-merge` and de-duplication

- Emit `auto-merge` after `flags interval` on every interval set: `A_`/`A6_`, `N_`/`N6_`,
  `P_` and `I_`. `M_` has no interval flag and stays as it is, as in VyOS. This is what
  fixes loading.
- De-duplicate the flattened member list, keeping the first occurrence: own members in
  config order, then each include depth-first. This is VyOS `nft_nested_group`, except
  that duplicates among own members are also dropped. YANG leaf-lists are unique, so that
  only matters for `Flex` spelling variants. De-duplication is cosmetic for nft, which
  accepts exact duplicates, but it keeps `show` and goldens stable.
- Report an include cycle instead of cutting it silently:
  `group include cycle LAN → DMZ → LAN: DMZ's include of LAN ignored`. VyOS rejects it.
- Port groups: `P_` is an `inet_service` interval set, so `80` + `80-90` and service names
  that overlap a range (`http` + `80-90`) conflict exactly like prefixes. Inline rule lists
  (`port 80,80-90`, `dscp`, `packet-length`, `mark`, `connection-mark`) become anonymous
  sets, which nft merges on its own (verified). They need no change.
- *Rejected:* merging intervals in insomnia. That duplicates nft's interval code for four
  element types, including the `ifname` wildcard. `auto-merge` is what VyOS uses.

### 3.2 X2: reference pre-pass

`plan_table(cfg, fam) -> TablePlan` runs before any line is emitted. It is pure, and the
validation RPC can call it ([commit-validation](commit-validation.md)).

1. **`RefIndex`.** It holds the nft set names the table will define, after `safe_name` and
   after any group exclusion (§3.3), and the custom chain names (`NAME[6]_x`) that pass
   `safe_name`. Port, mac and interface sets exist in both tables. Address and network
   sets are per family: an `ipv6` rule that names `address-group X` needs
   `ipv6-address-group X` (`A6_X`), as `firewall.rs:1683-1692` already assumes.
2. **Rule validity.** `render_rule` takes `&RefIndex`. An undefined group, interface-group
   or jump target becomes `Err(…)` and goes down the existing skip path. Negated
   references (`!NAME`) are checked on the bare name.
   - Errors: `address-group "MISSING" is not defined`, `interface-group "NOPE" is not
     defined`, `jump-target "NOWHERE" is not defined`.
   - *Policy:* skip the whole rule; never drop one matcher. Dropping one matcher broadens
     the rule: a `drop` rule loses its condition and drops everything. Emitting an empty
     set instead is also rejected, because `ip saddr != @A_EMPTY drop` drops everything.
3. **Default jump.** An undefined default-jump-target, or one equal to the chain itself,
   takes the existing fallback: `drop`, with
   `ipv4 FWD-filter: default-jump-target "GHOST" is not defined — using drop`. The comment
   keeps saying `default-action jump` (today's behaviour, `firewall.rs:1549`), so show
   counters still join.
4. **Jump graph.** Nodes are the base chains, which have no inbound edges, and the custom
   chains. Edges come from the rules that are still valid after step 2 and have
   `action jump`, plus the default jumps that survive step 3.
   - *Loops:* a depth-first search visits base chains in render order (forward filter,
     input filter, output filter, output raw, prerouting raw), then any custom chain not
     yet seen, in config order. It follows edges in rule-number order, with the default
     edge last. An edge into a chain that is still on the stack is a back edge and is
     removed. Removing every back edge leaves a DAG, and the result depends only on the
     config. A removed rule edge skips the rule:
     `jump to NAME_A loops (A → B → A) — rule skipped`. A removed default edge falls back
     to `drop`.
   - *Depth:* the longest path from each base chain. Warn at 8 jumps, as VyOS does. Skip
     any edge that would exceed 16, the kernel's `NFT_JUMP_STACK_SIZE` (the exact
     load-time boundary is *unverified*).
   - *Reachability:* `reaching_hooks(chain) -> HookSet` is computed here and exported.
     `HookSet` is a bit set over prerouting, input, forward and output (postrouting is
     reserved). [fw-matchers](fw-matchers.md) uses it to skip jumps from the output hook
     into chains that hold `ipsec` inbound or `synproxy` matches, and
     [fw-flowtable](fw-flowtable.md) uses it for `flow add`. `nft -c` catches none of
     these.
   - *Extension points* (proposed). These let other firewall features join the same graph
     and index instead of building their own:
     - `ChainGraph::add_entry(chain, HookSet)` registers a chain entered from base hooks.
       [fw-zones](fw-zones.md) uses it for `VZONE_<z>` (forward), `_IN` (input) and
       `_OUT` (output);
     - `ChainGraph::add_edge(from, to, origin)` adds a jump edge. fw-zones adds one per
       from, default-firewall and intra-zone jump, with the zone line's key as origin
       (`zone_LAN-from-WAN`). A removed zone edge is reported against that key, and
       fw-zones skips the jump+return pair;
     - `RefIndex::register(ObjKind, name)`, with `enum ObjKind { Set, Flowtable }`,
       registers other named objects: [fw-flowtable](fw-flowtable.md)'s flowtables
       (`Flowtable`), and [fw-dynamic-sources](fw-dynamic-sources.md)' per-rule
       `FQDN_*`/`GEOIP_*` sets (`Set`, so `reference` and the apply-loop exclusions treat
       them like group sets). Group-backed `D_`/`R_`/`DA_` sets need no call: they come
       from the group part of the index;
     - the loop, depth and reachability passes run after every registration.
   - *Bridge table.* `plan_table(cfg, Fam::Bridge, &ex)` ([fw-bridge](fw-bridge.md)) runs
     the same pre-pass over the bridge table: its own `RefIndex` (bridge sets and
     `NAME_` chains) and its own graph, whose base hooks are forward, input, output and
     prerouting. No second implementation.
5. **Warnings in render order.** The pre-pass stores reasons by rule comment key
   (`ipv4-FWD-filter-30`). `render_rules` emits them where the rule would have been, so the
   warning list is deterministic and goldens can assert it exactly.

### 3.3 Detecting a script nft still rejects

- **Considered: `nft -c` before every apply (what VyOS does). Rejected for the live path.**
  - `nft -f -` is already one transaction, so a failed apply changes nothing: `-c` adds no
    safety.
  - Verified above: `-c` misses exactly the commit-time errors that §3.2 has to prevent
    (loops, hook limits).
  - It doubles the cost of every commit.
- **Adopted: apply, then exclude and retry on the real error.**
  1. The renderer records an `Origin` for every output line:
     - `Rule(comment_key)` for a rule;
     - `Default(comment_key)` for a chain's default rule;
     - `Set(fam, set_name)` for every line from `set X {` to its `}`, and for the
       out-of-band `add element` fill lines of [fw-dynamic-sources](fw-dynamic-sources.md);
     - `Flowtable(fam, name)` for every line of a `flowtable` block
       ([fw-flowtable](fw-flowtable.md) F4);
     - `Fixed` for table and chain scaffolding, state-policy and frag chains.
  2. `nft -f -` fails → `parse_diags(stderr)` reads the `<src>:<line>:<c1>-<c2>: Error: <msg>`
     lines → each line number maps to its `Origin`.
  3. Exclusions:
     - `Rule` → exclude that rule;
     - `Set` → exclude that group. It is not emitted, so §3.2 then skips every rule that
       references it. This never broadens a rule;
     - `Default` → use the built-in default (accept for base chains, drop for custom);
     - `Flowtable` → the first time, render it without `flags offload` (software); the
       second time, exclude it. `RefIndex` then lacks it, so its offload rules take the
       missing-target skip, which only costs speed;
     - a `Fixed` line, or a diagnostic with no location → stop.
  4. Re-render with the exclusions and apply again. Allow at most 8 attempts. Each attempt
     removes at least one item, and nft reports errors in at most three passes: userspace
     evaluation, then kernel, then commit validation.
  5. Each exclusion becomes a warning:
     `ipv4 FWD-filter rule 50: rejected by nft (line 14: Could not parse Day of week …) —
     rule skipped`, or `address-group LAN: rejected by nft (line 9: conflicting intervals
     specified) — group skipped`.
  6. Total failure (a `Fixed` origin, no location, attempts exhausted, nft missing): the
     previous ruleset stays, as today. This is recorded in `ShowState.status`, and
     `show firewall` leads with it (§4.2).
- This catches whatever §3.1 and §3.2 miss: bad member syntax, the weekday spelling, a
  port matcher on a protocol with no ports, future renderer bugs. The real fixes for
  those stay in their own plans ([fw-matchers](fw-matchers.md) milestone 1, X14, for
  weekdays).
- `nft -c` is still used in two places:
  - an opt-in test that checks every golden (§5);
  - the dry-run validation RPC, where not touching the live ruleset matters. That is a
    requirement on [commit-validation](commit-validation.md): run `plan_table` and then
    `nft -c` on the candidate render, knowing that `-c` misses commit-time validation.

### 3.4 X9

A state-policy entry with no `action` renders
`ct state <s> [log prefix "[STATE-POLICY-<S3>-A]" [level L]] counter` with no verdict. The
log letter stays `A`, as in VyOS `nft_state_policy`. The packet then continues to the
rules of the base chain.

### 3.5 X12: compare before apply

- `ShowState` gains `applied: Option<Applied>`. `Applied` holds two values:
  - `rendered`, the first-attempt render, which is a pure function of the config;
  - `live`, the output of `nft -s -t list table ip zebra_firewall` and the same for `ip6`,
    captured right after the apply, with `<absent>` for a missing table. `-s` drops
    counters and `-t` drops set contents, so dynamic `RECENT_` members do not count as
    drift.
- Skip the apply when `rendered` is unchanged and a fresh listing equals `live`. That
  covers a resubscribe snapshot, and a commit that only changes `description`.
- Apply when the table was flushed or edited by hand, or when there is no previous apply.
  This keeps the self-healing that today's always-apply gives.
- Not persisted across insomnia restarts. An insomnia restart re-applies, as VyOS does at
  boot (open question §8).

### 3.6 Module-doc deviations to record (`firewall.rs` header)

- An undefined reference, a loop edge or an over-deep jump skips the rule. An unusable
  default jump becomes `drop`. VyOS rejects the commit.
- When nft rejects a script, the named rules or groups are dropped and the apply is
  retried. VyOS rejects the commit.
- Duplicate members are dropped. An include cycle is reported and cut. VyOS rejects
  cycles.
- An unchanged render does not reload; VyOS reloads on every firewall commit.
- Remove the claim at `firewall.rs:27-29`, or qualify it ("…or skipped by the apply
  loop").

## 4. Changes

### zebra-rs

None. YANG `mandatory`/`choice` constraints for the same rules belong to
[commit-validation](commit-validation.md) layer 1.

### insomnia (`src/firewall.rs`)

| Item | Change |
|:--|:--|
| `render_group_sets` (1322-1442) | `auto-merge` line when `kind.interval`; takes `&Exclusions`; returns the set names emitted |
| `collect_members` (1446-1482) | de-dup into `out`; cycle → warning naming the path |
| `Render` (1129-1160) | `origins: Vec<Origin>`; `line_from(indent, s, origin)` |
| new `struct RefIndex { sets: HashSet<String>, chains: HashSet<String>, flowtables: HashSet<String> }` + `register(ObjKind, name)`, `struct TablePlan { idx, skip: HashMap<String, String>, default_drop: HashMap<String, String>, reach: HashMap<String, HookSet> }`, `fn plan_table(cfg, fam, &Exclusions) -> TablePlan` (`fam` includes `Fam::Bridge` once fw-bridge lands) | §3.2 |
| `render_rule` (1556) | `idx: &RefIndex` parameter; `group_ref` closure (1669-1682), interface group (1729-1740) and jump (1882-1891) check `idx` |
| `render_default_rule` (1518-1551) | consults `plan.default_drop` |
| `render_rules` (1484-1514) | consults `plan.skip` first |
| state-policy (1280-1296) | no verdict when `action` is `None`; log letter `A` |
| `render(cfg)` (1173) | becomes `render_with(cfg, &Exclusions) -> Rendered { script, warnings, origins }`; `render()` = `render_with(cfg, &Exclusions::default())` (goldens unchanged in shape) |
| `nft_apply` (110-134) | returns `NftError::Rejected { stderr, diags }`; new `parse_diags(&str) -> Vec<Diag>` |
| new `async fn apply_loop<R: NftRunner>(cfg, runner) -> ApplyReport` | §3.3; `trait NftRunner { async fn run(&self, &str) -> Result<(), NftError>; async fn list_terse(&self) -> String; }` with `NftCli` and a test fake |
| `process` (84-105) | parse → `render_with(∅)` → X12 check → `apply_loop` → store `Applied` and `status` |
| `ShowState` (46-49) | `+ applied: Option<Applied>`, `+ status: ApplyStatus { Applied { skipped: usize } \| Kept { error: String } }`, `+ exclusions` (so `rule_conditions` shows `(not rendered)` for excluded rules) |
| `process_show` (195-281) | text views lead with the status line on `Kept`; JSON adds `"status": {"applied": bool, "error": …, "skipped": [...]}` |

In [nft-common](nft-common.md), `Origin`, `Exclusions`, `parse_diags`, `apply_loop`,
`NftRunner`, the group-set part of `RefIndex`, and the X12 decision (as
`nft::apply::apply_if_changed`) move to `crate::nft` unchanged. The chain graph
(`ChainGraph`, `TablePlan`, `reaching_hooks`) stays in the firewall backend, because zones
and flowtables extend it there.

**Worked example 1 (X1).** Config:

```json
{"group": {
  "network-group": [{"name": "LAN", "network": ["10.0.0.0/8", "10.1.0.0/16"], "include": ["DMZ"]},
                    {"name": "DMZ", "network": ["10.1.0.0/16", "192.0.2.0/24"]}],
  "port-group": [{"name": "WEB", "port": [80, "80-90", 443]}],
  "interface-group": [{"name": "UPLINK", "interface": ["eth0", "eth*"]}]}}
```

Expected render. Today's output is the same without the `auto-merge` lines and with
`10.1.0.0/16` twice in `N_LAN`, and `nft -c` rejects it on five lines. The expected text
below passes `nft -c`.

```
add table ip zebra_firewall
delete table ip zebra_firewall
add table ip6 zebra_firewall
delete table ip6 zebra_firewall
table ip zebra_firewall {
    set N_LAN {
        type ipv4_addr
        flags interval
        auto-merge
        elements = { 10.0.0.0/8,10.1.0.0/16,192.0.2.0/24 }
    }
    set N_DMZ {
        type ipv4_addr
        flags interval
        auto-merge
        elements = { 10.1.0.0/16,192.0.2.0/24 }
    }
    set P_WEB {
        type inet_service
        flags interval
        auto-merge
        elements = { 80,80-90,443 }
    }
    set I_UPLINK {
        type ifname
        flags interval
        auto-merge
        elements = { "eth0","eth*" }
    }
}
table ip6 zebra_firewall {
    set P_WEB { …same as above… }
    set I_UPLINK { …same as above… }
}
```

**Worked example 2 (X2).** Config:

```json
{"group": {"address-group": [{"name": "SERVERS", "address": ["10.0.0.1"]}]},
 "ipv4": {
  "forward": {"filter": {"default-action": "jump", "default-jump-target": "GHOST", "rule": [
    {"number": 10, "action": "accept", "source": {"group": {"address-group": "MISSING"}}},
    {"number": 20, "action": "accept", "inbound-interface": {"group": "!NOPE"}},
    {"number": 30, "action": "jump", "jump-target": "A"},
    {"number": 40, "action": "jump", "jump-target": "NOWHERE"},
    {"number": 50, "action": "accept", "destination": {"group": {"address-group": "SERVERS"}}}]}},
  "name": [
    {"name": "A", "rule": [{"number": 10, "action": "jump", "jump-target": "B"}]},
    {"name": "B", "rule": [{"number": 10, "action": "jump", "jump-target": "A"},
                           {"number": 20, "action": "return"}]}]}}
```

Expected `ip` table. This text passes `nft -c`; today's render fails on rules 10 and 20,
and then on 40 and the default rule.

```
table ip zebra_firewall {
    set A_SERVERS {
        type ipv4_addr
        flags interval
        auto-merge
        elements = { 10.0.0.1 }
    }
    chain ZEBRA_FORWARD_filter {
        type filter hook forward priority filter; policy accept;
        counter jump NAME_A comment "ipv4-FWD-filter-30"
        ip daddr @A_SERVERS counter accept comment "ipv4-FWD-filter-50"
        counter drop comment "FWD-filter default-action jump"
    }
    chain NAME_A {
        counter jump NAME_B comment "ipv4-NAM-A-10"
        counter drop comment "A default-action drop"
    }
    chain NAME_B {
        counter return comment "ipv4-NAM-B-20"
        counter drop comment "B default-action drop"
    }
}
table ip6 zebra_firewall {
}
```

Warnings, exactly and in this order:

```
ipv4 FWD-filter rule 10: address-group "MISSING" is not defined — rule skipped
ipv4 FWD-filter rule 20: interface-group "NOPE" is not defined — rule skipped
ipv4 FWD-filter rule 40: jump-target "NOWHERE" is not defined — rule skipped
ipv4 FWD-filter: default-jump-target "GHOST" is not defined — using drop
ipv4 NAM-B rule 10: jump to NAME_A loops (A → B → A) — rule skipped
```

**Worked example 3 (X9).** Config:
`"global-options": {"state-policy": {"established": {"log": null}, "invalid": {"action": "drop"}, "related": {}}}`
with an `ipv4 input filter` and no rules. The chain renders as follows in both tables
(this passes `nft -c`):

```
    chain ZEBRA_STATE_POLICY {
        ct state established log prefix "[STATE-POLICY-EST-A]" counter
        ct state invalid counter drop
        ct state related counter
        return
    }
```

**Show when nothing could be applied** (text). JSON carries the same fields under
`"status"`:

```
% Firewall ruleset from the last commit was NOT applied; the previous ruleset is still active.
% nft: /dev/stdin:3: Error: <message>
```

## 5. Tests

Golden-render tests, in `firewall::tests`. Each asserts the full script and the exact
warning list.

| Test | Reproduces |
|:--|:--|
| `x1_overlapping_members_auto_merge` | worked example 1 |
| `x1_address_range_overlaps_host` | `10.0.0.1` + `10.0.0.0-10.0.0.5` in one address-group |
| `x1_include_cycle_warns` | LAN ⇄ DMZ include; one warning; both sets render |
| `x1_golden_render_updated` | existing `golden_render` (2089-2193) gains `auto-merge` on `A_SERVERS`, `P_WEB` and `I_WAN` in both tables. A deliberate golden change; the commit message says why |
| `x2_dangling_references` | worked example 2 |
| `x2_family_scoped_group` | ipv6 rule naming `address-group X` where only the ipv4 group exists → skipped |
| `x2_self_jump_and_default_self` | custom chain whose rule and default both target itself |
| `x2_depth_limit` | chain of 18 custom chains → warning at 8, skip past 16 |
| `x2_show_marks_skipped` | `show_family_text` Conditions column shows `(not rendered)` for skipped rule 10 |
| `x9_state_policy_without_action` | worked example 3 |

Unit tests:
- `parse_diags_real_stderr`: fixtures are the verbatim `nft -c` outputs captured for this
  plan (the `/dev/stdin:13:18-27` and `/dev/stdin:6:22-31 … Could not process rule` shapes,
  plus a location-less `Error: Could not process rule: Operation not permitted`).
- `apply_loop_excludes_rule`: a fake `NftRunner` rejects the line of
  `ipv4-FWD-filter-50` once → second attempt omits it → one warning.
- `apply_loop_excludes_group_and_dependents`: the fake rejects a `set N_LAN` element line →
  `N_LAN` is absent → its referencing rule is skipped by the pre-pass.
- `apply_loop_gives_up`: a `Fixed` origin, or 9 consecutive rejections → status `Kept`, and
  the previous `Applied` is untouched.
- `x12_needs_apply` truth table over (no previous apply, render changed, live listing
  changed, both equal).

Opt-in check: `INSOMNIA_NFT_CHECK=1 cargo test nft_check_goldens -- --ignored` pipes every
golden through `sudo -n unshare -n nft -c -f -`. CI does not run it, since it needs root.

**BDD** `@fw_load_safety`:
- Topology: one router `r1` and host `h1` on a bridge.
- Node script: a new `tests/scripts/insomnia_node.sh`, which is `vrrp_node.sh` minus keepalived.
  It keeps the private `/run` and `/etc/swanctl`, and starts zebra-rs with
  `-c tests/configs/fw_load_safety/r1.conf` so that a restart reloads the same config.
  [nat](nat.md) and [commit-validation](commit-validation.md) plan the same generic
  script as `insomnia_node.sh`; it is one script, under whichever name lands first.
- Scenarios:
  1. **Setup.** Apply `r1.conf`: the X1 groups, plus the X2 rules on `input filter`.
     - `insomnia log … should eventually contain "nftables ruleset applied"`;
     - `command "nft list set ip zebra_firewall N_LAN" … contain "10.0.0.0/8"`;
     - the log contains each X2 warning.
  2. **Counters survive a zebra-rs restart.**
     - Ping 3 times from `h1` to a rule that counts ICMP.
     - `I execute "tests/scripts/fw_zebra_restart.sh fw_load_safety_r1" in namespace "r1"`.
     - The log contains `ruleset unchanged; not re-applied`.
     - The rule still shows `packets 3`.
  3. **Self-healing.** `nft flush ruleset` in `r1`, restart zebra-rs, and the table is
     back.
  4. **Teardown topology.**

## 6. Docs

- **ch-01-00:** qualify "one bad rule never blocks the rest". List what is skipped (rule,
  group, default jump), where the warnings go, and the `show firewall` status line.
- **ch-01-04 groups:**
  - overlapping members are merged;
  - included members are de-duplicated;
  - include cycles are cut with a warning;
  - a group nft rejects is skipped together with the rules that reference it.
- **ch-01-01 rules:** undefined jump targets, loops, the depth warning, and the `drop`
  fallback for default jumps.
- **ch-03-00 show firewall:** the status line and the JSON `status` object.
- **`firewall.rs` module doc:** §3.6.

## 7. Milestones

| # | Scope | Repo | Effort | Done when |
|:--|:--|:--|:--|:--|
| 1 | X1 + X9: `auto-merge`, de-dup, cycle warning, state-policy verdict; golden updates | insomnia | S | `x1_*`, `x9_*` pass; `golden_render` updated |
| 2 | X2 pre-pass: `RefIndex`, `TablePlan`, jump graph (loops, depth, reachability) | insomnia | S | `x2_*` pass; `reaching_hooks` exported for fw-matchers |
| 3 | Line origins, `parse_diags`, `apply_loop`, `ShowState.status`, show status line | insomnia | S | loop unit tests pass; show tests cover `Kept` |
| 4 | X12: `Applied`, terse live listing, skip decision | insomnia | S | `x12_needs_apply` passes |
| 5 | `insomnia_node.sh`, `fw_zebra_restart.sh`, `@fw_load_safety` feature, book chapters | insomnia | S | feature green locally; `make -C bdd docs` clean |

## 8. Risks and open questions

- **Commit-time validation errors.** For the errors `-c` misses (loops, hook limits),
  whether the real commit reports a line number is *unverified*. If it does not, the loop
  stops at "no location" and keeps the previous ruleset. The pre-pass is the primary
  defence, so add a BDD case that loads a loop rejected by a deliberately disabled
  pre-pass (test-only flag), to learn what nft prints.
- **Exact kernel jump-depth boundary** (16) is *unverified*. The pre-pass is conservative.
- **Skipping versus failing closed.** A skipped `drop` rule makes the ruleset more
  permissive than the operator wrote. This is the AGENTS.md policy, and the warning names
  the rule. Layer 2 of [commit-validation](commit-validation.md) is the real fix.
- **Persisting `Applied`** in `/run/insomnia/firewall/` would also keep counters across an
  insomnia restart, for example on upgrade. Deferred, because a stale file plus a
  hand-edited table could hide drift. The terse listing check mitigates that, so revisit
  when someone asks.
- **`nft -s -t` stability** with future stateful statements (`last`,
  [fw-matchers](fw-matchers.md)) is *unverified*. fw-matchers must re-check the X12 BDD
  scenario once `last-used` lands.

## 9. Acceptance criteria

- [ ] Every interval group set carries `auto-merge`; flattened members are unique and in
      order; an include cycle produces exactly one warning.
- [ ] Worked examples 1–3 are goldens, and each expected script passes `nft -c` in the
      opt-in test.
- [ ] An undefined group, interface-group, jump-target or default-jump-target, a loop
      edge or an over-deep jump never reaches nft.
- [ ] An nft rejection that has a location removes only the named rule or group, the apply
      succeeds within 8 attempts, and each exclusion is a warning.
- [ ] When nothing applies, the previous ruleset stays and `show firewall` (text and JSON)
      says so.
- [ ] A zebra-rs restart with an unchanged config does not reload, so counters survive
      (BDD). A flushed table is restored on the next snapshot.
- [ ] Module doc and book updated per §6.
