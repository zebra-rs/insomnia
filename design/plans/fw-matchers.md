# Firewall matchers — implementation plan

Status: plan, 2026-10-21. Covers: X14 ([vyos-gap](../vyos-gap.md) §3, a Phase 0
defect), then FW2, FW15, FW16, FW17, FW18 (§5).
Priority: P1 (X14, FW2) · P3 (the rest) · Effort: L in total (each item S) · Owner: both
Depends on: [nft-common](nft-common.md) (`crate::nft::rule::render_rule`, where every
matcher goes), [fw-load-safety](fw-load-safety.md) (`reaching_hooks`, the apply loop, and
`Applied` for the FW17 refresh); soft: [commit-validation](commit-validation.md)
(`findings.rs`; until C1 the skips are plain warnings), [conntrack](conntrack.md) (FW15
matches only once helpers are assigned) · Unblocks: [pbr](pbr.md) (matcher parity, since
PBR shares `parse_rule`), [fw-opmode](fw-opmode.md) (the `last-used` column),
[fw-bridge](fw-bridge.md) (`ipsec` and `last-used` in bridge rules; soft), [docs-corrections](docs-corrections.md) (the ch-01-02 weekday example waits on X14)

Milestone 1 (X14) does not wait for nft-common or fw-load-safety: it is a Phase 0 fix
in today's `render_time`, and moves with the code when nft-common lands.

Assumes D1: each VyOS `verify()` rule listed here becomes a render-time skip. The same
check later answers the validation RPC ([commit-validation](commit-validation.md)).

## 1. Goal

- **X14 (first, Phase 0).** `time weekdays Mon,Tue,…`, the book's own ch-01-02 example,
  renders `day {"Monday","Tuesday",…}`, so it no longer makes nft reject the whole
  ruleset.
- **FW2.** `rule … ipsec match-ipsec-in|match-none-in|match-ipsec-out|match-none-out`
  works on every hook where VyOS offers it. An input chain can accept decrypted traffic and
  drop cleartext from the same prefix, which is what insomnia's own policy-based IPsec
  needs.
- **FW15, FW16.** These match like VyOS:
  - `conntrack-helper`, `fib`, `gre`, `mac-address-mask`;
  - `last-used`;
  - `action synproxy` with `synproxy tcp mss|window-scale`;
  - `disable-conntrack` on the forward, input and output filter hooks.
- **FW17.** `time` matches the same wall-clock window in every timezone:
  - one `hour "a"-"b"` range, which may cross UTC midnight;
  - negated weekdays are kept (on top of the X14 expansion);
  - the hour rules are reloaded in place when the UTC offset changes.
- **FW18.** A config that VyOS would reject never gets broadened silently:
  - `address-mask` applies to address-group references;
  - `queue` accepts a range, so `fanout` works;
  - `recent` with only `count` or only `time`, and `inbound-interface name` together with
    `group`, skip the rule with a warning instead of dropping a matcher.

## 2. Current state

**insomnia** (`src/firewall.rs` @ `ee4dfaa`; after [nft-common](nft-common.md) the same
code lives in `crate::nft::rule`):
- `render_rule` follows VyOS `parse_rule` order (`firewall.rs:1556-1916`). None of the FW2,
  FW15 or FW16 matchers exist.
- Endpoint `address-mask` applies to `address` only (`1619-1636`). Group references ignore
  it (`1667-1699`).
- Interface matchers: `name` wins over `group` silently (`1721-1740`).
- `recent` renders only when both leaves are set and is dropped silently otherwise
  (`1813-1815`).
- `queue` is rendered as `to N` (`1892-1902`). The YANG leaf is `uint16`
  (`zebra-rs/yang/firewall.yang:258-261`), so `0-3` cannot be entered.
- `render_time` (`1954-2013`):
  - emits `hour >= "a"` and `hour < "b"` separately (`1977-1998`). nft converts both to UTC
    when it loads the rule, so a window that crosses UTC midnight never matches. Example:
    09:00–17:00 at UTC+10 becomes `>= 23:00 && < 07:00`;
  - passes weekdays through verbatim (`1999-2011`). nft accepts only `"Monday"`-style names
    or 0–6: `day {"Mon"}` fails with `Could not parse Day of week …` (verified with
    `nft -c`), so the book's example (ch-01-02, lines 93-97) fails to load the whole
    ruleset. This is X14 in vyos-gap §3;
  - drops `!`-negated days, which turns `!Sat,!Sun` into "every day".

**zebra-rs** (`zebra-rs/yang/firewall.yang` @ `141da2fc`):
- The module description lists `conntrack-helper, ipsec and synproxy matchers` as
  deferred (`19-46`).
- Rule bodies:
  - `rule-base` (`163-393`), shared by filter and raw rules;
  - `rule-common` (`395-478`), filter rules (action list at `397-408`);
  - `rule-raw-common` (`480-496`);
  - endpoints `l3-match-v4|v6` (`498-598`);
  - interface containers `match-interface-in|out` (`129-157`).
- Per-hook composition:

  | Family | forward filter | input filter | output filter | output raw | prerouting raw | name |
  |:--|:--|:--|:--|:--|:--|:--|
  | ipv4 | 736-744 | 752-759 | 767-774 | 779-786 | 814-822 | 836-843 |
  | ipv6 | 854-862 | 870-877 | 885-892 | 897-904 | 932-940 | 954-961 |

- zebra-rs has `choice` with sibling-case purge on set (`zebra-rs/src/config/configs.rs:646-650`).
  `mandatory` is enforced only when the parent container exists (`configs.rs:552-571`).
  A childless presence container marshals as `{}` (`configs.rs:409-419`).

**VyOS** (vyos-1x @ `7f2c893`):

| Item | Schema (`interface-definitions/include/firewall/`) | Hook placement | Render (`python/vyos/firewall.py`) | verify (`src/conf_mode/firewall.py`) |
|:--|:--|:--|:--|:--|
| FW2 | `match-ipsec.xml.i`, `match-ipsec-in.xml.i`, `match-ipsec-out.xml.i` | in: `ipv4-hook-input`, `ipv4-hook-prerouting`; out: `ipv4-hook-output` (filter and raw); both: `ipv4-hook-forward`, `ipv4-custom-name` (ipv6 the same) | `455-463`: `meta ipsec == 1\|0`, `rt ipsec exists\|missing` | `357-361` not both per direction; `195-202` chains jumped from output may not hold inbound matches |
| FW15 | `conntrack-helper.xml.i` (multi; ftp h323 pptp nfs sip tftp sqlnet, regex also rtsp) | `common-rule-inet` (filter, name) | `123-135`: h323→`RAS`,`Q.931`; nfs→`rpc`; sqlnet→`tns` | — |
| FW16 fib | `fib.xml.i` (lookup multi source-address\|destination-address; match route-type with `!`) | `common-rule-ipv4[-raw]`, ipv6 | `170-192` | `fib` needs lookup and match, not both lookups |
| FW16 gre | `gre.xml.i` (flags key\|checksum\|sequence [unset], inner-proto, key, version gre\|pptp) | `common-rule-inet` | `484-517`, `parse_gre_flags` `676-700` | protocol gre; key ⇒ explicit checksum flag; key excludes `flags key unset`; no key with pptp |
| FW16 mac-address-mask | `mac-address-mask.xml.i` | source/destination, all ipv4/ipv6 rules | `266-276` | requires mac-address |
| FW16 last-used | `last-used.xml.i` | all ipv4/ipv6 rules incl. raw | `585-586` (`last` before `counter`) | — |
| FW16 synproxy | `action.xml.i` (`synproxy` action), `synproxy.xml.i` (mss 501-65535, window-scale 1-14) | `common-rule-inet` | `378-379` `ct state invalid,untracked`; `660-667` `mss N wscale W timestamp sack-perm` | `synproxy` only with that action; no `state`; mss required; protocol tcp |
| FW16 disable-conntrack | `disable-conntrack.xml.i` | `ipv4\|ipv6-hook-{forward,input,output}` filter heads | `data/templates/firewall/nftables.j2:156-173`, `353-370` (chains at -320) | `state` forbidden in those chains; a warning with state-policy |
| FW17 time | `time.xml.i` | `common-rule-inet`, raw | `parse_time` `720-743`, `expand_weekday` `707-717`; refresh helper `src/helpers/vyos-nft-time-refresh.py` | — |
| FW18 | `address-mask.xml.i`, `nft-queue.xml.i` (queue `--allow-range 0-65535`), `recent.xml.i` | — | group mask `302-319` (address groups only); queue `651-658` | queue-options/fanout need a queue range (V9); recent needs both leaves (V15); name xor group (V23) |

Verified with `nft -c` (nftables 1.0.9, Linux 6.8): every expected snippet in §4. Not
caught by `-c`: `meta ipsec` in an output-hook chain or a chain jumped from one (rc 0).
The real commit rejects it in the kernel's hook validation; that is *unverified* here and
comes from kernel-source reading (`nft_meta_get_validate`, secpath limited to
prerouting/input/forward). VyOS's own comment says the same at
`src/conf_mode/firewall.py:199`.

## 3. Design

- **Placement.** Every matcher is added to `crate::nft::rule::render_rule` at its VyOS
  `parse_rule` position. PBR then inherits it for free:
  - after `state`: conntrack-helper;
  - after `protocol`: fib;
  - inside the endpoint: mac mask, group mask;
  - after the endpoints: the synproxy `ct state`;
  - after `dscp`: ipsec;
  - after `recent`: gre;
  - after `log`: `last`;
  - after the verdict: the synproxy options.
- **Skip, never broaden.** Each VyOS `verify()` rule in the table above that guards a
  matcher returns `Err` from `render_rule`, so the whole rule is skipped with a warning
  ([fw-load-safety](fw-load-safety.md) §3.2). This replaces today's silent drops for
  `recent` and interface name+group.
- **Hook reachability** (FW2 inbound matches, synproxy). `render_rule` cannot see the
  hook of a custom chain. Two checks cover it:
  - the firewall's pre-pass scans every custom chain for "hook-limited" expressions;
  - a jump rule whose target (transitively) holds one is skipped when it sits in a chain
    reachable from an incompatible hook. It uses `reaching_hooks` from fw-load-safety.

  Limits:

  | Expression | Allowed hooks (kernel validate) | Source |
  |:--|:--|:--|
  | `meta ipsec` (FW2 in) | prerouting, input, forward | VyOS `firewall.py:195-202`; kernel *unverified* |
  | `synproxy` | input, forward | kernel `nft_synproxy_validate` *unverified* |
  | `rt ipsec` (FW2 out) | any (never true before routing) | warn only when reachable from input/prerouting |

  Base chains are already safe, because the YANG offers only the right leaves per hook.
- **Choices.** FW2's `match-ipsec-in`/`match-none-in` pair and FW18's interface
  `name`/`group` pair become YANG `choice`s:
  - setting one purges the other in zebra-rs (`configs.rs:646-650`). VyOS rejects the
    commit instead. Record that as a deviation in the module doc;
  - the renderer still checks, for configs written before the YANG change.
- **X14 weekday expansion** (milestone 1, ahead of everything else here). VyOS
  `expand_weekday` (`python/vyos/firewall.py:707-717`): each positive weekday is
  matched case-insensitively against `Mon`…`Sun` and the full names and rendered
  title-cased in full (`day {"Monday",…}`); numerals pass through (`day {"1"}` is accepted
  by nft). Any other token skips the rule with `time weekdays "Xyz" is not a weekday`,
  instead of failing the load. `!`-negated days keep today's handling until FW17. It is
  a small change to `render_time` in `firewall.rs`, needs no YANG change, and does not
  wait for nft-common.
- **FW17 rendering.** `parse_time` line for line:
  - date bounds: `time >= "D[ T]"`, `time < "D[ T]"`;
  - one `hour "start|00:00"-"stop|23:59:59"` when a time has no date;
  - `day {…}` through the X14 expansion.
  - Deviations:
    - all-negated weekdays render `day != {…}`. VyOS renders `day {}`, which nft rejects;
    - mixed `Mon,!Tue` keeps the positives and warns.
  - Values are checked against VyOS's regexes (`hh:mm[:ss]`, `YYYY-MM-DD`), which
    zebra-rs cannot express without a pattern.
- **FW17 refresh.** VyOS re-arms a systemd timer (`vyos-nft-time-refresh.py --arm`). In
  insomnia:
  - the firewall task holds `next_refresh: Option<Instant>`, set by
    `next_offset_change(now)`. That function binary-searches `libc::localtime_r` →
    `tm_gmtoff` over ≤ 400 days, after `libc::tzset()`, exactly like VyOS's
    `next_offset_change`;
  - the run loop gets a third `select!` arm. When it fires (+5 s past the change), insomnia
    takes the `hour "` lines from `Applied` ([fw-load-safety](fw-load-safety.md)), finds
    their handles with `nft -j -a list table`, and sends one batch of
    `replace rule <fam> zebra_firewall <chain> handle <h> <line>`. That keeps counters and
    sets;
  - if the batch fails, fall back to a full apply;
  - re-arm after every apply and every refresh.
  - *Rejected:* a systemd timer (insomnia runs in containers and BDD without systemd
    control), and a 60 s poll (VyOS is exact to the second).
- **FW16 `last-used`.**
  - `counters::strip_tail` must also cut the trailing ` last`, so the Conditions column
    stays as it is today;
  - the "Last Used" column belongs to [fw-opmode](fw-opmode.md). The nft JSON shape of
    `last` is *unverified*;
  - fw-load-safety's X12 check uses `nft -s -t`. Re-check that `-s` hides `last used`.
- **FW16 `disable-conntrack`.** Chains are named `ZEBRA_DISABLE_CONNTRACK_INP_FWD[_V6]`
  (prerouting -320) and `ZEBRA_DISABLE_CONNTRACK_OUT[_V6]` (output -320). Each holds the
  VyOS `fib daddr . iif type unicast|local notrack` / `notrack` lines with their `DISABLE-CT-*`
  comments. A rule with `state` in an affected chain is skipped (VyOS V8). A state-policy
  then produces one warning, as in VyOS.
- **FW15** renders the matcher only. Helpers are assigned by `system conntrack modules`
  ([conntrack](conntrack.md)). Until then insomnia warns once per commit:
  `conntrack-helper matches only connections with an assigned helper (system conntrack modules)`.
- **FW18 queue.** The YANG leaf becomes a union of `uint16` and a range string. Render
  `to 0-3`. Skip when `fanout` has no range, or when queue or queue-options appear without
  `action queue`.

Module-doc deviations to add:
- `choice` purges instead of rejecting;
- `day != {…}` for all-negated weekdays;
- the time refresh is an in-process timer;
- jump rules into chains holding hook-limited matches are skipped, not rejected;
- with `rt ipsec` reachable from input/prerouting, insomnia only warns.

## 4. Changes

### zebra-rs (`zebra-rs/yang/firewall.yang`)

```yang
  // VyOS include/firewall/match-ipsec{,-in,-out}.xml.i, split by direction
  // so each hook offers only what it can evaluate.
  grouping ipsec-in-leaves {
    choice ipsec-in {
      case match-ipsec-in { leaf match-ipsec-in { ext:help "Inbound traffic that was IPsec encapsulated"; type empty; } }
      case match-none-in  { leaf match-none-in  { ext:help "Inbound traffic that was not IPsec encapsulated"; type empty; } }
    }
  }
  grouping ipsec-out-leaves { /* match-ipsec-out / match-none-out, same shape */ }
  grouping match-ipsec-in  { container ipsec { ext:help "Inbound IPsec packets";  uses ipsec-in-leaves; } }
  grouping match-ipsec-out { container ipsec { ext:help "Outbound IPsec packets"; uses ipsec-out-leaves; } }
  grouping match-ipsec     { container ipsec { ext:help "IPsec encapsulated packets";
                               uses ipsec-in-leaves; uses ipsec-out-leaves; } }
```

| Item | YANG change (VyOS include) | Where |
|:--|:--|:--|
| FW2 | `uses match-ipsec-in` / `match-ipsec-out` / `match-ipsec` | in: input filter, prerouting raw; out: output filter and raw; both: forward filter, name. Line ranges in §2, both families |
| FW15 | `leaf-list conntrack-helper { type enumeration { ftp h323 pptp nfs rtsp sip tftp sqlnet } }` (`conntrack-helper.xml.i`; `rtsp` from its regex) | `rule-common` |
| FW16 fib | `container fib { leaf-list lookup { enum source-address; enum destination-address; } container match { leaf route-type { type union { enumeration {local unicast broadcast multicast anycast blackhole unreachable prohibit} type string; } } } }` (`fib.xml.i`; the string arm carries `!x`) | `rule-match-v4`, `rule-match-v6` (filter and raw) |
| FW16 gre | `container gre { container flags { container key { presence "…"; leaf unset {type empty;} } /* checksum, sequence: same */ } leaf inner-proto { type union { enumeration {ip ip6 arp 802.1q 802.1ad gretap} type uint16; type string; } } leaf key { type uint32; } leaf version { type enumeration { enum gre; enum pptp; } } }` (`gre.xml.i`) | `rule-common` |
| FW16 mac mask | `leaf mac-address-mask { type yang:mac-address; }` (`mac-address-mask.xml.i`) | `l3-match-v4`, `l3-match-v6` |
| FW16 last-used | `leaf last-used { type empty; }` (`last-used.xml.i`) | `rule-base` |
| FW16 synproxy | `enum synproxy` in `rule-common` action; `container synproxy { container tcp { leaf mss { type uint16 { range "501..65535"; } } leaf window-scale { type uint8 { range "1..14"; } } } }` (`action.xml.i`, `synproxy.xml.i`) | `rule-common` |
| FW16 disable-conntrack | `leaf disable-conntrack { type empty; }` (`disable-conntrack.xml.i`) | directly in the forward/input/output `filter` containers (not `chain-base-head`, which raw shares) |
| FW17 | help text only: `weekdays` "Monday…Sunday, Mon…Sun or 0-6; negate with !" | `rule-base` `time` (368-392) |
| FW18 queue | `leaf queue { type union { type uint16; type string; } }`, help "<0-65535> or range <start-end>" (`nft-queue.xml.i`) | `rule-base` (258-261) |
| FW18 interface | `choice match { case name {…} case group {…} }` inside `inbound-interface` / `outbound-interface` | `match-interface-in/out` (129-157); NAT reuses them |

- Also update the module description (`19-46`): drop `conntrack-helper, ipsec and
  synproxy` from the deferred list.
- Layer-1 constraints requested from [commit-validation](commit-validation.md):
  - `mandatory true` on `recent count` and `recent time`;
  - `ext:non-empty` on `fib` and `gre`.
- No `exec.yang` change: show grammar is unchanged.
- JSON tests to add in zebra-rs: each new container's marshal shape. Choice nodes must not
  appear in the data tree, and `flags key {}` must stay `{}` (*unverified* until written).

### insomnia

`crate::nft::rule` model:
- `Rule` gains `ipsec: Option<IpsecMatch>`, `conntrack_helper: Vec<Flex>`,
  `fib: Option<Fib>`, `gre: Option<Gre>`, `last_used: bool`,
  `synproxy: Option<Synproxy>`;
- `Endpoint` gains `mac_address_mask: Option<Flex>`;
- `Rule.queue` stays `Option<Flex>` (a range arrives as a string);
- each struct is `#[serde(rename_all = "kebab-case", default)]`, with presence leaves via
  `de_presence`.

`firewall::Chain` gains `disable_conntrack: bool`.

| Function | Change |
|:--|:--|
| `render_rule` | new matchers at the §3 positions; `Err` for each verify rule in §2 |
| `render_time` | X14 first: `expand_weekday` only (milestone 1); then the FW17 rewrite per `parse_time` + deviations; value checks |
| `render_table` | `ZEBRA_DISABLE_CONNTRACK_*` chains after the custom chains; synproxy/ipsec reachability skips via the fw-load-safety `TablePlan` |
| `counters::strip_tail` | also strip ` last` |
| firewall `run` | third `select!` arm for the time refresh; `next_offset_change` and `refresh_hour_rules` |

**Worked example FW2.** Config:

```json
{"ipv4": {
  "forward": {"filter": {"rule": [
    {"number": 10, "action": "accept", "ipsec": {"match-ipsec-in": null, "match-ipsec-out": null}}]}},
  "input": {"filter": {"default-action": "drop", "rule": [
    {"number": 10, "action": "accept", "source": {"address": "10.0.1.0/24"}, "ipsec": {"match-ipsec-in": null}},
    {"number": 20, "action": "drop",   "source": {"address": "10.0.1.0/24"}, "ipsec": {"match-none-in": null}}]}},
  "output": {"filter": {"rule": [
    {"number": 10, "action": "jump", "jump-target": "IPSEC-IN"},
    {"number": 20, "action": "accept", "ipsec": {"match-ipsec-out": null}}]}},
  "name": [{"name": "IPSEC-IN", "rule": [{"number": 10, "action": "accept", "ipsec": {"match-ipsec-in": null}}]}]}}
```

Expected `ip` table (passes `nft -c`). The `ip6` table is empty.

```
table ip zebra_firewall {
    chain ZEBRA_FORWARD_filter {
        type filter hook forward priority filter; policy accept;
        meta ipsec == 1 rt ipsec exists counter accept comment "ipv4-FWD-filter-10"
        counter accept comment "FWD-filter default-action accept"
    }
    chain ZEBRA_INPUT_filter {
        type filter hook input priority filter; policy accept;
        ip saddr 10.0.1.0/24 meta ipsec == 1 counter accept comment "ipv4-INP-filter-10"
        ip saddr 10.0.1.0/24 meta ipsec == 0 counter drop comment "ipv4-INP-filter-20"
        counter drop comment "INP-filter default-action drop"
    }
    chain ZEBRA_OUTPUT_filter {
        type filter hook output priority filter; policy accept;
        rt ipsec exists counter accept comment "ipv4-OUT-filter-20"
        counter accept comment "OUT-filter default-action accept"
    }
    chain NAME_IPSEC-IN {
        meta ipsec == 1 counter accept comment "ipv4-NAM-IPSEC-IN-10"
        counter drop comment "IPSEC-IN default-action drop"
    }
}
```

The only warning:
`ipv4 OUT-filter rule 10: jump target IPSEC-IN is reached from the output hook and matches inbound IPsec (NAM-IPSEC-IN rule 10) — rule skipped`.

**Worked example FW15 + FW16.** `ipv4 input filter` rules:

| # | Config | Rendered line |
|:--|:--|:--|
| 5 | `conntrack-helper: ["ftp","h323"]`, accept | `ct helper {"ftp","RAS","Q.931"} counter accept comment "ipv4-INP-filter-5"` |
| 10 | `fib: {lookup: [destination-address], match: {route-type: local}}`, accept | `fib daddr type local counter accept comment "ipv4-INP-filter-10"` |
| 20 | `source: {mac-address: 00:11:22:00:00:00, mac-address-mask: ff:ff:ff:00:00:00}`, drop | `ether saddr & ff:ff:ff:00:00:00 == 00:11:22:00:00:00 counter drop comment "ipv4-INP-filter-20"` |
| 30 | `protocol gre`, `gre: {flags: {key: {}, checksum: {unset: null}}, inner-proto: ip, version: gre, key: 10}`, accept | `meta l4proto gre gre flags & 5 == 4 gre protocol ip gre version 0 @th,32,32 == 10 counter accept comment "ipv4-INP-filter-30"` |
| 40 | `protocol tcp`, `destination port 22`, `last-used`, accept | `meta l4proto tcp tcp dport {22} last counter accept comment "ipv4-INP-filter-40"` |
| 50 | `protocol tcp`, `destination port 80`, action `synproxy`, `synproxy: {tcp: {mss: 1460, window-scale: 7}}` | `meta l4proto tcp tcp dport {80} ct state invalid,untracked counter synproxy mss 1460 wscale 7 timestamp sack-perm comment "ipv4-INP-filter-50"` |

With `disable-conntrack` on the ipv4 forward, input and output filter hooks, the table
also gets these chains (passes `nft -c`):

```
    chain ZEBRA_DISABLE_CONNTRACK_INP_FWD {
        type filter hook prerouting priority -320; policy accept;
        fib daddr . iif type unicast notrack counter comment "DISABLE-CT-FWD"
        fib daddr . iif type local notrack counter comment "DISABLE-CT-INP"
    }
    chain ZEBRA_DISABLE_CONNTRACK_OUT {
        type filter hook output priority -320; policy accept;
        notrack counter comment "DISABLE-CT-OUT"
    }
```

**Worked example FW17.**

| Config `time` | Rendered |
|:--|:--|
| `starttime 22:00, stoptime 06:00, weekdays Mon,Fri` | `hour "22:00"-"06:00" day {"Monday","Friday"}` |
| `weekdays !Sat,!Sun` | `day != {"Saturday","Sunday"}` (deviation) |
| `startdate 2026-01-01, starttime 08:00:00, stoptime 17:00:00` | `time >= "2026-01-01 08:00:00" hour "00:00"-"17:00:00"` (VyOS parity) |
| `weekdays Mon,!Tue` | `day {"Monday"}` + warning |
| `starttime 9am` | skipped: `time starttime "9am" is not hh:mm[:ss]` |

**Worked example FW18.**
- `source: {address-mask: 0.0.0.255, group: {address-group: GW}}` →
  `ip saddr & 0.0.0.255 == @A_GW`. The same mask with a `network-group` renders without it,
  as VyOS does, plus the warning `address-mask ignored for network-group`.
- `action queue, queue "0-3", queue-options [fanout, bypass]` →
  `counter queue flags fanout,bypass to 0-3`. With `queue 3` and fanout, the rule is
  skipped (`queue-options fanout needs a queue range`).
- `recent {count: 5}` → skipped: `recent needs both count and time`.
- `inbound-interface {name: eth0, group: LAN}` → skipped:
  `inbound-interface name and group are mutually exclusive`.

Show: no new views. The Conditions column picks up the new matchers through
`render_rule`, with ` last` stripped.

## 5. Tests

Goldens, full script plus exact warnings:
- `golden_fw2_ipsec` (worked example FW2), and an ipv6 twin
  `golden_fw2_ipsec6` (`NAME6_` chain, `meta ipsec`).
- `fw2_rt_ipsec_reached_from_input_warns`.
- `golden_fw16_matchers`: rules 5–50 above.
- `golden_fw16_disable_conntrack`: the chains, plus a `state` rule in input that gets
  skipped.
- `fw16_verify_skips`:
  - gre without protocol gre;
  - gre key without a checksum flag;
  - key with `flags key unset`;
  - pptp with key;
  - fib with both lookups;
  - synproxy with `state`;
  - synproxy without mss;
  - synproxy on a non-tcp protocol;
  - mac mask without mac;
  - output filter jumping into a chain with synproxy.
- `x14_weekdays_expanded` (milestone 1): the book's `weekdays Mon,Tue,Wed,Thu,Fri`
  renders `day {"Monday","Tuesday","Wednesday","Thursday","Friday"}`; `mon`, `Monday`
  and `1` are accepted; `Xyz` skips the rule with a warning. The expected script passes
  the opt-in `nft -c` check.
- `golden_fw17_time`: the table rows.
- `fw17_next_offset_change`: a pure function over a stub `offset_at(t)` with DST jumps at
  known instants. It returns the first second of the new offset, and `None` with no change
  within 400 days.
- `fw17_refresh_batch`: given a `nft -j -a list table` fixture and an `Applied` script, it
  emits the exact `replace rule …` lines and only for `hour "` rules.
- `golden_fw18`: the four cases.
- Existing goldens are unchanged, except `render_time` users (no existing golden uses
  `time`).

zebra-rs: JSON marshal tests for `ipsec`, `gre.flags.key {}`, and the `choice` cases.

BDD:
- `@fw_ipsec` (FW2):
  - reuses `ipsec_node.sh` and the `ipsec_s2s` topology. `z2.conf` adds
    `input filter rule 10 source address 10.0.1.0/24 ipsec match-ipsec-in accept`,
    `rule 20 … match-none-in drop`, `default-action accept`;
  - scenarios: tunnel up; `ping -I 10.0.1.1 10.0.2.1` from z1 succeeds and rule 10's
    counter moves; cleartext `ping -I 10.0.1.1 192.0.2.9` fails and rule 20's counter moves
    (`command "nft list chain ip zebra_firewall ZEBRA_INPUT_filter" … should eventually not
    contain "packets 0 bytes 0 drop comment \"ipv4-INP-filter-20\""`); Teardown topology.
- FW15–FW18: no BDD. They are nft-only, the goldens plus the opt-in `nft -c` cover syntax,
  and time is not testable in real time. FW17's refresh is unit-tested.

## 6. Docs

- **ch-01-02 match criteria:**
  - new sections for `ipsec`, `fib`, `gre`, `conntrack-helper`, `mac-address-mask`,
    `last-used`;
  - fix the `time` section: a range crosses midnight; weekday spellings; negation; the
    DST refresh;
  - `queue` range.
- **ch-01-03 actions:** `synproxy`, including the SYN `notrack` rule in prerouting raw
  that VyOS also leaves to the user.
- **ch-01-06 connection tracking:** `disable-conntrack`; `conntrack-helper` needs helper
  modules.
- **ch-02-02 site-to-site:** an "accept decrypted, drop cleartext" example with
  `ipsec match-ipsec-in`.
- **`firewall.rs` / `nft::rule` module docs:** the §3 deviations.

## 7. Milestones

| # | Scope | Repo | Effort | Done when |
|:--|:--|:--|:--|:--|
| 1 | X14 (Phase 0): weekday expansion in today's `render_time`; book ch-01-02 example | insomnia | XS | `x14_weekdays_expanded`; the book example loads |
| 2 | FW2 YANG (groupings, per-hook `uses`, description) + JSON tests | zebra-rs | S | `set firewall ipv4 input filter rule 10 ipsec match-ipsec-in` parses; `match-ipsec-out` is rejected on input |
| 3 | FW2 render + reachability skip + goldens + `@fw_ipsec` | insomnia | S | goldens + BDD green |
| 4 | FW17 render (range, negation, value checks) | insomnia (+ zebra-rs help text) | S | `golden_fw17_time` |
| 5 | FW18: queue union + interface `choice` (zebra-rs); group mask, skips (insomnia) | both | S | `golden_fw18` |
| 6 | FW16a: fib, mac-address-mask, last-used, gre (YANG + render) | both | S | `golden_fw16_matchers` rows 10–40 |
| 7 | FW16b: synproxy (action, options, hook skip), disable-conntrack | both | S | rows 50, `golden_fw16_disable_conntrack`, verify skips |
| 8 | FW15 conntrack-helper (YANG + render + warning) | both | S | row 5 |
| 9 | FW17 offset-change refresh task | insomnia | S | `fw17_*` unit tests; manual DST check with `TZ` (see §8) |

Milestone 1 ships on its own, before nft-common, as one of the vyos-gap §10 Phase 0
defects. Milestones 2 onward follow nft-common milestone 1.

## 8. Risks and open questions

- **Kernel hook limits** for `meta ipsec` and `synproxy` are *unverified* (`-c` does not
  check them). If the real commit accepts them, the reachability skip is merely stricter
  than needed. The parity reference is VyOS's verify rule. Check once with a non-check
  apply in a throwaway netns during M3.
- **`day` and timezones.** nft converts `hour` to UTC. Whether `day` is evaluated in UTC
  or local time near midnight is *unverified*. The VyOS behaviour is the same, so document
  "weekday boundaries follow the kernel's evaluation".
- **`tzset`/`localtime_r`** inside a multi-threaded tokio runtime: glibc's `localtime_r`
  is thread-safe, and `tzset` is called only from the firewall task. When TZ changes via
  `/etc/localtime` at runtime, the next arm picks it up, the same limitation as VyOS.
- **`choice` JSON shape** must stay flat. If zebra-rs emitted a choice wrapper, the serde
  models would need `#[serde(flatten)]`. Pin it with the zebra-rs JSON tests in M2.
- **FW15 usefulness** depends on [conntrack](conntrack.md) helper assignment. Without it
  the matcher never matches. That is documented, not blocked.
- **GRE key offsets** assume no routing-present flag (VyOS's assumption, same comment).

## 9. Acceptance criteria

- [ ] X14: the book's `weekdays Mon,Tue,Wed,Thu,Fri` example loads, shipped in Phase 0
      ahead of the other milestones.
- [ ] FW2: each hook offers exactly the VyOS directions; the goldens pass `nft -c`;
      `@fw_ipsec` shows decrypted traffic accepted and cleartext dropped; an output-hook
      jump into an inbound-match chain is skipped with a warning.
- [ ] FW15/FW16: each matcher renders at its `parse_rule` position, byte-for-byte as in
      §4; each guarded verify rule skips the rule with a warning.
- [ ] FW17: hour windows render as one range; negated weekdays are kept; the refresh re-arms after every apply and replaces only hour rules.
- [ ] FW18: no matcher is ever dropped silently; `queue 0-3` with fanout renders; the
      interface name/group pair is a YANG `choice`.
- [ ] zebra-rs YANG description, help texts, and JSON shape tests updated; book chapters
      per §6.
