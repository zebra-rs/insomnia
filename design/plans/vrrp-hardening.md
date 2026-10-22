# VRRP hardening — implementation plan

Status: plan, 2026-10-21. Covers: §8.1 script checks, value limits
(delegated to commit-validation), VIP host check, IPv6-tentative wait, interface completion, BDD breadth; §8.3
`show vrrp <NAME> statistics|detail`, `restart vrrp`, `show log vrrp`
([vyos-gap](../vyos-gap.md) §8.1, §8.3, §4.1 VRRP row).
Priority: P2 (script and VIP checks, BDD) / P3 (tentative wait, completion, alias,
restart, log) · Effort: M · Owner: both
Depends on: [docs-corrections](docs-corrections.md) (feature rename in
`vrrp_node.sh`, word-order deviation recorded),
[commit-validation](commit-validation.md) (C3 owns the commit-time value
rules; layer 2 turns this plan's findings into commit errors; §3.2),
[exec-verbs](exec-verbs.md) (M6 only) ·
Unblocks: [vrrp-virtual-server](vrrp-virtual-server.md) (`host_findings`),
[vrrp-vrf](vrrp-vrf.md) (alias grammar is inherited by the `vrf` list)

## 1. Goal

- A health-check or transition script that is missing, not a regular file,
  not executable, or not an absolute path is named in a warning on every
  render, the way VyOS's `script` validator would have refused it.
- A VIP that is a network or broadcast address skips its group with a
  warning (a finding [commit-validation](commit-validation.md) layer 2
  turns into a refused commit). `password` > 8, `description` > 255 and
  `health-check timeout 0` are refused at commit by commit-validation C3;
  this plan does not re-implement them.
- A group with an IPv6 `hello-source-address` still undergoing DAD is not
  reloaded into keepalived until the address leaves `tentative` (bounded
  2 s, VyOS T5533).
- `set vrrp group G interface <TAB>` completes interface names.
- BDD covers IPv6/VRRPv3, unicast + authentication + VMAC, health-check and
  track → FAULT, transition scripts, no-preempt and sync groups.
- `show vrrp WAN statistics` (VyOS word order) works next to the shipped
  `show vrrp statistics group WAN`; `restart vrrp` and `show log vrrp`
  answer from insomnia.

## 2. Current state

insomnia @ `ee4dfaa`:
- Script values are checked only for quoting: `quotable()` (`src/vrrp.rs:354-356`)
  in `check_health` (`:630-672`) and `render_notify` (`:788-805`). Nothing
  stats the file. `ping` checks render `/usr/bin/ping -c1 <ip>` (`:639-641`)
  without checking that the binary exists.
- `password` > 8 bytes only warns "keepalived truncates it" (`:552-556`).
  `description` is copied with CR/LF stripped, no length cap (`:825-828`).
- VIPs are parsed by `parse_addr` (`:360-377`); `192.0.2.0/24` is accepted
  (`:441-469`). Unparseable `excluded-address` entries are dropped, not the
  group (`:486-491`).
- No tentative handling: `process()` renders and calls `keepalived::apply`
  directly (`:95-120`).
- Show paths: `/show/vrrp`, `/show/vrrp/{statistics,detail}[/group]`
  (`:1077-1087`). Provider routes by prefix `/show/vrrp` (`src/provider.rs:95`).
- BDD: one feature, `vrrp_pair` (IPv4 multicast pair, failover, unload;
  `bdd/tests/features/vrrp_pair.feature`). `vrrp_node.sh` still passes
  `--feature iso` (`bdd/tests/scripts/vrrp_node.sh:72`).

zebra-rs @ `141da2fc`:
- `vrrp.yang`: `password` plain `string` (`:255-258`), `description`
  pattern `'.*'` (`:267-275`), health-check `timeout` plain `uint32`
  (`:127-130`), the three interface leaves have no `ext:dynamic`
  (group `interface` `:208-211`, `virtual-address-entry interface` `:166-169`,
  `track interface` leaf-list `:322-325`).
- The parser enforces integer `range` (`config/parse.rs:154-186`) and
  `pattern` (`:146-152`, anchored, rest-of-line), but **ignores `length`**:
  `match_string` never reads `TypeNode.length` (`:146-152`; the field
  exists in libyang 2.2 `TypeNode`). A `length` statement is documentation
  only today.
- Commit-time value checks exist: `check::value_check` /
  `check::startup_tolerant_check` (`config/check.rs:64-92`), applied to the
  `+` lines of each commit by `value_errors` (`config/manager.rs:746-776`,
  `:870-879`). A startup-tolerant failure refuses a commit but only warns
  for the startup config.
- `ext:dynamic` candidates are offered in interactive completion only
  (`manager.rs:1597-1603`, `collect_dynamics`); the parse path never sees them, so values stay
  unconstrained (`parse.rs:435-441`).
- `ext:default-child` (`parse.rs:662-697`) lets a container route a bare
  token into a child list's key; used by `show bgp` (`exec.yang:525-531`).
- `show vrrp` grammar: grouping `vrrp-show-views` (`exec.yang:102-129`),
  `container vrrp` (`:434-439`). No `restart` or `show log` nodes exist
  (`exec.yang` top level: `help`, `configure`, `enable`, `disable`, `show`,
  `cli`).
- `is_vrrp` matches any path element named `vrrp` (`manager.rs:2034-2036`),
  so `show log vrrp` would already reach the `vrrp` provider; exec-verbs
  still asks for an exact predicate (§3.6).

VyOS @ `7f2c893`:
- `src/validators/script`: `shlex.split(arg)[0]`, then exists, then
  `isfile && access(X_OK)`; applied to health-check `script` and the four
  transition scripts (`interface-definitions/high-availability.xml.in:165-170`,
  `include/vrrp-transition-script.xml.i`).
- `password` regex `.{1,8}` (`high-availability.xml.in:97`),
  `generic-description.xml.i` regex `.{0,255}`, health-check `timeout`
  `numeric --positive` (`:181`), address validators `ip-host` + `ip-address`
  (`:293-294`; `ip-host` = `ipaddrcheck --is-any-host`).
- T5533: `apply()` polls `is_ipv6_tentative(interface, hello_source)` 20 ×
  0.1 s before `reload-or-restart` (`src/conf_mode/high-availability.py:218-228`;
  helper `python/vyos/utils/network.py:258-283` parses `ip -6 --json addr`).
- `show vrrp <NAME> statistics|detail` is a `virtualTagNode`
  (`op-mode-definitions/vrrp.xml.in`); `restart vrrp` → `restart.py` →
  `systemctl restart keepalived` (`src/op_mode/restart.py:77-80`);
  `show log vrrp` → `journalctl --no-hostname --boot --unit keepalived.service`
  (`op-mode-definitions/show-log.xml.in:960-964`).

## 3. Design

### 3.1 Script checks: insomnia, outside the renderer

The renderer stays a pure function of the model (golden tests must not
depend on the filesystem, and [commit-validation](commit-validation.md)
§4 item (c) requires it: layer 2 equals apply only if `render()` is pure).
Host checks live in `host_findings(&cfg, probe)` — the name and contract
commit-validation sets — which returns Warnings and is called by
`process()` after `render()` and by commit-validation's `validate()`:

- `script_path(cmd) -> Result<&str, ScriptProblem>` takes the first word
  POSIX-shell style (whitespace split, single quotes literal; `"` and `\`
  never reach here because `quotable()` already rejects them), matching
  VyOS's `shlex.split(...)[0]`. An unbalanced `'` is `Unparseable`. The
  zebra-rs leaves are plain one-word `string`s (`vrrp.yang:123-126`,
  `:139-154`), so arguments arrive only if the CLI's quoting carries a
  space (*unverified*); the rule costs nothing and matches VyOS.
- `probe(path) -> FileState` (`Missing | NotRegular | Regular { exec }`) via
  `std::fs::metadata` and `mode & 0o111` (insomnia runs as root, where
  `access(X_OK)` reduces to "any x bit").
- Checks, in order: absolute path (keepalived resolves relative paths
  differently from VyOS's cwd-relative `os.path.exists`, so warn), exists,
  regular file, executable.
- Scope: health-check `script` and `transition-script {master,backup,fault,stop}`
  of every non-disabled group and every sync group — operator-supplied
  values from the model only. Hooks insomnia generates itself (the
  `/usr/lib/insomnia/conntrack-failover` `notify` line of
  [conntrack-sync](conntrack-sync.md)) are never checked. Also, once at
  startup (`Keepalived::probe`), `/usr/bin/ping` exists — the `ping`
  health check hard-codes it.
- The script is still rendered. Rationale: keepalived re-reads scripts only
  on reload, a script installed after the commit works on the next commit,
  and skipping a health check silently changes failover behaviour more than
  a dead one. What keepalived 2.2.8 does at runtime with a missing script
  is *unverified* (`keepalived -t` as non-root does not flag it; checked
  on the dev host); M4 records it.
- The pass takes the probe as a closure, so tests inject a fake filesystem.
  [vrrp-virtual-server](vrrp-virtual-server.md) adds the real-server
  `health-check script` slots. Host findings stay Warnings in
  commit-validation too (VyOS rejects a missing script; recorded there as
  a deviation).

Rejected: checking in zebra-rs `check.rs` — zebra-rs may run on a
different host than keepalived (`--host tcp:`); only insomnia shares the
filesystem with keepalived.

### 3.2 Value limits: commit-validation's rows, this plan's VIP check

| Rule | Owner | Mechanism |
|:--|:--|:--|
| `password` 1-8 chars | [commit-validation](commit-validation.md) C3 | `check::startup_tolerant_check` on `/vrrp/group/authentication/password` |
| `description` ≤ 255 chars | commit-validation C3 | `startup_tolerant_check` |
| health-check `timeout` ≥ 1 | commit-validation C3 | `startup_tolerant_check` (group and sync group) |
| VIP / excluded VIP is a host address | this plan | render-time finding; commit-validation layer 2 refuses the commit through `validate()` |

- The gap row asked for YANG `length`/`range`. Not done, deliberately:
  the parser ignores `length` (`parse.rs:146-152`), and a `range` on an
  existing leaf drops startup lines that no longer parse (`manager.rs:2168-2176`).
  commit-validation §3.3 forbids parse-time tightening of existing leaves
  for that reason and leaves generic `length` enforcement to a separate
  zebra-rs decision; an inert `length` statement added now would turn into
  exactly that trap if the decision is taken. The `startup_tolerant_check`
  rows give the VyOS limits without it.
- The check paths commit-validation adds must also cover the
  [vrrp-vrf](vrrp-vrf.md) spelling (`/vrrp/vrf/group/…`): requirement on
  commit-validation, or on vrrp-vrf if it lands later.
- VIP host check, render-time, matching the existing "unparseable address
  skips the group" rule (`vrrp.rs:445-447`): IPv4 with prefix ≤ /30 whose
  host bits are all zero (network) or all one (broadcast), IPv6 with
  prefix ≤ /126 whose host bits are all zero (subnet-router anycast) →
  skip the group. Excluded addresses → drop the entry (as `:486-491`).
  Whether `ipaddrcheck --is-any-host` also rejects IPv4 broadcast and the
  IPv6 anycast is *unverified* (ipaddrcheck source not in the checkout);
  these rules are insomnia's choice and are recorded as such. The address
  is a list key, so a one-leaf `check.rs` rule would see it only on
  key-only lines (commit-validation §4.4 makes the same point).
- The renderer's password warning (`vrrp.rs:552-556`) stays as defence
  against configs committed before C3.

### 3.3 IPv6-tentative wait

- Before `keepalived::apply`, collect the IPv6 `hello-source-address` of
  every group that rendered. Poll `/proc/net/if_inet6` (fields: 32-hex
  address, ifindex, prefix len, scope, flags, ifname; `IFA_F_TENTATIVE` =
  0x40, `IFA_F_DADFAILED` = 0x08, `include/uapi/linux/if_addr.h`) every
  100 ms, at most 20 times, while any of them is tentative. No subprocess;
  the file is per network namespace, so it is correct in BDD and VRF-agnostic.
- Match on the address alone, on any interface (VyOS matches on the group
  interface; a hello source on another device is legal keepalived config).
- An address absent from the file → no wait (VyOS's helper returns False
  the same way). `dadfailed` → no wait.
- Split per [commit-validation](commit-validation.md): the *wait* is an
  apply-time action in `process()` (between `render()` and
  `keepalived::apply`); what it observes — "DAD failed for
  hello-source-address X; keepalived cannot bind it" and "X still
  tentative after 2 s; loaded anyway" — are Warnings of `host_findings`
  (`Effect::Kept`), so `validate()` reports them too without waiting.
- The wait blocks the backend's `select!` for ≤ 2 s, as VyOS blocks its
  commit; show orders queue behind it (channel depth 8, `src/main.rs:88`).
- Log at info when waiting starts.
- VyOS bug, not copied: its loop never breaks, so it re-runs `ip` 20 times
  even when the address is ready; insomnia stops at the first clean poll.

### 3.4 Interface completion

`ext:dynamic "rib:interface"` on the three interface leaves. Completion
only; values typed for interfaces that appear later still parse (BDD
applies configs non-interactively). VyOS completes broadcast interfaces
only (`generic-interface-broadcast.xml.i`); `rib:interface` offers all —
recorded as a cosmetic deviation.

### 3.5 `show vrrp <NAME> statistics|detail`

Grammar: the `vrrp-show-views` grouping gains a `list group` with
`ext:presence`, and `container vrrp` gains `ext:default-child "group"`.

Resulting forms and dispatch (`path_from_command`, `paths.rs:80-98`; the
default-child step is injected as a `Key` element named `group`,
`parse.rs:684-694`):

| Typed | Path | Args |
|:--|:--|:--|
| `show vrrp WAN` | `/show/vrrp/group` | `[WAN]` |
| `show vrrp WAN statistics` = `show vrrp group WAN statistics` | `/show/vrrp/group/statistics` | `[WAN]` |
| `show vrrp WAN detail` | `/show/vrrp/group/detail` | `[WAN]` |
| `show vrrp statistics group WAN` (shipped) | `/show/vrrp/statistics/group` | `[WAN]` |

Keyword ambiguity, from `parse.rs:676-697`: the positional probe wins only
when its match type beats the keyword match. A string key matches as
`Partial` (`match_word`, `parse.rs:87-93`); a keyword matches `Exact` or,
abbreviated, `Partial`. Therefore:
- A token equal to, or a prefix of, a sibling keyword at that level
  (`statistics`, `detail`, `group`, and `vrf` once [vrrp-vrf](vrrp-vrf.md)
  lands) is always the keyword. Abbreviations (`show vrrp s`, `show vrrp d`)
  keep working; nothing shipped regresses.
- A group named `detail`, `stat`, `g`, `vrf`, `v`, … is unreachable in
  VyOS order; it is still reachable as `show vrrp statistics group detail`
  or `show vrrp group detail statistics`. VyOS's `virtualTagNode` has the
  same shadowing. Documented in the book; no render warning (it would fire
  on harmless names and VyOS does not warn).
- `show vrrp WAN` alone answers the summary filtered to `WAN`. VyOS has no
  command there; recorded as a small extension.

### 3.6 `restart vrrp` and `show log vrrp`

Requires from [exec-verbs](exec-verbs.md): `OrderKind::Exec` with the
answered-exactly-once `Answer` (error flag), the `restart` container, the
`EXEC_ROUTES` row `restart vrrp` → `vrrp`, the insomnia `ROUTES` table and
`EXEC_TREES`, and the shared `show log` container (also extended by
[fw-opmode](fw-opmode.md) and [ipsec-opmode](ipsec-opmode.md)). This plan
adds only: `leaf vrrp { type empty; }` under `restart` ([vrrp-vrf](vrrp-vrf.md)
adds no `restart vrrp vrf NAME`: the leaf restarts every non-empty instance), a
`vrrp` leaf under `show log`, the exact predicate `is_log_vrrp` placed in
`SHOW_PROTOS` ahead of the any-segment tests (exec-verbs D-6; `is_vrrp`
would match too, but the shared rule is exact predicates), the insomnia
rows `(Exec, "/restart/vrrp", Vrrp)` / `(Show, "/show/log/vrrp", Vrrp)`,
`"vrrp"` in `EXEC_TREES`, and the handlers. Both handlers run in a
spawned task with a time bound (exec-verbs D-8): 30 s for `systemctl
restart`, 5 s for `journalctl`; a timeout answers an error. Any zebra-rs
per-order ceiling is at least 60 s (exec-verbs §8), above both bounds.

- `restart vrrp` (exec order `/restart/vrrp`): systemd mode →
  `systemctl restart <unit_for(i)>` for each instance whose `keepalived.conf`
  is non-empty (today `default`); answer one line per instance. Signal
  mode → `% restart vrrp needs --keepalived-control systemd (keepalived is
  not managed by insomnia here)`; insomnia never kills a process it did not
  start (exec-verbs §8 leaves this choice here; respawning keepalived
  from insomnia would contradict `design/vrrp.md` §7). The refusal is an
  error answer. With [vrrp-virtual-server](vrrp-virtual-server.md) the
  restart also restarts IPVS checking (one keepalived), as in VyOS.
- `show log vrrp` (a plain show order `/show/log/vrrp`; no exec kind
  needed): systemd mode → `journalctl --no-hostname --boot --no-pager
  -n 1000 --unit 'insomnia-keepalived@*'` (glob covers per-VRF instances).
  VyOS has no line cap because it pages; the reply here is one gRPC string,
  so the cap is a deviation. Signal mode → `% show log vrrp needs
  --keepalived-control systemd`. JSON mode → `journalctl -o json` lines
  wrapped into an array.
- `monitor log vrrp`: out of scope. `ShowChunk` allows several chunks
  (`proto/show.proto`), but `ShowRequest.resp` is a oneshot
  (`src/api.rs:35`) and the vty side's handling of an unbounded stream is
  *unverified*.

### 3.7 Out of scope

- mDNS repeater `vrrp-disable` hook: zebra-rs has no mDNS tree, and with
  native `notify_*` there is no FIFO dispatcher to hang it on. Recorded in
  `design/vrrp.md` §14.
- conntrack-sync failover hook: [conntrack-sync](conntrack-sync.md) renders
  it in keepalived's generic `notify` slot (its §3.5). This plan never
  renders `notify`, leaves the `notify_*` lines as they are, and its
  script checks skip the hook (§3.1).
- Password masking: [secret-redaction](secret-redaction.md) marks
  `authentication password` `ext:secret`; nothing here touches it, and
  no message in this plan prints a password (commit-validation §3.2).
  That plan delivers the gap's "password masking" row alone; this plan
  does not depend on it.

### 3.8 Deviations to record in the `src/vrrp.rs` module doc

- Script problems are host-finding warnings, not commit refusals.
- VIP network/broadcast addresses skip the group at render time; the
  broadcast and IPv6-anycast rules are insomnia's.
- Interface completion offers all interfaces.
- `show vrrp <NAME>` without a view answers a filtered summary.
- `show log vrrp` is capped at 1000 lines.

## 4. Changes

### zebra-rs

`yang/vrrp.yang` — completion only, no value changes (the value rules
are commit-validation C3's `check.rs` rows, §3.2):

```yang
// virtual-address-entry
leaf interface {
  ext:help "Interface to place this virtual address on";
  ext:dynamic "rib:interface";
  type string;
}
// group-list
leaf interface {
  ext:help "Network interface the group runs on";
  ext:dynamic "rib:interface";
  type string;
}
// track
leaf-list interface {
  ext:help "Interface name state check";
  ext:dynamic "rib:interface";
  type string;
}
```

`yang/exec.yang`, grouping `vrrp-show-views` (`:102-129`) gains:

```yang
list group {
  ext:help "One VRRP group (VyOS order: show vrrp NAME statistics|detail)";
  ext:presence "Summary for one VRRP group";
  key "name";
  leaf name { ext:help "VRRP group name"; type string; }
  container statistics { ext:help "VRRP statistics"; presence "Statistics for one VRRP group"; }
  container detail { ext:help "VRRP group details"; presence "Details for one VRRP group"; }
}
```

and `container vrrp` (`:434-439`) gains `ext:default-child "group";`.
`restart vrrp` and `show log vrrp`: the leaves and `is_log_vrrp` of §3.6
under the containers [exec-verbs](exec-verbs.md) adds; `EXEC_ROUTES` row
`restart vrrp`.

Tests (`config/manager.rs`):
- extend `show_vrrp_grammar_gated_on_insomnia` (`:8063`) with the four
  rows of the §3.5 table plus `show vrrp s` → `/show/vrrp/statistics`
  (abbreviation still wins) and `show vrrp group detail statistics` →
  `/show/vrrp/group/statistics` `[detail]`;
- `vrrp_interface_completion`: the three entries carry
  `ext:dynamic = rib:interface` in `shipped_tree(&["insomnia"])`;
- `show log vrrp` routes to `"vrrp"` and `restart vrrp` matches the
  `EXEC_ROUTES` row (with exec-verbs' mock provider).

### insomnia

`src/vrrp.rs`:
- `fn host_address(text: &str) -> Result<(), &'static str>` (proposed) next
  to `parse_addr`; called in the address loop (`:441-469`) → `skip(r,
  "address 192.0.2.0/24 is a network address, not a host")`, and in the
  excluded loop (`:481-494`) → drop with warning.
- `enum ScriptProblem`, `fn script_path`, `enum FileState`,
  `pub fn host_findings(cfg: &VrrpConfig, probe: &dyn Fn(&Path) -> FileState) -> Vec<String>`
  (all proposed; the return type becomes commit-validation's `Findings` of
  Warnings once its C1 lands). `process()` (`:95-120`) calls it with the
  real probe after `render()` and logs each line with the `vrrp:` prefix;
  commit-validation's `vrrp::validate()` calls it too.
- `async fn wait_tentative(addrs: &[Ipv6Addr], read: impl Fn() -> io::Result<String>)`
  (proposed; real reader = `tokio::fs::read_to_string("/proc/net/if_inet6")`),
  called in `process()` before `apply`. `fn if_inet6_flags(text, addr) -> Option<u8>`
  is the pure parser.
- `process_show` (`:1077-1087`): add `/show/vrrp/group` (summary filtered,
  `% VRRP group "X" not found` when absent), `/show/vrrp/group/statistics`,
  `/show/vrrp/group/detail`. Restructure the match into
  `fn parse_show(path, args) -> Option<(View, Option<String>)>` so
  [vrrp-vrf](vrrp-vrf.md) can prepend its `vrf` handling.
- Handlers `restart(ka)` and `show_log(ka, json)` (proposed), receiving
  the `ShowRequest` with `kind` that [exec-verbs](exec-verbs.md) adds to
  `src/api.rs` and answering an `Answer`.

`src/keepalived.rs`: `probe()` (`:125-171`) also warns when `/usr/bin/ping`
is missing.

`src/provider.rs`: the two `ROUTES` rows and `EXEC_TREES` entry of §3.6
(the table replaces today's if-chain, `:91-100`, in exec-verbs E5).

Worked example (render + checks). Config:

```
set vrrp group LAN interface eth0
set vrrp group LAN vrid 10
set vrrp group LAN address 192.0.2.254/24
set vrrp group LAN transition-script master /usr/local/bin/on-master
set vrrp group LAN health-check script /opt/check
set vrrp group DMZ interface eth1
set vrrp group DMZ vrid 20
set vrrp group DMZ address 198.51.100.0/24
```

Rendered `vrrp_instance LAN { … notify_master "/usr/local/bin/on-master" }`
exactly as today; no `vrrp_instance DMZ`. insomnia log (fake fs: on-master
exists without x bit, `/opt/check` missing):

```
WARN vrrp: group DMZ: address 198.51.100.0/24 is a network address, not a host; skipped
WARN vrrp: group LAN: transition-script master: /usr/local/bin/on-master is not executable
WARN vrrp: group LAN: health-check script: /opt/check does not exist
```

Show example (`show vrrp LAN statistics` on r2 of `vrrp_pair`): identical
text to `show vrrp statistics group LAN`, starting
`\nVRRP Instance: LAN\n  Advertisements:\n    Received: …`.

## 5. Tests

Unit (insomnia, CI):
- `vip_must_be_host`: `/24` network, `/24` broadcast, `/31` and `/32`
  accepted, IPv6 `/64` all-zero host skipped, `/127` accepted; excluded
  network address dropped, group kept. Golden text for the surviving
  groups unchanged.
- `script_path_first_word`: `"/a b"`→`/a`, `"'/x y' z"`→`/x y`, `"  /a"`→`/a`,
  `"'/a"`→`Unparseable`.
- `host_findings_cover_all_slots`: group HC, four group transitions,
  sync-group HC and transitions, disabled group ignored; each
  `FileState` variant produces its message.
- `if_inet6_flags_parse` (captured `/proc/net/if_inet6` lines, including
  the short-ifindex form seen on 6.8: `… 111b 40 20 80 ifname`) and
  `wait_tentative_stops_early` / `wait_tentative_gives_up` with a fake
  reader and paused tokio time.
- `show_paths`: `parse_show` for every row of §3.5 and the shipped forms.
- Existing `golden_render` and `skip_rules_warn_and_never_wedge` stay
  byte-identical (no renderer output changes in this plan; say so in the
  commit).

BDD (insomnia, not CI). `vrrp_node.sh` gains a helper directory in the
private `/run`: `/run/insomnia-bdd/check-health` (`[ -e /tmp/$NS.healthy ]`),
`notify-{master,backup,fault,stop}` (`echo <state> >> /tmp/$NS.transitions`);
it creates `/tmp/$NS.healthy` at start and `vrrp_node_stop.sh` removes both
files. `/tmp` is shared with the harness, so `command "cat /tmp/…"` and
`I execute "rm -f /tmp/…"` steps reach them. One Makefile target and one
`bdd/docs/<tag>.md` per feature; every feature ends with
`Scenario: Teardown topology`.

| Tag | Topology | Scenarios |
|:--|:--|:--|
| `@vrrp_v6` | `vrrp_pair` bridge; `2001:db8:10::{1,2,100}/64` added with `I add address`; VIP `2001:db8:10::254/64`; r1 `hello-source-address 2001:db8:10::1` applied right after the address is added | elect (MASTER/BACKUP); `ping from "h1" to "2001:db8:10::254"`; failover + preempt; delete → VIP gone |
| `@vrrp_unicast_auth` | same bridge, IPv4; `peer-address` + `hello-source-address` both sides; `authentication type plaintext-password` | elect; wrong password on r2 → both `MASTER`, r2 `show vrrp statistics` eventually not `Failure: 0`; fix → r2 `BACKUP`; `rfc3768-compatibility` → `ip link show` on r1 contains `vr1nsv10v4`, VIP answers |
| `@vrrp_fault` | `vrrp_pair` + `trk0` dummy on r1 | health-check script → remove `/tmp/vrrp_fault_r1.healthy` → r1 `FAULT`, r2 `MASTER`, r1 transitions file contains `fault`; restore → r1 `MASTER`, file contains `master`; `track interface trk0` down → `FAULT`; ping health check to h1, h1 link down → `FAULT`; `transition-script stop /run/insomnia-bdd/missing` → insomnia log contains `does not exist`; no-preempt both sides → after r1 recovers, r2 stays `MASTER` (`I wait 5 seconds`, then still `BACKUP` on r1) |
| `@vrrp_sync` | bridge (group A on `vr1ns`/`vr2ns`) + direct veth r1:`s1`↔r2:`s2` (group B, `198.51.100.0/24`); sync-group SG {A, B} | elect both on r1; r1 bridge link down → r2 MASTER for A and B (`show vrrp detail group B` contains `State: MASTER`); link up → back; sync-group health check (script) failure moves both |

The `@vrrp_fault` missing-script scenario also records what keepalived
does with it (state reached), closing the §3.1 *unverified* point.

## 6. Docs

- `book/src/ch-05-03-health-checks-and-sync-groups.md`: script checks
  (warnings, absolute paths, arguments allowed), ping binary.
- `book/src/ch-05-01-vrrp-groups.md` "Addresses": host-address rule;
  "Timers": timeout ≥ 1.
- `book/src/ch-05-02-unicast-and-authentication.md`: 1-8 char password is
  now refused at commit.
- `book/src/ch-05-04-keepalived-and-insomnia.md`: tentative wait under
  "What insomnia logs"; `restart vrrp` and `show log vrrp` vs control mode;
  new deviations under "Differences from VyOS".
- `book/src/ch-03-02-show-vrrp.md`: both word orders, the shadowing rule,
  `show vrrp NAME`.
- `book/src/ch-04-00-bdd-tests.md` "Features": the four new tags.
- `src/vrrp.rs` module doc: §3.8.
- `design/vrrp.md` §14: remove each item as it lands (the items themselves
  are added by [docs-corrections](docs-corrections.md)).

## 7. Milestones

| # | Scope | Repo | Effort | Done when |
|:--|:--|:--|:--|:--|
| M1 | `ext:dynamic "rib:interface"` on the three leaves, completion test | zebra-rs | S | `set vrrp group G interface <TAB>` lists interfaces |
| M2 | VIP host check (Error, group skipped); `host_findings` (scripts, ping binary); unit tests; module doc | insomnia | S | unit tests green; golden unchanged |
| M3 | Tentative wait + tests | insomnia | S | fake-reader tests green |
| M4 | `vrrp_node.sh` helpers; four features + configs + Makefile targets + docs pages | insomnia | M | all four tags green locally, `make -C bdd docs` clean |
| M5 | Show alias: exec.yang + grammar tests; `parse_show` + arms + tests; book | both | S | `show vrrp LAN detail` in `@vrrp_pair` gives `State: MASTER` (add one step there) |
| M6 | `restart vrrp`, `show log vrrp` (after [exec-verbs](exec-verbs.md) E4/E5) | both | S | unit tests for argv/answers/timeouts in both modes; `@vrrp_pair` runs `restart vrrp` through `I run {string} in namespace {string}` and gets the signal-mode refusal (the only effect the harness can observe; exec-verbs §5 asks the first consumer to assert one), and `show command "restart vrrp"` is refused |

M1–M4 are independent; M5 and M6 need the zebra-rs half first.

## 8. Risks and open questions

- The value limits arrive only with [commit-validation](commit-validation.md)
  C3; until then the renderer's password warning is the only signal, and
  a long description or `timeout 0` passes silently, as today.
- keepalived's runtime handling of a missing script (disabled? FAULT?) is
  *unverified*; M4 records it and the book states it.
- IPv6 VIP ordering: zebra-rs marshals keyed lists in key order
  (`manager.rs` `vrrp_json_marshal_contract`), so a link-local VIP cannot be
  forced first; whether keepalived needs it first for RFC 5798 interop is
  *unverified*. `@vrrp_v6` uses a global VIP only.
- The 2 s tentative wait delays queued `show vrrp` orders; acceptable at
  commit time, revisit if DAD is slowed (`dad_transmits` > 1).
- `show log vrrp` cap: 1000 lines may be too few on a flapping pair; make
  it a constant, not a flag, until someone asks.
- Shadowed group names: no warning by design; revisit if users trip on it.
- Decided (commit-validation §8 asks the VRRP owner): a sync-group
  member's own health check stays a Warning, ignored in favour of the
  sync group's (`design/vrrp.md` §6). VyOS rejects it; docs-corrections
  records that as a stronger deviation.

## 9. Acceptance criteria

- [ ] Password, description and timeout limits are left to commit-validation C3 (no YANG `length`/`range` added; reason recorded in §3.2).
- [ ] Network/broadcast VIP skips its group with an Error finding naming it.
- [ ] Missing / non-executable / relative scripts (all five slots, group and sync group) are `host_findings` Warnings on every render; `render()` stays pure and its output unchanged.
- [ ] Tentative IPv6 hello source delays the reload up to 2 s; DAD-failed / still-tentative are host findings.
- [ ] Interface completion on the three leaves.
- [ ] `@vrrp_v6`, `@vrrp_unicast_auth`, `@vrrp_fault`, `@vrrp_sync` green, each with teardown and a docs page.
- [ ] `show vrrp NAME statistics|detail` and `show vrrp NAME` work; abbreviations unchanged; shadowing documented.
- [ ] `restart vrrp` restarts every non-empty instance in systemd mode and refuses in signal mode; `show log vrrp` returns the journal tail or the signal-mode message.
- [ ] Module doc and book list every deviation in §3.8.
