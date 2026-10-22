# VRRP in a VRF — implementation plan

Status: plan, 2026-10-21. Covers: VRRP in a VRF (`design/vrrp.md` §13),
the shim corrections in `design/vrrp.md` §8.4 item 3
([vyos-gap](../vyos-gap.md) §8.1 first row, §8.4).
Priority: P1 spike, P2 implementation · Effort: S spike, then M (branch A)
or L (branch B) · Owner: both
Depends on: [docs-corrections](docs-corrections.md) (§13 text and the
shared-object note, D5; `--feature insomnia` in `vrrp_node.sh`);
[fw-global-options](fw-global-options.md) M3 (`crate::links`, the kernel
link watcher; A3/B4 only); [commit-validation](commit-validation.md) C1
(`Findings`, `host_findings` contract; soft);
[vrrp-hardening](vrrp-hardening.md) M5 is optional (its `group` alias is
inherited by the `vrf` show list) ·
Unblocks: [vrrp-snmp](vrrp-snmp.md) (per-VRF placement),
[vrrp-virtual-server](vrrp-virtual-server.md) (default-instance-only rule;
branch B's `keepalived::verb`),
[conntrack-sync](conntrack-sync.md) (a sync interface in a VRF: its §3.6 and M8)

## 1. Goal

- `set vrrp vrf red group WAN interface eth1 …` runs a VRRP group whose
  adverts, unicast peers, VMAC and `ping` health check all operate in VRF
  `red`.
- `show vrrp vrf red [statistics|detail …]` shows that VRF's groups; bare
  `show vrrp` stays the default VRF (zebra-rs convention); `show vrrp vrf`
  lists every VRF.
- How it is done is decided by a recorded spike (M1), not assumed: either
  one keepalived serves every VRF (branch A) or one keepalived per VRF
  runs under an `LD_PRELOAD` shim (branch B, `design/vrrp.md` §13).
- Branch B never runs a VRF instance in the default VRF by accident: no
  shim, wrong file, or shim not mapped → the instance is refused or
  stopped, with an error naming it.
- A `vrrp` group in the default tree whose interface is enslaved to a VRF
  is warned about in both branches.

## 2. Current state

insomnia @ `ee4dfaa`:
- Single instance hard-coded: `CONFIG_PATH = ["vrrp"]`,
  `DEFAULT_INSTANCE = "default"` (`src/vrrp.rs:50`, `:53`); `process()`
  applies only `default` (`:109-110`); show collects only `default`
  (`:1089`).
- The per-instance layout is ready: `Keepalived::instance(name)`
  (`src/keepalived.rs:173-182`), `unit_for` (`:186-191`), `apply(ka, name,
  conf)` (`:277-322`). `env_for` writes `LD_PRELOAD=<vrf_preload>` and
  `VRF=<name>` for any non-default name (`:195-201`). `apply` writes `env`
  but ignores whether it changed (`:282`), so a changed `LD_PRELOAD` would
  never restart keepalived.
- `--vrf-preload` defaults to `/usr/lib/insomnia/vrf.o` (`src/main.rs:71-73`);
  tests pin that name (`src/keepalived.rs:363`, `:387`, `:452`). No shim
  source exists anywhere; the `.deb` ships only the binary
  (`Cargo.toml:91-93`). A `.o` suffix suggests ET_REL, which ld.so refuses
  ("cannot be preloaded … ignored") and then *continues*, so a bad shim
  silently runs the instance in the default VRF.
- The template unit already reads the per-instance env file
  (`packaging/systemd/insomnia-keepalived@.service:18`).
- `render(cfg)` takes one tree (`src/vrrp.rs:936`).

zebra-rs @ `141da2fc`:
- `container vrrp` is `uses "vrrp:vrrp"` only (`yang/config.yang:5705-5709`);
  grouping `vrrp` = `disable`, `global-parameters`, `group`, `sync-group`
  (`yang/vrrp.yang:356-364`); `group-list` and `sync-group-list` are
  separate groupings (`:200`, `:335`).
- VRFs: top-level `list vrf` (`config.yang:5829`); `interface X vrf` is a
  leafref with `ext:sort "10"` so the enslave precedes addresses
  (`:5720-5727`); the RIB creates the VRF netdev under the VRF's name
  (`src/fib/netlink/handle.rs:3789-3794`).
- `show vrrp` grammar is the reusable grouping `vrrp-show-views`
  (`yang/exec.yang:102-129`, `:434-439`). `show bgp vrf` is the pattern to
  copy: `list vrf` with `ext:presence`, `ext:default-child`, key with
  `ext:dynamic "rib:vrf"` (`exec.yang:747-760`).
- The generic redirect looks up `"vrrp:vrf:<name>"`, finds no per-VRF
  channel for an external provider and falls through to the `vrrp`
  provider with the original paths (`src/config/manager.rs:1795-1817`), so
  insomnia receives `/show/vrrp/vrf…` with the VRF name first in `args`
  (`path_from_command`, `src/config/paths.rs:80-98`).

VyOS @ `7f2c893`: no VRF knob for VRRP; one keepalived in the default VRF
(`src/conf_mode/high-availability.py`, `10-override.conf.j2`). Everything
here is a zebra-rs extension.

keepalived 2.2.8 on the dev host lists `VRF` under "System options"
(`keepalived --version`); per `design/vrrp.md` §13 it enslaves a VMAC to
the parent's VRF master and binds source-bound unicast sockets to the VRF.

## 3. Design

### 3.1 The spike decides the shape (M1)

Hypothesis (vyos-gap §8.1): keepalived binds its advert sockets to the
member interface, and a socket bound to a VRF slave routes through the VRF
table, so plain keepalived in the `default` instance may already run a
group on an enslaved interface. What cannot work without help is anything
keepalived does not bind to the interface: the `ping` health check and
user scripts.

Run on a spike branch as a draft BDD feature `vrrp_vrf_spike` (not
merged): the `vrrp_pair` topology, routers built with `I create namespace
… with loopback and veth interface on the bridge`, then `set vrf red`,
`set interface vrXns vrf red`, `set interface vrXns ipv4 address …` so the
enslave precedes addressing. h1 stays in no VRF on the bridge, so
192.0.2.0/24 is routable only in `red` on the routers. Groups go in the
existing top-level `vrrp group` (no schema change needed for the spike).

| ID | Case (default instance, no shim unless stated) | Pass when |
|:--|:--|:--|
| S1 | IPv4 VRRPv2 multicast group on `vr1ns`/`vr2ns` | MASTER/BACKUP elected; VIP on r1's `vr1ns`; `ip route show vrf red` on r1 lists 192.0.2.0/24; h1 pings the VIP; failover + preempt |
| S2 | IPv6 VRRPv3 (`ff02::12`, link-local source) | as S1 with ping6 |
| S3 | Unicast `peer-address` + `hello-source-address` | elected; adverts in `show vrrp statistics` increase on both |
| S4 | Unicast without `hello-source-address` | as S3 |
| S5 | `rfc3768-compatibility` | `vr1nsv10v4` exists and `ip link show vr1nsv10v4` shows `master red`; h1 pings VIP |
| S6 | `health-check ping 192.0.2.100` | expected FAULT (default VRF has no route). Then, rendered by hand: `/usr/bin/ping -c1 -I red 192.0.2.100` keeps MASTER |
| S7 | Throwaway shim (scratch, ~40 lines): `LD_PRELOAD` + `VRF=red` on a keepalived started for instance dir `red` | S1, S3, S4 pass; S6 with plain `ping` keeps MASTER (the `cap_net_raw` / secure-execution question in §13); keepalived starts while `red` does not exist yet |
| S8 | GARP on transition | h1's neighbour entry for the VIP moves to r2's MAC on failover |
| S9 | `track interface` on an enslaved dummy | FAULT on down |

Decision rule, recorded in `design/vrrp.md` §13 "Spike results" with the
observed output of each row:
- **Branch A** if S1–S5, S8, S9 pass without the shim and S6 passes with
  `-I red`.
- **Branch B** if any of S1–S5 fails without the shim and passes under it
  (S7).
- **Stop and re-plan** if S7 fails too (e.g. keepalived's own socket
  handling defeats the shim); the alternative left is `ip vrf exec`, which
  §13 rejected because it moves the process out of its systemd cgroup.

The user-visible surface (schema shape, show grammar, paths `/show/vrrp/vrf…`)
is the same in both branches; only the backend differs. Milestones after
M1 are listed per branch in §7.

### 3.2 Common to both branches

- **Config tree.** zebra-rs's `router <proto> vrf <name>` convention: a
  `vrf` list under `vrrp`, key `name` (plain `string`, `ext:dynamic
  "rib:vrf"`, staging-friendly like the rest of `vrrp.yang`). No `vrf` leaf
  on a group; the enclosing list is the VRF.
- **VRF name rules** (insomnia, render-time; the name becomes a directory
  and a systemd instance in branch B and a `ping -I` argument in branch A):
  1-15 bytes, `[A-Za-z0-9_.-]`, not `.`/`..`, not `default`. Otherwise skip
  the VRF tree with a warning.
- **Interface membership** from the kernel, not config, through
  [fw-global-options](fw-global-options.md)'s shared `crate::links`
  (`Links::snapshot()` gives each device's `kind`, `master` and
  `vrf_table`; not re-implemented here). `vrf_of(ifname, &snapshot)`
  (proposed, a pure helper in `src/vrrp.rs`) follows `master` until a
  device whose `kind == "vrf"`, at most two hops (a bridge in a VRF).
  Warnings, emitted from vrrp's `host_findings` (the host-dependent pass
  [commit-validation](commit-validation.md) requires to stay out of
  `render()`): a `vrrp vrf red` group whose interface is not in `red`, or
  does not exist yet (normal with `dynamic_interfaces`, so the message
  says so); a default-tree group whose interface is in a VRF ("configure
  it under `vrrp vrf <vrf>`").
- **No multi-path subscription.** The `vrf` list is under `vrrp`, so the
  single `["vrrp"]` path still covers the config, and membership is the
  kernel's (what keepalived sees), not `interface … vrf` config.
  Requirement on [multi-path-subscribe](multi-path-subscribe.md): drop the
  `vrrp-vrf` consumer row (`vrrp`, `interface`). A membership change alone
  re-runs `host_findings` and the Pending check from a `LinkEvent`; the
  render is compared before apply as today (`keepalived::apply`), so no
  reload happens for it.
- **Show grammar** (`exec.yang`, inside `container vrrp`):

  ```yang
  list vrf {
    ext:help "VRRP in a VRF";
    ext:presence "VRRP groups of every VRF";
    ext:default-child "group";          // only once vrrp-hardening M5 exists
    key name;
    leaf name { ext:help "VRF name"; ext:dynamic "rib:vrf"; type string; }
    uses vrrp-show-views;
  }
  ```

  Dispatch: `show vrrp vrf` → `/show/vrrp/vrf` `[]` (all VRFs, extra `VRF`
  column); `show vrrp vrf red` → `/show/vrrp/vrf` `[red]`;
  `show vrrp vrf red statistics group WAN` → `/show/vrrp/vrf/statistics/group`
  `[red, WAN]`; alias forms `/show/vrrp/vrf/group/{statistics,detail}`
  `[red, WAN]`. `parse_show` (introduced by
  [vrrp-hardening](vrrp-hardening.md) M5, or here if it has not landed)
  strips `/vrf` and takes `args[0]` as the VRF.
- **`vrrp disable`** (top level) stops every VRF too: it is the kill
  switch, as VyOS's `high-availability disable`. `vrrp vrf red disable`
  stops only `red`.
- **VRID uniqueness** stays per (interface, VRID, family); interfaces are
  unique host-wide, so the same VRID may appear in two VRFs.
- **`snmp`** is never per VRF ([vrrp-snmp](vrrp-snmp.md)); IPVS is never
  per VRF ([vrrp-virtual-server](vrrp-virtual-server.md)).
- **Verbs.** `restart vrrp` ([vrrp-hardening](vrrp-hardening.md) M6)
  restarts every non-empty instance, so no `restart vrrp vrf NAME` is
  added; `show log vrrp` already globs `insomnia-keepalived@*`.
- **Hooks.** This plan claims no keepalived `notify` slot. The generic
  `notify` line belongs to [conntrack-sync](conntrack-sync.md) (its §3.5);
  its sync-group name resolves in the default tree until that plan adds a
  `vrf` qualifier (its §3.6).

### 3.3 Branch A: one keepalived, VRF-aware rendering

- Schema: the `vrf` list carries `disable`, `group-list`, `sync-group-list`
  only. `global-parameters` are `global_defs`, process-wide in keepalived,
  so the default tree's apply to every VRF; offering per-VRF copies that
  cannot be honoured would be a lie.
- Render: `render(cfg)` walks the default tree, then each VRF tree in key
  order, into the one `default` instance file. One shared `seen`
  (interface, VRID, family) set.
- keepalived instance names are process-global, so a group name may appear
  in only one tree: a later duplicate is skipped with a warning naming
  both VRFs. (Mangling names would leak into `show vrrp` and into
  `notify` arguments; ported VyOS configs have one namespace anyway.)
- Sync-group members must be in the sync group's own tree; others are
  dropped with a warning, matching branch B's behaviour.
- `ping` health check in VRF `red`: `script "/usr/bin/ping -c1 -I red <ip>"`.
  User scripts run in the default VRF; the book says to wrap them in
  `ip vrf exec <vrf>` (not done automatically: a script may not touch the
  network at all, and `ip vrf exec` needs cgroup2 + BPF).
- Show: one dump, filtered by the retained model's group-name sets per
  tree; `DISABLED` rows per tree.
- Removed as dead code: `--vrf-preload` (`src/main.rs:71-73`),
  `Keepalived::vrf_preload` and the VRF branch of `env_for`
  (`src/keepalived.rs:49`, `:195-201`), the book's `--vrf-preload` section
  (`book/src/ch-00-03-command-line-options.md:173`).
- That also settles docs-corrections D5's handover for branch A: with no
  preload there is nothing to rename to `vrf.so`, no shim to refuse, and
  no shim that can fail silently. A5
  replaces the shim note docs-corrections adds to `design/vrrp.md` §13.
- Deviation from §13 recorded there: "one keepalived per VRF" is replaced
  by "one keepalived; VRF via interface binding and `ping -I`", with the
  spike as evidence.

### 3.4 Branch B: one keepalived per VRF under a preload shim

**Shim (`vrf.so`).** New workspace member `vrf-shim/` (`crate-type =
["cdylib"]`, `[lints] workspace = true`, depends on `libc`), so CI's
`cargo test --workspace --exclude bdd` and clippy cover it with no second
toolchain. Behaviour:
- Interposes `socket()` only. After the real call (`dlsym(RTLD_NEXT,
  "socket")`), for `AF_INET`/`AF_INET6` with `$VRF` set and non-empty, it
  sets `SO_BINDTODEVICE` to `$VRF`. A new socket has no device binding, so
  "never override an existing binding" (§13) holds by construction;
  keepalived's own later `SO_BINDTODEVICE(<member>)` replaces it as
  intended (root has `CAP_NET_RAW`).
- Not interposing `bind`/`connect`: `ping` sends on an unconnected ICMP
  socket with `sendto`, which those hooks would miss.
- Fail closed: if `setsockopt` fails (VRF device absent: `ENODEV`), close
  the fd and return -1 with that errno. A process that cannot get a socket
  is visible; one in the wrong VRF is not.
- `$VRF` read once (`OnceLock`), `extern "C"` (a panic aborts; the code
  has no panicking paths). glibc-internal callers of `__socket` (the stub
  resolver) and static binaries are not affected — documented.
- Installed as `/usr/lib/insomnia/vrf.so`: Cargo.toml `assets` gains
  `["target/release/libvrf_shim.so", "usr/lib/insomnia/vrf.so", "644"]`;
  `packaging/Makefile:18` becomes `cargo build --release -p insomnia -p
  vrf-shim` (a plain `cargo build` in a non-virtual workspace builds only
  the root package); `bdd/Makefile:44` likewise, staging it as
  `.stage/lib/insomnia/vrf.so`.
- `--vrf-preload` default → `/usr/lib/insomnia/vrf.so`; tests updated.

Rejected: a C shim (second compiler in packaging and CI, no clippy, no
cargo tests); `ip vrf exec` in the unit (moves keepalived out of its
service cgroup, §13).

**Guards.**
- Static, before any start/reload of a non-default instance:
  `check_preload(path)` (proposed, `src/keepalived.rs`) — regular file;
  ELF magic; `EI_CLASS` = 64-bit and `EI_DATA` = little-endian matching the
  build; `e_type == ET_DYN` (3) — ld.so would also preload ET_EXEC
  (docs-corrections D5 checked the message on the dev host), but a
  preload library is never one, so it is refused; `e_machine` = host
  (`EM_X86_64` 62, `EM_AARCH64` 183 by `cfg(target_arch)`). This is the
  refuse-to-start check docs-corrections D5 leaves to this plan. Failure
  → `Applied::Refused`,
  conf written for inspection, nothing started, error log names the
  instance and the reason.
- Runtime, after each start/reload/restart of a non-default instance: the
  canonical shim path must appear in `/proc/<pid>/maps` of the parent pid
  (children fork without exec, so they inherit it). Missing → systemd
  mode: `systemctl stop` + error; signal mode: error only (insomnia does
  not own that process).

**Lifecycle** (`src/vrrp.rs`, `src/keepalived.rs`):
- Desired set = `default` if its tree renders non-empty, plus each valid
  VRF tree that renders non-empty. Applied set kept in the task state;
  on the first event after startup it is seeded by scanning
  `--keepalived-dir` for instance directories with a non-empty
  `keepalived.conf`, so a VRF removed while insomnia was down is stopped.
- Each desired instance: render its own file (the existing `render`, per
  tree); `env` = `LD_PRELOAD=<shim>\nVRF=<name>\n`.
- VRF device missing (no `kind == "vrf"` link of that name in
  `Links::snapshot()`) → `Applied::Pending`: the instance is stopped if
  running and its conf written. `run`'s `select!` gains a
  `Links::subscribe()` arm: `Added`/`Changed` of a pending VRF device
  retries that instance, `Removed` of a running instance's VRF stops it
  and marks it pending, `Resync` re-checks every instance. No timer.
- Env changed with a non-empty conf → `systemctl restart` (LD_PRELOAD is
  read at exec time). This plan owns that rule; [vrrp-snmp](vrrp-snmp.md)
  adds its own trigger to the same decision function. Signal mode → warn
  "restart required".
- Instances no longer desired → `apply(name, "")` (stop / idle).
- Show: `collect_json(ka, <vrf>)` per instance; `show vrrp vrf` collects
  every applied instance.

### 3.5 Deviations to record (module docs, `design/vrrp.md` §13)

- Whole feature: zebra-rs extension; VyOS has no VRF for VRRP.
- Top-level `vrrp disable` covers all VRFs.
- Branch A: per-VRF `global-parameters` not offered; group names unique
  across VRFs; `ping -I <vrf>`; user scripts not wrapped.
- Branch B: shim interposes `socket()` only and fails closed.

## 4. Changes

### zebra-rs

`yang/config.yang` (`:5705-5709`), branch A:

```yang
container vrrp {
  if-feature feat:insomnia;
  ext:help "Virtual Router Redundancy Protocol (VRRP)";
  uses "vrrp:vrrp";
  list vrf {
    ext:help "VRRP groups in a VRF";
    key "name";
    leaf name { ext:help "VRF name"; ext:dynamic "rib:vrf"; type string; }
    leaf disable { ext:help "Disable VRRP in this VRF"; type empty; }
    uses "vrrp:group-list";
    uses "vrrp:sync-group-list";
  }
}
```

Branch B: the same list with `uses "vrrp:vrrp";` in place of the last
three statements. `vrrp.yang`'s description drops "the per-VRF `vrf` list"
from its deferred list (`:41-44`).

`yang/exec.yang`: the `list vrf` of §3.2 inside `container vrrp`.

The VRRP value rows [commit-validation](commit-validation.md) C3 adds to
`check::startup_tolerant_check` (password, description, timeout,
advertise-interval) must also match the `/vrrp/vrf/group/…` callback
paths; if C3 landed matching `/vrrp/group/…` only, A2/B3 widens the match.

Tests (`src/config/manager.rs`): extend `shipped_vrrp_gated_on_insomnia`
(`:7949`) with the `vrf` branch; `vrrp_commands_parse_only_with_insomnia`
(`:7975`) with `set vrrp vrf red group WAN vrid 10` (and, branch A, a
negative for `set vrrp vrf red global-parameters version 3`);
`show_vrrp_grammar_gated_on_insomnia` (`:8063`) with every dispatch row of
§3.2 routing to `"vrrp"`; `vrrp_json_marshal_contract` (`:8112`) with a
`vrf` entry, pinning `"vrf": [{"name":"red","group": […]}]`.

### insomnia

Model (`src/vrrp.rs`): `VrrpConfig` gains `vrf: Vec<VrfTree>`;
`VrfTree { name: Option<Flex>, #[serde(flatten)] tree: VrrpConfig }`
(branch A: a narrower struct without `global_parameters`). `is_empty`
splits into `default_is_empty()` and per-tree checks.

`vrrp::run` takes a `Links` clone from `main.rs` (one watcher per process,
fw-global-options §3.2a); `fn vrf_of` and `fn host_findings(cfg, links,
probe)` (extending [vrrp-hardening](vrrp-hardening.md)'s) are pure over a
snapshot.

Branch A: `render` signature unchanged; per-tree loop; `check_health`
takes `vrf: Option<&str>` for the `-I` flag; `process_show` filters by
tree. Delete `vrf_preload` plumbing.

Branch B: `vrf-shim/` crate (`src/lib.rs` ≈ 60 lines, `examples/probe.rs`);
`keepalived.rs`: `check_preload`, `preload_mapped(pid, path)`,
`Applied::{Pending, Refused, Restarted}`, `fn verb(empty, conf_changed,
env_changed) -> Verb` (pure); `vrrp.rs`: `InstanceSet { applied, pending }`
in the task state, the `LinkEvent` arm, per-instance show.

Worked example (both branches). Config:

```
set vrf red
set interface eth1 vrf red
set vrrp vrf red group WAN interface eth1
set vrrp vrf red group WAN vrid 10
set vrrp vrf red group WAN address 203.0.113.254/24
set vrrp vrf red group WAN health-check ping 203.0.113.1
```

Branch B: `/run/insomnia/vrrp/red/keepalived.conf`

```
global_defs {
    dynamic_interfaces
    script_user root
}

vrrp_script healthcheck_WAN {
    script "/usr/bin/ping -c1 203.0.113.1"
    interval 60
    fall 3
    rise 1
}

vrrp_instance WAN {
    state BACKUP
    interface eth1
    virtual_router_id 10
    priority 100
    advert_int 1
    preempt_delay 0
    virtual_ipaddress {
        203.0.113.254/24
    }
    track_script {
        healthcheck_WAN
    }
}
```

`/run/insomnia/vrrp/red/env` = `LD_PRELOAD=/usr/lib/insomnia/vrf.so` /
`VRF=red`; then `systemctl reload-or-restart insomnia-keepalived@red.service`
and the maps check. The `default` instance renders empty (stopped or
unchanged).

Branch A: the same blocks in `/run/insomnia/vrrp/default/keepalived.conf`,
except `script "/usr/bin/ping -c1 -I red 203.0.113.1"`.

`show vrrp vrf` (both):

```
VRF  Name  Interface  VRID  State   Priority  Last Transition
---  ----  ---------  ----  ------  --------  ---------------
red  WAN   eth1       10    MASTER  100       2m3s
```

(`table()` from `src/text.rs:6-31`: two-space gaps, dashed header rule.)

## 5. Tests

Unit (CI):
- `vrf_tree_golden` (per branch): the worked example plus a default-tree
  group, a VRF sync group, and a disabled VRF tree; warnings for an
  invalid VRF name (`..`, `default`, 16 bytes) and, branch A, a duplicate
  group name across trees and a cross-tree sync member.
- `vrf_of`: hand-built `Link` snapshots with a VRF, a slave, a bridge in
  a VRF, a plain device and a missing device; membership findings.
- `show_vrf_paths`: every §3.2 dispatch row.
- Branch B: `check_preload_rejects` (missing, ET_REL, ET_EXEC, wrong
  machine, 32-bit, truncated) and accepts a synthetic ET_DYN header;
  `verb_table` for every (empty, conf_changed, env_changed) combination;
  `instances_reconcile` (desired vs applied incl. startup scan with
  temp dirs); keepalived.rs `unit_and_env_naming` updated to `vrf.so`.
- Branch B, `vrf-shim` crate (`tests/preload.rs`): runs
  `target/<profile>/examples/probe` with `LD_PRELOAD=<cdylib>`:
  `VRF=lo` → probe reports `SO_BINDTODEVICE` = `lo` for AF_INET and
  AF_INET6, unbound for AF_UNIX; `VRF` unset → unbound; `VRF=nosuchdev` →
  `socket()` fails with `ENODEV`. Binding an unbound socket needs no
  `CAP_NET_RAW` since Linux 5.7, so this runs unprivileged on CI
  (runner kernel *unverified*; skip with a message if `EPERM`).

BDD `@vrrp_vrf` (`bdd/tests/features/vrrp_vrf.feature`,
`bdd/tests/configs/vrrp_vrf/`): the spike topology made permanent. Configs
put the groups under `vrrp vrf red`.
1. Setup and elect: `show vrrp vrf red` MASTER on r1 / BACKUP on r2;
   `show vrrp` (default) on r1 does not contain `LAN`; VIP on `vr1ns`.
2. Traffic: h1 pings the VIP; `command "ip route show vrf red"` on r1
   contains `192.0.2.0/24`.
3. Health check in the VRF: `health-check ping 192.0.2.100` keeps r1
   MASTER; h1 link down → r1 FAULT, r2 MASTER.
4. Unicast peers inside the VRF.
5. Failover/preempt by link.
6. Misplaced group: a default-tree group on `vr1ns` → insomnia log
   contains `is in VRF red`.
7. Declarative unload of `vrrp vrf red` → VIP gone; branch B: insomnia log
   `stopped` for instance `red`.
8. Teardown.

Branch B node script: `vrrp_node.sh <ns> [vrf …]` starts one keepalived
per listed VRF in `/run/insomnia/vrrp/<vrf>` with `LD_PRELOAD=<stage
shim> VRF=<vrf>`, each from a background waiter that starts it only once
`/sys/class/net/<vrf>` exists (the shim fails closed before that);
insomnia gets `--vrf-preload <stage>/lib/insomnia/vrf.so`;
`vrrp_node_stop.sh` kills every recorded keepalived pid.

## 6. Docs

- `design/vrrp.md` §13: spike results table and branch decision (M1);
  then rewritten to what was built (branch A replaces "one process per
  VRF"; branch B keeps it, with the shim and guard details). §7 flag table
  and §14 updated.
- `book/src/ch-05-04-keepalived-and-insomnia.md` "One instance per VRF":
  the chosen model, VRF device timing, (B) the shim and its errors, (A)
  `ip vrf exec` for user scripts.
- `book/src/ch-05-01-vrrp-groups.md`: a VRF example.
- `book/src/ch-03-02-show-vrrp.md`: `show vrrp vrf`.
- `book/src/ch-00-03-command-line-options.md:173`: (A) remove
  `--vrf-preload`; (B) new default and what the guard checks.
- `src/vrrp.rs` / `src/keepalived.rs` module docs: §3.5.
- `book/src/ch-04-00-bdd-tests.md`: `@vrrp_vrf`.

## 7. Milestones

| # | Scope | Repo | Effort | Done when |
|:--|:--|:--|:--|:--|
| M1 | Spike S1–S9 on a branch; results + decision in `design/vrrp.md` §13 | insomnia | S | table committed; branch chosen |
| A2 | `vrf` list (reduced) + show grammar + tests | zebra-rs | S | manager tests green |
| A3 | Model, per-tree render, `-I`, membership findings over `crate::links`, show filters, delete preload plumbing, goldens | insomnia | M | unit tests green |
| A4 | `@vrrp_vrf` | insomnia | S | green locally |
| A5 | Docs | insomnia | S | book builds |
| B2 | `vrf-shim` crate + tests; packaging and stage; `vrf.so` default; `check_preload`, `preload_mapped` | insomnia | M | CI green incl. shim tests; `.deb` contains `/usr/lib/insomnia/vrf.so` |
| B3 | `vrf` list (full grouping) + show grammar + tests | zebra-rs | S | manager tests green |
| B4 | Per-instance lifecycle, `LinkEvent`-driven pending, env-change restart, per-instance show, membership findings, goldens | insomnia | M | unit tests green |
| B5 | Node script multi-instance; `@vrrp_vrf` | insomnia | M | green locally |
| B6 | Docs | insomnia | S | book builds |

A2/B3 can be prepared during M1 but merge only after the decision.

## 8. Risks and open questions

- S6/S7 secure-execution: `ping` with file capabilities under a root
  keepalived should not trigger `AT_SECURE`, so `LD_PRELOAD` survives;
  if it does not, branch B falls back to rendering `ping -I <vrf>` as in
  branch A.
- keepalived at startup may open an `AF_INET` socket for ioctls; with the
  shim failing closed and the VRF absent that call fails. Systemd mode
  never starts an instance before its VRF device exists (Pending), and the
  BDD waiter covers signal mode; S7 confirms keepalived survives anyway.
- `raw_l3mdev_accept` (default 1) and `tcp_l3mdev_accept` (zebra-rs sets
  it) change what unbound sockets see; a host that changed them may
  behave differently from the spike. Record the values seen in M1.
- Branch A puts every VRF's groups in one reload blast radius (one bad
  file reloads all); acceptable because the renderer never emits an
  invalid file.
- The spike may pass for IPv4 and fail for IPv6 (S2). Rule: any failure in
  S1–S5 selects branch B; no per-family split.
- `crate::links` lands with [fw-global-options](fw-global-options.md) M3;
  if A3/B4 come first, they wait for it rather than adding a second
  netlink reader (fw-global-options rejects one watcher per backend).

## 9. Acceptance criteria

- [ ] Spike results and the branch decision are in `design/vrrp.md` §13.
- [ ] `set vrrp vrf red …` parses only with `--feature insomnia`; JSON contract pinned.
- [ ] A VRF group elects, carries its VIP, health-checks and fails over inside the VRF (`@vrrp_vrf` green).
- [ ] `show vrrp vrf [NAME] [statistics|detail …]` and bare `show vrrp` (default only) answer correctly, text and JSON.
- [ ] Invalid VRF names and misplaced groups are warned; nothing is written outside `--keepalived-dir`.
- [ ] Branch B: `vrf.so` ships in the `.deb`; a missing, ET_REL, wrong-arch or unmapped shim refuses or stops the instance with an error; env changes restart; removed VRFs stop, including across an insomnia restart; missing VRF devices are retried.
- [ ] Branch A: `--vrf-preload` and the env VRF branch are gone; `ping -I` rendered; duplicate names skipped.
- [ ] Module docs, `design/vrrp.md` §13 and the book describe the chosen branch only.
