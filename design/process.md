# Process management and daemons in a VRF — design

Status: implemented, 2026-11-09 (zebra-rs branch `process-cli`, insomnia
branch `process-vrf`): work items 1–4 of §11; item 5 (`vrrp vrf <name>`)
remains. §14 records what the implementation changed. §4 replaces the
`LD_PRELOAD` shim of `design/vrrp.md` §13 and the VRF-binding options of
`design/dhcp.md` §19.

insomnia renders configuration for daemons that run beside it:
- keepalived, one instance per VRF;
- insomnia-dhcp-relay, one process for every VRF;
- later Kea, one instance per family per VRF.

This document settles three questions:
- who supervises those daemons (§3);
- how a daemon runs in a VRF (§4);
- how an operator sees and controls them: `show process`, `start process`,
  `stop process` and `restart process`, the commands openconfigd had (§5–§8).

Baselines (line numbers and file names refer to these):

| Source | Version |
|:--|:--|
| insomnia | `main` @ `7b5fa01`, plus branch `dhcp-relay-backend` (`src/process.rs`, `src/relayd.rs`) |
| zebra-rs | `ddaedbd6` |
| openconfigd | `ab833f88` (2026-08-19) |
| systemd | Ubuntu 24.04 `255.4-1ubuntu8.18` (arm64) |
| Kernel | `6.8.0-149-generic` |

## Decisions at a glance

| # | Question | Decision | § |
|:--|:--|:--|:--|
| PM1 | Who supervises | systemd, for daemons that read their config from files and must outlive insomnia. In-process supervision only for a child whose state the parent pushes in and that must die with it (zebra-rs's cradle engine) | 3 |
| PM2 | One daemon per VRF | A template unit instance `name@<vrf>.service`; `default` is the global table | 4.1 |
| PM3 | Binding to the VRF | `BPFProgram=sock_create:/sys/fs/bpf/insomnia/vrf/%i`, pinned by insomnia, guarded by `AssertPathExists=`. No `LD_PRELOAD` shim; no `ip vrf exec` under systemd | 4.2–4.6 |
| PM4 | Registry | `insomnia::process` holds every daemon instance under a stable name: `keepalived@red`, `dhcp-relay`, `kea-dhcp4@red` | 5 |
| PM5 | Operator commands | `show process [name]`, `start\|stop\|restart process <name>` in zebra-rs exec mode, gated on `feat:insomnia`, answered by insomnia | 6 |
| PM6 | What `stop` means | An operator hold in `/run/insomnia/holds/`. Commits still render the file but never start or reload a held instance. Survives an insomnia restart, not a reboot. The `disable` leaves stay the persistent switch | 6.2 |
| PM7 | Signal mode (BDD, containers) | The harness owns the processes and starts VRF instances under `ip vrf exec`. `show process` works; `start`, `stop` and `restart` are refused | 7 |
| PM8 | Transport | The zebra.show.v1 provider stream, unchanged. zebra-rs routes `start`, `stop` and `restart process` orders to the provider named `process`, as it routes `show` orders today | 8 |
| PM9 | cradle | Stays on zebra-rs's own supervisor and out of `show process` for now | 3, 12 |

## 1. Where we are

- **insomnia** (`src/process.rs`):
  - `Control::Systemd` drives a daemon's unit; `Control::Signal` only sends `SIGHUP` to a pid file, for the BDD harness.
  - `reload()` compares before reloading. An empty config stops the unit (systemd mode).
  - keepalived runs as `insomnia-keepalived@<vrf>.service` (`design/vrrp.md` §7). For VRF instances, its `env` file carries `LD_PRELOAD=<--vrf-preload>` and `VRF=<name>`. The shim itself was never written.
  - insomnia-dhcp-relay runs as `insomnia-dhcp-relay.service`: `DynamicUser=yes`, two capabilities, the full sandbox. It binds its own per-VRF sockets, so it needs no VRF help (`design/dhcp.md` §10).
  - Daemon status is visible only through feature commands (`show vrrp`, `show dhcp relay statistics`). There is no process list and no operator start or stop.
- **zebra-rs** supervises the cradle engine in-process (`zebra-rs/src/cradle/supervisor.rs`):
  - adopt an engine already answering, or spawn one;
  - a readiness probe sends `EngineEvent::Up`, after which zebra-rs re-applies every port;
  - respawn with backoff from 1 s to 30 s, reset after 60 s of healthy running;
  - stop with `SIGTERM`, then `SIGKILL` after 5 s;
  - `PR_SET_PDEATHSIG` plus `kill_on_drop`, so the root engine never outlives zebra-rs.
- **VRF binding so far:**
  - `design/vrrp.md` §13 chose the `vrf.o` `LD_PRELOAD` shim.
  - `design/vyos-gap.md` §8.4 item 3 found that a missing shim fails open: ld.so prints a warning and the instance runs in the default VRF.
  - `design/dhcp.md` §19 left Kea's binding open between the shim and `ip vrf exec`.

## 2. What openconfigd does

The engine is the vendored `github.com/coreswitch/process`
(`vendor/github.com/coreswitch/process/process.go`); openconfigd wraps it in
`config/process_extensions/process.go`.

- **Registry.** A global slice behind a mutex. A process's index is its position in the slice.
- **Commands** (`config/command.go`):
  - `show process` (`:279`, exec mode): index, `name@vrf`, state, pid, the last lookup, start and wait errors, and the arguments.
  - `start process WORD` and `stop process WORD` (`:357`, configure mode). The handlers (`:48`, `:61`) accept only a numeric index from `show process`, ignore anything else silently, and print nothing.
- **Start.** A goroutine loops for as long as the process is registered:
  - waits an optional start delay: 3 s for dhcpd, bgpd and ospfd; 10 s for keepalived (`vrrp.go:73`);
  - runs the binary from `PATH` in the foreground (`-d`, `-D -n`, `-f`);
  - waits for it to exit, then sleeps a fixed 1 s and starts it again.
  - In a VRF it sets `VRF=<name>` and `LD_PRELOAD=/usr/bin/vrf_socket.so`.
- **Stop.** Cancelling the context makes Go `SIGKILL` the child. Then an optional `KillPidFile` gets `kill -TERM`: keepalived's VRRP child (`vrrp.go:74`).
- **Config changes.** `ProcessWithConfig.Equal` compares the rendered config files plus name, VRF and arguments. Any difference means stop and start (`MaybeRestart`); nothing is ever reloaded in place. `ProcessMap` applies the same rule to keyed sets.
- **Process-count tracker** (`process_count_tracker.go`, used from `nexthop_walker.go:10`): fires Up or Down when the number of Quagga processes crosses zero.
- **Exit.** Each handler's `Exit()` unregisters its processes (`config.go:882`).
- **What it ran:**
  - dhcpd per interface and dhcrelay per interface (`dhcp.go:340`, `relay.go`), from the IETF-draft DHCP model zebra-rs dropped in favour of the VyOS trees;
  - keepalived per VRF;
  - Quagga bgpd and ospfd per VRF;
  - gobgpd.

Weaknesses this design does not repeat:

- **Unstable addresses.** Unregistering re-indexes the slice, so after a commit `stop process 3` can hit a different daemon.
- **A stop that does not stick.** It lasts until the next config change for that process, which registers a fresh `Process`, and nothing records it.
- **`SIGKILL` on every stop, and a restart on every change.** For keepalived that is a VRRP failover per commit.
- **Orphans.** Children are not tied to openconfigd's lifetime. If it dies, they keep running, and the new openconfigd's copies fail to bind and retry forever.
- **Root everywhere, no backoff, no readiness.** A process is also marked Running when its start failed.

## 3. Who supervises (PM1)

| | insomnia spawns its daemons (openconfigd) | systemd runs them |
|:--|:--|:--|
| insomnia restarts or is upgraded | children die with it (failover, DHCP outage) or are orphaned | daemons keep serving on their last config (`KillMode=process`, `RuntimeDirectoryPreserve=yes`) |
| Privilege | children inherit insomnia's root; sandboxing means reimplementing namespaces, seccomp and capability dropping | per-unit sandbox; the relay agent runs as a dynamic user with exactly two capabilities (`design/dhcp.md` §10) |
| VRF | `LD_PRELOAD` | `BPFProgram=sock_create`, attached by systemd (§4) |
| Restart after a crash | hand-written (fixed 1 s in openconfigd; cradle needed its own backoff) | `Restart=`, start-rate limits |
| Logs, limits, ordering | hand-written | journal, `MemoryMax=`, `After=` |
| Config change | stop and start | reload in place: `SIGHUP`, or Kea's `config-reload` |
| insomnia's own size | an init system | a renderer plus a reloader |

The costs of the systemd model:
- **Signal mode.** Without systemd (BDD, containers) a second, smaller code path is needed. The ISO always has systemd, so this matters only for tests.
- **No restart notice.** insomnia does not learn when systemd restarts a daemon. For our daemons that is fine: keepalived, the relay agent and Kea read their config from files on start, so there is nothing to push again. `show process` asks systemd when it runs.

**Rule.** Supervise a child in-process only when all three hold:
- the parent pushes its state into the child after every restart;
- the parent needs to know when the child is ready;
- the child must not outlive the parent.

The cradle engine meets all three, so its supervisor stays in zebra-rs. No
insomnia daemon meets even one.

## 4. Daemons in a VRF (PM2, PM3)

### 4.1 Instances

- **One template instance per VRF:** `insomnia-keepalived@<vrf>.service`, `insomnia-kea-dhcp4@<vrf>.service`. The instance name is the VRF; `default` is the global table.
- **Per-instance paths** already follow this: `/run/insomnia/vrrp/<vrf>/` (`design/vrrp.md` §7), `/run/insomnia/kea/<vrf>/` (`design/dhcp.md` §8.1).
- **A daemon that binds its own sockets per VRF needs no instance per VRF.** insomnia-dhcp-relay is one process for all VRFs.

### 4.2 The mechanism

`ip vrf exec` works by attaching a cgroup-BPF program of type
`BPF_PROG_TYPE_CGROUP_SOCK` to a cgroup, at the `BPF_CGROUP_INET_SOCK_CREATE`
hook. On every IPv4 and IPv6 socket a process in that cgroup creates, the
program sets `bound_dev_if` to the VRF device's interface index. The socket
is bound to the VRF before the daemon sees it, so binds, connects and route
lookups happen in the VRF's table. iproute2 builds the program from five raw
instructions (`ip/ipvrf.c`, `prog_load`):

| # | Instruction | Meaning |
|:--|:--|:--|
| 1 | `r6 = r1` | keep the context, a `struct bpf_sock *` |
| 2 | `r3 = <ifindex>` | the VRF device |
| 3 | `*(u32 *)(r1 + 0) = r3` | `ctx->bound_dev_if` (offset 0) |
| 4 | `r0 = 1` | allow the socket |
| 5 | `exit` | |

systemd attaches such a program to a unit's own cgroup:
`BPFProgram=sock_create:<path>` names a program pinned in bpffs
(systemd.resource-control(5)). So:
- **systemd (pid 1) attaches the program**, and the daemon needs no privilege for it.
- **Children of the daemon inherit it.** keepalived's health-check `ping` runs in the VRF, which removes the `cap_net_raw` caveat of `design/vrrp.md` §13.
- **It covers only `AF_INET` and `AF_INET6` sockets at creation.** `AF_PACKET` sockets (Kea's raw DHCPv4 mode, the relay's reply socket) are per interface and need nothing. Netlink is unaffected.
- **A daemon may still bind a socket to a member interface itself** (keepalived does), which overrides the VRF on that socket. Changing an already-bound socket needs `CAP_NET_RAW` (§4.3).

The trap: if the pinned program does not exist, systemd starts the unit anyway
and only logs a warning (systemd.resource-control(5): "unit activation will
continue"). The daemon would run in the default VRF. Every template therefore
carries `AssertPathExists=` on the same path, **in `[Unit]`**: systemd
ignores it in `[Service]` (§4.3, row 9).

### 4.3 What was verified

Run on 2026-11-08 on the baseline host:
- a scratch namespace with VRF `red` (table 10) and a dummy member `d0` holding `198.51.100.1/24` and `2001:db8:51::1/64`;
- the program pinned by a 40-line loader using `bpf(BPF_PROG_LOAD)` and `bpf(BPF_OBJ_PIN)`;
- each case a systemd unit in the namespace, probing which device a fresh socket is bound to and whether `198.51.100.2` / `2001:db8:51::2`, routed only in `red`, is reachable.

| # | Unit | Result |
|:--|:--|:--|
| 1 | No binding (control) | unbound; "Network is unreachable" |
| 2 | `BPFProgram=sock_create:…/red`, `DynamicUser=yes`, `CapabilityBoundingSet=` (none), `SystemCallFilter=@system-service`, `ProtectSystem=strict`, `RestrictAddressFamilies=` | bound to `red`, routed |
| 3 | As 2, program not pinned | **runs unbound**: systemd only warns |
| 4 | As 3, plus `AssertPathExists=` on the pin | start refused: "Starting requested but asserts failed" |
| 5 | `ip vrf exec red …` inside a `DynamicUser` unit | fails: "Failed to setup vrf cgroup2 directory" |
| 6 | `ip vrf exec red …` as root | bound, routed; the process lands in a cgroup `ip` created inside the unit's (`/system.slice/run-u40299.service/vt-ns/vrf/red`) |
| 7 | Unprivileged `SO_BINDTODEVICE "red"`, what a shim would do | allowed without `CAP_NET_RAW` |
| 8 | Template unit `insomnia-vrftest@.service` with `%i` in `BPFProgram=` and `AssertPathExists=`; `ExecStart=/bin/sh -c 'python3 …'` | instance `red`: IPv4 and IPv6 sockets of the shell's child bound to `red`, both routed; instance `blue` (no pin): refused |
| 9 | As 8, `AssertPathExists=` placed in `[Service]` | ignored: `blue` started and ran unbound |
| 10 | Instance `red` re-binding a fresh (already bound) socket to member `d0` | `EPERM` without capabilities; allowed with `AmbientCapabilities=CAP_NET_RAW` |
| 11 | Instance `default` with a program writing `bound_dev_if = 0` | unbound, like no program at all |

Everything was removed afterwards: units, pins, namespace.

### 4.4 Unit templates

The lines every per-VRF template gains:

```ini
[Unit]
# insomnia pins the program before it starts the instance. Without this
# line a missing program would run the daemon in the default VRF.
AssertPathExists=/sys/fs/bpf/insomnia/vrf/%i

[Service]
BPFProgram=sock_create:/sys/fs/bpf/insomnia/vrf/%i
```

- **`insomnia-keepalived@.service`** loses `EnvironmentFile=-/run/insomnia/vrrp/%i/env` and its shim comment. keepalived runs as root, so its own member-interface binds keep working (§4.3 row 10).
- **`insomnia-kea-dhcp4@.service` / `-dhcp6@`** (`design/dhcp.md` §8.3) gain the two lines. Kea keeps `CAP_NET_RAW` for its raw sockets, which also covers any member-interface bind.
- **`insomnia-dhcp-relay.service`** is unchanged: one process, its own per-VRF sockets.

### 4.5 Pin lifecycle

insomnia owns `/sys/fs/bpf/insomnia/vrf/<vrf>`:

- **The program.**
  - The five instructions of §4.2, loaded with `bpf(BPF_PROG_LOAD)` and pinned with `bpf(BPF_OBJ_PIN)` through `libc`. No compiler, libbpf or aya.
  - For `default`, the same program with interface index 0 (§4.3 row 11), so one template serves every instance.
  - insomnia records the interface index each pin was built for in `/run/insomnia/vrf/<vrf>.ifindex`.
- **Before starting an instance:** pin the VRF if it is not pinned, or if its interface index changed.
- **VRF re-created under a new index:** a running unit keeps the program it was started with, so its sockets point at a dead interface. Re-pin, then restart every instance of that VRF.
- **VRF deleted:** stop its instances, then unpin.
- **insomnia startup:** pins outlive an insomnia restart (bpffs lasts until reboot). Re-pin every VRF from current state, and unpin VRFs that no longer exist.
- **Interface indexes and VRF events** come from the `crate::links` netlink watcher planned in `design/dhcp.md` §7.3, extended with VRF devices.
- **A VRF that does not exist yet:** do not start its instance. Log once, and retry when the watcher reports the device, as the relay agent does for missing interfaces.

### 4.6 Failure modes

| Failure | Effect | Handling |
|:--|:--|:--|
| Pin missing at start | systemd would run the daemon unbound | `AssertPathExists=` refuses the start (§4.3 rows 4, 8) |
| `AssertPathExists=` in the wrong section | silently ignored (§4.3 row 9) | a unit test parses the shipped templates and checks it sits in `[Unit]` |
| VRF re-created | the daemon's sockets use a dead interface index | re-pin and restart (§4.5) |
| Program load fails | no pin | the instance is not started; `show process` shows the error |
| Daemon re-binds sockets to member interfaces without `CAP_NET_RAW` | `EPERM` (§4.3 row 10) | such daemons keep `CAP_NET_RAW` (keepalived as root, Kea) |
| Host without the unified cgroup hierarchy | cgroup-BPF unavailable | not a target: Ubuntu 24.04 and the ISO use cgroup v2 |

### 4.7 Signal mode and BDD

In signal mode the harness starts each daemon itself. A VRF instance is
started under `ip vrf exec <vrf>` as root inside the test namespace: the same
kernel hook as `BPFProgram=` (§4.3 row 6), so BDD exercises the binding the
units use. insomnia does not pin anything in signal mode. Its pinning code is
unit-tested (§10), and the systemd path is covered by a root-only script that
repeats §4.3.

### 4.8 What this replaces

- **`design/vrrp.md` §13:**
  - the `vrf.o` shim, the per-instance `env` file and the `--vrf-preload` flag (`src/keepalived.rs` `env_for`, `src/main.rs`);
  - the spike items about the shim and the `ping` health check;
  - `design/vyos-gap.md` §8.4 item 3 (the shim's name and failure mode) becomes moot.
- **`design/dhcp.md` §19:** Kea's binding options.
- **openconfigd's `vrf_socket.so`.**

## 5. The process registry (PM4)

`insomnia::process` grows from the reload helper into a registry. Each backend
registers the instances it manages; an entry holds:

| Field | Example | Source |
|:--|:--|:--|
| Name | `keepalived@red`, `dhcp-relay`, `kea-dhcp4@default` | the backend; stable, and equal to the unit's instance name |
| VRF | `red` | the backend |
| Control | unit `insomnia-keepalived@red.service`, or a pid file in signal mode | flags |
| Config | `/run/insomnia/vrrp/red/keepalived.conf` | the backend |
| Reload | `SIGHUP` through `ExecReload=`, or Kea's `config-test` + `config-reload` | the backend |
| Desired | running or stopped, from the last render | each commit |
| Hold | set by `stop process` | `/run/insomnia/holds/<name>` |
| Observed | state, sub-state, main pid, start time, restart count | `systemctl show -p ActiveState,SubState,MainPID,ExecMainStartTimestampMonotonic,NRestarts,Result <unit>`, or pid liveness in signal mode |
| Last error | `systemctl reload-or-restart … exited 1: …` | the last failed apply |

Reconcile is the existing `process::reload`, plus the hold. A held instance
still gets its config file written, so `start process` brings it up on the
current config, but it is never started or reloaded.

## 6. Operator commands (PM5, PM6)

### 6.1 Grammar

zebra-rs `exec.yang`, gated on `feat:insomnia`:

```
show process [<name>]
start process <name>
stop process <name>
restart process <name>
```

- **Exec mode, not configure mode** as in openconfigd. These are operational actions and change no config.
- **Names, not indexes.** A name stays the same across commits, and it is the unit's instance name, so `systemctl` and `journalctl -u` agree with the CLI.
- **Completion:** v1 takes any string. An unknown name answers `% No process "<name>"; see show process`.

### 6.2 Semantics

| Command | Running, wanted by config | Stopped, nothing configured or `disable` set | Held by `stop process` |
|:--|:--|:--|:--|
| `stop process` | hold, then `systemctl stop` | hold (keeps it down if config appears later) | no change |
| `start process` | no change | clear any hold; `% Nothing configured for "<name>"` | clear the hold, then reconcile: start on the current config |
| `restart process` | `systemctl restart` | `% Nothing configured for "<name>"` | `% "<name>" was stopped by an operator; use start process` |

- **Holds are files in `/run/insomnia/holds/`.** They survive an insomnia restart but not a reboot. An operator's stop is temporary; the config's `disable` leaves are the persistent, VyOS-compatible way to keep something off.
- **Holds survive package upgrades.** cargo-deb restarts every non-template unit the package ships (`insomnia-dhcp-relay.service`). insomnia, restarted by the same upgrade, re-applies its holds at startup and stops held units again.
- **Commits.** A commit that changes a held instance's config renders the file and logs that the instance stays held.

### 6.3 Output

```
Name               VRF      State    Admin  PID    Uptime   Restarts  Last error
-----------------  -------  -------  -----  -----  -------  --------  ----------
dhcp-relay         -        running  up     81321  2d4h11m  0
keepalived@default default  running  up     80410  2d4h12m  0
keepalived@red     red      stopped  held   -      -        0
```

`show process -j` returns the registry entries as JSON, one object per
instance, in the order above.

## 7. Signal mode (PM7)

- **The harness owns the processes.** It starts each daemon (under `ip vrf exec` for a VRF instance) and stops it at teardown, so insomnia must not.
- `show process` works from the pid files: running or stopped, and the pid.
- `start`, `stop` and `restart process` answer `% Not supported in signal mode: the process is managed outside insomnia`.

## 8. zebra-rs changes (PM8)

- **Grammar** (`exec.yang`, insomnia-gated): `process` under `show` with an optional name; top-level `start`, `stop` and `restart` containers, each with a `process` list keyed by name. zebra-rs has no `process` node anywhere today, so the name does not collide.
- **Routing** (`config/manager.rs`):
  - an `is_process` entry in `SHOW_PROTOS` routes to provider key `"process"`;
  - `start`, `stop` and `restart` orders are dispatched to providers the way `show` orders are. Today only `show` reaches a provider (`RedirectShow`).
  - With no provider connected, the existing not-running fallback answers.
- **No protocol change.** A `ShowOrder` already carries any path, its arguments and the JSON flag, and gets a text answer: `/stop/process` with `args = ["keepalived@red"]`.
- **Tests,** in the style of the VRRP and DHCP ones: grammar gated on insomnia, the four dispatch paths, routing to `"process"`.

## 9. insomnia changes

- `src/process.rs`: the registry, holds, observation through `systemctl show`, the §6.2 actions, and `show process` rendering.
- `src/vrf.rs` (new): load, pin, unpin and sweep (§4.5).
- `crate::links`: VRF devices and their interface indexes (shared with `design/dhcp.md` §7.3).
- `src/keepalived.rs`: drop `env_for` and `--vrf-preload`; register instances; pin before start.
- `src/provider.rs`: register `process`, and route `/show/process`, `/start/process`, `/stop/process` and `/restart/process` to the registry.
- `packaging/systemd/insomnia-keepalived@.service`: the §4.4 lines in place of the `env` file.

## 10. Testing

- **Unit tests:**
  - the program bytes for a given interface index (golden);
  - the shipped templates: `AssertPathExists=` sits in `[Unit]` and names the same path as `BPFProgram=`;
  - the registry: desired × hold × observed → action (§6.2), holds on disk;
  - `show process` rendering and the provider routing.
- **Root-only script** (`bdd/tests/scripts/vrf_units.sh`, run by hand like BDD): §4.3 rows 2, 4, 8, 10 and 11 against the shipped templates.
- **BDD:** the per-VRF VRRP feature of `design/vrrp.md` §13 (daemons under `ip vrf exec`), and `show process` in signal mode.

## 11. Work breakdown

In order; each item is one PR.

| # | Repo | Branch | Content | Effort |
|:--|:--|:--|:--|:--|
| 1 | zebra-rs | `process-cli` | §8: grammar, routing, tests | S–M |
| 2 | insomnia | `process-registry` | §5–§7: registry, holds, observation, the four commands, provider | M |
| 3 | insomnia | `links` | `crate::links` with VRF devices (also `design/dhcp.md` §17 item 3) | S–M |
| 4 | insomnia | `vrf-bind` | §4.5 pin lifecycle, template changes, removal of the shim plumbing, `vrf_units.sh` | M |
| 5 | insomnia | `vrrp-vrf` | `vrrp vrf <name>` (`design/vrrp.md` §13) on top of 4, with its BDD feature | M |

Kea instances per VRF follow `design/dhcp.md`, using item 4.

Status 2026-11-09: items 1, 2 and 4 built together (with Kea per VRF on top
of 4); item 3 came with the DHCP server (`design/dhcp.md` §17 item 3);
item 5 remains.

## 12. Open questions

- **cradle in `show process`.** zebra-rs would merge its engine's row with insomnia's answer. Not in v1: cradle is in the other daemon, and `show ebpf` already reports it.
- **VyOS-spelled aliases** (`restart vrrp`, `restart dhcp relay-agent`) mapped onto `restart process`. Only if operators ask.
- **Name completion** from insomnia's registry. zebra-rs's `ext:dynamic` completions are local to zebra-rs today.

## 13. References

- systemd.resource-control(5), `BPFProgram=`: attach types, and "If a specified program does not exist … unit activation will continue".
- systemd.unit(5), `AssertPathExists=` (a `[Unit]` setting).
- iproute2 `ip/ipvrf.c`, `prog_load()`: the five-instruction program.
- openconfigd: `vendor/github.com/coreswitch/process/process.go`, `config/process_extensions/process.go`, `config/command.go`, `config/relay.go`, `config/vrrp.go`, `config/dhcp.go`.
- zebra-rs: `zebra-rs/src/cradle/supervisor.rs`.

## 14. Implementation notes

What the implementation changed against §4–§10, and why:

- **The program** is the five instructions of §4.2. iproute2's has a sixth,
  `r2 = offsetof(bound_dev_if)`, that nothing reads. `src/vrf.rs` builds it,
  loads it with `bpf(BPF_PROG_LOAD)` and pins it with `bpf(BPF_OBJ_PIN)`; a
  failed load reports the verifier's log.
- **Who pins.** `Registry::bind(vrf)` pins (or re-pins, when the recorded
  interface index differs) right before a per-VRF unit starts: in
  `process::reload` for keepalived, in `Kea::apply` for Kea, and in `start
  process` / `restart process`. `vrf::run` reconciles the pins with the
  kernel's VRFs at startup and on every link change: a deleted VRF has its
  units stopped and its pin removed; a VRF re-created under a new index is
  re-pinned and its running units `try-restart`ed. In practice a deleted
  VRF also makes Kea's render serve nothing (no member interfaces), so the
  backend stops the instance too, and starts it again on the re-created
  VRF through `bind`; both paths end with the instance bound to the new
  device.
- **Registration.** Backends register an instance when they apply it, so
  `show process` lists what insomnia has rendered: the relay agent and
  keepalived@default always, Kea instances once they have served (an
  instance that never had a configuration is never started and not
  listed). The Admin column is `up` (the configuration wants it), `held`
  (`stop process`) or `down` (nothing configured).
- **Signal mode.** Kea's pid file is its own (`<kea-dir>/<vrf>/
  kea-dhcp4.kea-dhcp4.pid`, from `KEA_PIDFILE_DIR`); keepalived's and the
  relay agent's are the ones the harness names.
- **zebra-rs** routes a line whose *first* word is `start`, `stop` or
  `restart` like a show order, so config leaves of those names (a DHCP
  range's `start` / `stop`) are unaffected; `is_process` is the first entry
  of `SHOW_PROTOS`, because a process name is a free-form key that could
  spell another protocol's node.
- **The root-only script** (`bdd/tests/scripts/vrf_units.sh`) runs zebra-rs
  and insomnia in systemd mode in a scratch namespace, with the shipped Kea
  template installed in `/run/systemd/system` and a drop-in that only
  supplies Kea's binary, root for the absent `_kea`, and the namespace. Its
  28 checks cover §4.3 rows 2, 4 and 8 with the shipped template (Kea's UDP
  socket bound to `red`, a lease to a client in `red`, the start refused
  without a pin, `AssertResult=no`), the §6.2 table (stop holds across a
  commit, restart refused while held, start on the configuration committed
  meanwhile), and a VRF deleted and re-created (new index, re-pinned,
  serving). insomnia is started there with `nsenter --net`: `ip netns exec`
  remounts `/sys`, which hides the host's bpffs.
