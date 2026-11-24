# shirudo on an insomnia router — integration plan

Status: plan, 2026-11-23. Nothing is implemented and no spike has been
run. Read against shirudo `1e81ff59` (`0.0.0-dev`, pre-release), insomnia
`19ac3b0`. Facts about shirudo come from its `Documentation/`; facts
about insomnia from the code. What is inferred and still to be tried on
a target is marked *to confirm* and collected in §11.

## Decisions at a glance

| # | Question | Recommendation |
|:--|:--|:--|
| S1 | What does "integrate" cover? | Coexist, show, and run shirudo's own timers. Not: decide from zebra-rs config what BPF a target runs (§2) |
| S2 | Does insomnia render shirudo's settings? | No, on a target. They live in an operator-signed image that root cannot change, and insomnia is root. Only the unsigned unit plumbing is a candidate (§7) |
| S3 | `default` daemon instances and BPF | Stop requiring a pinned program for `default`, on every host (§4.2) |
| S4 | Per-VRF daemons on an enforcing target | Not started, with a warning that says why. A binding that survives enforcement is a later step (§4.3) |
| S5 | Show output | Pass shirudo's own text and JSON through; do not re-render (§5) |
| S6 | CLI root | `show shirudo …`, a top-level insomnia-gated node |
| S7 | First step | The spike of §11, in shirudo's test VM, before any code |

## 1. What shirudo is, in the terms that matter here

- **A BPF lockdown plus signed micropatches.** After `shirudo init` runs
  in the initrd, a BPF program is loaded only through a loader signed
  with the operator's key. Map creation, attaching and pinning are
  reserved to processes exec'ed from shirudo's own dm-verity runtime
  image. This holds for root and lasts until reboot.
- **Agentless.** No daemon and no socket. Everything is a one-shot
  `shirudo` command, run by root or by five systemd timers: keepalive
  (60 s), map export (5 s), XDP reconcile (60 s, and on every new network
  device through udev), package update (60 s) and tree sync (60 s).
- **Root on the target is the adversary.** The executable and bootstrap
  settings are in a dm-verity runtime image pinned from the UKI.
  Repositories, the upatch tree subscription, node labels, keys and the
  export settings are in a config image whose root hash the operator
  signs. A target reads none of these from `/etc`.
- **Pull-based.** The operator publishes signed packages and a signed
  "upatch tree" to an OCI registry; targets pull and verify.
- **Measured.** Every change to the loaded set extends a TPM register;
  `shirudo attest` gives evidence the operator verifies offline.
- **Demanding platform.** A bpf-next kernel with the signed-loader ABI
  and shirudo's patches (the test kernel reports `7.4.0-rc1-bpf-next+`),
  a TPM 2.0, a UKI, and an initrd built with shirudo's dracut module.
  Installing the `shirudo-target` package alone enforces nothing.

## 2. What integration can and cannot mean

insomnia's pattern is: zebra-rs owns configuration, insomnia renders it
for an engine and answers `show`. shirudo fits two thirds of that.

| insomnia does for an engine | For shirudo |
|:--|:--|
| Renders its configuration from the zebra-rs store | **Does not fit.** The store is writable by root on the target, which is exactly who shirudo's signed config image is built to exclude. `shirudo bpm config register` is refused on a target with a config image, and the settings files under `/etc/shirudo` are not read there |
| Owns the daemon's lifecycle | There is no daemon. There are timers and one-shot services, which the process registry can list and trigger |
| Answers `show` from the engine's live state | Fits. `shirudo status --json`, `upatch list --json`, `bpm list --json` are structured and read-only |
| Keeps working beside it | **The urgent part.** shirudo's lockdown refuses BPF that insomnia itself loads (§4) |

A zebra-rs leaf that chose packages or repositories would also break
attestation: the operator predicts the register from the artifacts it
published, and a target that installs by local configuration no longer
matches. The upatch tree is shirudo's declarative layer, and it is signed.

## 3. Three host states

insomnia must behave sensibly in each, and tell them apart cheaply.

| State | How to tell | insomnia |
|:--|:--|:--|
| A. shirudo absent | no `shirudo` binary | as today; `show shirudo` answers "shirudo is not installed" |
| B. installed, not enforcing | binary present, no `/run/shirudo/bpffs/lsm_link` | as today; show works (`lsm-off`, `init-pending`) |
| C. enforcing target | `/run/shirudo/bpffs/lsm_link` exists (the directory stays listable) | BPF loads fail; the runtime binary is `/run/shirudo/runtime/usr/bin/shirudo`, and `/usr/bin/shirudo` is refused |

Development and the BDD suite live in A and B. C needs the kernel and
boot chain of §1 and is reached only in shirudo's test VM for now.

## 4. Coexistence: what breaks on an enforcing target

### 4.1 Findings

| insomnia or zebra-rs feature | On an enforcing target | Source |
|:--|:--|:--|
| VRF socket program (`src/vrf.rs`: `BPF_PROG_LOAD`, `BPF_OBJ_PIN`) | Refused with `EACCES` (`LoadNotLoader`). No signed route exists either: the attach kinds are fentry/fexit, fmod_ret, lsm, tp_btf, kprobe, uprobe, `cgroup_skb` on the root cgroup, netfilter and xdp. None is a cgroup socket program, and none attaches per unit | shirudo `interoperability.rst`, `attach-kinds.rst` |
| `BPFProgram=` in the template units | "Not applied": systemd finds BPF unsupported and starts the unit without it | `interoperability.rst` |
| `keepalived@default`, `kea-dhcp4@default`, `kea-dhcp6@default` | **Do not start** (*to confirm*). `Registry::bind("default")` loads the no-op program, the load fails, the pin is missing, and `AssertPathExists=` holds the unit. So VRRP and the DHCP server are down in every VRF, the global table included | `src/process.rs:358`, the template units |
| `PrivateDevices=`, `DeviceAllow=` on the Kea and relay units | The device-cgroup half is not applied; the private `/dev` mount still is | `interoperability.rst` |
| nftables, strongSwan, keepalived itself, Kea's and the relay's packet filters | Unaffected. nft is netlink; socket filters are classic BPF, which does not go through `bpf()` | same |
| cradle-rs's XDP/TC data plane, and the BFD echo offload that rides on it | Cannot run. cradle loads two XDP and two TC programs with aya (`BPF_PROG_LOAD`, refused), creates its maps from userspace (refused) and writes them on every FIB change (refused, even for maps created before `init`). No upatch route either: shirudo has an `xdp/<mask>` kind but no TC kind, and builds from C, not from cradle's Rust objects. If both could attach, they would also contend for the one XDP slot per device | cradle-rs `5cdc41d` `crates/cradle/src/control.rs`, shirudo `attach-kinds.rst` |
| `ip vrf exec` (BDD scripts, `vrf_units.sh`) | Refused, so those cannot run on such a host | same |
| kexec, hibernation, unsigned modules | Refused host-wide; nothing insomnia does needs them | same |

In the other direction: insomnia runs as root with no seccomp filter
(`insomnia.service` sets none), so a `shirudo` it starts from the runtime
image is granted runtime authority like one started from a root shell.
The Kea and relay units do carry seccomp filters, which only matters if
they ever exec shirudo; they do not.

### 4.2 `default` without a program (S3)

`default` gets a program today only so that one template serves every
instance. Under shirudo that uniformity is what takes VRRP and DHCP
down. Proposal:

- `vrf::Pins` pins nothing for `default`, and `Registry::bind("default")`
  returns at once.
- The templates keep `AssertPathExists=` and `BPFProgram=`, so every
  other instance still fails closed. The package ships a per-instance
  override for each template, `insomnia-keepalived@default.service.d/`
  and its Kea siblings, that resets both to empty.
- The unit test that pins the `[Unit]` placement of the assert gains the
  override.

This is right without shirudo too: it removes a BPF load nobody needs.

### 4.3 Per-VRF instances (S4)

On a state C host a VRF instance cannot be bound. It must not start
unbound, which the assert already prevents. What changes is the message:
"vrrp vrf red: not started: binding a daemon to a VRF needs a BPF
program, which shirudo refuses on this host", once per instance, and the
same reason in `show process`.

Ways to lift the limit, none for the first release:

| Option | Cost |
|:--|:--|
| A cgroup socket attach kind in shirudo, attached per unit, with the VRF index as data | Upstream work in shirudo; the index is dynamic and only shirudo's binary may write a map |
| The `LD_PRELOAD` shim that `design/process.md` §4 replaced | No BPF, but fail-open by nature and defeated by file capabilities |
| Daemon-native binding (keepalived binds its advert sockets itself; Kea has nothing) | Partial, per daemon |

## 5. Show (S5, S6)

```
show shirudo                     verdict, conditions, moved counters, loaded upatches
show shirudo status detail       the folded sections too (keyrings, TPM, assets)
show shirudo upatch [<name>]     archived and loaded upatches; one in detail
show shirudo package             installed packages
show shirudo key                 trusted and revoked certificates
show shirudo config              the settings in effect
```

- **Pass-through.** Text mode prints what `shirudo status` prints; JSON
  mode (`vtyctl show -j`) what `--json` prints. shirudo's documentation
  explains its own report field by field, and a second layout here would
  go stale with every shirudo release. This is the VRRP rule for JSON
  (the raw keepalived dump), applied to the text as well.
- **Runner** (`src/shirudo.rs`): resolve the binary by state (§3), run it
  with a cleaned environment (shirudo refuses to run with any
  `SHIRUDO_*` bootstrap override set), no stdin, and a deadline. `status`
  holds shirudo's operation lock and can wait 30 s behind a tree sync, so
  the deadline is above that and the answer says when it was hit.
- **Verdict, not exit status.** `status` exits 0 for `tampered`. The
  show answer leads with the verdict line.
- **Who may look.** `status` needs root on a target, and insomnia would
  hand its output to any zebra-rs CLI user. It lists certificate
  fingerprints, upatch names and tamper counters, no secrets. Decide
  whether that is acceptable or the views need a privileged CLI level.

## 6. Timers and verbs

The process registry gains shirudo's units as externally owned entries:
`shirudo-keepalive`, `shirudo-map-export`, `shirudo-xdp-reconcile`,
`shirudo-bpm-repo-update`, `shirudo-bpm-tree-sync`.

| Line | Does |
|:--|:--|
| `show process` | each timer's state, last run and its result |
| `restart process shirudo-bpm-tree-sync` | `systemctl start` of the service: sync now |
| `stop process <name>` / `start process <name>` | stop or start the timer, with the registry's hold |

This needs no new verb in zebra-rs: `start|stop|restart process` already
reach insomnia. It stretches `restart` to "run once now" for a oneshot,
which the help text must say. Stopping the keepalive or the tree sync is
something root can already do; a backend sees the node go stale.

Not offered: `upatch load|unload`, `bpm install|uninstall`,
`image update`, `attest`. They change measured state or take files and a
challenge, and they belong to the operator's procedure, not to a router
CLI.

Glue shirudo leaves to the integrator: on a state C host each timer
service needs a drop-in that runs the runtime image's binary, and
shirudo's generator writes one for `shirudo.service` only. Whether the
insomnia package ships those is decision S8 in §12.

## 7. Configuration (S2)

Nothing in the first release. The candidates, if a tree is wanted later,
are the files shirudo itself leaves unauthenticated:

| Candidate leaf | Renders to | Note |
|:--|:--|:--|
| registry CA, credentials file, proxy | `/etc/shirudo/bpm/environment` | credentials are secrets (`vyos-gap.md` §4.6) |
| OTLP endpoint overrides | `/etc/shirudo/map-export.env` | the config image's `map_export.*` normally decides |
| timer on/off and interval | systemd drop-ins | same effect as §6's `stop process` |

Explicitly out: repositories, the tree subscription, node labels, keys,
`map_export.*`, package selection. On a host without a config image
these are plain files and could be rendered, but a tree that works in
the lab and is silently ignored on a real target is a trap.

Open and unsolved: **the VRF shirudo pulls through.** On a router whose
registry and collector are reachable only in a management VRF, shirudo's
services need a VRF binding, and §4.1 says the one insomnia has cannot
exist on the hosts where shirudo enforces.

## 8. zebra-rs changes

1. `exec.yang`: the `show shirudo` views, insomnia-gated; `is_shirudo`
   in `SHOW_PROTOS` with a "shirudo" not-running fallback. X15 of
   `vyos-gap.md` applies to `show shirudo upatch <name>`.
2. No config schema (§7), no new verb (§6).
3. Worth raising there, not planned here: refuse or warn on
   `interface … ebpf enabled` when the host enforces.

## 9. Packaging and platform

- `Suggests: shirudo-target`. It conflicts with `shirudo-operator`, and a
  router is never an operator host.
- The per-instance `default` overrides of §4.2.
- The book: a chapter "insomnia on a shirudo target" with the table of
  §4.1, and `show shirudo`.
- **Outside insomnia, and the long pole:** a kernel that meets shirudo's
  requirements, a UKI and initrd with its module (Ubuntu 24.04 builds
  its initrd with initramfs-tools, shirudo ships a dracut module), a TPM,
  and the runtime and config images. Until the zebra-live image has
  those, state C exists only in shirudo's test VM, and phases 1–3 below
  are still worth having: they are what makes the day it arrives a
  non-event.

## 10. Testing

- **Unit:** the runner against a stub binary (resolution by state,
  environment cleaning, deadline, non-zero exit, `tampered` at exit 0);
  show pass-through against captured `status --json` and text; the
  `default` override and `bind("default")`.
- **BDD:** a `shirudo` stub script on `--shirudo-bin`, as signal mode
  stands in for systemd elsewhere: the show views, and the registry rows
  in signal mode. No enforcement in BDD; the kernel cannot be assumed.
- **State C:** a script in the manner of `vrf_units.sh` that installs
  the staged insomnia and zebra-rs into shirudo's test VM
  (`testing/vm`, software TPM) and asserts §4: default instances up, a
  VRF instance refused with the message, nft and IPsec applied, `show
  shirudo` answering, and which tamper counters insomnia moves at
  start. That last list goes in the book, since operators are told to
  learn their baseline.

## 11. Spike first (S7)

In shirudo's test VM, with insomnia 0.3.0 and a zebra-rs of v26.11.2 or
later, before any code:

1. `set vrrp group …` and `set service dhcp-server …` in the global
   table: do `keepalived@default` and `kea-dhcp4@default` start? §4.1
   says no. Which counter moves?
2. The same with the assert and `BPFProgram=` reset by a hand-written
   override: do they start and work?
3. A firewall ruleset and an IPsec peer: applied as usual?
4. `tokio::process::Command` on the runtime binary from insomnia: is the
   mark granted? shirudo refuses an exec from a task that shares its
   filesystem context, and insomnia is multi-threaded.
5. `status --json` while a tree sync runs: how long does it wait?
6. Does the test kernel boot Ubuntu 24.04's userspace with systemd 255,
   or does the VM's own userspace have to host insomnia?

## 12. Work breakdown and open decisions

One PR per row; 1–3 need no zebra-rs change.

| # | Repo | Content | Needs |
|:--|:--|:--|:--|
| 0 | — | the spike of §11; record the results here | shirudo test VM |
| 1 | insomnia | `default` without a pin; per-instance overrides; tests (§4.2) | 0 |
| 2 | insomnia | host state detection; the VRF-instance message and `show process` reason (§4.3) | 1 |
| 3 | insomnia | book chapter and the state C script (§9, §10) | 2 |
| 4 | zebra-rs | `show shirudo` grammar and routing (§8) | — |
| 5 | insomnia | `src/shirudo.rs` runner, show provider, stub-based tests (§5) | 4 |
| 6 | insomnia | shirudo timers in the process registry (§6) | 5 |
| 7 | insomnia | packaging: `Suggests`, drop-ins if S8 says yes | 6 |

Open, for the owner of the product:

| # | Decision |
|:--|:--|
| S1 | Is the thin scope right, or is the aim that zebra-rs configures shirudo? If the latter, §2 has to be answered first |
| S4 | Per-VRF VRRP and DHCP on an enforcing target: acceptable to lose for now? |
| S5 | Pass-through text, or VyOS-style tables rendered here |
| S6 | `show shirudo`, or under a broader node such as `security` |
| S8 | Should the insomnia package ship the runtime-binary drop-ins for shirudo's timer services |
| S9 | May any CLI user read `show shirudo`, which is root-only on the target itself |
| S10 | Is a config tree for the unsigned plumbing (§7) wanted at all |

## 13. References

- shirudo `1e81ff59`: `README.md`, `AGENTS.md`;
  `Documentation/operate/plan/interoperability.rst` (what the lockdown
  refuses, systemd's BPF settings, the exec rule),
  `concepts/operator-and-target.rst`, `reference/configuration.rst`
  (where a target's settings come from), `reference/systemd-units.rst`,
  `reference/cli/{status,bpm,upatch-list}.rst`,
  `reference/formats/status-json.rst`, `reference/environment.rst`,
  `upatches/write/attach-kinds.rst`,
  `operate/plan/system-requirements.rst`, `start/install.rst`.
- insomnia `19ac3b0`: `src/vrf.rs`, `src/process.rs` (`Registry::bind`),
  `packaging/systemd/*.service`, `design/process.md` §4,
  `design/vyos-gap.md` §4.2 and §4.6.
