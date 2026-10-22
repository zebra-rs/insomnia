# `service conntrack-sync` (conntrackd) — implementation plan

Status: plan, 2026-10-21. Covers: §6.5, the conntrack-sync row of §8.1, the
conntrack-sync op-mode rows of §4.2 ([vyos-gap](../vyos-gap.md) §6.5, §8.1,
§4.2, §4.5).
Priority: P3 · Effort: M · Owner: both
Depends on: [conntrack](conntrack.md) (live table sizes; helper
re-probe; `ctread` parser), [exec-verbs](exec-verbs.md) (`reset` and
`restart conntrack-sync`: `Register.exec`, `EXEC_ROUTES`, `ROUTES`,
`Answer`), [charon-lifecycle](charon-lifecycle.md) (`src/fsutil.rs`:
`write_if_changed` and `systemctl`, moved out of `keepalived.rs`),
[commit-validation](commit-validation.md) (`crate::findings`),
[vrrp-vrf](vrrp-vrf.md) (only for a sync interface inside a VRF),
[ebpf-netfilter](ebpf-netfilter.md) (behaviour on eBPF ports) ·
Unblocks: [conntrack](conntrack.md) `modules nfs|sqlnet` (conntrackd
registers the userspace `rpc`/`tns` helpers)

## 1. Goal

- `set service conntrack-sync …` runs one conntrackd in FTFW mode, over
  multicast or UDP unicast, rendered and restarted by insomnia the way
  keepalived is.
- `failover-mechanism vrrp sync-group <g>` makes the VRRP sync group commit
  the external cache on MASTER and resync on BACKUP. User
  `transition-script`s on the same sync group keep working.
- conntrackd's hash sizes follow what [conntrack](conntrack.md) has
  applied, without manual ordering.
- The following work:
  - `show conntrack-sync cache external|internal [main|expect]`;
  - `show conntrack-sync statistics` and `show conntrack-sync status`;
  - `reset conntrack-sync external-cache|internal-cache` and
    `restart conntrack-sync`.

## 2. Current state

**insomnia @ `ee4dfaa`:**
- `src/vrrp.rs` renders `transition-script` as native
  `notify_master|backup|fault|stop` lines:
  - per group through `render_notify` (`vrrp.rs:788-805`, called at `:917`);
  - per sync group at `vrrp.rs:1056-1058`.
- The module doc lists "no conntrack-sync notify helper" as a deviation
  (`vrrp.rs:22`). `design/vrrp.md:285-288` and `:669-671` defer it.
- **`keepalived.rs` is the lifecycle template:**
  - `write_if_changed` (`:245-252`) and `write_atomic` (`:229-243`);
  - `systemctl` (`:254-275`);
  - `apply` (`:277-324`): compare-before-reload, `stop` on empty, `start`
    when unchanged;
  - signal mode with pid liveness (`:204-227`).

  These helpers are private to that file today.
- `main.rs:58-73` defines the keepalived flags. There is no conntrackd flag,
  unit or asset. `Cargo.toml` assets ship only the binary, and `recommends`
  lists `strongswan-swanctl, charon-systemd, keepalived`.

**zebra-rs @ `141da2fc`:**
- No `service` container. The top-level nodes are `logging`, `bridge`,
  `vxlan`, `vlan`, `mpls`, `system`, `vty`, `bfd`, `router`, the policy
  sets, `firewall`, `vpn`, `vrrp`, `interface`, `vrf` and `policy`
  (`config.yang:370-5897`).
- `vrrp sync-group` exists (`vrrp.yang`). `container vrrp` is
  insomnia-gated (`config.yang:5705-5709`).

**VyOS `7f2c893`:**
- **`src/conf_mode/service_conntrack-sync.py`:**
  - It reads the live `/sys/module/nf_conntrack/parameters/hashsize` and
    `/proc/sys/net/netfilter/nf_conntrack_max` (`:55-56`).
  - `verify` (`:63-122`):
    - `interface` is required and must exist;
    - unicast and multicast cannot be mixed;
    - each sync interface needs an address in the peer's or group's family;
    - `expect-sync all` is exclusive;
    - `listen-address` must be assigned and match the peer family;
    - the sync-group must be set and must exist.
  - `apply` (`:134-153`): `systemctl reload-or-restart conntrackd`, `stop`
    when unconfigured, and `resync_vrrp()` on the first start and the final
    stop.
- **`data/templates/conntrackd/conntrackd.conf.j2:1-119`:**
  - `Sync { Mode FTFW {…} UDP|Multicast {…} Options { ExpectationSync } }`;
  - an unconditional `Helper` block (`rpc` tcp/udp on NFQUEUE 3/4, `tns`
    on 5, `:56-78`);
  - `General` with `HashSize`, `HashLimit = 2 × max`, the ctl socket
    `/var/run/conntrackd.ctl` and `Filter From Userspace`.
- **The keepalived hook** (`data/templates/high-availability/keepalived.conf.j2:189-194`):
  `notify_master|backup|fault "/usr/libexec/vyos/vyos-vrrp-conntracksync.sh <state> <group>"`
  on the named sync group. VyOS has no clash because user transition scripts
  go through `notify_fifo` and a dispatcher.
- **`src/helpers/vyos-vrrp-conntracksync.sh:40-154`:**

  | State | Actions |
  |:--|:--|
  | master | `-c`, `-c exp`, `-f`, `-R`, `-B` |
  | backup | `-s` (start conntrackd with `-d` if that fails), then `-t`, `-n` |
  | fault | `-t` |

- **Op mode:**
  - `src/op_mode/conntrack_sync.py:37-200`: `-e|-i ct|expect -x` (XML),
    `-s`, `-f internal|external`, `-R`, `-n`, `-B`, and
    `systemctl restart conntrackd`;
  - `op-mode-definitions/conntrack-sync.xml.in` holds the grammar.

**keepalived behaviour, tested for this plan** (`keepalived 2.2.8
--config-test` on a scratch config):
- A second `notify_master` in one `vrrp_sync_group` is rejected with
  `vrrp group SG: notify_master script already specified - ignoring /bin/true two`.
  The gap's open question, whether keepalived honours more than one
  `notify_master`, is answered: **no**.
- A generic `notify "<cmd>"` line in the same block is accepted next to
  `notify_master`.

## 3. Design

**3.1 Schema placement: `service conntrack-sync`.**
- This is VyOS's spelling, inside a new top-level `container service` that
  carries `if-feature feat:insomnia`.
- **Rejected:**
  - A top-level `conntrack-sync` node. `vrrp` dropped its wrapper because
    `high-availability` also holds IPVS (`design/vrrp.md`). `service` is
    VyOS's home for many daemons insomnia may own later (§9 of the gap: DHCP
    under D9, DNS forwarding), so keeping it costs nothing.
  - Gating `service` children one by one. That leaves an empty `service`
    node in non-insomnia builds. If a core zebra-rs service ever needs
    `service`, the `if-feature` moves down to the children then.

**3.2 Backend and lifecycle.**
- `src/conntrack_sync.rs` holds the subscription to `["service",
  "conntrack-sync"]`, the model, `render` and show.
- `src/conntrackd.rs` holds process control, mirroring `keepalived.rs`:
  - **Directory:** `--conntrackd-dir` (default `/run/insomnia/conntrackd`,
    inside the existing `RuntimeDirectory=insomnia` with
    `RuntimeDirectoryPreserve=yes`). It holds `conntrackd.conf` (0644, no
    secrets), `conntrackd.ctl` (UNIX socket), `conntrackd.lock`,
    `failover-state` and `env`. These paths keep it clear of a distribution
    conntrackd on `/var/run/conntrackd.ctl`.
  - **`--conntrackd-control systemd|direct`:**
    - `systemd`: `systemctl restart|stop|start` on `--conntrackd-unit`
      (default `insomnia-conntrackd.service`).
    - `direct` (BDD, containers):
      - start with `conntrackd -C <conf> -d`;
      - stop with `conntrackd -C <conf> -k`;
      - liveness is `conntrackd -C <conf> -s`, which succeeds only while
        the ctl socket answers.

      No pid file is needed, and an insomnia restart does not kill the
      detached daemon.
  - **Apply:**
    - write the config if changed;
    - unchanged → `start` (a no-op when running);
    - changed → **restart**, not reload. conntrackd has no documented
      config reload (*unverified*), and VyOS's `reload-or-restart` resolves
      to a restart unless the unit defines `ExecReload`;
    - empty → `stop`.

    After every (re)start, run `conntrackd -n` (request a resync) and `-B`
    (bulk send), as VyOS `restart()` does.
- **Shared helpers.** `src/fsutil.rs` provides `write_if_changed` and
  `systemctl`. [charon-lifecycle](charon-lifecycle.md) M1 moves them out of
  `keepalived.rs` into the `fsutil.rs` that
  [ipsec-render-fixes](ipsec-render-fixes.md) M1 creates (or creates the
  file itself if it lands first). This plan adds nothing there. Liveness in direct mode is `conntrackd -s`,
  so no pid helper is needed.
- Every `conntrackd`, `systemctl` and `ip` call runs under a timeout: 5 s,
  or 30 s for `systemctl restart` ([exec-verbs](exec-verbs.md) D-8).

**3.3 Render.**
- `render(cfg, &Inputs) -> (String, Findings)` follows the VyOS template line
  for line, with insomnia paths. It is pure. `Findings` is
  [commit-validation](commit-validation.md)'s `crate::findings`.
- `host_findings(cfg, &Inputs)` covers the interface-address checks, which
  are host state. `conntrack_sync::validate(parts)` joins the validator
  `UNITS` as `"conntrack-sync"`. Through that, VyOS's "Cannot mix unicast
  and multicast" and similar rules become commit-time errors once layer 2
  is live.
- `Inputs` carries:
  - `hash_size` and `table_size`, from [conntrack](conntrack.md)'s
    `CtSizes` watch, falling back to reading `/sys` and `/proc` when that
    task has not yet published;
  - each sync interface's first IPv4/IPv6 address
    (`ip -j addr show dev X`), for `IPv4_interface`;
  - `userspace_helpers: bool` (below).
- **Skip with warning** (VyOS `verify`). The whole config is skipped, and
  conntrackd stopped, when any of these holds:
  - no `interface`;
  - mixed unicast and multicast;
  - a sync interface with no address of the right family;
  - `expect-sync all` combined with other values;
  - a `listen-address` whose family differs from the peer's;
  - no `failover-mechanism vrrp sync-group`.

  Rendering a partial conntrackd is worse than none, because the peer would
  then hold a half-synced cache.
- A sync-group that the vrrp task did not render (watch below) is a warning,
  and the hook is not rendered. conntrackd still runs.
- **Deviation: the `Helper` block** is rendered only when
  [conntrack](conntrack.md) reports `modules nfs` or `sqlnet` (in-process
  watch). VyOS always renders it. That claims NFQUEUE 3-5 for userspace
  helpers, which collides with firewall `action queue` rules on those
  queues, and it makes conntrackd depend on `nfnetlink_queue` for an
  unrelated feature.

**3.4 Ordering with `system conntrack`.**
- VyOS orders by commit priority (conntrack 218 before conntrack-sync). Here
  the two backends are separate tasks, wired in-process:
  - **[conntrack](conntrack.md) → conntrack-sync:**
    `watch<CtSizes { buckets, max }>`, published after each sysctl apply,
    and `watch<UserspaceHelpersWanted>`.
  - **conntrack-sync → conntrack:** `watch<ConntrackdUp>`, so conntrack
    re-probes `rpc`/`tns`.
  - **vrrp ↔ conntrack-sync** (§3.5).
- A change in `CtSizes` re-renders. `HashSize` changes need a restart, which
  §3.2 already does.
- On startup, the conntrack-sync task waits up to 5 s for the first
  `CtSizes` before it renders, then falls back to the live values.
- **Rejected:** having conntrack-sync subscribe to `system conntrack` and
  `vrrp` through [multi-path-subscribe](multi-path-subscribe.md).
  - Both trees are already parsed by sibling tasks in the same process.
  - What conntrackd needs is the *applied* kernel value, not the configured
    one: they differ when a key is read-only in a netns (see
    [conntrack](conntrack.md) §2, fact 1).
  - VyOS itself couples these backends procedurally (`resync_vrrp`).
  - So this plan is not a multi-path-subscribe consumer; that plan's §3
    lists it under "Not consumers".

**3.5 The VRRP notify-slot conflict.**
- **Fact:** keepalived keeps only the first `notify_master` per block (§2,
  tested). Rendering the conntrack helper as `notify_master` would silently
  drop the user's transition script, or the helper.
- **Options:**
  - (a) keepalived's generic `notify "<cmd>"`. It runs for every transition
    with `GROUP|INSTANCE`, the name, the target state and the priority
    appended (keepalived.conf(5)). The exact argument list for sync groups
    on 2.2.8 is *unverified* by a live transition. It is a separate slot
    from `notify_*`, and zebra-rs's `transition-script` does not expose it.
  - (b) An insomnia-generated wrapper per sync group that calls the user
    script and then the helper. That means extra files, and quoting the
    user's command line into a script.
  - (c) `notify_fifo` plus an insomnia-side dispatcher, as in VyOS. Failover
    would then depend on insomnia being up, and keepalived is deliberately
    independent of insomnia (`keepalived.rs:12-18`).
- **Decision: (a).** User `notify_*` lines are untouched. The helper owns
  `notify`. keepalived.conf(5) runs `notify` after the `notify_*` script
  (*unverified* on 2.2.8). The BDD scenario checks that both run.
- **Rendering.** `vrrp::render(cfg, &VrrpHooks)` (new parameter):

  ```rust
  pub struct VrrpHooks { pub conntrack_sync: Option<SyncHook> }
  pub struct SyncHook { pub sync_group: String, pub command: String }
  ```

  When the named sync group renders, the hook line follows its transition
  scripts.
- **Wiring:**
  - The conntrack-sync task publishes `watch<Option<SyncHook>>`. The vrrp
    task `select!`s on it and re-renders, and keepalived reloads through
    the existing compare-before-reload.
  - The vrrp task publishes `watch<BTreeSet<String>>` of the sync groups it
    rendered, for the warning in §3.3.
  - On startup, the vrrp task waits up to 2 s for the first hook value
    before its first apply, so a restart does not reload keepalived twice.
- **Helper script.** `/usr/lib/insomnia/conntrack-failover` is a Cargo
  `assets` entry, mode 0755, shell. It is invoked as `<script> <conf> GROUP
  <name> <STATE> <prio>`:

  ```sh
  #!/bin/sh
  # keepalived generic notify: $1 conf, then GROUP|INSTANCE NAME STATE PRIORITY
  conf=$1; state=$4; dir=$(dirname "$conf")
  ctl() { /usr/sbin/conntrackd -C "$conf" "$@" || logger -t insomnia-conntrack-failover "conntrackd $* failed"; }
  /usr/sbin/conntrackd -C "$conf" -s >/dev/null 2>&1 || { logger -t insomnia-conntrack-failover "conntrackd not running"; exit 1; }
  echo "$state $(date -Is)" > "$dir/failover-state"
  case "$state" in
    MASTER) ctl -c; ctl -c exp; ctl -f; ctl -R; ctl -B ;;
    BACKUP) ctl -t; ctl -n ;;
    FAULT)  ctl -t ;;
    *)      : ;;   # STOP, DELETED: VyOS has no action either
  esac
  ```

  **Deviation:** the BACKUP branch never starts conntrackd (VyOS runs
  `conntrackd -d`). The lifecycle stays with insomnia and systemd.

**3.6 VRF.**
- The first cut is the default VRF only. One conntrackd per host: the
  conntrack table is per netns, not per VRF.
- A sync interface enslaved to a VRF needs conntrackd's sockets bound into
  that VRF. Reuse the [vrrp-vrf](vrrp-vrf.md) mechanism once it is chosen:
  - shim branch: an `env` file with `LD_PRELOAD=<vrf.so>` and `VRF=<name>`,
    read by the unit or exported in direct mode;
  - otherwise `ip vrf exec <vrf> conntrackd …`.

  Until then, a VRF-enslaved sync interface is skipped with a warning.
- The hook command talks over the UNIX ctl socket, so it works whichever
  keepalived instance (per-VRF or default) holds the sync group. The
  `failover-mechanism vrrp sync-group` name resolves in the default
  instance. A `vrf` qualifier waits for [vrrp-vrf](vrrp-vrf.md).
- **ct zones** ([conntrack](conntrack.md) FW13): whether conntrackd carries
  `CTA_ZONE` in FTFW messages is *unverified*. If it does not, flows from
  VRF zones land in zone 0 on the peer and break after failover. The BDD
  checks it. Until it passes, warn when VRF zones and conntrack-sync are
  both active.

**3.7 Show, reset, restart.**
- **`show conntrack-sync cache external|internal [main|expect]`** runs
  `conntrackd -C <conf> -e|-i ct|expect -x`, parses the XML, and prints
  VyOS's table. This needs an XML parse; `quick-xml` would be a new
  dependency. The alternative is the plain `-e ct` text output, which is
  the same `key=value` format the conntrack reader parses
  ([conntrack](conntrack.md) `ctread`), so the parser is reused. Choose the
  text form.
- **`show conntrack-sync statistics`** relays `-s` (and `-s exp` with
  `expect-sync`) verbatim; VyOS does the same.
- **`show conntrack-sync status`** shows the sync interfaces, the failover
  mechanism, the sync group, the last transition (from `failover-state`)
  and the expect-sync protocols, from the retained model, as VyOS
  `show_status` does.
- **Reset and restart**, through [exec-verbs](exec-verbs.md):
  - `reset conntrack-sync external-cache` runs `-f external` then `-n`;
  - `reset conntrack-sync internal-cache` runs `-f internal`, `-R`, `-B`;
  - `restart conntrack-sync` restarts per §3.2.

  In direct mode, "restart" is `-k` then `-d`.
- **Wiring** ([exec-verbs](exec-verbs.md)):
  - zebra-rs: the `EXEC_ROUTES` rows `reset conntrack-sync` and
    `restart conntrack-sync` → key `conntrack-sync` (listed there);
    `container conntrack-sync` under `reset`, and `leaf conntrack-sync`
    under `restart`.
  - insomnia: `"conntrack-sync"` in the show names and in `EXEC_TREES`, and
    the `ROUTES` rows `(Show, "/show/conntrack-sync", …)`,
    `(Exec, "/reset/conntrack-sync", …)` and
    `(Exec, "/restart/conntrack-sync", …)`. Prefixes match on a segment
    boundary (exec-verbs D-8 `route()`).
  - Each handler runs in a spawned task, holding an `Arc` of the retained
    model. It answers `Answer { text, error }` exactly once.
  - An unconfigured service answers `error: true`, `% conntrack-sync is not
    configured`, as VyOS's `UnconfiguredSubsystem` does.
- **eBPF ports.** Flows that cradle forwards in XDP/TC create no conntrack
  entry ([ebpf-netfilter](ebpf-netfilter.md)), so there is nothing to sync.
  A failover then breaks every such flow that a stateful firewall on the
  peer would treat as `new`. Document that conntrack-sync covers
  kernel-forwarded flows only.

**3.8 Deviations to record (module doc of `src/conntrack_sync.rs`, and the
`src/vrrp.rs` doc line 22 replaced):**
- Paths live under `/run/insomnia/conntrackd/`, with the unit
  `insomnia-conntrackd.service`.
- A config change restarts conntrackd. It is never reloaded.
- The `Helper` block is rendered only when nfs or sqlnet helpers are
  configured.
- An invalid config stops conntrackd instead of rejecting the commit.
- The VRRP hook uses keepalived's generic `notify` slot, not
  `notify_master|backup|fault`. User transition scripts and the hook
  coexist.
- The helper never starts conntrackd.
- Default VRF only, until [vrrp-vrf](vrrp-vrf.md).

## 4. Changes

### zebra-rs

`yang/config.yang`, a sketch. The leaves and defaults are VyOS's
(`service_conntrack-sync.xml.in`); the defaults are filled by the renderer, as
for VRRP.

```yang
container service {
  if-feature feat:insomnia;
  ext:help "Services";
  container conntrack-sync {
    ext:help "Connection tracking synchronization (conntrackd)";
    leaf-list accept-protocol { type enumeration { enum tcp; enum udp; enum icmp;
      enum icmp6; enum sctp; enum dccp; } }
    leaf disable-external-cache { type empty; }
    leaf disable-syslog { type empty; }
    leaf event-listen-queue-size { ext:help "MB (VyOS default: 8)"; type uint32; }
    leaf-list expect-sync { type enumeration { enum all; enum ftp; enum sip;
      enum h323; enum nfs; enum sqlnet; } }
    leaf startup-resync { type empty; }
    container failover-mechanism { container vrrp {
      leaf sync-group { ext:help "VRRP sync-group"; type string; } } }
    leaf-list ignore-address { type union { type inet:ipv4-address; type inet:ipv6-address; } }
    list interface { key name;
      leaf name { ext:dynamic "rib:interface"; type string; }
      leaf peer { type union { type inet:ipv4-address; type inet:ipv6-address; } }
      leaf port { type uint16 { range "1..65535"; } } }
    leaf-list listen-address { type union { type inet:ipv4-address; type inet:ipv6-address; } }
    leaf mcast-group { ext:help "Multicast group (VyOS default: 225.0.0.50)";
      type union { type inet:ipv4-address; type inet:ipv6-address; } }
    leaf sync-queue-size { ext:help "MB (VyOS default: 1)"; type uint32; }
    leaf purge-timeout { ext:help "Seconds (VyOS default: 60)";
      type uint32 { range "1..2147483647"; } }
  }
}
```

- **Commit checks** ([commit-validation](commit-validation.md) layer 1):
  - `mandatory` cannot express "at least one `interface`". That check stays
    a render check.
  - `mcast-group` is validated as multicast in the renderer.
- **`yang/exec.yang`:** `show conntrack-sync { cache { external { main;
  expect } internal { main; expect } } statistics status }` as presence
  containers, insomnia-gated.
- **`reset` / `restart` grammar:** from [exec-verbs](exec-verbs.md).
- **`src/config/manager.rs`:** `is_conntrack_sync`, anchored at `paths[1]`
  like `is_conntrack`, with the `SHOW_PROTOS` entry
  `("conntrack-sync", "Conntrack sync")`.

### insomnia

- **New `src/conntrack_sync.rs`:**
  - the model (`Flex` everywhere, `de_flex_vec` for the leaf-lists);
  - `render` and `render_str` (cfg(test)), both returning `(String, Findings)`;
    `host_findings`; `validate`;
  - `run(host, ctl, sizes_rx, helpers_rx, groups_rx, hook_tx, up_tx, rx)`.
    `rx` carries show and exec orders (`ShowRequest { kind, .. }`);
  - `process_order`, for show plus `reset` and `restart`.
- **New `src/conntrackd.rs`:** `Conntrackd { dir, control, unit }`,
  `apply(&Conntrackd, conf) -> Applied`, and `ctl(args, timeout) ->
  Result<String>`. It uses `fsutil::{write_if_changed, systemctl}`.
- **`src/vrrp.rs`:**
  - `render(cfg, &VrrpHooks) -> (String, Findings)`, the return type from
    [commit-validation](commit-validation.md). `render_str` and
    `vrrp::validate` pass `VrrpHooks::default()`, so every existing golden is
    byte-identical, and validation never depends on the conntrack-sync
    task;
  - the sync-group block gains the hook line after `render_notify`
    (`:1056-1058`);
  - `run` takes `hook_rx` and `groups_tx`;
  - doc line 22 is updated.
- **`src/main.rs`:** the flags `--conntrackd-dir`, `--conntrackd-control`
  and `--conntrackd-unit`; the channels; spawning `conntrack_sync::run`.
- **`src/provider.rs`:** register `"conntrack-sync"`.
- **Packaging:**
  - `packaging/systemd/insomnia-conntrackd.service`, added to
    `systemd-units` with `enable = false, start = false`:

    ```
    [Unit]
    Description=conntrackd (conntrack state sync), driven by insomnia
    After=network-online.target insomnia.service
    [Service]
    Type=simple
    EnvironmentFile=-/run/insomnia/conntrackd/env
    ExecStartPre=/bin/rm -f /run/insomnia/conntrackd/conntrackd.lock
    ExecStart=/usr/sbin/conntrackd -C /run/insomnia/conntrackd/conntrackd.conf
    ```

    `Type=simple` with conntrackd in the foreground (no `-d`).
    `Type=notify` needs a conntrackd built with systemd support and a
    `Systemd on` option (*unverified* for Debian's build).
  - The asset `["packaging/conntrack-failover", "usr/lib/insomnia/", "755"]`.
  - `recommends += conntrackd`.

**Worked example.**

```text
set vrrp sync-group PAIR member LAN
set vrrp sync-group PAIR transition-script master /usr/local/bin/sg-master
set service conntrack-sync interface eth1
set service conntrack-sync accept-protocol tcp
set service conntrack-sync accept-protocol udp
set service conntrack-sync expect-sync ftp
set service conntrack-sync failover-mechanism vrrp sync-group PAIR
```

The inputs are `eth1` = 192.0.2.1/24, `CtSizes { buckets: 65536, max:
262144 }`, and no userspace helpers. `conntrackd.conf`:

```
### Rendered by insomnia from `service conntrack-sync` — do not edit.

# Synchronizer settings
Sync {
    Mode FTFW {
        PurgeTimeout 60
        DisableExternalCache off
        StartupResync off
    }
    Multicast {
        IPv4_address 225.0.0.50
        IPv4_interface 192.0.2.1
        Group 3780
        Interface eth1
        SndSocketBuffer 1048576
        RcvSocketBuffer 1048576
        Checksum on
    }
    Options {
        ExpectationSync {
            ftp
        }
    }
}

# General settings
General {
    HashSize 65536
    HashLimit 524288
    LogFile off
    Syslog on
    LockFile /run/insomnia/conntrackd/conntrackd.lock
    UNIX {
        Path /run/insomnia/conntrackd/conntrackd.ctl
    }
    NetlinkBufferSize 2097152
    NetlinkBufferSizeMaxGrowth 8388608
    NetlinkOverrunResync off
    NetlinkEventsReliable on
    Filter From Userspace {
        Protocol Accept {
            TCP
            UDP
        }
    }
}
```

The keepalived sync-group block that `vrrp::render` produces with the hook:

```
vrrp_sync_group PAIR {
    group {
        LAN
    }
    notify_master "/usr/local/bin/sg-master"
    notify "/usr/lib/insomnia/conntrack-failover /run/insomnia/conntrackd/conntrackd.conf"
}
```

`show conntrack-sync status`:

```
sync-interface        : eth1
failover-mechanism    : vrrp [sync-group PAIR]
last state transition : MASTER 2026-10-21T10:12:03+00:00
ExpectationSync       : ftp
```

## 5. Tests

**Golden and unit tests:**

| Test | Asserts |
|:--|:--|
| `conntrack_sync::tests::golden_multicast` | The worked example, byte for byte |
| `golden_unicast_peer_port_listen` | Two `UDP {}` blocks, `IPv4_address`, `Port 3790`, `IPv4_Destination_Address` |
| `golden_ipv6_mcast` | `IPv6_address ff02::…`, no `IPv4_interface` |
| `golden_helper_block_when_userspace_helpers` | The `Helper` block appears only with `userspace_helpers = true` |
| `expect_sync_all_renders_on` | `ExpectationSync on` |
| `skip_rules` | Each §3.3 condition → empty render + one named warning |
| `defaults_filled` | `sync-queue-size`/`event-listen-queue-size`/`purge-timeout` defaults → 1 MiB / 8 MiB / 60 |
| `conntrackd::tests::apply_direct_no_daemon` | Direct mode with no conntrackd: the file lands, `Applied::NotRunning`, no spawn when unchanged (scratch dir, as `keepalived::tests::apply_writes_files_and_detects_unchanged`) |
| `vrrp::tests::golden_render_conntrack_hook` | The sync-group block above; the user's `notify_master` stays first |
| `vrrp::tests::hook_for_missing_group_not_rendered` | A hook naming an unknown group adds no line; warning |
| `vrrp::tests::golden_render` | Unchanged (default hooks) |
| `show_status_from_model` / `show_cache_from_fixture` | Text tables from a captured `conntrackd -e ct` output |

**BDD feature `@conntrack_sync`** (needs `conntrackd` and keepalived on the
host):
- **Topology:** the `vrrp_pair` topology, with r1/r2 on bridge `br` and h1.
  A second bridge `sync` links r1/r2 for the sync interface.
- **Node script:** `tests/scripts/vrrp_node.sh` gains
  `--conntrackd-control direct`; conntrackd is started by insomnia.
- **Scenarios:**
  1. Setup. The VRRP master is elected. `show conntrack-sync status` on
     both routers shows `eth`.
  2. h1 opens a long-lived TCP connection to the VIP (`nc`). `show
     conntrack-sync cache external` on r2 eventually contains h1's address.
  3. Failover: link down on r1. r2 becomes MASTER. `show conntrack table
     ipv4` on r2 contains h1's address, which shows the external cache was
     committed. `/tmp/<ns>.transitions` shows the user `transition-script`
     ran too.
  4. With [conntrack](conntrack.md) VRF zones active, a zoned flow keeps its
     zone on r2 (the §3.6 open question).
  5. `reset conntrack-sync external-cache` on r2 (once exec-verbs lands),
     then the external cache is repopulated by the resync.
  6. Teardown topology.

## 6. Docs

- **Book:**
  - new `ch-05-07-conntrack-sync.md`, under VRRP: FTFW, multicast versus
    unicast, the failover hook, and the `notify` slot;
  - `ch-05-04-keepalived-and-insomnia.md`: the hook line;
  - `ch-03-02-show-vrrp.md` or a new `ch-03-07-show-conntrack-sync.md`;
  - `ch-00-03-command-line-options.md`: the three flags;
  - `ch-00-01-install.md`: `conntrackd`.
- **`design/vrrp.md`:**
  - §6 "No conntrack-sync helper" → the `notify` slot;
  - §14: drop the deferred item.

  Coordinate with [docs-corrections](docs-corrections.md), which edits the
  same file.
- **Module docs:** the §3.8 list. `src/vrrp.rs` replaces "no conntrack-sync
  notify helper" with the `notify`-slot deviation.

## 7. Milestones

| # | Scope | Repo | Effort | Done when |
|:--|:--|:--|:--|:--|
| M1 | `service conntrack-sync` YANG, `show conntrack-sync` grammar, anchored `is_conntrack_sync` | zebra-rs | S | Schema tests; routes to a provider named `conntrack-sync` |
| M2 | `src/conntrackd.rs` on `fsutil`, the unit file, the flags, bounded `ctl` calls | insomnia | S | `conntrackd::tests` pass; `keepalived::tests` unchanged |
| M3 | Model, `render`, skip rules, `CtSizes`/helper watches with [conntrack](conntrack.md) | insomnia | M | §5 goldens |
| M4 | VRRP hook: `VrrpHooks`, the watches, the helper script asset, the module-doc change | insomnia | S | vrrp goldens; `keepalived --config-test` of the rendered example is clean (dev check) |
| M5 | `show conntrack-sync cache\|statistics\|status` | insomnia | S | Show tests |
| M6 | `reset conntrack-sync …`, `restart conntrack-sync`: `EXEC_TREES`, `ROUTES`, `Answer` handlers ([exec-verbs](exec-verbs.md)) | both | S | BDD scenario 5 |
| M7 | BDD `@conntrack_sync`, scenarios 1-4 and 6 | insomnia | M | Passes twice in a row |
| M8 | VRF support through [vrrp-vrf](vrrp-vrf.md)'s mechanism | insomnia | S | A VRF sync interface works in BDD, or stays documented as unsupported |
| M9 | Book, `design/vrrp.md`, CHANGELOG | insomnia | S | `mdbook build` clean |

## 8. Risks and open questions

- **Generic `notify` arguments.** The argument list and ordering for sync
  groups are only from keepalived.conf(5). The BDD scenario 3 must observe
  `GROUP PAIR MASTER`. If 2.2.8 passes something else, the script parses by
  position from the end.
- **No reload.** conntrackd reload semantics are *unverified*. If a reload
  exists and keeps the caches, prefer it to a restart: a restart on the
  BACKUP drops the external cache until the next resync.
- **Sizes.** `HashSize` and `HashLimit` follow the kernel. In a child netns
  `nf_conntrack_max` cannot change ([conntrack](conntrack.md) fact 1), so
  the BDD sees the host values. Expected.
- **Zones.** See §3.6. If conntrackd drops zones, VRF zones and
  conntrack-sync are mutually exclusive until upstream support is found.
- **Two writers of `/run/insomnia/conntrackd/env`.** None today; the VRF case
  adds one (this task only).
- **Requirements on other plans:**
  - [charon-lifecycle](charon-lifecycle.md) /
    [ipsec-render-fixes](ipsec-render-fixes.md): `src/fsutil.rs` (§3.2).
    Nothing is added to it.
  - [conntrack](conntrack.md): the `CtSizes`, `UserspaceHelpersWanted` and
    `ConntrackdUp` watches, and the reusable `key=value` parser in `ctread`.
  - [exec-verbs](exec-verbs.md): the `EXEC_ROUTES` rows and the
    segment-boundary `route()` (D-8), both already in that plan.
  - [vrrp-hardening](vrrp-hardening.md): its script-existence check must
    accept the shipped `/usr/lib/insomnia/conntrack-failover`, and must not
    warn about the `notify` line. Its §3.1 scope already excludes this
    generated hook.
  - [vrrp-virtual-server](vrrp-virtual-server.md): it also widens
    `vrrp::render`, to `render(cfg, vs)`. Whichever plan lands second folds
    both into one inputs struct (`VrrpHooks` gains the `vs` slice, or the
    reverse), so `render_str` keeps one default and the goldens stay
    byte-identical.

## 9. Acceptance criteria

- [ ] `service conntrack-sync` exists only with `--feature insomnia`.
- [ ] A valid config starts conntrackd under insomnia's paths. A change
      restarts it, removal stops it, and an invalid config stops it with a
      warning naming the cause.
- [ ] `HashSize`/`HashLimit` track the kernel after a `system conntrack`
      change, without a manual restart.
- [ ] A sync group with both a `transition-script` and the failover hook
      runs both on MASTER/BACKUP/FAULT. keepalived logs no "already
      specified" error.
- [ ] Failover in BDD commits the external cache on the new master.
- [ ] Show, reset and restart commands answer, text and `-j` where VyOS has
      raw output.
- [ ] Goldens, clippy and fmt are clean. Existing vrrp goldens are
      unchanged.
