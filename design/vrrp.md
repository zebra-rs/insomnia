# VRRP (VyOS-derived `vrrp` tree) — design

Status: proposal, 2026-09-07. Nothing implemented yet.

insomnia gains a third backend next to firewall and IPsec: it subscribes to the
`vrrp` running-config subtree, renders it into a `keepalived.conf`,
reloads keepalived, and answers `show vrrp …` on the zebra-rs CLI. The schema and
the show grammar live in zebra-rs, as they do for the other two backends.

Open-source choice: **keepalived**. It was our first choice and it is also what
VyOS uses, so the VyOS templates and op-mode scripts can be followed line for
line the way the nftables and swanctl backends follow theirs.

Placement decision (2026-09-07): the config tree is rooted at a top-level
`vrrp` node, not VyOS's `high-availability vrrp`. VyOS's wrapper exists only to
co-locate VRRP with its IPVS load balancer (`virtual-server`); zebra-rs has no
such grouping, and a load balancer would get its own top-level node. Below
`vrrp` the tree is VyOS's verbatim (plus the §2 extensions), so a VyOS config
ports by dropping the `high-availability` prefix.

## 1. What VyOS does (verified against vyos-1x `current`)

| Piece | vyos-1x file | What it does |
|:------|:-------------|:-------------|
| Schema | `interface-definitions/high-availability.xml.in` (+ `include/vrrp/garp.xml.i`, `include/vrrp-transition-script.xml.i`) | `high-availability { disable, vrrp { group, sync-group, global-parameters, snmp }, virtual-server }` |
| Conf mode | `src/conf_mode/high-availability.py` | `verify()` rules (below), renders `keepalived.conf.j2` to `/run/keepalived/keepalived.conf` and a systemd override, then `systemctl reload-or-restart keepalived.service`; `systemctl stop` when the tree is absent or `disable` is set |
| Template | `data/templates/high-availability/keepalived.conf.j2` | `global_defs`, one `vrrp_script` per health check, one `vrrp_instance` per group, `vrrp_sync_group`, `virtual_server` (IPVS) |
| Unit override | `data/templates/high-availability/10-override.conf.j2` | `keepalived --use-file /run/keepalived/keepalived.conf --pid /run/keepalived/keepalived.pid --dont-fork [--snmp]`, `KillMode=process` |
| Transition scripts | `src/system/keepalived-fifo.py` | Not rendered as `notify_*`; keepalived writes `INSTANCE "name" MASTER 100` lines to a FIFO and a Python dispatcher runs the configured script |
| Op mode | `src/op_mode/vrrp.py`, `python/vyos/ifconfig/vrrp.py` | Sends keepalived its JSON signal (`SIGRTMIN+2`), waits for `/tmp/keepalived.json`, parses it, deletes it. `show vrrp` is a table; `statistics` and `detail` are Jinja text blocks |

Facts about the keepalived on the development host (Ubuntu 24.04, keepalived
2.2.8): built with `JSON`, `VRRP_VMAC`, `VRRP_AUTH`, `BFD`, `DBUS`, `SNMP`;
`keepalived --signum=JSON` prints `36`; the stock unit reads
`/etc/keepalived/keepalived.conf`, reloads with `SIGHUP`, and is **already
running on this machine** with a local config (pid file `/run/keepalived.pid`).
The test design in §10 keeps BDD nodes away from it.

keepalived source facts the design relies on (v2.2.8 `core/main.c`,
`vrrp/vrrp_json.c`): a config with no `vrrp_instance` starts the parent, logs
"Warning - keepalived has no configuration to run" and idles; the JSON dump is
written to `<tmp_dir>/keepalived.json` (`/tmp` by default) and its shape is an
array of `{ "data": {…}, "stats": {…} }` objects (`json_version 1`).

## 2. FRR's VRRP model, compared

FRR ships its own daemon (`vrrpd`: native RFC 3768 / RFC 5798, no
keepalived). Its config tree was reviewed as the other shape we could have
adopted. The differences are why the VyOS tree stays, and where three FRR
knobs are worth borrowing.

### Shape

| | FRR (`yang/frr-vrrpd.yang`, `vrrpd/vrrp_vty.c`) | VyOS |
|:--|:--|:--|
| Placement | augments the interface list: `interface eth0` → `vrrp 5 priority 200`, `vrrp 5 ip 10.0.2.16`, `vrrp 5 ipv6 2001:db8::1` | global `high-availability vrrp group <name>` (zebra-rs: top-level `vrrp group <name>`); `interface` is a leaf inside the group |
| Key | virtual router ID; groups have no name | operator-chosen name; `vrid` is a leaf |
| Address families | one group carries `v4` and `v6` address lists, run as two independent state machines | one family per group (keepalived cannot mix them; VyOS `verify()` rejects a mix) |
| Global commands | `vrrp default …` (defaults for groups created later), `vrrp autoconfigure` (derive groups from macvlans already on the box) | `global-parameters` (garp, startup-delay, version) |
| HA orchestration | none | sync groups, health checks, tracked interfaces, transition scripts, unicast peers |
| Show | `show vrrp [interface IF] [VRID] [json]` (one vertical table per group, both families side by side) and `show vrrp … summary` (Interface, VRID, Priority, IPv4, IPv6, State v4, State v6) | `show vrrp` (Name, Interface, VRID, State, Priority, Last Transition), `statistics`, `detail`, filtered by group name |
| States | Initialize, Master, Backup | INIT, BACKUP, MASTER, FAULT (keepalived adds FAULT for tracked-object failure) |

### Knob by knob

| FRR leaf | VyOS equivalent | keepalived keyword | Note |
|:---------|:----------------|:-------------------|:-----|
| `virtual-router-id` 1-255, list key | `vrid` 1-255, plain leaf | `virtual_router_id` | |
| `version` 2 or 3, default 3, per group | `global-parameters version`, default 2, global only | `version` per instance, `vrrp_version` global | keepalived supports per-group; VyOS does not expose it. IPv6 forces 3 in both |
| `priority` 1-254, default 100 | `priority` 1-255, default 100 | `priority` | FRR reserves 255 for the address owner |
| `preempt` bool, default true | `no-preempt` presence, `preempt-delay` 0-1000 s | `nopreempt`, `preempt_delay` | FRR has no delay |
| `accept-mode` bool, default true | none | `accept` / `no_accept` | FRR's docs state accept mode is not implemented |
| `checksum-with-ipv4-pseudoheader` bool, default true | none | `v3_checksum_as_v2`, global or per instance | same interop problem, inverse sense |
| `advertisement-interval` centiseconds 1-4095 (CLI in ms, 10-40950) | `advertise-interval` 1-255 whole seconds | `advert_int`, fractional seconds allowed | VyOS's schema is the limiter, not keepalived |
| `shutdown` bool | `disable` presence | instance omitted | same effect |
| `v4/virtual-address`, `v6/virtual-address` in one group | one family per group | `virtual_ipaddress` | |
| none | `authentication` (password or AH) | `authentication` | FRR dropped it deliberately; RFC 3768 removed it |
| none (multicast only) | `peer-address`, `hello-source-address` | `unicast_peer`, `unicast_src_ip` / `mcast_src_ip` | unicast VRRP is keepalived-only |
| none | `health-check`, `track interface`, `sync-group`, `transition-script` | `vrrp_script`, `track_interface`, `vrrp_sync_group`, `notify_*` | |
| none | `garp`, `startup-delay`, `description`, `rfc3768-compatibility`, `excluded-address` | `garp_*`, `vrrp_startup_delay`, `use_vmac`, `virtual_ipaddress_excluded` | |
| `vrrp default …`, `vrrp autoconfigure` | none | none | FRR conveniences |

### Operational differences

- **Virtual MAC and address ownership.** FRR never creates interfaces or
  addresses: the operator pre-creates one macvlan per group and family with
  the RFC virtual MAC (`00:00:5e:00:01:<vrid>` / `00:00:5e:00:02:<vrid>`) in
  `bridge` mode, puts the virtual address on it, and FRR only flips the
  macvlan into `protodown` while in Backup. keepalived adds and removes the
  virtual addresses itself, on the parent interface by default or on a macvlan
  it creates when `use_vmac` is set. Under keepalived, zebra-rs will see
  addresses appear and vanish over netlink on every election; that is what
  VyOS already lives with.
- **Kernel floor.** FRR needs Linux 5.1+ (macvlan protodown). keepalived has
  no such requirement.
- **Filtering.** FRR filters shows by interface and VRID; VyOS by group name.
  This design follows VyOS.

### Decision

The VyOS group model stays, hoisted to a top-level `vrrp` node (placement
decision above). insomnia's whole ISO surface is VyOS-shaped, keepalived
is the backend, and FRR's per-interface placement would force a nameless,
VRID-keyed model that cannot express sync groups or health checks. Nothing in
FRR's model argues for switching.

Three FRR knobs are adopted as **zebra-rs extensions** inside the VyOS group,
because keepalived already implements them and VyOS merely fails to expose
them. They are marked `[ext]` in §4 and §6:

1. **Per-group `version 2|3`**, rendered as keepalived's instance-level
   `version`, so an IPv4 group can run VRRPv3 without changing the global
   default. Absent → `global-parameters version` → keepalived's own default
   (2 for IPv4, 3 for IPv6).
2. **`v3-checksum-as-v2`** (presence), rendered as the instance-level
   `v3_checksum_as_v2`. Same interop fix as FRR's
   `no checksum-with-ipv4-pseudoheader`, for peers that omit the IPv4
   pseudoheader from the VRRPv3 checksum. keepalived's name is kept because
   the mapping is 1:1.
3. **Fractional `advertise-interval`**: the leaf becomes `decimal64` (two
   fraction digits, 0.01-255) instead of `uint 1-255`. Existing VyOS configs
   (`advertise-interval 1`) still parse; keepalived accepts fractional seconds
   for VRRPv3. Render-time rules: version 2 groups need whole seconds 1-255
   (fractional → warn, round up); version 3 groups allow 0.01-40.95 (above →
   warn, clamp), matching the 12-bit centisecond wire field.

Not carried over: FRR's `accept-mode`. FRR does not implement it, and
keepalived's `no_accept` pulls in an nftables/iptables dependency that would
interact with the firewall backend's tables.

## 3. Scope

In scope for the first release:

- `vrrp disable`
- `vrrp group <name>` — every leaf VyOS has (§4), plus the three FRR-derived `[ext]` leaves (§2)
- `vrrp sync-group <name>`
- `vrrp global-parameters`
- `show vrrp`, `show vrrp statistics`, `show vrrp detail`, each with an optional
  group filter, text and JSON

Deliberately deferred (§13): `virtual-server` (IPVS load balancing, not VRRP;
would be its own top-level node),
`vrrp snmp trap`, the conntrack-sync failover hook, commit-time reference
validation.

## 4. Config tree (zebra-rs `vrrp.yang`)

Grouping-library module in the `firewall.yang` / `ipsec.yang` style,
instantiated in `config.yang` as

```yang
container vrrp {
  if-feature feat:iso;
  ext:help "Virtual Router Redundancy Protocol (VRRP)";
  uses "vrrp:vrrp";
}
```

Leaf names are VyOS's, verbatim, so a VyOS `set high-availability vrrp …` line
ports as `set vrrp …` with nothing else changed. Types follow the VyOS validators; defaults are applied by
the renderer (constants, as `ipsec.rs` does), because the JSON batch carries
only what the operator set. Leaves marked `[ext]` are the three FRR-derived
extensions from §2; a config that omits them is exactly VyOS's.

```
vrrp
├── disable                                  empty   stop keepalived entirely
├── global-parameters
│   ├── garp
│   │   ├── interval                     decimal 0.000-1000   (default 0)
│   │   ├── master-delay                 1-1000               (default 5)
│   │   ├── master-refresh               0-255                (default 5)
│   │   ├── master-refresh-repeat        1-255                (default 1)
│   │   └── master-repeat                1-255                (default 5)
│   ├── startup-delay                    1-600 seconds
│   └── version                          2 | 3
├── group <name>                         list, key name
│   ├── interface                        string   REQUIRED
│   ├── vrid                             1-255    REQUIRED
│   ├── version                          2 | 3    [ext] per-group, overrides global-parameters version
│   ├── v3-checksum-as-v2                empty    [ext] VRRPv3 IPv4 checksum without pseudoheader
│   ├── address <ip[/len]>               list, key address, REQUIRED (>=1)
│   │   └── interface                    string   (`dev` for this VIP)
│   ├── excluded-address <ip[/len]>      list, key address
│   │   └── interface                    string
│   ├── advertise-interval               decimal 0.01-255 s   (default 1)   [ext: fractional]
│   ├── authentication
│   │   ├── password                     string, 1-8 chars
│   │   └── type                         plaintext-password | ah
│   ├── description                      rest-of-line string
│   ├── disable                          empty   instance omitted, shown DISABLED
│   ├── garp                             same five leaves as global garp
│   ├── health-check
│   │   ├── failure-count                positive             (default 3)
│   │   ├── interval                     positive seconds     (default 60)
│   │   ├── ping                         ipv4 | ipv6
│   │   ├── script                       path
│   │   └── timeout                      seconds
│   ├── hello-source-address             ipv4 | ipv6
│   ├── peer-address                     leaf-list ipv4 | ipv6   (unicast VRRP)
│   ├── no-preempt                       empty
│   ├── preempt-delay                    0-1000 seconds       (default 0)
│   ├── priority                         1-255                (default 100)
│   ├── rfc3768-compatibility            empty   (VMAC interface)
│   ├── track
│   │   ├── exclude-vrrp-interface       empty
│   │   └── interface                    leaf-list string
│   └── transition-script
│       ├── master | backup | fault | stop   path
└── sync-group <name>                    list, key name
    ├── member                           leaf-list string (group names)
    ├── health-check                     same as group
    └── transition-script                same as group
```

Schema conventions carried over from ipsec.yang: no `pattern` on value leaves,
`description` uses the rest-of-line pattern, references (`member`, `interface`)
are plain strings rather than leafrefs so referents may be staged after
referrers.

## 5. Backend shape (insomnia `src/vrrp.rs`)

Identical to the other two backends; nothing new in the plumbing:

1. `subscribe_json(host, ["vrrp"])` — the whole subtree, so `disable` and every
   group arrive in one batch.
2. `run` loop `select!`s between config events and show requests; reconnects
   with `RECONNECT_DELAY`; the snapshot re-render is idempotent.
3. JSON → `VrrpConfig` serde model. Every operator string is `Flex`; `disable`,
   `no-preempt`, `rfc3768-compatibility`, `exclude-vrrp-interface` use
   `de_presence`; `peer-address`, `member`, `track interface` use `de_flex_vec`.
4. `render(&cfg) -> (String, Vec<String>)` produces the complete
   `keepalived.conf` text plus warnings.
5. Apply (§7). Anything that cannot be rendered safely is skipped with a warning
   naming the group; the rendered file is always valid keepalived syntax, so
   one bad group never wedges the commit.

`main.rs` spawns `vrrp::run` next to the other two and `provider.rs` registers
the name `vrrp` alongside `firewall` and `ipsec`, routing orders whose path
starts with `/show/vrrp` to it.

## 6. Rendering

Follows `keepalived.conf.j2` line for line. Mapping:

| Config | keepalived.conf |
|:-------|:----------------|
| (always) | `global_defs { dynamic_interfaces  script_user root … }` |
| `global-parameters startup-delay` | `vrrp_startup_delay N` |
| `global-parameters garp *` | `vrrp_garp_interval`, `vrrp_garp_master_delay`, `vrrp_garp_master_refresh`, `vrrp_garp_master_refresh_repeat`, `vrrp_garp_master_repeat` |
| `global-parameters version` | `vrrp_version 2\|3` |
| `group <name>` | `vrrp_instance <name> { … }` (omitted when `disable` is set) |
| `description` | `# text` comment line inside the instance |
| (always) | `state BACKUP` — every node starts as backup and elects |
| `interface` | `interface IF` |
| `vrid` | `virtual_router_id N` |
| `version` [ext] | `version 2\|3` on the instance |
| `v3-checksum-as-v2` [ext] | `v3_checksum_as_v2` on the instance |
| `priority` | `priority N` (default 100) |
| `advertise-interval` | `advert_int N` (default 1; fractional seconds pass through for version 3, see §2) |
| `garp *` (per group) | `garp_interval`, `garp_master_delay`, `garp_master_repeat`, `garp_master_refresh`, `garp_master_refresh_repeat` |
| `track exclude-vrrp-interface` | `dont_track_primary` |
| `no-preempt` | `nopreempt` |
| `preempt-delay` (only without `no-preempt`) | `preempt_delay N` |
| `peer-address …` | `unicast_peer { addr … }` |
| `hello-source-address` | `unicast_src_ip A` when peers are set, else `mcast_src_ip A` |
| `rfc3768-compatibility` | `use_vmac <if>v<vrid>v<4\|6>` (family from the first `address`), plus `vmac_xmit_base` when unicast peers are set |
| `authentication` | `authentication { auth_pass "pw"  auth_type PASS\|AH }` |
| `address …` | `virtual_ipaddress { addr [dev IF] … }` |
| `excluded-address …` | `virtual_ipaddress_excluded { addr [dev IF] … }` |
| `track interface …` | `track_interface { IF … }` |
| `health-check` (group not in a sync-group) | `vrrp_script healthcheck_<name> { script "<script>" or "/usr/bin/ping -c1 <ip>"  interval N  [timeout N]  fall <failure-count>  rise 1 }` and `track_script { healthcheck_<name> }` in the instance |
| `sync-group <name>` | `vrrp_sync_group <name> { group { members… } [track_script { healthcheck_sg_<name> }] }` with its own `vrrp_script healthcheck_sg_<name>` |
| `transition-script master\|backup\|fault\|stop` | `notify_master "…"`, `notify_backup "…"`, `notify_fault "…"`, `notify_stop "…"` on the instance or sync group — **deviation, see below** |
| `vrrp disable` or empty tree | empty config; keepalived is stopped (§7) |

Deliberate deviations from VyOS, to be recorded in the module doc comment:

- **Transition scripts** render as native keepalived `notify_*` lines. VyOS
  goes through `notify_fifo` + a Python dispatcher because that dispatcher also
  drives mDNS-repeater and conntrack-sync; insomnia has neither. No
  `notify_fifo` / `notify_fifo_script` lines are emitted.
- **No `enable_traps`** and no `--snmp` (SNMP deferred).
- **No conntrack-sync `notify_*` helper** on sync groups (deferred).
- **Defaults are filled by the renderer**, not by the config store.

Render-time checks (VyOS `verify()`, turned into skip-with-warning where VyOS
rejects the commit):

| Rule | Action |
|:-----|:-------|
| `vrid`, `interface`, at least one `address` present | skip the group otherwise |
| `authentication` has both `type` and `password` | skip the group otherwise |
| virtual addresses all IPv4 or all IPv6 | skip the group on a mix |
| `(interface, vrid, family)` unique across groups | skip the later duplicate |
| `hello-source-address` and every `peer-address` match the VIP family | skip the group |
| `sync-group member` names an existing, enabled group | drop that member with a warning |
| a sync-group member's own `health-check` | ignored (sync-group check wins), warning |
| `health-check` has exactly one of `script` / `ping` | omit the health check, warning |
| `health-check timeout` < `interval` | rendered as is, warning |
| `password` longer than 8 bytes | keepalived truncates; warn |
| `advertise-interval` fractional in a version 2 group | round up to whole seconds, warning |
| `advertise-interval` above 40.95 in a version 3 group | clamp to 40.95, warning |

## 7. Applying: keepalived lifecycle

**Decision: keepalived stays a separately supervised process; insomnia writes
the file and asks for a reload.** This mirrors VyOS and the existing charon
contract. The alternative — insomnia spawning keepalived as a child — was
rejected because insomnia is restarted on every package upgrade
(`restart-after-upgrade = true`), which would kill the VRRP master and force a
failover for a config-daemon restart. Keeping keepalived independent means
insomnia restarts never move a virtual address.

Files and flags (defaults in parentheses):

| Flag | Default | Meaning |
|:-----|:--------|:--------|
| `--keepalived-conf` | `/run/insomnia/keepalived.conf` | rendered file; written to a temp file in the same directory and renamed into place |
| `--keepalived-pid` | `/run/insomnia/keepalived.pid` | keepalived parent pid file; used by signal mode and by `show vrrp` |
| `--keepalived-json` | `/tmp/keepalived.json` | where keepalived writes its JSON dump (keepalived's tmp dir + fixed name) |
| `--keepalived-control` | `systemd` | `systemd` or `signal` |
| `--keepalived-unit` | `insomnia-keepalived.service` | unit used in systemd mode |

Control modes:

- **`systemd`** (production): after writing the file run
  `systemctl reload-or-restart <unit>`; when the tree is empty or `disable` is
  set, write an empty file and run `systemctl stop <unit>`. A failing
  `systemctl` is logged and the commit still succeeds, exactly like a missing
  `swanctl` today.
- **`signal`** (containers, BDD, anyone running keepalived by hand): after
  writing the file send `SIGHUP` to the pid in the pid file; on an empty tree
  write the empty file and `SIGHUP` as well, so keepalived withdraws every
  instance but keeps running. If the pid file is absent or stale, warn and
  leave the file for the next start.

Packaging:

- `Recommends: keepalived` (like strongSwan; the other backends work without
  it).
- Ship `packaging/systemd/insomnia-keepalived.service`, **a separate unit**, so
  the distribution's `keepalived.service` and `/etc/keepalived/keepalived.conf`
  are never touched:

  ```ini
  [Unit]
  Description=keepalived (VRRP) driven by insomnia
  After=network-online.target insomnia.service
  Wants=network-online.target

  [Service]
  Type=notify
  ExecStart=/usr/sbin/keepalived --dont-fork --use-file /run/insomnia/keepalived.conf --pid /run/insomnia/keepalived.pid
  ExecReload=/bin/kill -HUP $MAINPID
  KillMode=process
  ```

  It is not enabled; insomnia starts it on the first non-empty config
  (`reload-or-restart` starts a stopped unit) and stops it when the config goes
  away.
- `insomnia.service` gains `RuntimeDirectory=insomnia` and
  `RuntimeDirectoryPreserve=yes` so `/run/insomnia` survives insomnia restarts
  while keepalived is still using the file and pid path.
- Startup probe: run `keepalived --version` once; warn if `JSON` is missing
  from the "Config options" line (show commands would have nothing to read).

## 8. Show commands

Grammar (zebra-rs `exec.yang`, gated on `feat:iso`, same presence-container
style as `show firewall`):

```
show vrrp                        summary table, all groups
show vrrp statistics [<group>]   counters, VyOS text layout
show vrrp detail     [<group>]   full instance dump, VyOS text layout
```

Orders reach insomnia as `/show/vrrp`, `/show/vrrp/statistics`,
`/show/vrrp/detail` with the optional group name in `args`.

Data source, following `vyos/ifconfig/vrrp.py`:

1. Read the pid from `--keepalived-pid`. No pid or no process → answer
   `VRRP data is not available (process not running or no active groups)`.
2. Remove a stale `--keepalived-json` file.
3. Send the JSON signal. The number comes from `keepalived --signum=JSON`,
   probed once at startup (fallback `SIGRTMIN+2`), never hard-coded.
4. Poll for the file to appear and its size to stop changing (keepalived writes
   it in one go; VyOS waits up to 30 s, insomnia uses a short bounded wait).
5. Parse, delete the file, render.

JSON shape (per instance): `data.iname`, `data.ifp_ifname`, `data.vrid`,
`data.state` (0 INIT, 1 BACKUP, 2 MASTER, 3 FAULT), `data.wantstate`,
`data.base_priority`, `data.effective_priority`, `data.last_transition`
(epoch seconds), `data.adver_int`, `data.nopreempt`, `data.preempt_delay`,
`data.auth_type` (0 none, 1 PASS, 2 AH), `data.vips[]`, `data.evips[]`,
`data.track_ifp[]`, `data.track_script[]`, `data.garp_*`, `data.version`;
`stats.advert_rcvd`, `advert_sent`, `become_master`, `release_master`,
`packet_len_err`, `ip_ttl_err`, `invalid_type_rcvd`, `advert_interval_err`,
`addr_list_err`, `invalid_authtype`, `authtype_mismatch`, `auth_failure`,
`pri_zero_rcvd`, `pri_zero_sent`.

Rendering:

- `show vrrp`: columns `Name  Interface  VRID  State  Priority  Last Transition`
  (humanised seconds since `last_transition`), followed by one `DISABLED` row
  per group carrying `disable` in the last committed model — the backend keeps
  that model exactly as the firewall backend keeps its `ShowState`.
- `statistics` and `detail`: port the two Jinja templates in
  `src/op_mode/vrrp.py` verbatim, including the boolean spellings
  (`Preempt: Enabled/Disabled`, `Accept: Enabled/Disabled`,
  `Notify deleted: Deleted/Fault`).
- JSON mode (`vtyctl show -j`): the raw dump array, filtered to the named group
  when one is given, decoded through `serde_json` with `preserve_order`.

## 9. zebra-rs changes

Two small PRs (may land as one):

1. **Schema** — `zebra-rs/yang/vrrp.yang` and the iso-gated `container
   vrrp` in `config.yang` (VyOS leaves verbatim plus the three
   `[ext]` leaves from §2); presence tests next to the firewall and
   ipsec ones in `config/manager.rs` (`shipped_tree(&["iso"])`).
2. **Show grammar and routing** — the three commands in `exec.yang` under
   `if-feature feat:iso`; `is_vrrp()` in `config/manager.rs` returning `"vrrp"`
   from `show_proto()` and `"VRRP"` in the not-running fallback; a routing unit
   test like the existing `"firewall"` / `"ipsec"` ones.

`zebra.config.v1 Subscribe` already accepts any path, so no gRPC change is
needed for the `["vrrp"]` subscription.

## 10. Testing

**Unit (insomnia, CI):** golden-render tests through the `cfg(test)`
`render_str` helper, one per template branch — minimal group, unicast peers
with `hello-source-address`, VMAC with and without peers, authentication,
health-check script/ping, sync-group with members and its own check, per-group
and global garp, `no-preempt` vs `preempt-delay`, top-level `disable`, the three `[ext]`
leaves from §2, empty tree. Skip-with-warning tests for every row of the §6 rule table. Show renderers
tested against a captured `keepalived.json` fixture (checked into the test
module as a string, like the VICI samples in `ipsec.rs`).

**BDD (`bdd/tests/features/vrrp_pair.feature`, tag `@vrrp_pair`):**

```
 h1 192.0.2.100/24 ─┐
                    br ── r1 192.0.2.1/24  priority 200 ┐  VIP 192.0.2.254/24
                    └─── r2 192.0.2.2/24  priority 100 ┘  vrid 10
```

Scenarios:

1. Setup: three namespaces on one bridge; `r1`/`r2` run
   `tests/scripts/vrrp_node.sh`; apply `r2.conf` then `r1.conf` (order does not
   matter for VRRP, unlike the IPsec responder-first rule); `show vrrp` on `r1`
   eventually contains `MASTER`, on `r2` `BACKUP`; the VIP is present on `r1`'s
   interface and absent on `r2`'s.
2. Traffic: `ping from "h1" to "192.0.2.254" should eventually succeed`.
3. Failover: bring `r1`'s bridge link down; `r2` becomes `MASTER`, VIP moves,
   ping from `h1` still succeeds; link up again → `r1` preempts back.
4. Declarative unload: delete `vrrp` on `r1`; the insomnia log
   shows the unload; the VIP disappears from `r1`; `show vrrp` on `r1` reports
   no data.
5. Teardown, asserting a clean environment.

`vrrp_node.sh` follows `ipsec_node.sh`: `unshare -m`, tmpfs over `/run`
**and `/tmp`**, then start keepalived on an empty `/run/insomnia/keepalived.conf`
(`--dont-fork --use-file … --pid /run/insomnia/keepalived.pid --log-console`,
log bind-mounted to `logs/<ns>.keepalived.log`), zebra-rs with `--feature iso`,
and insomnia with `--keepalived-control signal`. The private `/run` and `/tmp`
keep each node's pid file and JSON dump apart from each other and from the
keepalived service already running on the development host; signal mode means
no node ever calls `systemctl`.

Existing steps cover almost everything (`I spawn … in namespace`, `show command
… should eventually contain`, `ping from … should eventually succeed`,
`I bring link down in namespace`, `insomnia log … should eventually contain`).
One new step is likely needed for "the command `ip -4 addr show dev …` in
namespace X should eventually contain / not contain Y".

`make -C bdd vrrp_pair` target with a comment naming the `keepalived` host
prerequisite, and `make -C bdd docs` regenerates `bdd/docs/vrrp_pair.md`.

## 11. Work breakdown

In order; each item is one PR on its own branch.

| # | Repo | Branch | Content |
|:--|:-----|:-------|:--------|
| 1 | zebra-rs | `vrrp-yang` | §9 item 1 |
| 2 | zebra-rs | `vrrp-show` | §9 item 2 |
| 3 | insomnia | `vrrp-backend` | `src/vrrp.rs` model + renderer + golden tests, apply with both control modes, `main.rs` flags, provider name, startup probes |
| 4 | insomnia | `vrrp-show` | JSON collect + the three renderers + fixture tests |
| 5 | insomnia | `vrrp-packaging` | `Recommends`, `insomnia-keepalived.service`, `RuntimeDirectory`, CHANGELOG entry |
| 6 | insomnia | `vrrp-bdd` | feature, configs, `vrrp_node.sh`, Makefile target, docs page |
| 7 | insomnia | `vrrp-docs` | book chapters (VRRP concepts, `show vrrp`), CLAUDE.md third-backend notes |

Item 3 needs the zebra-rs schema installed (or staged via
`ZEBRA_PREFIX`) only for the BDD run; its unit tests are self-contained.

## 12. Spike before item 3

Run in a scratch network namespace with a private mount namespace, never
against the host keepalived:

- keepalived started on an **empty** `--use-file` idles; a `SIGHUP` after
  adding a `vrrp_instance` starts the VRRP child; a `SIGHUP` after removing it
  withdraws the VIP and returns to idle. (Source reading says yes; confirm.)
- The JSON signal produces `/tmp/keepalived.json` in the node's private `/tmp`
  and the file is complete when it first appears (decides the wait strategy).
- `use_vmac` creates the macvlan on a veth inside a namespace and the VIP
  answers ARP through it.
- Two nodes on a Linux bridge see each other's multicast advertisements
  (224.0.0.18 is link-local and always flooded; confirm with snooping enabled).

## 13. Deferred, with reasons

- **`virtual-server` / `real-server`** — IPVS load balancing rendered into
  `virtual_server` blocks. Separate feature; needs the `ip_vs` module and its
  own show commands (`show virtual-server`). It would be its own top-level
  node: VyOS keeps it beside `vrrp` under `high-availability`, a wrapper this
  design does not have.
- **`vrrp snmp trap`** — needs `--snmp` on the unit and an agentx master; no
  SNMP story in zebra-rs yet.
- **conntrack-sync failover hook** — VyOS's `notify_*` helper on the sync group
  named by `service conntrack-sync failover-mechanism vrrp`; needs the
  conntrack-sync tree first.
- **Commit-time validation** of `member` and `interface` references — the same
  shared zebra-rs follow-up already open for firewall and IPsec references.
- **DBus instead of the JSON signal** for show — keepalived's DBus interface
  exposes state but not statistics; revisit only if the signal-and-file dance
  proves unreliable.
- **IPv6 groups in BDD** — the renderer handles them; add a second feature once
  the IPv4 pair is green.
- **FRR's `accept-mode`** — see §2: FRR itself does not implement it, and
  keepalived's `no_accept` needs nftables rules of its own.
- **FRR-style per-interface spelling** (`interface eth0` / `vrrp 5 …`) as an
  alias onto the same model — only if operators coming from FRR ask for it;
  §2 explains why it is not the primary tree.

## 14. References

- vyos-1x `current`:
  `src/conf_mode/high-availability.py`,
  `data/templates/high-availability/keepalived.conf.j2`,
  `data/templates/high-availability/10-override.conf.j2`,
  `interface-definitions/high-availability.xml.in`,
  `interface-definitions/include/vrrp/garp.xml.i`,
  `interface-definitions/include/vrrp-transition-script.xml.i`,
  `src/op_mode/vrrp.py`, `python/vyos/ifconfig/vrrp.py`,
  `src/system/keepalived-fifo.py`
- FRR (`~/frr`, master): `yang/frr-vrrpd.yang`, `vrrpd/vrrp_vty.c`,
  `vrrpd/vrrp.h` (defaults), `doc/user/vrrp.rst`
- keepalived v2.2.8: `keepalived/core/main.c`, `keepalived/vrrp/vrrp_daemon.c`,
  `keepalived/vrrp/vrrp_json.c`, `man keepalived.conf` (`json_version`,
  `notify_fifo`, `use_vmac`, `dynamic_interfaces`)
- zebra-rs: `zebra-rs/yang/ipsec.yang` (module style),
  `zebra-rs/src/config/manager.rs` (`show_proto`, `SubscribeShow`,
  `ConfigSubscribe`), `docs/design/vpn-ipsec-followups.md`
- insomnia: `src/ipsec.rs` (backend shape and defaults-in-renderer),
  `bdd/tests/scripts/ipsec_node.sh` (private mount namespace recipe)
