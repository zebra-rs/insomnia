# VRRP SNMP (`vrrp snmp`, `vrrp snmp trap`) — implementation plan

Status: plan, 2026-10-21. Covers: `vrrp snmp` (keepalived AgentX
subagent) and `vrrp snmp trap` ([vyos-gap](../vyos-gap.md) §8.1 SNMP row,
§8.4 items 4 and 6).
Priority: P3 · Effort: M · Owner: both
Depends on: none hard. Interacts with [vrrp-vrf](vrrp-vrf.md) (VRF
placement, and the restart decision function if branch B lands first) ·
Unblocks: [vrrp-virtual-server](vrrp-virtual-server.md) (soft: it adds its
"has services" trigger to `keepalived::verb`, which this plan introduces if
it lands before vrrp-vrf branch B)

## 1. Goal

- `set vrrp snmp` makes the `default` keepalived instance run as an AgentX
  subagent (`--snmp`), so an existing net-snmp master serves keepalived's
  MIBs.
- `set vrrp snmp trap` adds `enable_traps`, so state changes are sent as
  traps by that master.
- Turning either on or off **restarts** the instance (VyOS does the same);
  every other change still reloads.
- SNMP is a default-instance feature by construction; VRF instances never
  register MIBs, so two subagents never claim the same OIDs.
- The master agent is a documented host prerequisite; insomnia warns when
  it is plainly missing.

## 2. Current state

insomnia @ `ee4dfaa`:
- No SNMP: the module doc says so (`src/vrrp.rs:22`); `global_defs` emits
  `dynamic_interfaces`, `script_user root`, then the global parameters
  (`:947-959`).
- The instance `env` file is empty for `default` (`src/keepalived.rs:195-201`).
  `apply` writes it but ignores whether it changed (`:282`); the systemd
  verb depends only on (empty, conf changed) (`:290-297`): there is no
  restart path.
- The unit's `ExecStart` takes no extra options
  (`packaging/systemd/insomnia-keepalived@.service:19-23`); it already
  reads `EnvironmentFile=-/run/insomnia/vrrp/%i/env` (`:18`).
- `probe()` reads the "Config options:" line only for `JSON`
  (`src/keepalived.rs:138-150`).

zebra-rs @ `141da2fc`: no `snmp` node; `vrrp.yang` lists `vrrp snmp trap`
as deferred (`yang/vrrp.yang:41-44`). zebra-rs has no SNMP agent or
SNMP configuration anywhere (vyos-gap §8.1).

VyOS @ `7f2c893`:
- Schema: `high-availability vrrp snmp` node with valueless `trap`
  (`interface-definitions/high-availability.xml.in:15-26`).
- `--snmp` on `ExecStart` whenever `vrrp.snmp` exists
  (`data/templates/high-availability/10-override.conf.j2:2,15`);
  `enable_traps` in `global_defs` when `trap` is set
  (`keepalived.conf.j2:8-10`, right after `dynamic_interfaces`).
- `node_changed(['high-availability','vrrp','snmp'])` → `systemctl
  restart` instead of `reload-or-restart`
  (`src/conf_mode/high-availability.py:62-63`, `:230-234`).

keepalived 2.2.8 (dev host):
- Built with `SNMP_VRRP SNMP_CHECKER SNMP_RFCV2 SNMP_RFCV3`
  (`keepalived --version`); options `-x, --snmp` and `-A,
  --snmp-agent-socket=FILE` (`keepalived --help`).
- `keepalived.conf(5)`: `snmp_socket` (default `unix:/var/agentx/master`),
  `enable_snmp_vrrp`, `enable_snmp_checker`, `enable_snmp_rfc`,
  `enable_snmp_rfcv2`, `enable_snmp_rfcv3`, `enable_traps`.
- MIBs installed with the package: `KEEPALIVED-MIB` at
  enterprises.9586.100.5 (`/usr/share/snmp/mibs/KEEPALIVED-MIB.txt:160-164`),
  `VRRP-MIB` mib-2.68, `VRRPv3-MIB` mib-2.207.
- Ubuntu's `keepalived` Depends on `libsnmp40t64`; `snmpd` is not
  installed on the dev host.
- A rendered `global_defs` with `enable_traps` passes `keepalived -t`
  (rc 0).

## 3. Design

### 3.1 Schema: outside the shared grouping

A new grouping `vrrp:snmp` holding a presence container (`set vrrp snmp`
alone must be settable; zebra-rs marshals a childless presence container
as `{}`, `src/config/configs.rs:409-421`) with a `type empty` `trap` leaf.
It is used only by the top-level `container vrrp` in `config.yang`, never
by the `vrf` list of [vrrp-vrf](vrrp-vrf.md). That settles the per-VRF MIB
conflict structurally:
- Branch A (one keepalived for every VRF): one subagent already covers
  every VRF's groups.
- Branch B (one keepalived per VRF): only `default` registers. Several
  subagents registering the same subtrees on one master would collide
  (net-snmp's exact `duplicateRegistration` behaviour and whether
  keepalived can register under an AgentX context are *unverified*).
  VRF groups are therefore invisible to SNMP; documented.
- Rejected: per-VRF masters (`--snmp-agent-socket` per instance, one
  snmpd each) — operational burden for a P3 feature.

### 3.2 Rendering

- `snmp` present → instance `env` gains `KEEPALIVED_OPTIONS=--snmp`; the
  unit's `ExecStart` ends with `$KEEPALIVED_OPTIONS`. An unbraced `$VAR`
  in `ExecStart` is split into words and an empty value adds no argument
  (systemd.service(5), "Command lines"), so the `default` instance without
  SNMP keeps today's command line. Branch-B VRF env files (`LD_PRELOAD`,
  `VRF`) never carry it.
- `snmp trap` → `enable_traps` in `global_defs` after `dynamic_interfaces`
  (VyOS's position). `trap` without the subagent is meaningless but
  harmless; it cannot happen here because `trap` lives inside `snmp`.
- No `enable_snmp_*` keywords and no `snmp_socket`: VyOS exposes neither.
  Which MIBs `--snmp` alone enables is *unverified*; M3 records it.
  Rejected: driving SNMP only through `enable_snmp_*` in `global_defs`
  (no `--snmp`) — whether a reload honours those keywords is *unverified*,
  and VyOS uses `--snmp`.
- `--snmp` applies whenever the `default` instance runs — VRRP, IPVS
  ([vrrp-virtual-server](vrrp-virtual-server.md)) or both; with `vrrp
  disable` and services present the checker MIB is still served. VyOS's
  `disable` stopped everything, so there is no VyOS behaviour to match.

### 3.3 Restart, not reload

`keepalived::verb(empty, conf_changed, env_changed, snmp_changed) -> Verb`
(pure; proposed). If [vrrp-vrf](vrrp-vrf.md) branch B has landed, the
function and its env-change trigger exist and this plan adds
`snmp_changed`; otherwise this plan introduces the function with both
triggers. [vrrp-virtual-server](vrrp-virtual-server.md) may add a third
("has services ↔ none", its §3.5) to the same function.
- `snmp_changed` compares the `global_defs` lines starting with
  `enable_traps`, `enable_snmp_` or `snmp_socket` in the file on disk and
  in the new render. Derived from files, not from the in-memory model, so
  it is right across insomnia restarts (`/run/insomnia` is preserved,
  `packaging/systemd/insomnia.service:19-20`).
- `env_changed` covers the `--snmp` toggle (and, in branch B, a moved
  shim).
- Non-empty conf and (`env_changed` or `snmp_changed`) → `systemctl
  restart`; `Applied::Restarted`; log `vrrp: keepalived restarted (SNMP
  settings changed)`.
- Signal mode cannot restart a process it does not own: SIGHUP as usual
  and warn `vrrp: SNMP settings changed; restart keepalived for instance
  default to apply them`.
- Consequence (same as VyOS, documented): a restart withdraws the VIPs, so
  toggling SNMP on the master fails the group over to the backup and back
  (if preempting).

### 3.4 The master agent: a host prerequisite

Decision: document, do not manage. zebra-rs has no SNMP story, and running
snmpd is a host-management concern (communities, views, users) that
neither zebra-rs nor insomnia models.
- Book: install `snmpd`; `snmpd.conf` needs `master agentx` (and the
  default `agentXSocket unix:/var/agentx/master`); for traps,
  `trap2sink`/`trapsink`/`informsink` lines; a sample `snmpwalk` against
  enterprises.9586.100.5.
- `Cargo.toml` `[package.metadata.deb] suggests` gains `snmpd`.
- Warnings (insomnia, when `vrrp snmp` is configured):
  - the startup probe found no `SNMP_VRRP` in keepalived's "Config
    options" → `keepalived was built without SNMP; vrrp snmp has no effect`;
  - `/var/agentx/master` does not exist → `no AgentX master socket at
    /var/agentx/master; run snmpd with "master agentx"`. keepalived keeps
    running either way; whether and how often it retries the master is
    *unverified* (M3).

### 3.5 Deviations to record

In the `src/vrrp.rs` module doc and `design/vrrp.md` §6: SNMP default
instance only; `--snmp` through the env file; `--snmp` stays on under
`vrrp disable` when IPVS runs; the signal-mode restart warning. Remove
"no `enable_traps` / SNMP" from the deviation list.

## 4. Changes

### zebra-rs

`yang/vrrp.yang`:

```yang
grouping snmp {
  container snmp {
    ext:help "Enable SNMP (keepalived AgentX subagent)";
    presence "Run keepalived as an AgentX subagent of the host's SNMP master";
    leaf trap {
      ext:help "Enable SNMP traps";
      type empty;
    }
  }
}
```

`yang/config.yang` (`:5705-5709`): `uses "vrrp:snmp";` inside `container
vrrp`, next to `uses "vrrp:vrrp";` (not inside any `vrf` list). Module
description: drop `vrrp snmp trap` from the deferred list.

Tests (`src/config/manager.rs`): `shipped_vrrp_gated_on_insomnia`
(`:7949`) asserts the `snmp` branch; `vrrp_commands_parse_only_with_insomnia`
(`:7975`) adds `set vrrp snmp`, `set vrrp snmp trap`, and (once
[vrrp-vrf](vrrp-vrf.md) lands) the negative `set vrrp vrf red snmp`;
`vrrp_json_marshal_contract` (`:8112`) pins `"snmp":{}` and
`"snmp":{"trap":null}`.

### insomnia

- `src/vrrp.rs`: `VrrpConfig.snmp: Option<Snmp>`, `Snmp { #[serde(deserialize_with
  = "de_presence")] trap: bool }`; `render` emits `enable_traps`;
  `process` passes `options = ["--snmp"]` for `default` when `snmp` is
  set.
- `src/keepalived.rs`: `env_for(name, options: &[&str])` writes
  `KEEPALIVED_OPTIONS=<joined>` when non-empty; `snmp_keywords(conf) ->
  Vec<&str>`; `verb` (§3.3); `Applied::Restarted`; `probe` keeps the
  parsed "Config options" set (`features: BTreeSet<String>`) for the
  `SNMP_VRRP` check.
- `packaging/systemd/insomnia-keepalived@.service`: append
  `$KEEPALIVED_OPTIONS` to `ExecStart`; update the env-file comment
  (`:16-17`).
- `bdd/tests/scripts/vrrp_node.sh`: reads `$KEEPALIVED_OPTIONS` from the
  environment when it starts keepalived (used by the optional feature).
- `Cargo.toml`: `suggests = "zebra-rs, snmpd"`.

Worked example. Config:

```
set vrrp snmp trap
set vrrp group LAN interface eth0
set vrrp group LAN vrid 10
set vrrp group LAN address 192.0.2.254/24
```

`/run/insomnia/vrrp/default/keepalived.conf` starts:

```
global_defs {
    dynamic_interfaces
    enable_traps
    script_user root
}
```

`/run/insomnia/vrrp/default/env`:

```
KEEPALIVED_OPTIONS=--snmp
```

First commit with `snmp` (instance already running): `systemctl restart
insomnia-keepalived@default.service`, log `vrrp: keepalived restarted
(SNMP settings changed)`. A later `set vrrp group LAN priority 150`:
`reload-or-restart` as today. `delete vrrp snmp trap`: `enable_traps`
leaves the file → restart. `delete vrrp snmp`: env becomes empty →
restart.

## 5. Tests

Unit (CI):
- `snmp_render`: golden `global_defs` with and without `trap`; `snmp`
  alone adds nothing to the file.
- `snmp_keywords_extract`: only `global_defs` lines count; an
  `enable_traps` string elsewhere (a `# description` comment) does not.
- `verb_table`: every (empty, conf_changed, env_changed, snmp_changed)
  combination for both control modes, including "only env changed" →
  restart.
- `env_for_options`: `default` with and without `--snmp`; branch-B VRF
  names never get options.
- `unit_file_passes_options`: `include_str!` of the template unit
  contains `$KEEPALIVED_OPTIONS` on the `ExecStart` line.
- `probe_features`: the dev host's "Config options" line parses into the
  set; a line without `SNMP_VRRP` produces the warning.

BDD (optional, `@vrrp_snmp`, needs `snmpd` and `snmp` client tools on the
host; Makefile comment says so; not part of §9's required set). The
`vrrp_pair` topology; `vrrp_node.sh` with `VRRP_NODE_SNMP=1` mounts a
tmpfs over `/var/agentx` (exists once `snmpd` is installed) inside the
node's private mount namespace, starts `snmpd -f -Lo -C -c <generated
conf: master agentx, rocommunity public 127.0.0.1, trap2sink 127.0.0.1>`
and `snmptrapd -f -On -Lf /tmp/$NS.traps` (generated conf:
`disableAuthorization yes`), and starts keepalived with
`KEEPALIVED_OPTIONS=--snmp` (signal mode cannot restart, so the option is
given at start).
1. Setup: both routers elect.
2. `command "snmpwalk -v2c -c public 127.0.0.1 1.3.6.1.4.1.9586.100.5.2"`
   in r1 eventually contains `LAN`.
3. `set vrrp snmp trap` on r1; insomnia log contains the signal-mode
   restart warning; restart r1's keepalived via the node script helper;
   bring r1's link down and up; `/tmp/<ns>.traps` eventually contains
   `.1.3.6.1.4.1.9586.100.5`.
4. Teardown (snmpd, snmptrapd, keepalived, insomnia stopped; trap log
   removed).

## 6. Docs

- `book/src/ch-05-04-keepalived-and-insomnia.md`: new "SNMP" section
  (what `snmp` and `trap` do, restart-and-failover warning, default
  instance only, snmpd prerequisite and sample config, MIB names and
  OIDs).
- `book/src/ch-00-01-install.md`: `snmpd` as an optional package.
- `src/vrrp.rs` module doc and `design/vrrp.md` §6/§14: §3.5; the §14
  SNMP item (split by [docs-corrections](docs-corrections.md)) is removed.
- `book/src/ch-04-00-bdd-tests.md`: `@vrrp_snmp` and its prerequisites.

## 7. Milestones

| # | Scope | Repo | Effort | Done when |
|:--|:--|:--|:--|:--|
| M1 | `vrrp:snmp` grouping, `config.yang`, manager tests | zebra-rs | S | tests green; `set vrrp vrf red snmp` rejected once the VRF list exists |
| M2 | Model, `enable_traps`, env options, unit `ExecStart`, `verb` + restart, probe features, warnings, unit tests | insomnia | S | CI green; golden for `global_defs` updated deliberately (commit says why) |
| M3 | Manual check on a host with snmpd: which MIBs `--snmp` registers, trap delivery, behaviour without a master; results into §3.2/§3.4 and the book | insomnia | S | findings recorded, *unverified* marks resolved |
| M4 | Optional `@vrrp_snmp` feature + node-script support | insomnia | S | green on a host with snmpd |
| M5 | Book, module doc, `design/vrrp.md` | insomnia | S | book builds |

## 8. Risks and open questions

- A toggle restarts keepalived and fails the master over; operators must
  know. No way around it if `--snmp` is a command-line option.
- MIB set enabled by `--snmp` alone (*unverified*): if it is only the
  KEEPALIVED-MIB VRRP branch, the RFC MIBs need `enable_snmp_rfcv2` /
  `enable_snmp_rfcv3` — a schema extension VyOS does not have; decide
  after M3, not before.
- Branch-B VRF groups are invisible to SNMP. If that matters, the
  follow-up is a single subagent (one keepalived) — which is branch A of
  [vrrp-vrf](vrrp-vrf.md), not a change here.
- AgentX socket permissions/AppArmor on the target distribution
  (*unverified*); keepalived runs as root, which normally suffices.
- A keepalived build without SNMP still starts with `--snmp`? (*unverified*;
  if it refuses, the probe warning becomes "not passed" and insomnia
  omits the option.)

## 9. Acceptance criteria

- [ ] `set vrrp snmp [trap]` parses with `--feature insomnia`, only at top level.
- [ ] `--snmp` reaches the `default` instance through the env file and `$KEEPALIVED_OPTIONS`; VRF instances never get it.
- [ ] `trap` renders `enable_traps` in VyOS's position.
- [ ] Any SNMP change restarts (systemd) or warns (signal); all other changes reload as before.
- [ ] Missing SNMP build support or AgentX master socket is warned.
- [ ] Book documents the prerequisite, the failover-on-toggle, and the default-only scope.
