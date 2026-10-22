# IPVS `virtual-server` — implementation plan

Status: plan, 2026-10-21. Covers: `virtual-server` / `real-server`
([vyos-gap](../vyos-gap.md) §8.2, §8.1 row, §8.3 `show virtual-server`).
Assumes D8 (top-level `virtual-server`, rendered into the VRRP keepalived
instance) and D3 (multi-path subscribe).
Priority: P3 · Effort: M · Owner: both
Depends on: [multi-path-subscribe](multi-path-subscribe.md) (hard);
[vrrp-hardening](vrrp-hardening.md) M2 (`host_findings`, soft);
[commit-validation](commit-validation.md) C1 (`Findings`, soft);
[fw-packet-modification](fw-packet-modification.md) or [pbr](pbr.md)
(only to retire the fwmark warning); [vrrp-vrf](vrrp-vrf.md) (soft: the
default-instance-only rule, and branch B's `keepalived::verb`) or
[vrrp-snmp](vrrp-snmp.md) (soft: the same function, if it lands first) ·
Unblocks: none

## 1. Goal

- `set virtual-server WEB address 198.51.100.10 port 80 …` with
  `real-server` entries load-balances TCP or UDP through IPVS, in NAT,
  direct-routing or tunnel mode, with TCP/UDP or script health checks —
  every VyOS leaf, ported by dropping the `high-availability` prefix.
- The services live in the same keepalived instance as VRRP (so a VRRP
  VIP can front them, as on VyOS); `vrrp disable` stops VRRP only.
- `show virtual-server` lists services and real servers (text and JSON).
- Every VyOS `verify()` rule holds per virtual server — including the
  real-server port rule VyOS applies only to the last one.
- `fwmark` services render and warn until zebra-rs can set marks.

## 2. Current state

insomnia @ `ee4dfaa`:
- No IPVS anywhere; the module doc lists "no `virtual_server` (IPVS)
  blocks" as a deviation (`src/vrrp.rs:22-23`).
- One subscription, `["vrrp"]` (`src/vrrp.rs:50`, `src/subscribe.rs:11-27`
  takes one path). `render` ends after `vrrp_sync_group`
  (`src/vrrp.rs:1044-1067`). `VrrpConfig::is_empty` = `disable` or no
  groups/sync groups (`:144-146`); empty render → `apply` stops the
  instance (`src/keepalived.rs:290-297`).
- `show vrrp` always signals keepalived and waits up to 3 s for the JSON
  dump (`src/keepalived.rs:326-352`); keepalived's dump covers VRRP only.
- The provider registers `firewall`, `ipsec`, `vrrp` (`src/provider.rs:17-27`)
  and routes by prefix (`:91-100`).

zebra-rs @ `141da2fc`: no `virtual-server` node (`yang/vrrp.yang:31-44`
lists it as deferred). `Subscribe` JSON for a path is `subtree_json`
(`src/config/manager.rs:652-663`); for a **list** node `Config::json`
emits a bare array (`src/config/configs.rs:425-437`), and an absent path
is `"{}"`.

VyOS @ `7f2c893`:
- Schema `interface-definitions/high-availability.xml.in:427-610`:
  `virtual-server <alias>` with `address` (ipv4|ipv6), `algorithm`
  (7 values, default `least-connection`), `delay-loop` (1-3600, default
  10), `forward-method` (`direct|nat|tunnel`, default `nat`), `fwmark`
  (1-2147483647), `port` (0-65535), `persistence-timeout` (0-86400,
  default 300), `protocol` (`tcp|udp`, default `tcp`), `real-server <ip>`
  with `port`, `connection-timeout` (1-86400), `health-check script`.
- Template `data/templates/high-availability/keepalived.conf.j2:199-254`:
  after the sync groups, `# Virtual-server configuration`, `# Vserver
  <alias>`, `virtual_server <addr> <port>` or `virtual_server fwmark N`,
  `delay_loop`, `lb_algo rr|wrr|lc|wlc|sh|dh|lblc`, `lb_kind NAT|DR|TUN`,
  `persistence_timeout` when > 0, `protocol TCP|UDP`, then per real server
  `real_server <ip> <port> { weight 1  MISC_CHECK { misc_path … } |
  TCP_CHECK/UDP_CHECK { [connect_timeout N] } }`.
- `verify()` (`src/conf_mode/high-availability.py:157-174`): address or
  fwmark; port or fwmark; not both; at least one real server; each real
  server has a port. **Bug:** the real-server loop (`:172-174`) is dedented
  out of the per-virtual-server loop, so only the last virtual server's
  real servers are checked (and a last one without real servers raises
  `KeyError`).
- `show virtual-server`: `Virtual server not configured!` or `sudo
  ipvsadm --list --numeric` (`src/op_mode/show_virtual_server.py`).
- `high-availability disable` stops keepalived, VRRP and IPVS together.

keepalived 2.2.8 (dev host, `keepalived -t`, run as non-root on scratch
files under the session scratchpad):
- An address/port service with an empty `TCP_CHECK { }` and a quoted
  `misc_path "/usr/local/bin/check 10.0.0.12"` parses clean (rc 0).
- VyOS's fwmark shape (`protocol` line + `real_server <ip> <port>`)
  returns rc 5 with "protocol specified for fwmark - protocol will be
  ignored" and "real server … has port specified - clearing". Omitting
  `protocol` and moving the port to `connect_port` in the check parses
  clean (rc 0).
- Debian/Ubuntu `keepalived` Recommends `ipvsadm`; `ip_vs` ships as a
  module on the dev kernel (`modinfo ip_vs`).

## 3. Design

### 3.1 Placement and lifecycle (D8)

- Top-level insomnia-gated `list virtual-server`, leaves verbatim, the same
  hoisting rule as `vrrp` (`design/vrrp.md` placement decision). Rejected:
  `load-balancing virtual-server` (VyOS's `load-balancing` holds haproxy
  and WAN-LB, so it would not port verbatim either).
- Rendered into the `default` keepalived instance file, after the sync
  groups, as VyOS does. Rejected: a second, checker-only keepalived
  (`--check`, its own unit and directory) — more packaging, and it splits
  what VyOS keeps in one process.
- Default VRF only: IPVS state is per network namespace, not per VRF; with
  [vrrp-vrf](vrrp-vrf.md) branch B, VRF instances never carry
  `virtual_server` blocks.

### 3.2 Two subtrees, one file

Uses [multi-path-subscribe](multi-path-subscribe.md)'s API, not a local
one: the vrrp task's single stream becomes
`subscribe::subscribe_json_multi(&host, &[&["vrrp"], &["virtual-server"]],
Fallback::PrimaryOnly)` (the consumer row that plan already lists; D-10:
one stream per backend, so any later VRRP path is appended to the same
list). One snapshot covers both trees; one `MultiUpdate` per commit
touching either, with every part present. `virtual-server` is a list root,
whose present form is a bare JSON array (`configs.rs:425-437`) and absent
form `"{}"`; each part is parsed with that plan's `json::parse_subtree`
(`parse_subtree::<Vec<VirtualServer>>` maps `"{}"` to an empty `Vec`).

insomnia keeps the last model of both trees and re-renders the whole file
on every update; `keepalived::apply` compares before reloading, so an
update that changes neither rendering reloads nothing. With
`PrimaryOnly` against a zebra-rs without `SubscribeMulti`, the
`virtual-server` part is always `"{}"`: VRRP works as today, services are
not rendered, and the subscription logs its one warning per connection.

Emptiness: `vrrp_active` = not `vrrp disable` and some group or sync group;
`ipvs_active` = some virtual server renders. The file is empty (instance
stopped) only when neither is active. `vrrp disable` drops the VRRP
blocks and keeps the services (deviation: VyOS's `high-availability
disable` stopped both; zebra-rs has no wrapper, and deleting
`virtual-server` is the IPVS switch). `global_defs` is emitted whenever the
file is non-empty.

`show vrrp` when `vrrp_active` is false answers the not-running text
immediately instead of signalling a keepalived that may have no VRRP child
(avoids the 3 s timeout).

### 3.3 Rendering

Defaults filled by the renderer (VyOS schema defaults): `algorithm
least-connection`, `delay-loop 10`, `forward-method nat`,
`persistence-timeout 300`, `protocol tcp`. `weight 1` is fixed, as in VyOS.

| Config | keepalived |
|:--|:--|
| (first service) | `# Virtual-server configuration` |
| `virtual-server <name>` | `# Vserver <name>` then the block |
| `address A` + `port P` | `virtual_server A P {` |
| `fwmark N` | `virtual_server fwmark N {` (address ignored, warning if set) |
| `delay-loop` | `delay_loop N` |
| `algorithm` | `lb_algo rr\|wrr\|lc\|wlc\|sh\|dh\|lblc` |
| `forward-method` | `lb_kind NAT\|DR\|TUN` |
| `persistence-timeout` | `persistence_timeout N` when N > 0 |
| `protocol` | `protocol TCP\|UDP` — **omitted for fwmark** (deviation) |
| `real-server R port P` | `real_server R P {` — fwmark: `real_server R {` with `connect_port P` in the check (deviation) |
| (always) | `weight 1` |
| `health-check script S` | `MISC_CHECK { misc_path "S" }` (quoted; VyOS leaves it bare) |
| otherwise | `TCP_CHECK {` / `UDP_CHECK {` by protocol, `[connect_port P]`, `[connect_timeout N]`, `}` |

Spacing follows insomnia's renderer (a blank line between top-level
blocks, `src/vrrp.rs:331-334`), not the Jinja output's; cosmetic.

Checks: the file always stays valid. Findings go through
[commit-validation](commit-validation.md)'s `Findings` once its C1 lands
(Error + `Skipped("virtual server")` / `Dropped("real server")`; the
fwmark row is Warning + `Kept`), so layer 2 refuses a commit the
renderer would skip:

| Rule | Source | Action |
|:--|:--|:--|
| address or fwmark | VyOS | skip VS |
| port or fwmark | VyOS | skip VS |
| not both port and fwmark | VyOS | skip VS |
| ≥ 1 real server | VyOS | skip VS |
| each real server has a port | VyOS, **checked per VS** (bug fixed) | drop that RS; VS with none left skipped |
| name is a plain token | insomnia (`safe_name`, it lands in a comment) | skip VS |
| duplicate (address, port, protocol) or fwmark | insomnia (keepalived would merge or reject; *unverified*) | skip the later VS |
| RS family ≠ VS address family (address services) | insomnia (IPVS NAT/DR need one family) | drop RS |
| health-check script not quotable | insomnia (`quotable`) | drop RS check → TCP/UDP check, warning |
| fwmark service | insomnia | render, warn: `virtual-server MARK: fwmark 7 is rendered, but no zebra-rs config sets packet marks yet (see fw-packet-modification / pbr); traffic must be marked outside zebra-rs` |

Real-server health-check scripts also go through the host-dependent
pass of [vrrp-hardening](vrrp-hardening.md) §3.1 (`host_findings` gains
the virtual-server slots; never inside `render()`).

When a mark source exists ([fw-packet-modification](fw-packet-modification.md)
`set mark` or [pbr](pbr.md)), the warning is reworded to a book note; it is
not made conditional on the firewall model (that would need a third
subtree for one warning). IPVS matches `skb->mark` exactly; the bit-31
fragment mark of [nft-common](nft-common.md) (X10) is cleared by its
`filter + 10` unmark chains; that this runs before IPVS's LOCAL_IN hook
for packets to a local VIP is *unverified* (M1 can check with a
fragmented UDP probe).

### 3.4 `show virtual-server`

Decision: parse `/proc/net/ip_vs` for both text and JSON.
- JSON needs a parser either way; the kernel's fixed hex format
  (`ip_vs_info_seq_show`, `net/netfilter/ipvs/ip_vs_ctl.c`) is a better
  input than ipvsadm's human text.
- One source keeps text and JSON consistent; no subprocess; correct per
  network namespace (BDD); works on hosts installed without Recommends.
- Rejected: `ipvsadm -Ln` (VyOS-verbatim text, but text-only and an extra
  dependency at runtime); IPVS generic netlink (needs a netlink client
  insomnia does not have).
- Deviation: the text is produced by insomnia in the `ipvsadm -Ln` layout
  rather than by running ipvsadm. The layout is copied from ipvsadm 1.31
  output captured in M1.

Answers:
- no virtual server in the retained model → `Virtual server not configured!`
  (VyOS string);
- configured but `/proc/net/ip_vs` absent → `% IPVS is not loaded (no
  /proc/net/ip_vs)`;
- JSON: `[{"name": "WEB", "protocol": "TCP", "address": "198.51.100.10",
  "port": 80, "fwmark": null, "scheduler": "rr", "persistent": null,
  "real-server": [{"address": "10.0.1.11", "port": 8080, "forward": "Masq",
  "weight": 1, "active": 0, "inactive": 0}]}]` — `name` matched back from
  the model (null when the kernel has a service insomnia did not render).

zebra-rs: `show virtual-server` (presence container, insomnia-gated);
`SHOW_PROTOS` entry `(is_virtual_server, "virtual-server", "Virtual
server")` (`manager.rs:2078-2092`). insomnia registers the provider name
`virtual-server` and routes `/show/virtual-server` to the vrrp task, which
owns the model. A separate name (rather than reusing `vrrp`) keeps the
not-running message right and lets another daemon serve it later.

### 3.5 Kernel and runtime

- `ip_vs`: whether keepalived's checker loads it itself is *unverified*;
  M1 checks. Fallback: insomnia runs `modprobe ip_vs` before `apply` when a
  service is configured and `/proc/net/ip_vs` is missing (warn on failure).
  Scheduler modules (`ip_vs_rr`, …) are autoloaded by the kernel on
  service add.
- Reload: whether a `SIGHUP` that adds the first `virtual_server` starts
  the checker child (and one that removes the last stops it) is
  *unverified*; M1 checks. If not, the transition "has services ↔ none"
  joins the restart triggers in `keepalived::verb` (introduced by
  [vrrp-vrf](vrrp-vrf.md) branch B or [vrrp-snmp](vrrp-snmp.md),
  whichever lands first; this plan adds the trigger, and introduces the
  function itself only if neither has landed).
- `restart vrrp` ([vrrp-hardening](vrrp-hardening.md) M6) restarts IPVS
  checking too (one process), as VyOS.
- NAT mode forwards replies from the real servers through this host:
  forwarding must be on, and a stateful firewall in the forward hook may
  treat IPVS replies as untracked (`net.ipv4.vs.conntrack` defaults to 0;
  exact interaction *unverified*). Documented, not managed: the sysctl
  would belong to the [fw-global-options](fw-global-options.md) writer if
  ever exposed.

### 3.6 Deviations to record in the module doc

`vrrp disable` keeps IPVS; fwmark services omit `protocol` and carry the
real-server port as `connect_port`; `misc_path` quoted; real-server port
rule per service; family and duplicate checks; show text produced from
`/proc/net/ip_vs`; spacing. Remove "no `virtual_server` blocks" from the
`src/vrrp.rs` deviation list.

## 4. Changes

### zebra-rs

New `yang/virtual-server.yang` (grouping library, prefix `vs`):

```yang
grouping virtual-server-entry {
  leaf name { ext:help "Load-balancing virtual server alias"; type string; }
  leaf address { ext:help "Virtual server address"; type union { type inet:ipv4-address; type inet:ipv6-address; } }
  leaf algorithm { ext:help "Schedule algorithm (VyOS default: least-connection)";
    type enumeration { enum round-robin; enum weighted-round-robin; enum least-connection;
      enum weighted-least-connection; enum source-hashing; enum destination-hashing;
      enum locality-based-least-connection; } }
  leaf delay-loop { ext:help "Interval between health checks, seconds (VyOS default: 10)"; type uint32 { range "1..3600"; } }
  leaf forward-method { ext:help "Forwarding method (VyOS default: nat)"; type enumeration { enum direct; enum nat; enum tunnel; } }
  leaf fwmark { ext:help "Firewall mark of the service"; type uint32 { range "1..2147483647"; } }
  leaf port { ext:help "Virtual server port"; type uint16; }
  leaf persistence-timeout { ext:help "Persistence timeout, 0 disables (VyOS default: 300)"; type uint32 { range "0..86400"; } }
  leaf protocol { ext:help "Protocol for port checks (VyOS default: tcp)"; type enumeration { enum tcp; enum udp; } }
  list real-server {
    ext:help "Real server address";
    key "address";
    leaf address { ext:help "Real server address"; type union { type inet:ipv4-address; type inet:ipv6-address; } }
    leaf port { ext:help "Real server port"; mandatory true; type uint16; }
    leaf connection-timeout { ext:help "Server connection timeout, seconds"; type uint32 { range "1..86400"; } }
    container health-check { ext:help "Health check script";
      leaf script { ext:help "Health check script file"; type string; } }
  }
}
```

A new module may use plain `mandatory` from day one
([commit-validation](commit-validation.md) §3.3); only the real-server
`port` qualifies (the other VyOS requirements are either-or rules, which
stay render-time findings and layer 2). The renderer keeps its own check
as defence.

`config.yang`: `import virtual-server { prefix vs; }` and, next to
`container vrrp` (`:5705-5709`):

```yang
list virtual-server {
  if-feature feat:insomnia;
  ext:help "Load-balancing virtual server (IPVS)";
  key "name";
  uses "vs:virtual-server-entry";
}
```

`exec.yang`, under `show`: `container virtual-server { if-feature
feat:insomnia; ext:help "IPVS virtual servers"; presence "IPVS virtual
server table"; }`. `manager.rs`: `is_virtual_server` + the `SHOW_PROTOS`
row.

Tests (`manager.rs`): `shipped_virtual_server_gated_on_insomnia`;
`virtual_server_commands_parse_only_with_insomnia` (negatives: `fwmark 0`,
`port 70000`, `delay-loop 0`, `algorithm fastest`, `persistence-timeout
86401`); `virtual_server_json_marshal_contract` pinning the bare-array
document; `show_virtual_server_routes_to_provider`.

### insomnia

- New `src/ipvs.rs` (proposed): `VirtualServer`, `RealServer`,
  `RsHealthCheck` serde models (`Flex` everywhere, `kebab-case`);
  `pub fn render(vs: &[VirtualServer]) -> (String, Vec<String>)`;
  `fn parse_proc(text) -> Vec<Service>`; `fn show_text(&[Service])`,
  `fn show_json(&[Service], &[VirtualServer])`.
- `src/vrrp.rs`: task subscribes via the multi-path API; `ShowState` gains
  `vs: Vec<VirtualServer>`; `process` re-renders from both models;
  `render(cfg, vs)` appends `ipvs::render` after the sync groups and emits
  `global_defs` when either is active ([conntrack-sync](conntrack-sync.md)
  adds a `&VrrpHooks` parameter to the same function, its §3.5; whichever
  lands second takes both); `vrrp_active()` replaces the
  emptiness use of `is_empty()`; `process_show` gains
  `/show/virtual-server` and the `show vrrp` short-circuit.
  `#[cfg(test)] render_vs_str(vrrp_json, vs_json)`.
- `src/provider.rs`: register `virtual-server`; route
  `/show/virtual-server` to the vrrp task.
- `src/vrrp.rs` `host_findings`: real-server script slots.
- `Cargo.toml`: `suggests` gains `ipvsadm` (operator tool, not used by
  insomnia); extended description mentions `show virtual-server`.

Worked example. Config:

```
set vrrp group FRONT interface eth0
set vrrp group FRONT vrid 20
set vrrp group FRONT address 198.51.100.10/24
set virtual-server WEB address 198.51.100.10
set virtual-server WEB port 80
set virtual-server WEB algorithm round-robin
set virtual-server WEB real-server 10.0.1.11 port 8080
set virtual-server WEB real-server 10.0.2.12 port 8080
set virtual-server WEB real-server 10.0.2.12 connection-timeout 3
set virtual-server DNS fwmark 7
set virtual-server DNS protocol udp
set virtual-server DNS forward-method direct
set virtual-server DNS real-server 10.0.1.11 port 53
set virtual-server BAD address 198.51.100.11
set virtual-server BAD port 443
```

Rendered tail of `/run/insomnia/vrrp/default/keepalived.conf` (after
`vrrp_instance FRONT { … }`):

```
# Virtual-server configuration
# Vserver DNS
virtual_server fwmark 7 {
    delay_loop 10
    lb_algo lc
    lb_kind DR
    persistence_timeout 300
    real_server 10.0.1.11 {
        weight 1
        UDP_CHECK {
            connect_port 53
        }
    }
}

# Vserver WEB
virtual_server 198.51.100.10 80 {
    delay_loop 10
    lb_algo rr
    lb_kind NAT
    persistence_timeout 300
    protocol TCP
    real_server 10.0.1.11 8080 {
        weight 1
        TCP_CHECK {
        }
    }
    real_server 10.0.2.12 8080 {
        weight 1
        TCP_CHECK {
            connect_timeout 3
        }
    }
}
```

`BAD` emits nothing. Services and real servers come in key order, as
zebra-rs marshals keyed lists. The full file (with `FRONT` on a real host
interface) passes `keepalived -t` 2.2.8 with rc 0 and no messages. Warnings:

```
virtual-server BAD: real-server ip is required but not set; skipped
virtual-server DNS: fwmark 7 is rendered, but no zebra-rs config sets packet marks yet (see fw-packet-modification / pbr); traffic must be marked outside zebra-rs
```

`show virtual-server` (text, layout per §3.4; illustrative until M1's
fixtures pin the exact columns):

```
IP Virtual Server version 1.2.1 (size=4096)
Prot LocalAddress:Port Scheduler Flags
  -> RemoteAddress:Port           Forward Weight ActiveConn InActConn
TCP  198.51.100.10:80 rr persistent 300
  -> 10.0.1.11:8080               Masq    1      0          0
  -> 10.0.2.12:8080               Masq    1      0          0
FWM  7 lc persistent 300
  -> 10.0.1.11:0                  Route   1      0          0
```

## 5. Tests

Unit (CI):
- `vs_golden_render`: the worked example; plus `vrrp disable` + services
  (no `vrrp_instance`, services kept); services only (global_defs +
  services); neither (empty string).
- `vs_verify_rules`: each §3.3 row, including **two** virtual servers where
  only the first has a real server without a port — the first is fixed up
  (RS dropped), not ignored as in VyOS; and a last VS with no real
  servers (VyOS `KeyError`) → clean skip.
- `vs_defaults`: every default materialised; `persistence-timeout 0`
  omits the line; each algorithm and forward method mapped.
- `vs_parts_parse`: `MultiUpdate` fixtures whose `virtual-server` part is
  `[]`, `[{…}]` and `"{}"` (PrimaryOnly) all render as expected; parsing
  itself is `parse_subtree`'s, tested in that plan.
- `proc_ip_vs_parse`: fixtures captured in M1 (IPv4, IPv6, fwmark,
  persistent, empty table) → text matches ipvsadm's captured `-Ln` output
  for the same state; JSON shape; name matching.
- Existing VRRP goldens unchanged.

BDD `@vs_nat` (`bdd/tests/features/vs_nat.feature`, configs in
`bdd/tests/configs/vs_nat/`), host prerequisites `keepalived` and a
loadable `ip_vs` (Makefile comment):

```
 c1 198.51.100.100/24 ── br fr ── lb vlbns 198.51.100.1/24, VIP 198.51.100.10 (vrrp FRONT, sole router)
 lb to-rs1 10.0.1.1/24 ─── rs1 to-lb 10.0.1.11/24 (default via 10.0.1.1), HTTP :8080 answering "rs1"
 lb to-rs2 10.0.2.1/24 ─── rs2 to-lb 10.0.2.12/24 (default via 10.0.2.1), HTTP :8080 answering "rs2"
```

lb runs `vrrp_node.sh vs_nat_lb`; rs1/rs2 run a new
`tests/scripts/http_node.sh <ns> <text>` (`python3 -m http.server 8080
--directory /tmp/<ns>.www`, pid in `/tmp/<ns>.http.pid`) with
`http_node_stop.sh`. The back links use `I connect namespace … interface …`,
addresses and routes the existing steps; `I execute "sysctl -w
net.ipv4.ip_forward=1" in namespace "lb"`. Config: `algorithm
round-robin`, `persistence-timeout 0`, `delay-loop 2`, `connection-timeout 1`.

1. Setup: `show vrrp` on lb contains `MASTER`; `show virtual-server`
   eventually contains `10.0.1.11:8080` and `10.0.2.12:8080`.
2. Balancing: `command "curl -s --max-time 2 http://198.51.100.10/" in
   namespace "c1"` eventually contains `rs1`, and eventually `rs2`.
3. Health check: stop rs2's listener → `show virtual-server` eventually
   not contains `10.0.2.12:8080`; restart it → back.
4. `vrrp disable` keeps IPVS: VIP leaves `vlbns`, `show virtual-server`
   still lists both real servers; `delete vrrp disable` restores the VIP.
5. Declarative unload: `delete virtual-server` → `show virtual-server`
   contains `Virtual server not configured!`; `command "cat
   /proc/net/ip_vs" in namespace "lb"` eventually not contains `->`.
6. Teardown, clean environment.

## 6. Docs

- New `book/src/ch-05-06-virtual-server.md` (concepts, NAT/DR/TUN
  requirements, health checks, the fwmark caveat, forwarding and
  firewall note) and a `show virtual-server` section in
  `book/src/ch-03-02-show-vrrp.md` (or a new chapter; numbers are allocated in [README](README.md)); `SUMMARY.md`.
- `book/src/ch-05-04-keepalived-and-insomnia.md`: one keepalived for VRRP
  and IPVS; `vrrp disable` semantics; deviations.
- `book/src/ch-04-00-bdd-tests.md`: `@vs_nat`.
- `design/vrrp.md` §14: remove the `virtual-server` item; `vrrp.yang`
  description: drop it from the deferred list.
- `src/vrrp.rs` / `src/ipvs.rs` module docs: §3.6.

## 7. Milestones

| # | Scope | Repo | Effort | Done when |
|:--|:--|:--|:--|:--|
| M1 | Spike in a scratch netns: `ip_vs` autoload by keepalived; checker child start/stop on SIGHUP; capture `/proc/net/ip_vs` + `ipvsadm -Ln` fixtures (v4, v6, fwmark, persistent) | insomnia | S | findings in this plan's §3.5 and fixtures in the test module |
| M2 | `virtual-server.yang`, config/exec grammar, `SHOW_PROTOS`, tests | zebra-rs | S | manager tests green |
| M3 | `src/ipvs.rs` model + renderer + checks; `render` integration with `vrrp_active`; goldens | insomnia | M | unit tests green (single-path stub for the second tree until M4) |
| M4 | `subscribe_json_multi` (PrimaryOnly) in the vrrp task, `parse_subtree` per part; restart trigger if M1 requires it | insomnia | S | snapshot of both trees renders once; reconnect resyncs; old zebra-rs keeps VRRP working |
| M5 | `show virtual-server` text/JSON, provider name, `show vrrp` short-circuit | insomnia | S | fixture tests green |
| M6 | `@vs_nat`, `http_node.sh`, Makefile target, docs page | insomnia | M | green locally |
| M7 | Book, module docs, `design/vrrp.md` §14 | insomnia | S | book builds |

M4 waits for [multi-path-subscribe](multi-path-subscribe.md); M2/M3 do not.

## 8. Risks and open questions

- No two-stream fallback: [multi-path-subscribe](multi-path-subscribe.md)
  rejects merging single-path streams, and here a VRRP snapshot rendered
  before the services' would reload away live IPVS services. If that plan
  slips, M4 waits; M2/M3/M5 do not.
- keepalived behaviour for duplicate service keys, `ip_vs` loading and
  checker-child reload is *unverified* (M1).
- `/proc/net/ip_vs` format details (IPv6 bracket form, fwmark and
  persistence suffixes) are *unverified* until M1's fixtures; the parser
  is fixture-driven.
- IPVS + nft conntrack in NAT mode (§3.5) is *unverified*; the BDD runs
  with no firewall rules. A follow-up BDD with `firewall` forward rules
  would settle it.
- VyOS users more often reach for `load-balancing haproxy`; this feature
  stays P3 and minimal (fixed weight, two check kinds), like VyOS's.

## 9. Acceptance criteria

- [ ] `set virtual-server …` parses only with `--feature insomnia`; JSON is a bare array; contract test pins it.
- [ ] Services render after the sync groups in the `default` instance; every VyOS leaf mapped; defaults filled.
- [ ] Every VyOS verify rule applies per virtual server (dedent bug not reproduced); insomnia's extra checks warn and skip.
- [ ] `vrrp disable` keeps services; deleting both trees stops keepalived.
- [ ] fwmark services render warning-free under `keepalived -t` and log the mark warning.
- [ ] `show virtual-server` answers text and JSON from `/proc/net/ip_vs`, with the VyOS not-configured string.
- [ ] `@vs_nat` green: balancing, health-check removal, `vrrp disable`, unload, teardown.
- [ ] Module doc, book and `design/vrrp.md` updated.
