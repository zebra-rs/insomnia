# DHCP server and relay (VyOS-derived `service` trees) — design

Status: proposal, 2026-10-26. Nothing here is implemented. This document
settles open decision D9 in `design/vyos-gap.md`, which ranks DHCP second
among the missing insomnia-shaped features, after NAT.

insomnia gains DHCP in two parts:

- **Server.** Two backends subscribe to `service dhcp-server` and
  `service dhcpv6-server`, render complete Kea configurations, load them into
  Kea instances that insomnia owns, and answer `show dhcp server …` and
  `show dhcpv6 server …`.
- **Relay.** One backend subscribes to `service dhcp-relay` and
  `service dhcpv6-relay` and renders the config file of a small relay daemon
  written in Rust and shipped with insomnia.

As with the other backends, the schema and the show grammar live in zebra-rs.

Baselines (line numbers and file names refer to these):

| Source | Version |
|:--|:--|
| vyos-1x | `rolling` @ `089c767` (2026-10-23) |
| zebra-rs | `0dfd3fe4` (2026-10-26) |
| insomnia | `492c7aa` |
| Kea | Ubuntu 24.04 `2.4.1-3ubuntu0.2` (arm64) |

The Kea facts in §4 come from the packages themselves:
- contents, AppArmor profiles and changelog read from the `.deb` files;
- configurations checked with `kea-dhcp4 -t` / `kea-dhcp6 -t`;
- the control-socket commands exercised against a `kea-dhcp4` that bound no
  interfaces.

## Decisions at a glance

| # | Question | Decision | § |
|:--|:--|:--|:--|
| DH1 | Schema shape (gap D9) | VyOS's four trees verbatim, under a new insomnia-gated `service` node. Delete the unused IETF-draft `system dhcp` | 3 |
| DH2 | Server engine | Ubuntu's Kea 2.4.1, `kea-dhcp4-server` and `kea-dhcp6-server` only: no control agent, no DDNS daemon | 4 |
| DH3 | Relay engine | A native Rust relay in the insomnia workspace, not ISC `dhcrelay` (end of life, Ubuntu universe) | 5 |
| DH4 | Who runs Kea | Template units owned by insomnia: one Kea per family per VRF. The distribution's Kea units are left alone in the package and disabled in the ISO | 8 |
| DH5 | How a commit reaches Kea | `config-test`, then `config-reload` over the control socket. A config change never restarts Kea | 8 |
| DH6 | Confinement | systemd sandboxing on every unit, plus a named AppArmor profile where AppArmor runs | 8, 12 |
| DH7 | Failover | Kea's HA hook on its dedicated listener, only with mutual TLS. So it waits for `pki`, and a bad HA block fails closed | 9 |
| DH8 | Where Kea listens | Never `"*"`. Only on interfaces connected to a configured subnet, unless `listen-interface` or `listen-address` says otherwise | 7.3 |
| DH9 | DHCPv6-PD routes | insomnia installs `proto dhcp` routes, triggered by Kea and checked against Kea's lease table. Kea gets no `CAP_NET_ADMIN` | 7.5 |
| DH10 | VRFs | Paths and units are per VRF from the first release. The `vrf` lists come later | 19 |

## 1. Where we are

- **`system dhcp` in zebra-rs.**
  - Source: `zebra-rs/yang/dhcp.yang`, 289 lines, an IETF dhc working-group draft dated 2016-08-25 that was never published.
  - It is not gated on `feat:insomnia`, so every stock zebra-rs accepts it.
  - Nothing reads it, and no config in zebra-rs, insomnia, cradle-rs or folksy-rs uses it.
  - Server part: global lease times, `ping-check`, options, and named pools carrying interface, subnet, gateway, hosts, ranges and failover leaves.
  - Relay part: only server groups with IPv4 addresses. No interface binding and no DHCPv6.
- **DHCP client.** `interface <if> ipv4 address dhcp` is gated on `feat:insomnia`. It is stored and then ignored: `rib/link.rs` consumes the value without acting on it.
- **`proto dhcp` routes.** zebra-rs imports kernel routes with `proto dhcp` as `RibType::Dhcp`, shown as `D` in `show ip route` (`fib/netlink/handle.rs`). §7.5 reuses this.
- **The ISO.**
  - `mkiso.sh` installs `kea-dhcp4-server` and `kea-dhcp6-server`, enabled, with the stock config. That config binds no interface (`"interfaces": [ ]`) but still opens a control socket.
  - `mkiso.sh` edits the stock DHCPv6 config to use an EN `server-id`.
  - SBOM finding S10 (`design/sbom.md`): Kea costs 15 packages and 27 MiB. It should be opt-in until a backend exists, and a design should compare footprints. §4.2 is that comparison.
- **Relay.** No relay is on the ISO.
- **insomnia.** No DHCP code yet.

## 2. What VyOS does

| Piece | vyos-1x file | What it does |
|:--|:--|:--|
| Server schema | `interface-definitions/service_dhcp-server.xml.in`, `service_dhcpv6-server.xml.in`, with `include/dhcp/*.xml.i` (common config, `option-v4`, `option-v6`, DDNS, ping-check) | `service dhcp-server { shared-network-name, client-class, high-availability, listen-interface \| listen-address, dynamic-dns-update, hostfile-update, log-level, disable }` and `service dhcpv6-server { shared-network-name, global-parameters, listen-interface, preference, disable-route-autoinstall, log-level, disable }` |
| Per-VRF server | `interface-definitions/vrf.xml.in` | The same two trees again under `vrf name <n> service` |
| Server conf mode | `src/conf_mode/service_dhcp-server.py`, `service_dhcpv6-server.py` | `verify()` (the rules in §7.6). `exclude` addresses split ranges (`dhcp_slice_range`). Renders `/run/kea/kea-dhcp4.conf` (`kea-<vrf>-dhcp4.conf` in a VRF), runs `kea-dhcp4 -t`, then `systemctl restart` on every commit |
| Templates | `data/templates/dhcp-server/kea-dhcp4.conf.j2`, `kea-dhcp6.conf.j2`, `kea-dhcp-ddns.conf.j2`. JSON built by `python/vyos/kea.py` and filters in `python/vyos/template.py` (`kea_shared_network_json`, `kea_high_availability_json`) | memfile leases in `/config/dhcp/dhcp4-leases.csv`, multi-threading on, `lease_cmds` always loaded; `ha`, `run_script` and `ping_check` hooks when configured. With neither `listen-*` leaf, `"interfaces": [ "*" ]` |
| Units | `src/etc/systemd/system/isc-kea-dhcp4-server.service.d/override.conf`, `isc-kea-dhcp4-server@.service`, `src/system/kea-vrf-helper` | Overrides ISC's own unit. VRF instances run `ip vrf exec <vrf> setpriv --reuid=_kea … kea-dhcp4` |
| Packages | — | ISC's Kea packages (`isc-kea-*`), not Debian's or Ubuntu's |
| Relay | `service_dhcp-relay.xml.in`, `service_dhcpv6-relay.xml.in`, `src/conf_mode/service_dhcp{,v6}-relay.py`, `data/templates/dhcp-relay/dhcrelay{,6}.conf.j2`, `src/systemd/isc-dhcp-relay{,6}.service` | ISC `dhcrelay -4` / `-6` with a rendered `OPTIONS` line. No VRF support |
| Op mode | `op-mode-definitions/dhcp.xml.in`, `src/op_mode/dhcp.py` | Leases via `lease{4,6}-get-all`, the loaded config via `config-get`, `clear` via `lease{4,6}-del`, all on Kea's control socket. Pool statistics are computed from the configured ranges and a lease count |
| PD routes | `src/system/on-dhcpv6-event.sh`, a Kea `run_script` hook | On `leases6_committed`: `sudo ip -6 route replace <prefix> via <requester link-local> dev <if> proto static`. On release, expiry or decline: delete |

## 3. Schema (DH1)

### 3.1 Options

| | A: keep `system dhcp` | B: VyOS trees | C: RFC 9243 |
|:--|:--|:--|:--|
| What it is | IETF dhc draft from 2016, never published | `service dhcp-server`, `dhcpv6-server`, `dhcp-relay`, `dhcpv6-relay` | IETF YANG for DHCPv6: server, relay and client modules |
| DHCPv4 | yes, thin | yes | no (no IETF DHCPv4 model was ever published) |
| DHCPv6 and PD | no | yes | yes |
| Relay | a list of server addresses | v4 listen/upstream split and option-82 policy; v6 per-interface | v6 only |
| Fit | no other insomnia tree is IETF-shaped | `firewall`, `vpn ipsec` and `vrrp` are all VyOS-shaped, and their renderers port the VyOS templates line for line | — |
| VyOS configs port | no | yes | no |

**Decision: B.** Delete `system dhcp` and the draft module. Nothing uses it, so nothing breaks. A saved config containing `system dhcp` would stop loading, so the CHANGELOG says so.

### 3.2 Placement: a `service` node

`vrrp` was hoisted out of VyOS's `high-availability` wrapper because that
wrapper exists only to sit beside one sibling, the IPVS load balancer. `service` is different:
- VyOS has 31 `service_*` definitions.
- The insomnia-shaped backlog in `vyos-gap.md` §9 lives under `service` in VyOS: DNS forwarding, NTP, conntrack-sync, LLDP, SNMP and SSH.
- One insomnia-gated `service` container keeps every `set service …` line portable and gives those future trees a home.

```yang
container service {
  if-feature feat:insomnia;
  ext:help "System services";
  container dhcp-server   { uses "dhcp:dhcp-server"; }
  container dhcpv6-server { uses "dhcp:dhcpv6-server"; }
  container dhcp-relay    { uses "dhcp:dhcp-relay"; }
  container dhcpv6-relay  { uses "dhcp:dhcpv6-relay"; }
}
```

### 3.3 Leaves not carried over

A leaf the backend cannot apply stays out of the schema, so `set` fails
instead of storing something that is silently ignored:

| VyOS leaf | Why not | Comes back with |
|:--|:--|:--|
| `dynamic-dns-update` (global and per scope) | Needs `kea-dhcp-ddns-server` and a DNS server to update | `service dns forwarding` |
| `hostfile-update` | VyOS writes `/etc/hosts` from a `run_script` hook. It belongs with the system's own name service | DNS forwarding, `system static-host-mapping` |
| `ping-check` (all levels) | `libdhcp_ping_check.so` is not in Ubuntu's 2.4.1 `kea-common` | a newer Kea |
| `high-availability` | Must be mutually authenticated (§9), which needs `pki` | `pki` |
| `dhcp-relay interface` | Deprecated in VyOS in favour of `listen-interface` + `upstream-interface` | — |

`[ext]` marks a zebra-rs extension. There are none in the config tree. The
two relay show commands in §11 are extensions.

## 4. Server engine (DH2)

### 4.1 Kea from the Ubuntu archive

What the noble packages contain and do:

- **Version.** `2.4.1-3ubuntu0.2` in `noble-security`. The changelog's latest entry fixes CVE-2026-3608, a DoS through the API socket or the HA listener (2026-06-05).
- **Sizes.**
  - `kea-common` 14.1 MiB: the libraries plus the hooks `bootp`, `flex_option`, `ha`, `lease_cmds`, `mysql_cb`, `pgsql_cb`, `run_script` and `stat_cmds`.
  - `kea-dhcp4-server` and `kea-dhcp6-server` 1.1 MiB each.
  - `kea-common` depends on `liblog4cplus`, `libmysqlclient21`, `libpq5` and `libssl3t64`.
- **Hooks.** `kea-dhcp4 -W` reports "Premium hooks: no". There is no `ping_check` hook.
- **Multi-threading.** On by default: `status-get` reports `multi-threading-enabled: true` for a config with no `multi-threading` block.
- **Option names.** Every option name VyOS renders exists, except `classless-static-route` (option 121): "definition for the option 'dhcp4.classless-static-route' does not exist". The same routes sent as raw code 121 data are accepted (§7.2).
- **Missing interfaces.** Kea refuses the whole configuration when `interfaces-config` or a shared network's `interface` names an absent interface ("Failed to select interface: interface 'eth1' doesn't exist in the system").
- **DHCPv6 data directory.** `data-directory` is accepted in `Dhcp6` and must exist.
- **Control socket.** `config-test` (with the config inline), `config-reload`, `lease4-get-all`, `lease4-add`, `stat-lease4-get` and `status-get` work. `config-reload` keeps the leases, and `stat-lease4-get` reflects a resized pool immediately.
- **AppArmor.** The packages ship enforcing AppArmor profiles for `kea-dhcp4`, `kea-dhcp6` and `kea-lfc`. They allow reading only `/etc/kea/**`, the control socket only at `/run/kea/kea{4,6}-ctrl-socket`, and leases only at `/var/lib/kea/kea-leases{4,6}.csv*`.
- **Path restrictions.** None: a lease file and a hooks path outside the defaults were accepted.

**Security status.** Ubuntu marks two Kea CVEs that affect 2.4.0–2.4.1 as **Ignored, "backport too intrusive"** for noble:
- CVE-2025-32801: configuration and API directives can load a malicious hook library.
- CVE-2025-32802: they can overwrite arbitrary files.

The tracker's note says that on noble the daemons run as non-root and are confined by AppArmor, which mitigates them. The ISO does not install the `apparmor` package; `design/sbom.md` Appendix A lists only `libapparmor1`. So that mitigation is absent on our image unless we supply it. That is DH6 (§8.3, §12).

### 4.2 Footprint comparison (SBOM S10)

| Option | Footprint | Source and patch path (SBOM P3, P6) | v4 | v6 + PD | Failover | Control API | Verdict |
|:--|:--|:--|:--|:--|:--|:--|:--|
| Ubuntu Kea 2.4.1 | 15 packages, 27 MiB (`sbom.md` §5, M2 → M3) | Ubuntu main, USN-tracked (CVE-2026-3608 shipped); the two 2025 CVEs not backported | yes | yes | HA hook | JSON on a unix socket | **chosen** |
| ISC's Kea packages (what VyOS uses) | not measured | A second source for the L1 layer, against P3; ISC patches first | yes | yes | yes | yes | not now; revisit with the next base LTS |
| `dnsmasq-base` | 1 package, 0.9 MiB | Ubuntu main | yes | addresses, but no prefix delegation | none | none (lease file only) | rejected: no PD, no failover, no lease API |
| An in-house Rust server | — | ours to patch (P7) | — | — | — | — | rejected: a server is a much larger surface to own than a relay |

The database client libraries that Kea pulls in are SBOM class E4: present
but not reachable, because only the memfile backend is configured. The SBOM
records them as VEX `not_affected`. Kea's packet parser is E1 (remote,
unauthenticated) on the interfaces it listens on, and only there. DH8 keeps
that set small.

## 5. Relay engine (DH3)

| Option | Status | Footprint | Families |
|:--|:--|:--|:--|
| `isc-dhcp-relay` 4.4.3-P1 (VyOS's choice) | Ubuntu **universe**. ISC ended development of the relay in early 2022; 4.4.3 was its final release, and ISC says it "should not be used in production any longer" | 1 package, 1.7 MiB | v4, v6 |
| `dhcp-helper` 1.2 | universe, IPv4 only, no option 82 | small | v4 |
| `dnsmasq` in relay mode | main, but a full DNS/DHCP/TFTP server installed for the relay function | 0.9 MiB | v4, v6 |
| Native Rust relay | ours (P7) | one binary, no packages | v4, v6 |

**Decision: native.**
1. A relay parses packets from every client on every listen interface: SBOM class E1. `dhcrelay` has no upstream maintainer and sits in universe, so nobody patches it. That fails P6 for exactly the class of component where it matters most.
2. A relay is small: it is stateless and handles two message formats, and the parser is memory-safe and fuzzable.
3. Owning it lets the relay bind VRF sockets itself (no preload shim). It can later grow RFC 8987 route installation for delegated prefixes, which no packaged relay does.

The cost is that we own its CVEs (P7): fuzz targets for the codec, and the
crates appear in insomnia's binary SBOM like any other.

## 6. Scope

First release, default VRF only:

- **`service dhcp-server`:**
  - structure: shared networks, subnets, ranges, `exclude`, static mappings, `subnet-id`;
  - all `option` leaves and client classes;
  - `listen-interface` / `listen-address`, `lease`, `authoritative`, `ignore-client-id`, `log-level`;
  - `disable` at every level.
- **`service dhcpv6-server`:**
  - structure: shared networks, subnets, address and prefix ranges, prefix delegation, static mappings, `subnet-id`, `lease-time`;
  - options, `global-parameters`, `preference`;
  - `listen-interface` and `interface`, `disable-route-autoinstall`, `log-level`, `disable`.
- **Relays:** `service dhcp-relay` and `service dhcpv6-relay`.
- **Show:** leases, statistics and static mappings for both families, plus relay statistics `[ext]`.

Deferred (§20): HA, per-VRF instances, DDNS and `hostfile-update`,
`ping-check`, the `clear` / `restart` verbs, PD route installation in the
relay, and the DHCP client.

## 7. Config tree and rendering

### 7.1 Tree (zebra-rs `dhcp.yang`)

A grouping-library module in the `firewall.yang` / `vrrp.yang` style. Leaf
names and types follow VyOS. Defaults are applied by the renderer, because
the JSON batch carries only what the operator set. References
(`client-class`, `listen-interface`, `interface`) are plain strings, so a
referent can be staged after its referrer. `MANDATORY` marks the structural
rules that move into YANG (validation layer 1, `vyos-gap.md` §4.1). VyOS
checks them in `verify()`.

```
service
├── dhcp-server
│   ├── disable                                  empty
│   ├── listen-address <ipv4>                    leaf-list   Kea UDP sockets (relayed traffic only)
│   ├── listen-interface <if>                    leaf-list   Kea raw sockets
│   ├── log-level                                fatal|error|warn|info|debug  (default info)
│   ├── client-class <name>                      list
│   │   ├── disable                              empty
│   │   ├── relay-agent-information { circuit-id, remote-id }     text or 0x-hex
│   │   ├── hostname { value | substring value }
│   │   ├── vendor-class-id { value | substring value }
│   │   └── option                               <option-v4>
│   └── shared-network-name <name>               list
│       ├── authoritative, description, disable
│       ├── option                               <option-v4>
│       └── subnet <ipv4-prefix>                 list
│           ├── subnet-id                        1-4294967294        MANDATORY
│           ├── option                           <option-v4>
│           ├── client-class, description, disable, ignore-client-id
│           ├── exclude <ipv4>                   leaf-list
│           ├── lease                            seconds (default 86400)
│           ├── range <name>                     list
│           │   ├── start, stop                  ipv4                MANDATORY
│           │   └── option, client-class
│           └── static-mapping <hostname>        list
│               ├── ip-address, mac | duid
│               └── option, description, disable
├── dhcpv6-server
│   ├── disable, disable-route-autoinstall       empty
│   ├── listen-interface <if>                    leaf-list
│   ├── log-level                                (default info)
│   ├── preference                               0-255
│   ├── global-parameters name-server <ipv6>     leaf-list
│   └── shared-network-name <name>               list
│       ├── description, disable, interface
│       ├── option                               <option-v6>
│       └── subnet <ipv6-prefix>                 list
│           ├── subnet-id                        MANDATORY
│           ├── interface, option
│           ├── lease-time { default, minimum, maximum }
│           ├── range <name> { prefix | start + stop, option }
│           ├── prefix-delegation prefix <ipv6>  list
│           │   ├── prefix-length 32-64, delegated-length 32-96      MANDATORY
│           │   └── excluded-prefix, excluded-prefix-length
│           └── static-mapping <hostname> { mac | duid, ipv6-address*, ipv6-prefix*, option, disable }
├── dhcp-relay
│   ├── disable                                  empty
│   ├── listen-interface <if>                    leaf-list
│   ├── upstream-interface <if>                  leaf-list
│   ├── server <ipv4>                            leaf-list
│   └── relay-options
│       ├── hop-count                            1-255   (default 10)
│       ├── max-size                             64-1400 (default 576)
│       └── relay-agents-packets                 append|replace|forward|discard (default forward)
└── dhcpv6-relay
    ├── disable                                  empty
    ├── listen-interface <if> { address }        list
    ├── upstream-interface <if> { address* }     list, address MANDATORY
    ├── max-hop-count                            1-255   (default 10)
    └── use-interface-id-option                  empty

<option-v4>  bootfile-name, bootfile-server, bootfile-size, captive-portal, capwap-controller,
             client-prefix-length, default-router, domain-name, domain-search*, interface-mtu,
             ip-forwarding, ipv6-only-preferred, name-server*, ntp-server*, pop-server*,
             server-identifier, smtp-server*, static-route <prefix> { next-hop MANDATORY },
             tftp-server-name, time-offset, time-server*, time-zone,
             vendor-option ubiquiti unifi-controller, wins-server*, wpad-url
<option-v6>  captive-portal, capwap-controller, domain-search*, info-refresh-time, name-server*,
             nis-domain, nis-server*, nisplus-domain, nisplus-server*, sip-server*, sntp-server*,
             time-zone, vendor-option cisco tftp-server*
```

`*` = leaf-list. VyOS's `listen-interface` validator, a regex of VyOS
interface-name prefixes, becomes a plain string, because zebra-rs names
interfaces differently.

### 7.2 Rendering `kea-dhcp4.conf`

Follows `kea-dhcp4.conf.j2` and `kea_parse_subnet` / `kea_parse_options`:

| Config | Kea JSON |
|:--|:--|
| (always) | `interfaces-config` (§7.3) with `service-sockets-max-retries 60`, `service-sockets-retry-wait-time 5000` |
| (always) | `control-socket` unix at `<kea-dir>/<vrf>/kea4-ctrl-socket` |
| (always) | `lease-database` memfile, `persist true`, `name <state-dir>/<vrf>/kea-leases4.csv` |
| (always) | `option-def` for `wpad-url` (252, string) and `ubnt` (vendor-encapsulated), as VyOS |
| (always) | `hooks-libraries`: `libdhcp_lease_cmds.so` and `libdhcp_stat_cmds.so` |
| (always) | `loggers`: `kea-dhcp4` to stdout (the journal), severity from `log-level` |
| `client-class` | `client-classes`, test expressions built as `kea_build_client_class_test` does; disabled classes omitted |
| `shared-network-name` | `shared-networks[] { name, authoritative, option-data, boot-file-name, next-server, subnet4[] }`; disabled networks and subnets omitted |
| `subnet` | `{ subnet, id, option-data, client-class, pools[], reservations[] }` |
| `lease` | `valid-lifetime` and `max-valid-lifetime` |
| `ignore-client-id` | `match-client-id false` |
| `range` (after slicing out `exclude`) | `pools[] { pool "start - stop", option-data, client-class }` |
| `static-mapping` | `reservations[] { hostname, hw-address \| duid, ip-address, option-data }`; disabled ones omitted |
| option leaves | named `option-data` using VyOS's `kea4_options` map; `client-prefix-length` → `subnet-mask`; `ip-forwarding`; `time-zone` → `pcode` + `tcode` |
| `static-route` (+ `default-router`) | option 121 as raw data, **deviation**, see below |
| `bootfile-name`, `bootfile-server` | also the `boot-file-name` and `next-server` fields |
| `listen-address` | `interfaces` as `<if>/<addr>` with `dhcp-socket-type udp`, as `kea_address_json` |

Deliberate deviations, recorded in the module doc comment:

- **Option 121 is rendered as data**, because Kea 2.4.1 has no definition for
  `classless-static-route`.
  - Rendered as `{ "code": 121, "csv-format": false, "data": "<hex>" }` in RFC 3442 encoding: a width octet, the significant destination octets, then the router.
  - As in VyOS, `default-router` is appended as `0.0.0.0/0`, because RFC 3442 clients ignore option 3 when option 121 is present.
  - Verified: `080AC00002FE00C0000201` (10.0.0.0/8 via 192.0.2.254, default via 192.0.2.1) passes `kea-dhcp4 -t`.
- **`stat_cmds` is loaded** for the statistics view (§11). VyOS loads only
  `lease_cmds`.
- **No `"*"` listening** (§7.3).
- **No `enable-ping-check` user-context**: there is no `ping-check` (§3.3).
- **Paths** live under insomnia's directories, not `/config/dhcp` (§8.1).
- **Loading** is by `config-reload`, not a restart (§8.2).

### 7.3 Where Kea listens (DH8)

VyOS:
- `listen-address` → UDP sockets;
- `listen-interface` → raw sockets on those interfaces;
- neither → `"interfaces": [ "*" ]` in raw mode: **every** interface, the WAN included.

A DHCP server answering on the uplink is a rogue server on someone else's
network. insomnia never renders `"*"`. With neither leaf, the interface
list is the set of interfaces carrying an IPv4 address inside an enabled
subnet, which is the test VyOS's own `verify()` uses (`is_subnet_connected`).

- An interface that is named but absent is dropped with a warning. Kea would
  otherwise refuse the whole config (§4.1).
- An empty set with no `listen-address` means Kea is not started, with a
  warning. VyOS rejects that commit with "None of the configured subnets have
  an appropriate primary IP address…".
- DHCPv6 is the same: `listen-interface`, else the shared-network and subnet
  `interface` leaves, else the interfaces with an address inside an enabled
  subnet.

This needs insomnia to see links and addresses and to re-render when they
change. [fw-global-options](plans/fw-global-options.md) §3.2a already
proposes `crate::links`, a shared watcher for links (`RTMGRP_LINK`). DHCP
extends it with interface addresses (`RTMGRP_IPV4_IFADDR`,
`RTMGRP_IPV6_IFADDR`); that is work item 3 in §17. Compare-before-reload
(§8.2) keeps unrelated link churn from reloading Kea.

### 7.4 Rendering `kea-dhcp6.conf`

Follows `kea-dhcp6.conf.j2` and `kea6_parse_subnet` / `kea6_parse_options`.
It differs from §7.2 in these rows:

| Config | Kea JSON |
|:--|:--|
| (always) | `server-id { type EN, persist true }` with `data-directory <state-dir>/<vrf>`, so the DUID survives restarts and needs no interface at first start. This replaces the folksy-rs edit of the stock config |
| `global-parameters name-server`, `preference` | global `option-data` `dns-servers`, `preference` |
| `shared-network-name … interface`, `subnet … interface` | `interface` on the shared network or subnet; it must exist (§7.3) |
| `range` | `pools[] { pool "<prefix>" \| "start - stop", option-data }` |
| `prefix-delegation prefix` | `pd-pools[] { prefix, prefix-len, delegated-len, excluded-prefix, excluded-prefix-len }` |
| `lease-time` | `valid-lifetime`, `min-valid-lifetime`, `max-valid-lifetime` |
| `static-mapping` | `reservations[] { hostname, hw-address \| duid, ip-addresses, prefixes, option-data }` |
| `sip-server` | `sip-server-addr` for addresses, `sip-server-dns` for names |
| `time-zone` | `new-posix-timezone` + `new-tzdb-timezone` |
| PD configured and no `disable-route-autoinstall` | `libdhcp_run_script.so` calling `/usr/lib/insomnia/kea-notify` (§7.5) |

Every option name in `kea6_options` passed `kea-dhcp6 -t`.

### 7.5 Routes for delegated prefixes (DH9)

VyOS's hook runs `sudo ip -6 route replace … proto static`. That needs sudo
for `_kea`. It also tags the route `static`, which zebra-rs imports as a plain
kernel route.

insomnia instead:

1. Points `run_script` at `/usr/lib/insomnia/kea-notify`, a tiny program that
   copies `QUERY6_IFACE_NAME`, `QUERY6_REMOTE_ADDR` and the
   `LEASES6_AT<i>_{TYPE,ADDRESS,PREFIX_LEN}` variables into one datagram. It
   sends that to `<kea-dir>/<vrf>/events`, a socket that insomnia creates with
   mode 0660, group `_kea`.
2. Treats the datagram only as a claim. insomnia installs or replaces a route
   only after `lease6-get` confirms an active `IA_PD` lease for that exact
   prefix. So a forged datagram can at most re-point a route for a prefix that
   really is leased, and only Kea's user can send one.
3. Installs `ip -6 route replace <prefix> via <requester link-local> dev <if>
   proto dhcp`. zebra-rs imports it as a `D` route, so it is visible and
   redistributable.
4. Removes routes on release, expiry or decline events. It also sweeps every
   60 s and at startup, deleting any `proto dhcp` route for a prefix inside a
   configured `prefix-delegation` range that has no active lease.
   - Ownership rule: insomnia touches only routes inside configured PD ranges.
   - This keeps it clear of the default route that a future zebra-rs DHCP client
     installs with the same protocol.

Kea keeps only `CAP_NET_BIND_SERVICE` and `CAP_NET_RAW`.
`disable-route-autoinstall` renders no hook, and no routes are installed.

### 7.6 Render-time checks

zebra-rs cannot veto a commit on insomnia's behalf (`vyos-gap.md` §4.1), so
each VyOS `verify()` rule becomes one of three things:
- a YANG constraint (§7.1);
- a skip-with-warning naming the element;
- fail closed: Kea is not started, or keeps its previous configuration.

Skipping must never widen who is served. So a range that names a missing
client class is skipped, not served to everyone.

| Rule (VyOS `verify()`) | Action |
|:--|:--|
| no enabled shared network | empty render, Kea stopped |
| shared network without a subnet | skip the network |
| duplicate `subnet-id`; duplicate or overlapping subnet | skip the later subnet |
| range outside its subnet, `stop` < `start`, overlapping ranges | skip the range |
| `exclude` outside the subnet | ignore that address |
| subnet with neither a range nor an enabled static mapping | skip the subnet |
| `client-class` reference to a missing or disabled class | skip the subnet or range that names it |
| client class with no match condition, bad hex, both `value` and `substring`, a quote in `substring` | skip the class (and so everything that references it) |
| static mapping: address outside the subnet; `mac` and `duid` both or neither; duplicate address, MAC or DUID among enabled mappings | skip that mapping (the later one for duplicates) |
| `listen-address` not assigned on any interface | drop it |
| `listen-address` together with `listen-interface` | use `listen-address` only |
| nothing left to listen on (§7.3) | Kea not started |
| v6 range outside its subnet, or `start` without `stop` | skip the range |
| v6 PD: `prefix-length` > `delegated-length`; excluded prefix not longer than the delegated length, or outside the PD prefix | skip that PD prefix |
| v6 static mapping address outside the subnet, or a duplicate address or prefix | skip that mapping |
| anything Kea still rejects (`config-test`) | Kea keeps its previous configuration (§8.2); the error is logged and shown as stale (§11) |

### 7.7 Relay config

The relay backend renders one JSON file for both families. The relay daemon
validates it again on load. The relay's VyOS rules are:
- `server` is required;
- `listen-interface` and `upstream-interface` must come together;
- v6 listen interfaces need a global address;
- `lo` is refused.

The renderer turns each into skip-with-warning.

## 8. Applying: Kea lifecycle (DH4–DH6)

### 8.1 Files, units and flags

| Flag | Default | Holds |
|:--|:--|:--|
| `--kea-dir` | `/run/insomnia/kea` | `<vrf>/kea-dhcp{4,6}.conf` (mode 0640, root:_kea), the control sockets `kea{4,6}-ctrl-socket`, Kea's lock files, the `events` socket |
| `--kea-state-dir` | `/var/lib/insomnia/kea` | `<vrf>/kea-leases{4,6}.csv`, kea-lfc's work files, the DHCPv6 server DUID |
| `--kea-control` | `systemd` | `systemd` starts and stops the template units. `socket` only talks to a Kea that somebody else started, which is what BDD does |
| `--kea-unit4`, `--kea-unit6` | `insomnia-kea-dhcp4@.service`, `insomnia-kea-dhcp6@.service` | template units; the instance name is the VRF (`default` for the global table) |

Control-socket paths stay well under the 108-byte `AF_UNIX` limit even with a
15-character VRF name. The limit was hit while testing from a long scratch
path.

The distribution's `kea-dhcp4-server.service` and `kea-dhcp6-server.service`
are not touched, as with keepalived in `design/vrrp.md` §7. Their lease files
and control sockets are at different paths, so the two cannot collide. On the
ISO they are disabled (§15). insomnia logs a warning at startup if either is
active.

### 8.2 Apply sequence

Per family, per VRF, after every config event and every relevant link or
address change:

1. **Render.** Nothing to serve (no tree, `disable`, nothing valid) →
   `systemctl stop`, done.
2. **Compare.** The render equals the last *loaded* text and the instance is
   running → nothing to do.
3. **Running instance.** Send `config-test` with the JSON inline. On success,
   write the file (temp + rename) and send `config-reload`. On failure, leave
   the file and the running config alone and record Kea's error.
4. **Stopped instance.** Write the file, run `kea-dhcp{4,6} -t`, then
   `systemctl start`.

Why reload rather than VyOS's restart on every commit:
- a reload keeps Kea's in-memory state and (later) its HA state;
- it does not drop the packets that arrive during a restart;
- a config Kea rejects never takes the service down.

`config-reload` re-reads the file Kea was started with, hence the fixed path.

### 8.3 Unit and confinement (DH6)

```ini
[Unit]
Description=Kea DHCPv4 server for VRF %i, driven by insomnia
After=network-online.target insomnia.service
Wants=network-online.target

[Service]
User=_kea
Group=_kea
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
Environment=KEA_LOCKFILE_DIR=/run/insomnia/kea/%i
ExecStart=/usr/sbin/kea-dhcp4 -c /run/insomnia/kea/%i/kea-dhcp4.conf
Restart=on-failure
StateDirectory=insomnia/kea/%i
# Confinement: always the sandbox; the AppArmor profile where AppArmor runs.
AppArmorProfile=-insomnia-kea-dhcp4
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/run/insomnia/kea/%i
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_PACKET AF_NETLINK
RestrictNamespaces=yes
LockPersonality=yes
SystemCallArchitectures=native
```

- **Sandboxing.** The systemd sandbox applies on every host. It is the only
  confinement on the ISO, which has no AppArmor.
- **AppArmor.** `/etc/apparmor.d/insomnia-kea` holds two named profiles,
  `insomnia-kea-dhcp4` and `insomnia-kea-dhcp6`.
  - They are Ubuntu's rules with insomnia's paths.
  - Each has a child profile for `kea-lfc`, because Ubuntu's own `kea-lfc` profile allows only `/var/lib/kea`.
  - Each has a child profile for `kea-notify`.
  - postinst loads them when AppArmor is enabled.
  - `AppArmorProfile=` attaches the named profile. The path-attached
    distribution profile does not apply, because insomnia's paths differ from
    the stock ones.
- **The `-` prefix.** It lets the unit start where the profile is absent. On an
  AppArmor host the package always loads it.
- **Whether to install `apparmor` on the ISO** is a separate SBOM decision
  (§15). It would restore the mitigation Canonical's triage of the 2025 CVEs
  assumes.

Packaging takes the lesson of PR #18: the template units are plain `assets`,
not extra `systemd-units` entries. Under cargo-deb 3.7.0, a second entry with
`enable = false` replaced the maintainer-script fragments for
`insomnia.service`.

## 9. Failover (DH7) — designed now, built after `pki`

- **What VyOS renders.**
  - Kea's `libdhcp_ha.so`: `active-active` → `load-balancing`, `active-passive` → `hot-standby`.
  - Peers at `http://<addr>:647/`, and `this-server-name` is the hostname.
  - Heartbeat 10 s, max-response-delay 60 s, max-ack-delay 5 s, max-unacked-clients 10.
  - Optional TLS from `pki`.
- **What Kea 2.4.1 offers.**
  - The HA hook supports `http-dedicated-listener`, so no `kea-ctrl-agent` is needed. The ISO already leaves the control agent out.
  - It has `require-client-certs` and `restrict-commands`.
  - Basic authentication appears only on the client side (`addBasicAuthHttpHeader`). The listener is constructed with a TLS context and nothing else.
  - The reading of these symbols is that on 2.4.1 the only way to authenticate a partner is mutual TLS. The spike confirms it (§18).
- **The risk.** Without authentication, anyone who can reach TCP 647 can send HA
  commands, lease updates among them.
- **Decision.**
  - HA renders only with `certificate`, `ca-certificate`, `require-client-certs true` and `restrict-commands true`. So it ships with `pki`.
  - A `high-availability` block that cannot be rendered securely means the server is **not started**. Two unsynchronised servers on one pool hand out duplicate addresses, so this is fail closed, not degrade.
- **With VRRP.** On a VRRP pair, `source-address` and `remote` must be the
  routers' own addresses, never the VRRP virtual address, which moves to the
  peer on failover. The renderer warns when either equals a configured VIP.
- **Until then.** A pair serves one subnet with *split scopes*: each router
  owns a disjoint range of the same subnet, for example 80/20, and there is no
  lease sync. This needs no code; the book documents it.
- **Firewall.** Allow TCP 647 only from the peer.

## 10. The relay daemon (DH3)

### 10.1 Process

- **Code.** Two new workspace crates:
  - `dhcp-packet/`: the codec, with no I/O. It covers the DHCPv4 header and options, and DHCPv6 client and relay messages and options. It has property tests and `cargo fuzz` targets.
  - `dhcp-relay/`: the binary `insomnia-dhcp-relay`.
- **One process** for both families and every VRF. It binds per-interface and
  per-VRF sockets itself, so it needs no preload shim.
- **Unit.** `insomnia-dhcp-relay.service` has no `[Install]`; insomnia starts
  and stops it. It runs with `DynamicUser=yes`, `CAP_NET_BIND_SERVICE` and
  `CAP_NET_RAW`, and the §8.3 sandbox. It keeps `AF_NETLINK` for reading
  interface addresses.
- **Config and reload.** The config is `/run/insomnia/dhcp-relay/relay.json`,
  mode 0644, with no secrets. Reload is `SIGHUP`, after the same
  compare-before-reload as Kea.
- **Counters** are served on `/run/insomnia/dhcp-relay/control`. There is one
  request, `stats`, answered in JSON.
- **Why not inside insomnia.** insomnia runs as root and also enforces the
  firewall, IPsec and VRRP. A separate, unprivileged, sandboxed process
  confines a parser bug to the relay. An insomnia restart on upgrade does not
  touch the relay.

### 10.2 DHCPv4

| VyOS leaf | `dhcrelay` | Native relay |
|:--|:--|:--|
| `listen-interface` | `-id` | Accept BOOTREQUESTs from clients here. If `giaddr` is 0, set it to this interface's primary IPv4 address |
| `upstream-interface` | `-iu` | Accept BOOTREPLYs from servers only here |
| `server` | positional | Unicast each request to every server on UDP 67, from port 67 |
| `relay-options hop-count` | `-c` | Drop a request whose `hops` would exceed the limit; increment `hops` |
| `relay-options max-size` | `-A` | Never send a packet larger than this. Match `dhcrelay`'s handling of an oversized packet during implementation and record it |
| `relay-options relay-agents-packets` | `-m` | A request that already carries option 82: `forward` it unchanged (default), `append` ours, `replace` it, or `discard` the request |
| (VyOS always passes `-a`) | `-a` | Add option 82 with circuit-id = the listen interface's name, and strip it from replies |

Reply delivery: whole IPv4 datagrams through one `AF_PACKET` socket, as
`dhcrelay` sends them:
- broadcast flag set, no `yiaddr`, or not Ethernet → to 255.255.255.255 at
  ff:ff:ff:ff:ff:ff on the listen interface;
- otherwise → to `yiaddr` at `chaddr`, because a client without an address
  cannot answer ARP.

Replies are trusted by where they arrive. With `upstream-interface`, only
there. A reply arriving on a listen interface needs that interface in
`upstream-interface` and a sender in `server`: any client there can send a
BOOTREPLY, and without the check the relay would carry a forged offer onto
another listen interface's segment. `dhcrelay` checks neither (a deviation).

Sockets:
- per listen interface, UDP `255.255.255.255:67` with `SO_BINDTODEVICE`:
  client broadcasts only;
- per address of a listen interface, UDP `<address>:67` bound to the VRF
  device (unbound in `default`). Requests leave from the first address, the
  giaddr, so server replies and downstream relays' unicast arrive on these;
- `AF_PACKET` with protocol 0, for sending only.

Never `0.0.0.0:67`. Kea's raw-mode fallback socket binds `<its
address>:67` without `SO_REUSEADDR` to hold the port, and the kernel
refuses that bind next to any wildcard socket on the port, even a
device-bound one. A relay on `0.0.0.0:67` stopped a Kea serving another
interface of the same router from starting ("Address already in use"); the
layout above coexists with it in either start order.

Receiving through UDP rather than raw sockets means the firewall's input
chain sees requests and server replies. Replies to clients leave through
`AF_PACKET` and bypass the output chain.

Verified 2026-10-27 in network namespaces against Ubuntu's Kea 2.4.1 with
`dhcpcd` as the client: unicast and broadcast replies, Kea in the relay's
namespace on another interface (both start orders), forged replies from a
client dropped, and the same in a VRF.

### 10.3 DHCPv6

| VyOS leaf | `dhcrelay -6` | Native relay |
|:--|:--|:--|
| `listen-interface <if> [address <a>]` | `-l a%if` | Join ff02::1:2 on the interface; accept client messages and Relay-forw. `link-address` = `address`, else the interface's first global address |
| `upstream-interface <if> address <a>…` | `-u a%if` | Send Relay-forw to each address (unicast, or a multicast such as ff05::1:3) out of that interface; accept Relay-repl there |
| `max-hop-count` | `-c` | Drop Relay-forw at the limit |
| `use-interface-id-option` | `-I` | Add Interface-ID (option 18) and use it on the way back |

A Relay-repl is unwrapped. The inner message goes to `peer-address`, port
546 (547 if the peer is another relay), on the interface named by the
Interface-ID or matched by `link-address`. A Relay-repl arriving on a
listen interface must come from a unicast server pinned to that interface,
for the reason given in §10.2.

Sockets:
- per listen interface, UDP `[::]:547` with `SO_BINDTODEVICE`, joined to
  ff02::1:2. Replies to clients leave through it;
- per VRF, UDP `[::]:547` bound to the VRF device (unbound in `default`) with
  `IPV6_MULTICAST_ALL` off, so it sees no client multicast. Relay-forw leaves
  through it, and Relay-repl comes back to it.

Kea 2.4.1 sets `SO_REUSEADDR` on its DHCPv6 sockets, so these wildcard
sockets coexist with it. Unicast to a listen interface in a VRF matches both
sockets equally, so the relay judges a message by the interface it arrived
on, not the socket that received it.

## 11. Show commands

Grammar (zebra-rs `exec.yang`, gated on `feat:insomnia`, VyOS's spelling):

```
show dhcp   server leases          [pool <name>] [state <state>] [sort <key>] [origin local|remote]
show dhcp   server statistics      [pool <name>]
show dhcp   server static-mappings [pool <name>] [sort <key>]
show dhcpv6 server leases | statistics | static-mappings      (same filters, v6 sort keys)
show dhcp   relay statistics       [ext]
show dhcpv6 relay statistics       [ext]
```

Orders reach insomnia under one provider name, `dhcp`, with the prefixes
`/show/dhcp` and `/show/dhcpv6`. insomnia sends `…/server/…` to that
family's server backend and `…/relay/…` to the relay backend.

| View | Source | Rendering |
|:--|:--|:--|
| leases | `lease4-get-all` / `lease6-get-all` (`lease_cmds`); pool = the shared network of the lease's `subnet-id` in the last loaded model | VyOS's columns. v4: IP Address, MAC address, State, Lease start, Lease expiration, Remaining, Pool, Hostname, Origin. v6: IPv6 address, MAC address, State, Last communication, Lease expiration, Remaining, Pool, Hostname, Type, DUID |
| statistics | `stat-lease4-get` / `stat-lease6-get` (`stat_cmds`): per-subnet totals and assigned counts, summed per shared network | VyOS's columns Pool, Size, Leases, Available, Usage. **Deviation:** Size comes from Kea, so `exclude` addresses do not count. VyOS sums the configured ranges |
| static-mappings | the last loaded model | Pool, Subnet, Hostname, IP Address, MAC Address, DUID, Description |
| relay statistics | the relay's control socket | received, forwarded and dropped (per reason), per interface |

- **Lease states.** Kea's states are 0 → `active`, 1 → `declined` (VyOS prints
  `rejected`) and 2 → `expired`. The `state` filter keeps VyOS's eight
  keywords; the ones Kea never produces return an empty table, as on VyOS.
- **Origin.** VyOS hard-codes `origin` to `local` (a TODO for HA), and so does
  insomnia until HA exists.
- **Not running.** No socket gives a not-running message.
- **Stale.** If the last apply was rejected, every view starts with "DHCP server
  is running an older configuration:" and Kea's error.
- **JSON** (`vtyctl show -j`) returns Kea's `arguments`, filtered like the text.

Blocked on `vyos-gap.md` §4.2 (non-show verbs):
- `clear dhcp-server lease <ip>` (`lease4-del`);
- `restart dhcp server`;
- `restart dhcp relay-agent`.

The control-socket client supports them already. Only the verb plumbing is
missing.

## 12. Security

| Surface | Reachable by | SBOM class | Controls |
|:--|:--|:--|:--|
| Kea packet parsing | hosts on a listen interface, and anything a relay forwards | E1 | DH8's minimal listen set; non-root `_kea`; sandbox; AppArmor where present; Ubuntu USNs |
| Kea control socket | local root and `_kea` | local | Directory 0770 root:_kea, never on TCP, no control agent; insomnia is the only client. This is the vector of CVE-2025-32801 and CVE-2025-32802, not fixed in noble |
| HA listener (later) | peers, TCP 647 | E1 | mutual TLS, `restrict-commands`, firewall to the peer |
| Relay packet parsing | hosts on a relay listen interface; servers | E1 | Rust, fuzzed codec, `DynamicUser`, sandbox |
| `kea-notify` events | local `_kea` | local | a trigger only: insomnia checks the lease before acting (§7.5) |
| Database client libraries | not reachable (memfile only) | E4 | VEX `not_affected` |

Firewall interplay:

- **DHCPv4 in raw mode bypasses nftables.** Kea receives and sends DHCPv4
  through `AF_PACKET` sockets, which see frames before the IP stack. So
  `firewall ipv4 input` rules do not filter it. With `listen-address` (UDP
  mode) they do.
  - The relay receives through UDP, so its traffic is filtered.
  - Only its unicast replies to clients are sent through `AF_PACKET`.
  - The spike confirms this with an input `default-action drop`.
- **DHCPv6 is ordinary UDP** for both Kea and the relay. An input
  `default-action drop` needs a rule for UDP 547. The book says so. Like
  VyOS, insomnia adds no rules automatically.
- **HA** uses TCP 647.

Lease files hold MAC addresses and hostnames: mode 0640, owner `_kea`.

## 13. Interactions

- **VRRP:** split scopes now, HA later (§9). `default-router` normally names the
  VRRP virtual address; nothing to check.
- **eBPF fast path** (`vyos-gap.md` §4.7). XDP runs before `AF_PACKET` taps. If
  cradle's XDP program consumes DHCP broadcasts on an `ebpf enabled` port,
  neither Kea nor the relay sees them. This is a spike item.
- **DHCP client and IPsec `dhcp-interface`.** The client is zebra-rs core and
  out of scope. `dhcp-packet` starts in insomnia's workspace. It moves to
  zebra-rs `crates/` (next to `nd-packet`) if the client wants to share it.
- **DNS forwarding** (`vyos-gap.md` §9, item 4) brings DDNS and
  `hostfile-update` back.
- **Image-based updates** (`design/sbom.md` §7). `/var/lib/insomnia/kea` is
  state that must survive an image switch, as `/config/dhcp` does on VyOS.

## 14. zebra-rs changes

1. **Schema.**
   - Replace `yang/dhcp.yang` with the grouping library (`dhcp-server`, `dhcpv6-server`, `dhcp-relay`, `dhcpv6-relay`, `option-v4`, `option-v6`).
   - Add the gated `service` container to `config.yang` (§3.2) and delete `system dhcp`.
   - Add presence tests next to the firewall, IPsec and VRRP ones.
   - Add `service` to the `insomnia` feature description in `zebra-features.yang`.
2. **Show grammar and routing.**
   - The §11 commands in `exec.yang`, declared through a grouping so the per-VRF form can reuse them.
   - `is_dhcp()` in `config/manager.rs` returning `"dhcp"`, a `"DHCP"` label in `SHOW_PROTOS`, and routing unit tests like the `"vrrp"` ones.

`zebra.config.v1 Subscribe` already takes any path, so no gRPC change is needed.

## 15. Packaging, ISO and SBOM

**insomnia `.deb`:**
- `Recommends: kea-dhcp4-server, kea-dhcp6-server`.
- Assets:
  - `/usr/sbin/insomnia-dhcp-relay` and `/usr/lib/insomnia/kea-notify`;
  - the three units (`insomnia-kea-dhcp4@.service`, `insomnia-kea-dhcp6@.service`, `insomnia-dhcp-relay.service`);
  - `/etc/apparmor.d/insomnia-kea`.
- postinst loads the AppArmor profiles when AppArmor is enabled.
- A CHANGELOG entry.

**folksy-rs `mkiso.sh`** (private repo):
- Keep the two Kea packages, now that they are used.
- `systemctl disable` the stock units.
- Drop the edit to the stock `kea-dhcp6.conf`.

**SBOM (`design/sbom.md`):**
- S10 closes: Kea is integrated, and it is E1 only when bound.
- The relay adds no packages.
- Record VEX for CVE-2025-32801 and CVE-2025-32802 as affected and mitigated (non-root, sandbox, socket permissions).
- Decide separately whether the ISO gains `apparmor`.

## 16. Testing

**Unit (insomnia, CI):**
- **Golden renders** through the `cfg(test)` `render_str` helper, one per mapping-table row in §7.2 and §7.4.
- **Helpers:**
  - the option 121 encoder, against the verified vector;
  - `exclude` slicing, ported from `dhcp_slice_range` with its docstring example;
  - listen-set derivation.
- **Skip-with-warning** tests for every §7.6 row.
- **Show renderers** against Kea 2.4.1 replies captured as fixtures, as the
  VRRP tests do with keepalived's JSON. Shapes:
  - `lease4-get-all`: `cltt`, `hostname`, `hw-address`, `ip-address`, `state`, `subnet-id`, `valid-lft`;
  - `stat-lease4-get`: columns `subnet-id`, `total-addresses`, `cumulative-assigned-addresses`, `assigned-addresses`, `declined-addresses`.
- **Codec:** round-trip and property tests. Fuzz targets run outside `cargo test`.

**Kea acceptance (BDD stage, not CI):** every golden render must also pass
`kea-dhcp4 -t` / `kea-dhcp6 -t`, inside a namespace whose interfaces exist.
Kea rejects missing interfaces, so this cannot run in CI.

**BDD:**
- `@dhcp_server`. `r1` runs zebra-rs, insomnia and Kea in a private mount namespace (`kea_node.sh`, after `vrrp_node.sh`; insomnia with `--kea-control socket`). `h1` runs `dhcpcd` (present on the development host). Scenarios:
  - a lease from the range;
  - a static mapping wins;
  - `show dhcp server leases` lists it;
  - statistics show usage;
  - declarative unload stops serving;
  - teardown.
- `@dhcpv6_server`: an address and a delegated prefix. The PD route appears as `D` in `r1`'s IPv6 RIB, and is gone after the lease is released.
- `@dhcp_relay`: `h1` — `r1` (relay) — `r2` (Kea). `h1` gets a lease from the subnet that matches `r1`'s `giaddr`, and the relay counters move.
- `@dhcpv6_relay`: the same for v6.

## 17. Work breakdown

In order within each track; each item is one PR.

| # | Repo | Branch | Content | Effort |
|:--|:--|:--|:--|:--|
| 1 | zebra-rs | `dhcp-yang` | §14 item 1 | M |
| 2 | zebra-rs | `dhcp-show` | §14 item 2 | S |
| 3 | insomnia | `links` | `crate::links` as proposed in fw-global-options §3.2a, plus interface addresses | S–M |
| 4 | insomnia | `kea-control` | `src/kea.rs`: units, control-socket client, §8.2 sequence, both control modes | M |
| 5 | insomnia | `dhcp4-backend` | `src/dhcp4.rs`: model, renderer, §7.6 checks, golden tests | M |
| 6 | insomnia | `dhcp-show` | the three views for both families, fixtures | S–M |
| 7 | insomnia | `dhcp-packaging` | units, AppArmor profiles, `Recommends`, CHANGELOG | S |
| 8 | insomnia | `dhcp6-backend` | `src/dhcp6.rs` | M |
| 9 | insomnia | `dhcp6-pd-routes` | `kea-notify`, the §7.5 checks, sweep and route install | S–M |
| 10 | insomnia | `dhcp-packet` | the codec crate and fuzz targets | M |
| 11 | insomnia | `dhcp-relay` | the relay daemon (v4 and v6), the relay backend `src/dhcp_relay.rs`, relay statistics | M–L |
| 12 | insomnia | `dhcp-bdd` | the four features, `kea_node.sh`, make targets, docs pages | M |
| 13 | insomnia | `dhcp-docs` | book chapters, AGENTS.md backend notes | S |
| 14 | folksy-rs | `mkiso-kea` | disable the stock units, drop the dhcp6 edit | S |

Server track: 1–2, 3, 4, 5, 6, 7, then 8–9. The relay track (10–11) can
start once item 1 lands. Item 12 follows each track.

## 18. Spike, before item 4

Run in scratch namespaces on the development host (AppArmor enabled), and
once on an ISO build (no AppArmor):

- **The unit as written in §8.3.**
  - Kea starts as `_kea` under the sandbox and the named profile.
  - `kea-lfc` runs under its child profile.
  - Hook libraries load under `NoNewPrivileges`.
- **Interface changes.** What `config-reload` does when the listen interfaces
  change, and what a running Kea does when one disappears.
- **Raw-socket bypass.** DHCPv4 in raw mode is still served with an input
  `default-action drop`. The relay's UDP receive is filtered.
- **cradle.** DHCP broadcasts reach Kea on an `ebpf enabled` port.
- **HA authentication.** Two namespaces: confirm that 2.4.1's dedicated
  listener cannot require basic authentication, and that mutual TLS plus
  `restrict-commands` work.
- **Relay sockets.**
  - Per-device UDP sockets on port 67 receive 255.255.255.255.
  - They coexist with Kea's sockets on other interfaces.
  - An `AF_PACKET` unicast to `chaddr` reaches a client without an address.
- **`run_script` under `_kea`.** It provides `QUERY6_REMOTE_ADDR` and
  `QUERY6_IFACE_NAME` as VyOS's script expects.

## 19. Per-VRF (future)

- **Schema.** `service dhcp-server vrf <name> …`, reusing the same grouping.
  This is zebra-rs's `<feature> vrf <name>` convention (`design/vrrp.md` §13);
  VyOS spells it `vrf name <n> service dhcp-server`.
- **Instances.** One Kea per family per VRF (`insomnia-kea-dhcp4@<vrf>`), which
  is already the path and unit layout.
- **Binding Kea to the VRF.** Kea is not VRF-aware. Run it under the `vrf.o`
  preload shim from `design/vrrp.md` §13, through the instance's environment
  file, or under `ip vrf exec` as VyOS does. `ip vrf exec` needs root to attach
  its cgroup program and then a drop to `_kea`.
  - `AF_PACKET` sockets are per interface and need nothing.
  - UDP sockets (UDP mode, DHCPv6, HA) need the binding.
  - Shares the VRRP VRF spike.
- **Relay.** It binds per-VRF sockets itself. VyOS has no VRF relay; ours would
  be `service dhcp-relay vrf <name>`.
- **Show.** `show dhcp server vrf <name> …`, as VyOS has.

## 20. Deferred, with reasons

| Item | Reason |
|:--|:--|
| HA | §9: needs `pki` for mutual TLS |
| `dynamic-dns-update`, `hostfile-update` | need a DNS server or forwarder; come with `service dns forwarding` |
| `ping-check` | no hook in Ubuntu's 2.4.1 |
| `clear dhcp-server lease`, `restart dhcp …` | the non-show verbs, `vyos-gap.md` §4.2 |
| PD route installation in the relay (RFC 8987) | the first improvement for the native relay once it ships |
| `origin remote`, relay-agent information in `show` | needs HA, or Kea's extended lease info |
| DHCP client (`interface … address dhcp`, `show dhcp client leases`, `renew` / `release`) | zebra-rs core |
| Newer Kea (ISC packages, or the next base LTS) | when the base LTS moves, or when 2.4.1 blocks a needed feature; brings path restrictions and `ping_check` |

## 21. References

- **vyos-1x `rolling` @ `089c767`:**
  - `interface-definitions/service_dhcp-server.xml.in`, `service_dhcpv6-server.xml.in`, `service_dhcp-relay.xml.in`, `service_dhcpv6-relay.xml.in`, `vrf.xml.in`, `include/dhcp/`;
  - `src/conf_mode/service_dhcp-server.py`, `service_dhcpv6-server.py`, `service_dhcp-relay.py`, `service_dhcpv6-relay.py`;
  - `data/templates/dhcp-server/`, `data/templates/dhcp-relay/`;
  - `python/vyos/kea.py`, `python/vyos/template.py`;
  - `src/op_mode/dhcp.py`, `op-mode-definitions/dhcp.xml.in`;
  - `src/etc/systemd/system/isc-kea-*`, `src/systemd/isc-dhcp-relay{,6}.service`;
  - `src/system/kea-vrf-helper`, `src/system/on-dhcpv6-event.sh`.
- **Ubuntu noble `isc-kea` 2.4.1-3ubuntu0.2:**
  - `kea-common`, `kea-dhcp4-server`, `kea-dhcp6-server`;
  - file lists, `usr.sbin.kea-dhcp{4,6}` and `usr.sbin.kea-lfc` AppArmor profiles, `changelog.Debian.gz`.
- **ISC:**
  - [ISC DHCP](https://www.isc.org/dhcp/): the relay's end of development;
  - [ISC DHCP Server has reached EOL](https://www.isc.org/blogs/isc-dhcp-eol/).
- **Ubuntu CVE tracker:** [CVE-2025-32801](https://ubuntu.com/security/CVE-2025-32801), [CVE-2025-32802](https://ubuntu.com/security/CVE-2025-32802).
- **RFCs:**
  - RFC 2131 / 1542 (DHCPv4, relay); RFC 3046 (option 82); RFC 3442 (option 121);
  - RFC 8415 (DHCPv6, relay); RFC 8925 (option 108);
  - RFC 8987 (relay routes for delegated prefixes); RFC 9243 (DHCPv6 YANG).
- **zebra-rs:**
  - `zebra-rs/yang/dhcp.yang`, `config.yang` (`system dhcp`, `interface … ipv4 address`), `zebra-features.yang`;
  - `src/rib/link.rs`, `src/fib/netlink/handle.rs` (`RibType::Dhcp`), `src/config/manager.rs` (`SHOW_PROTOS`).
- **insomnia:**
  - `src/keepalived.rs` (process-control pattern), `src/provider.rs`;
  - `packaging/systemd/insomnia-keepalived@.service`;
  - `design/vrrp.md`, `design/vyos-gap.md`, `design/sbom.md`, [plans/fw-global-options](plans/fw-global-options.md).
