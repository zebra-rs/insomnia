# DHCP server and relay BDD suite, with VRFs — design

Status: implemented, 2026-11-09. Phases R1 and R2 (`@dhcp_relay`,
`@dhcpv6_relay`, `@dhcp_relay_vrf`), then S1, S2, V1 and V2
(`@dhcp_server`, `@dhcpv6_server`, `@dhcp_server_relay`,
`@dhcp_server_vrf`, `@dhcp_vrf_e2e`) with the Kea backend the same day;
what changed on the way is in §10. This replaces the
BDD paragraph of `design/dhcp.md` §16 and expands work item 12 of
`design/dhcp.md` §17 into one item per feature (§9).

The suite drives the whole chain with real daemons inside network namespaces:
- zebra-rs's `service` trees, VRFs and interfaces;
- insomnia's relay and server backends;
- the insomnia-dhcp-relay agent and Kea;
- real DHCP clients.

It covers the default VRF and VRFs, including two VRFs that use the same
addresses. It is built on the existing harness (`bdd/`): scoped namespaces,
node scripts in private mount namespaces, `I apply config`, `show command`
and `command` assertions, and `the test environment should be clean`.

Baselines:

| Source | Version |
|:--|:--|
| insomnia | `main` @ `7b5fa01`, plus branch `dhcp-relay-backend` (relay backend, signal mode, `--pid-file`) |
| zebra-rs | branch `service-dhcp-relay` (the relay trees, `show dhcp[v6] relay statistics`) |
| Kea | Ubuntu 24.04 `2.4.1-3ubuntu0.2` |
| Client | `dhcpcd` (present on the development host) |

## Decisions at a glance

| # | Question | Decision | § |
|:--|:--|:--|:--|
| B1 | Features | Eight, in four phases that follow the implementation: relay (3, runnable now), server (3), server per VRF (1), relay to server per VRF (1) | 3 |
| B2 | Who runs the daemons | The harness, in signal mode (`design/process.md` §7): node scripts start zebra-rs, insomnia, the relay agent and Kea inside the router's private mount namespace | 4.1 |
| B3 | VRF binding in BDD | VRFs, members and their addresses come from zebra-rs config. Kea instances in a VRF start under `ip vrf exec <vrf>`, the kernel hook the units use (`design/process.md` §4.7) | 4.2 |
| B4 | Overlapping tenants | VRF features give `red` and `blue` the same subnets with disjoint pools, so the address a client gets proves which server answered | 3.3 |
| B5 | Relay features' servers | A standalone Kea per server namespace, from a fixed JSON config, not managed by insomnia. The relay is under test, not the server | 4.3 |
| B6 | Proving option 82 and Interface-ID end to end | The server puts a client in a class matched on the relay's circuit-id or interface-id, and the class has its own range | 3.1, 3.2 |
| B7 | Clients | `dhcpcd` per client namespace, with a private `/run` and `/var/lib/dhcpcd`, through `dhcp_client.sh` | 4.4 |
| B8 | New steps | Five DHCP-client steps and one generic log step; everything else reuses existing steps | 5 |
| B9 | Out of BDD | systemd units, sandboxes and `BPFProgram=` binding (root-only scripts), HA, DDNS, fuzzing, `kea -t` acceptance | 8 |

## 1. What the suite must prove

| Area | Claim |
|:--|:--|
| Schema → render | A `set service …` commit reaches the agent's `relay.json` and Kea's config, and a `delete` reaches them too |
| Relay v4 | giaddr, hop count, option 82 with the listen interface as circuit-id, broadcast and unicast replies (`design/dhcp.md` §10.2) |
| Relay v6 | Relay-forw / Relay-repl, link-address, Interface-ID on and off (§10.3) |
| Relay safety | A client's forged BOOTREPLY or Relay-repl is dropped and counted (§10.2) |
| Server v4 | ranges, `exclude`, static mappings, options including option 121 as raw data, client classes, listen set (DH8) |
| Server v6 | IA_NA, static mappings by DUID, options, IA_PD and the `proto dhcp` route insomnia installs (DH9) |
| Lifecycle | `config-reload` keeps leases (DH5); Kea and the agent keep serving while insomnia is stopped; `disable` and `delete` stop serving |
| Show | relay statistics; server leases, statistics and static mappings, per VRF; `show process` |
| VRF | relay and server per VRF; overlapping tenants stay apart; a VRF that is deleted and re-created comes back |

## 2. Topology conventions

- **Nodes:**
  - `c1`, `c2`, … are clients;
  - `r1` and `r2` are routers: zebra-rs, insomnia and the relay agent, plus Kea where the feature tests the server;
  - `s1`, `sred`, `sblue` are standalone servers.
- **Links** use `I connect namespace … interface … to namespace … interface …` with names chosen per feature: `lan1`, `lan2`, `wan1`, `lanred`, `wanblue`. All are under the 15-byte limit.
- **Client MACs are fixed** (`ip link set c0 address 02:00:00:00:01:01`), so static mappings and lease assertions are deterministic.
- **Router addresses** are set through zebra-rs config (`set interface lanred ipv4 address …`), not `ip`: zebra-rs enslaves an interface to its VRF before adding addresses, and enslaving flushes IPv6 addresses added earlier.
- **Addressing plan:**

| Network | IPv4 | IPv6 |
|:--|:--|:--|
| Client LAN 1 / `red` LAN / `blue` LAN | `10.1.0.0/24`, router `.1` | `2001:db8:1::/64`, router `::1` |
| Client LAN 2 | `10.2.0.0/24` | `2001:db8:2::/64` |
| Default-VRF LAN in VRF features | `10.9.0.0/24` | `2001:db8:9::/64` |
| Server side (every VRF the same) | `192.0.2.0/24`, server `.10` | `2001:db8::/64`, server `::10` |
| Delegated prefixes | — | pool `2001:db8:8000::/48`, `/56` each |

- **Pools that tell servers apart:** `red` hands out `10.1.0.100–149` and `2001:db8:1::100–14f`; `blue` hands out `10.1.0.150–199` and `2001:db8:1::150–19f`. In relay features, the class matched on option 82 gets `10.1.0.50–59`.

## 3. Features

Each feature ends with `Scenario: Teardown topology` and
`the test environment should be clean`. Tags put the feature tag first,
because the first non-special tag scopes every namespace:
`@serial @dhcp_relay @dhcp`.

### 3.1 Phase R1: `@dhcp_relay` (DHCPv4 relay, default VRF)

```
c1 (c0) ── lan1 ─ r1 ─ wan1 ── (s0) s1   standalone kea-dhcp4
c2 (c0) ── lan2 ─┘
```

- **`s1` serves both client LANs by giaddr.** A class `circuit-lan1` (`relay4[1].hex == 'lan1'`) gets `10.1.0.50–59`; everyone else gets the normal range.
- **Config:**
  ```
  set service dhcp-relay listen-interface lan1
  set service dhcp-relay listen-interface lan2
  set service dhcp-relay upstream-interface wan1
  set service dhcp-relay server 192.0.2.10
  ```

Scenarios:
1. **Setup:** topology, `dhcp_node.sh` on `r1`, `kea_server.sh` on `s1`, apply config. The agent log shows `dhcp4 listen lan1: open`.
2. **Lease through the relay, unicast reply:** `c1` gets an address in `10.1.0.50–59`, which proves option 82 reached the server with circuit-id `lan1`. The lease carries `routers 10.1.0.1`.
3. **Broadcast reply:** `c2` with the broadcast flag (`dhcpcd -J`) gets an address in `10.2.0.0/24`, from the normal range: its circuit-id is `lan2`.
4. **Counters:** `show dhcp relay statistics` lists `lan1`, `lan2` and `wan1` with `Forwarded` above zero; `-j` gives the same rows.
5. **A forged reply is dropped:** `dhcp_forge.py` on `c1` sends a BOOTREPLY to `10.1.0.1:67` with giaddr `10.2.0.1`. `show dhcp relay statistics` shows `wrong-upstream`, and nothing reaches `c2`: a capture on `c2` stays empty.
6. **Hop limit:** with `relay-options hop-count 2`, a forged request with `hops 2` is dropped as `hop-limit`.
7. **Adding a listen interface does not disturb the others:** `c1` gets the same address again while `lan2` is removed and re-added.
8. **`disable`, then `delete`:** `ss -ulpn` in `r1` shows no `insomnia-dhcp` sockets, and `c1` gets no address. Re-applying the config brings leases back.
9. **Teardown.**

### 3.2 Phase R1: `@dhcpv6_relay` (DHCPv6 relay, default VRF)

The same topology, with standalone `kea-dhcp6` on `s1`. A class
`ifid-lan1` (`relay6[0].option[18].hex == 'lan1'`) gets
`2001:db8:1::50–5f`.

Scenarios:
1. **Setup** with `listen-interface lan1`, `upstream-interface wan1 address 2001:db8::10`.
2. **IA_NA through the relay:** `c1` gets an address in the normal range (no Interface-ID yet), selected by link-address `2001:db8:1::1`.
3. **Interface-ID on:** after `set service dhcpv6-relay use-interface-id-option`, `c1` gets an address in `2001:db8:1::50–5f`.
4. **Explicit link-address:** `listen-interface lan1 address 2001:db8:1::1` keeps the selection; an address outside every subnet makes the server refuse, and the client gets nothing.
5. **Counters and a forged Relay-repl:** `dhcp_forge.py` sends a Relay-repl from `c1` to `r1`'s link-local address. The counter `unknown-server` moves, and nothing reaches the client.
6. **Multicast server:** `upstream-interface wan1 address ff05::1:3` still yields a lease.
7. **Delete; teardown.**

### 3.3 Phase R2: `@dhcp_relay_vrf` (both families, two overlapping VRFs)

```
c1 (c0) ── lanred  ─┐            ┌─ wanred  ── (s0) sred    kea4 + kea6, pools .100–149
                    r1 (red,blue) │
c2 (c0) ── lanblue ─┘            └─ wanblue ── (s0) sblue   kea4 + kea6, pools .150–199
c9 (c0) ── lan9 (default VRF) ── r1 ── wan9 ── (s0) s9
```

- **`red` and `blue` use identical addresses.** `lanred` and `lanblue` are both `10.1.0.1/24` and `2001:db8:1::1/64`; `wanred` and `wanblue` are both `192.0.2.1/24` and `2001:db8::1/64`.
- **zebra-rs config:**
  ```
  set vrf red
  set vrf blue
  set interface lanred vrf red
  set interface wanred vrf red
  set interface lanblue vrf blue
  set interface wanblue vrf blue
  (addresses as above)
  set service dhcp-relay vrf red listen-interface lanred
  set service dhcp-relay vrf red upstream-interface wanred
  set service dhcp-relay vrf red server 192.0.2.10
  (blue the same with its interfaces)
  set service dhcp-relay listen-interface lan9 …                (default VRF)
  set service dhcpv6-relay vrf red listen-interface lanred
  set service dhcpv6-relay vrf red upstream-interface wanred address 2001:db8::10
  (blue and the default VRF the same)
  ```

Scenarios:
1. **Setup.** The agent log eventually shows `dhcp4 vrf red address 10.1.0.1: open` and the same for `blue`. "Eventually", because the agent may read the interfaces while zebra-rs is still moving them into the VRF; its first bind then fails and its 5 s retry succeeds.
2. **Each tenant's client gets a lease from its own server:** `c1` in `10.1.0.100–149`, `c2` in `10.1.0.150–199`, `c9` in `10.9.0.0/24`. The same for IPv6.
3. **Counters per VRF:** `show dhcp relay statistics` has rows for `default`, `red` and `blue`.
4. **Isolation in the routing tables:** `ping` from `r1` to `192.0.2.10` fails in the default VRF; `ip vrf exec red ping 192.0.2.10` reaches `sred`, never `sblue`. The kernel route for `192.0.2.0/24` appears in both VRF tables and not in the main table.
5. **No cross-tenant reply:** a forged BOOTREPLY on `lanred` with giaddr `10.1.0.1` is dropped (`wrong-upstream`), and nothing reaches `c2`.
6. **Removing one tenant leaves the other alone:** `delete service dhcp-relay vrf blue`, after which `c2` gets nothing and `c1` still gets its lease. The agent log closes only `blue`'s sockets.
7. **A VRF that is deleted and re-created comes back:** `delete vrf blue`, then the config again. The agent reopens `blue`'s sockets, and `c2` gets a lease.
8. **Teardown.**

### 3.4 Phase S1: `@dhcp_server` (DHCPv4 server, default VRF)

```
c1 (c0) ── lan1 ─┐
c2 (c0) ── lan2 ─┼─ r1   zebra-rs + insomnia + kea-dhcp4 (dhcp_node.sh … kea default)
c3 (c0) ── lan3 ─┘       (lan3 has an address but no subnet)
```

- **Config:** shared network `LAN` with `10.1.0.0/24` (`subnet-id 1`), range `.100–.199`, `exclude 10.1.0.100`, and options:
  - `default-router`, `name-server`, `domain-name`;
  - `static-route 198.51.100.0/24 next-hop 10.1.0.1`;
  - `ntp-server`.
- **Also:** a static mapping `printer` (`c1`'s MAC → `10.1.0.10`); a client class `voip` on `vendor-class-id` with range `.50–.59` in shared network `LAN2` (`10.2.0.0/24`).

Scenarios:
1. **Setup.** The insomnia log shows `config-reload`, and Kea's log shows the subnet.
2. **Static mapping:** `c1` gets `10.1.0.10`.
3. **Range, `exclude` and options:** a second client on `lan1` gets `10.1.0.101`, not `.100`. Its lease carries `routers`, `domain_name_servers`, `domain_name` and `ntp_servers`. The kernel route `198.51.100.0/24 via 10.1.0.1` appears on the client, which proves the raw option 121 encoding (`design/dhcp.md` §7.2).
4. **Client class:** `c2` with `dhcpcd -i <voip vendor class>` gets an address in `10.2.0.50–59`.
5. **Listen set (DH8):** `c3` on `lan3`, which has no subnet, gets nothing; Kea's log shows it is not listening on `lan3`.
6. **Show commands:**
   - `show dhcp server leases` lists `c1` and the second client;
   - `… leases pool LAN` filters;
   - `show dhcp server statistics` shows `LAN` with 2 leases;
   - `show dhcp server static-mappings` lists `printer`.
7. **A config change keeps leases:** adding `option time-zone` makes the insomnia log show a reload. The leases are still listed, and `c1` renews to the same address.
8. **insomnia stopped, Kea keeps serving:**
   - stop insomnia (`dhcp_node.sh … stop-insomnia`);
   - a new client still gets a lease;
   - start insomnia again: its log says the configuration is unchanged, and Kea is not reloaded.
9. **Render-time skip:** a subnet whose range lies outside it is skipped with a warning naming it, while the rest is still served.
10. **`disable`, then `delete`:** clients get nothing, and `show dhcp server leases` answers that nothing is served.
11. **Teardown.**

### 3.5 Phase S1: `@dhcpv6_server` (DHCPv6 server, default VRF)

The same router. `c1` asks for IA_NA, `c2` for IA_PD (`ia_pd 1` in its
`dhcpcd.conf`).

Scenarios:
1. **IA_NA from the range,** with `name-server` and `domain-search` in the reply.
2. **Static mapping by DUID:** `c1`'s DUID-LL gets `2001:db8:1::10`.
3. **Prefix delegation (DH9):** `c2` gets a `/56` from `2001:db8:8000::/48`. On `r1`, the kernel route for it via `c2`'s link-local address is `proto dhcp` and appears in zebra-rs's IPv6 RIB as `D`.
4. **Release removes the route:** `dhcp_client.sh … release` sends the release; the route is gone, and the lease shows released.
5. **`disable-route-autoinstall`:** a delegation installs no route.
6. **Show:** `show dhcpv6 server leases` lists both, with type `IA_PD` for `c2`.
7. **Teardown.**

### 3.6 Phase S2: `@dhcp_server_relay` (our relay to our server)

```
c1 (c0) ── lan1 ─ r1 (relay) ─ wan1 ── r2 (server: zebra-rs + insomnia + Kea)
c2 (c0) ── lan2 ─┘
```

- **`r2` serves only relayed traffic:** `listen-address 192.0.2.2` for v4 (Kea's UDP socket, DH8), `listen-interface wan1` for v6.
- **One shared network holds `10.1.0.0/24` and `10.2.0.0/24`.** A client class on `relay-agent-information circuit-id lan1` gets `10.1.0.50–59`.

Scenarios:
1. **Subnet by giaddr:** `c1` gets an address in `10.1.0.50–59` (class matched), `c2` an address in `10.2.0.0/24`.
2. **v6 by link-address,** with Interface-ID on.
3. **Counters on both routers:** the relay statistics on `r1`, and the server statistics on `r2`.
4. **Teardown.**

### 3.7 Phase V1: `@dhcp_server_vrf` (servers per VRF, overlapping tenants)

```
c1 (c0) ── lanred  ─┐
c2 (c0) ── lanblue ─┼─ r1   Kea instances default, red, blue (kea4 + kea6 each)
c9 (c0) ── lan9    ─┘
```

- **`red` and `blue` each run** `service dhcp-server vrf <name>` and `service dhcpv6-server vrf <name>`. Both tenants serve `10.1.0.0/24` and `2001:db8:1::/64`, with the disjoint pools of §2. The default VRF serves `10.9.0.0/24`.
- **The harness starts each instance** with `dhcp_node.sh <ns> kea <vrf>`, under `ip vrf exec <vrf>` for `red` and `blue`.

Scenarios:
1. **Each tenant's client gets a lease from its own instance:** `c1` in `10.1.0.100–149`, `c2` in `10.1.0.150–199`, `c9` in `10.9.0.0/24`. IPv6 the same.
2. **Show per VRF:** `show dhcp server vrf red leases` lists `c1` and not `c2`; the statistics are per VRF.
3. **`show process`** lists `kea-dhcp4@default`, `kea-dhcp4@red`, `kea-dhcp4@blue` and `dhcp-relay`, all running (`design/process.md` §6.3, signal mode).
4. **PD in a VRF:** a client on `lanred` with IA_PD makes `r1` install the route in `red`'s table (`ip -6 route show vrf red … proto dhcp`), not in the main table.
5. **Removing one tenant:** `delete service dhcp-server vrf blue`; `c2` gets nothing, and `red` keeps serving.
6. **Teardown.**

### 3.8 Phase V2: `@dhcp_vrf_e2e` (relay per VRF to server per VRF)

```
c1 ── lanred  ─┐                ┌─ red   ─┐
               r1 (relay red,blue) ─ wan ─ r2 (server red,blue)
c2 ── lanblue ─┘                └─ blue  ─┘
```

- **The link between the routers carries each VRF on its own pair of interfaces** (`wanred`, `wanblue`). Both tenants use the same addresses.

Scenarios:
1. **Both tenants get leases from their own `r2` instance through their own `r1` relay instance,** in both families.
2. **The relay statistics and the server leases on both routers line up per VRF.**
3. **Teardown.**

## 4. Harness additions

### 4.1 `dhcp_node.sh` (router)

After `vrrp_node.sh`:
- **Private mount namespace** (`unshare -m`), with tmpfs over `/run`, `/var/lib/insomnia` and `/etc/swanctl`.
- **Start order:**
  - the relay agent: `insomnia-dhcp-relay --pid-file /run/insomnia/dhcp-relay/relay.pid`;
  - zebra-rs: `--feature insomnia`, `-c /dev/null`, the staged YANG;
  - insomnia: `--keepalived-control signal --dhcp-relay-control signal --kea-control socket`.
- **Host-global pid files:** `/tmp/<ns>.{relay,insomnia}.pid`.
- **Logs:** `logs/<ns>.relay.log` and `logs/<ns>.insomnia.log`, beside zebra-rs's `logs/<ns>.log`.
- **Subcommands:**
  - `kea <vrf>`: enter the node's mount and network namespaces (`nsenter -t <insomnia pid> -m -n`). Write a bootstrap config at the path insomnia renders (`/run/insomnia/kea/<vrf>/kea-dhcp{4,6}.conf`): no interfaces, the instance's control socket, the memfile under `/var/lib/insomnia/kea/<vrf>`. Start `kea-dhcp4` and `kea-dhcp6` on it, under `ip vrf exec <vrf>` unless `<vrf>` is `default`. insomnia's later `config-test` and `config-reload` replace the bootstrap, as SIGHUP replaces keepalived's empty file.
  - `stop-insomnia` and `start-insomnia`, for §3.4 scenario 8.
- **`dhcp_node_stop.sh`:** stops Kea, the agent and insomnia. zebra-rs is stopped by the regular step.

### 4.2 VRFs

- **VRFs, members and their addresses** are zebra-rs config applied by the feature, as tested by hand on 2026-11-08.
- **Kea in a VRF runs under `ip vrf exec`.** The relay agent needs nothing: it binds its own VRF sockets.

### 4.3 `kea_server.sh` (standalone server)

- **Runs `kea-dhcp4` and/or `kea-dhcp6`** in a server namespace on `tests/configs/<tag>/<node>-kea{4,6}.json`. The `.json` configs are hand-written, as in the manual relay tests.
- **Per-node files:** `KEA_LOCKFILE_DIR` and `KEA_PIDFILE_DIR` point at `/tmp/<ns>.kea/`; logs go to `logs/<ns>.kea{4,6}.log`.
- **No mount namespace is needed:** every path is per node.

### 4.4 `dhcp_client.sh`

- **`dhcp_client.sh <ns> <iface> 4|6|pd [dhcpcd args]`:**
  - one `dhcpcd -B -1 -L -t 25` run inside `unshare -m`, with tmpfs over `/run` and `/var/lib/dhcpcd`, because the host runs its own dhcpcd;
  - writes the lease variables (`dhcpcd -U`) to `logs/<ns>.<iface>.lease{4,6}`;
  - exits with dhcpcd's status.
- **`dhcp_client.sh <ns> <iface> pd-hold` and `release`:** for §3.5 scenario 4, dhcpcd stays running in the background, and `release` sends it SIGHUP (dhcpcd's own `-k`).
- **IPv6 runs wait for DAD** on the client's link-local address before starting.

### 4.5 `dhcp_forge.py`

`python3 -I`, run in a client namespace. It sends one crafted message:
- a BOOTREPLY with a given giaddr to a relay address;
- a BOOTREQUEST with a given `hops`;
- a Relay-repl with a given link-address to a relay's link-local address.

These are the packets used by hand on 2026-10-27 and 2026-11-08.

### 4.6 Make targets

- **One target per feature** (`make -C bdd dhcp_relay`, …), each with a comment listing the host packages it needs.
- **An aggregate `make -C bdd dhcp`** (`--tags "@dhcp"`).
- **`stage` already builds and copies `insomnia-dhcp-relay`.**

## 5. New steps

The harness is shared with zebra-rs, so the new steps keep its vocabulary. On
failure, each DHCP-client step dumps the tail of the node logs, the relay
statistics and the server logs, so a failure is diagnosable from the log alone.

| Step | Does |
|:--|:--|
| `DHCPv4 client on interface {string} in namespace {string} should obtain an address in {string}` | runs `dhcp_client.sh … 4`; the address must fall in the prefix or the `a–b` range |
| `DHCPv6 client on interface {string} in namespace {string} should obtain an address in {string}` | the same with `6` |
| `DHCPv6 client on interface {string} in namespace {string} should obtain a prefix in {string}` | the same with `pd` |
| `DHCPv4 client on interface {string} in namespace {string} should not obtain an address` | at most 15 s; also a `DHCPv6` form |
| `the DHCPv4 lease on interface {string} in namespace {string} should have {string} {string}` | one `dhcpcd -U` variable, e.g. `routers` `10.1.0.1`; also a `DHCPv6` form |
| `log {string} in namespace {string} should eventually contain {string}` | `logs/<ns>.<name>.log` for `relay`, `kea4`, `kea6`, …; it generalizes the insomnia and daemon log steps, which stay |

Everything else reuses existing steps:
- `I apply config`, `I apply command` (for `delete …`: `vtyctl apply` merges, so removals need explicit deletes);
- `show command … should eventually contain` (with the full `show …` string);
- `command … should eventually contain`, `kernel route …`, `ping …`;
- `I execute`, `I spawn`, `I run`.

## 6. Host requirements

- **`kea-dhcp4-server` and `kea-dhcp6-server`** (Ubuntu noble). The distribution units can stay disabled: the stock config binds no interface, and the nodes use private `/run`. On a host without the packages, `KEA_PREFIX=<tree>` points the scripts at an unpacked copy, and they set `LD_LIBRARY_PATH` from it, as the manual tests did.
- **`dhcpcd`** (present), **`python3`**, **`tcpdump`** (for the "nothing reaches `c2`" checks).
- **`ip vrf exec`** needs cgroup v2 mounted, which is the default on noble.
- **The staged zebra-rs** must include the `service` trees: `make -C bdd stage ZEBRA_PREFIX=…` until a zebra-rs release has them.

## 7. Coverage

| Claim (§1) | relay | v6 relay | relay VRF | server | v6 server | server + relay | server VRF | VRF e2e |
|:--|:--|:--|:--|:--|:--|:--|:--|:--|
| Schema → render, delete | ● | ● | ● | ● | ● | ● | ● | ● |
| giaddr, option 82 class | ● | | ● | | | ● | | ● |
| Broadcast and unicast replies | ● | | | ● | | | | |
| Link-address, Interface-ID | | ● | ● | | | ● | | ● |
| Forged replies dropped | ● | ● | ● | | | | | |
| Ranges, exclude, static mappings, options, classes | | | | ● | ● | ● | ● | |
| Option 121 raw encoding | | | | ● | | | | |
| Listen set (DH8) | | | | ● | | ● | | |
| PD route (DH9) | | | | | ● | | ● | |
| `config-reload` keeps leases | | | | ● | | | | |
| Survives insomnia stop | | | | ● | | | | |
| Show commands | ● | ● | ● | ● | ● | ● | ● | ● |
| `show process` | | | | | | | ● | |
| Overlapping tenants | | | ● | | | | ● | ● |
| VRF deleted and re-created | | | ● | | | | | |

## 8. Not in BDD, and where it is covered

| What | Why not BDD | Where |
|:--|:--|:--|
| systemd units, the relay and Kea sandboxes | BDD runs in signal mode | a root-only script repeating the 2026-11-08 transient-unit test (`bdd/tests/scripts/dhcp_units.sh`) |
| `BPFProgram=` VRF binding and the pin lifecycle | the same | `vrf_units.sh` (`design/process.md` §10) |
| `kea-dhcp4 -t` acceptance of every golden render | needs only namespaces, not a topology | the Kea acceptance stage of `design/dhcp.md` §16 |
| HA | waits for `pki` (DH7) | a later `@dhcp_ha` feature |
| DDNS, `hostfile-update`, `ping-check` | not carried over (`design/dhcp.md` §3.3) | — |
| Codec robustness | not a topology question | unit tests and fuzz targets |
| Kea's raw-socket firewall bypass | a property of Kea, recorded in `design/dhcp.md` §12 | the spike |

## 9. Order and readiness

| Phase | Features | Needs | Ready |
|:--|:--|:--|:--|
| R1 | `@dhcp_relay`, `@dhcpv6_relay` | the relay branches; §4 scripts and §5 steps | implemented |
| R2 | `@dhcp_relay_vrf` | the same | implemented |
| S1 | `@dhcp_server`, `@dhcpv6_server` | `design/dhcp.md` §17 items 1–9 (schema, Kea control, backends, show, PD routes) | implemented |
| S2 | `@dhcp_server_relay` | S1 | implemented |
| V1 | `@dhcp_server_vrf` | the server trees' `vrf` lists, per-VRF Kea, `show process` (`design/process.md`) | implemented |
| V2 | `@dhcp_vrf_e2e` | V1 | implemented |

The scripts and steps of §4 and §5 land with phase R1. Each later phase adds
only its feature, configs and docs page (`make -C bdd docs`).

## 10. Implementation notes

What the implementation changed against §3–§6, and why:

- **zebra-rs readiness.** The `show …` steps fail on the first connection
  error instead of retrying, and a debug zebra-rs takes seconds to start
  serving. Each router therefore waits for `insomnia log … "show provider
  registered"` first: insomnia registers only once zebra-rs accepts gRPC.
- **Kea and DAD.** kea-dhcp6 joins ff02::1:2 through a socket on the
  interface's link-local address. Started while that address is tentative,
  it fails the bind, never retries, and serves unicast only.
  `kea_server.sh` waits for duplicate address detection to finish. The same
  trap applies to an insomnia-managed Kea (`design/dhcp.md` §7.3).
- **Client identity.** `clientid ""` makes dhcpcd 10.0.6 send a one-byte
  client identifier, which Kea refuses ("identifier is too short").
  `dhcp_client.sh` sends `clientid 01:<mac>` instead.
- **Lease variables** come from a dhcpcd hook (`new_*` variables on every
  bind), not `dhcpcd -U`: in dhcpcd 10, `-U` asks a running daemon, and a
  one-shot run has exited by then.
- **Log marks.** The harness marked only zebra-rs's and insomnia's logs
  when a node started, so log steps could match an earlier run's lines.
  `mark_log_start` now marks every `logs/<ns>.*.log`, and Kea servers are
  started with `I spawn` so their logs are marked too.
- **Kea from an unpacked tree.** The harness runs scripts through
  `sudo ip netns exec … env PATH=…`, which drops other variables, so
  `KEA_PREFIX` is recorded in the stage (`.stage/kea-prefix`) by
  `make stage KEA_PREFIX=…`.
- **§3.1 scenario 5.** The forged reply is asserted by the agent's drop log
  and the `wrong-upstream` counter. The "nothing reaches `c2`" capture was
  left out: the agent never sends a packet it drops.
- **§3.1 scenario 7** became: with `lan2` removed, `c2` gets nothing and
  `c1` still gets its lease; re-adding `lan2` brings `c2` back.
- **§3.2 scenario 6** uses `ff02::1:2`, not `ff05::1:3`, as the multicast
  server address: Kea 2.4.1 joins only ff02::1:2 (its sockets show
  `[ff02::1:2]%s0`).
- **§3.3 scenario 4** checks the routes with `ip route show vrf …` and the
  main table, `ping` from the default VRF failing, and
  `ip vrf exec red ping` reaching `sred`. Scenario 7 removes the members'
  `vrf` leaves before `delete vrf blue` (they are leafrefs to it), keeps
  the relay config, and checks that the agent waits for the VRF device and
  recovers when the config is applied again.
- **The agent** now logs a successful upward DHCPv6 relay at debug level,
  as it already did for DHCPv4; without it, a lost packet could not be
  placed between the agent and the server.
- **Router Kea (S1).** `dhcp_node.sh NS kea` starts kea-dhcp4 and kea-dhcp6
  on a bootstrap configuration at the paths insomnia renders to, before
  insomnia (`--kea-control socket`, leases under `/run/insomnia/kea-state`
  inside the node's private `/run`). `stop-insomnia` / `start-insomnia`
  re-enter the node's mount namespace with `nsenter --wd`, because
  `nsenter -m` otherwise starts in `/`.
- **Requested options.** Kea sends only the options a client asks for, so
  the S1 lease assertions run dhcpcd with `option …` lines (`option
  ntp_servers`, `option tzdb_timezone`, `option dhcp6_name_servers`, …).
- **§3.4.** c1's MAC address is pinned for the static mapping; scenario 3's
  "second client on lan1" is c1 with another MAC address (a new client-id
  and chaddr), which gets `10.1.0.101`. The option 121 check is the
  `classless_static_routes` lease variable (`198.51.100.0/24 10.1.0.1
  0.0.0.0/0 10.1.0.1`), not a kernel route: dhcpcd's one-shot run does
  not keep its routes. The reload scenario proves the reload with a new
  option (`time-zone` → `tzdb_timezone`) on a renewed lease. The skip
  scenario adds a range outside its subnet (a separate config file: `start`
  and `stop` are mandatory, so one `vtyctl apply -c` line cannot carry
  them). The listen-set check is the absence of a packet socket on lan3.
- **§3.5.** The static mapping and the range use c1's DUID-LL, changed by
  changing its MAC address. "Release removes the route" became "the route
  goes when the lease expires": the PD subnet has a 20-second lease, and
  Kea's reclaim timer runs the `lease6_expire` hook; releasing would need
  a long-running dhcpcd per client. The new step `DHCPv6 client … should
  obtain a prefix in …` reads dhcpcd's `dhcp6_ia_pd1_prefix1` variables.
- **Found by the suite:** Kea 2.4 answers NoAddrsAvail to a directly
  connected DHCPv6 client unless the subnet has an `interface`, so the
  renderer now fills it in (`design/dhcp.md` §7.4).
- **§3.6 (S2).** A shared network is one link to Kea: giaddr or
  link-address picks the network, then any of its subnets may serve. The
  DHCPv4 side keeps the planned single network (its 10.1.0.0/24 has only
  the class range, so a client without circuit-id `lan1` can only get
  10.2.0.0/24); the DHCPv6 subnets get a network each. Kea 2.4 receives
  DHCPv6 on each interface's link-local and ff02::1:2 sockets, and VyOS's
  `listen-interface` cannot name a unicast address, so the relay sends to
  ff02::1:2 on the server link.
- **§3.7 (V1).** `show process` runs in signal mode: the rows come from
  the instances' pid files (Kea's own, in the instance directory), and
  `stop process` is refused because the harness owns the processes. The
  systemd side (pins, units, holds) is `vrf_units.sh`
  (`design/process.md` §10). VRF instances start after zebra-rs
  has created the VRFs (`dhcp_node.sh … kea-vrf <vrf>`, under
  `ip vrf exec`); insomnia retries an instance that no Kea answers every
  5 s, and the script starts Kea on a configuration insomnia already
  rendered rather than overwriting it. "Removing one tenant" deletes
  `service dhcp-server vrf blue`: blue's instance is loaded idle.
- **§3.8 (V2).** r2 serves both tenants with `listen-address 192.0.2.2` in
  each VRF: two UDP sockets on the same address and port, each bound to
  its VRF by `ip vrf exec`. The return routes to the tenants' LAN are
  kernel routes added per VRF with `ip route add … vrf <name>`.
