# DHCP

The DHCP show commands are answered by insomnia. The server views read
live state from Kea; the relay views read the relay agent's counters.
Every command also takes `-j` (`vtyctl show -j "…"`) for JSON.

```
show dhcp server [vrf <name>] leases [pool <name>]
show dhcp server [vrf <name>] statistics [pool <name>]
show dhcp server [vrf <name>] static-mappings [pool <name>]
show dhcpv6 server [vrf <name>] leases | statistics | static-mappings [pool <name>]
show dhcp relay [vrf <name>] statistics
show dhcpv6 relay [vrf <name>] statistics
show process [<name>]
```

A *pool* is a shared network: `pool LAN` keeps the rows of
`shared-network-name LAN`. Without `vrf <name>` the server views show
the server of the default routing table.

## show dhcp server leases

The leases Kea currently holds, static mappings that are in use
included:

```console
$ show dhcp server leases
IP Address  MAC address        State   Lease start          Lease expiration     Remaining  Pool  Hostname  Origin
----------  -----------------  ------  -------------------  -------------------  ---------  ----  --------  ------
10.1.0.10   02:00:00:00:00:01  active  2026-11-09 08:17:35  2026-11-10 08:17:35  23:58:12   LAN   printer   local
10.1.0.101  02:00:00:00:00:02  active  2026-11-09 08:18:02  2026-11-10 08:18:02  23:58:39   LAN   -         local
10.2.0.50   02:00:00:00:00:03  active  2026-11-09 08:18:40  2026-11-10 08:18:40  23:59:17   LAN2  phone1    local
```

- Times are UTC. `Lease start` is the client's last contact, which
  moves forward at every renewal.
- `Hostname` is the name the client sent, `-` when it sent none.
- `State` is `active`, `rejected` (the address was declined as in use
  by another host) or `expired`.

```console
$ show dhcp server leases pool LAN2
```

## show dhcp server statistics

How full each pool is, from Kea's own counters:

```console
$ show dhcp server statistics
Pool  Size  Leases  Available  Usage
----  ----  ------  ---------  -----
LAN   99    2       97         2%
LAN2  110   1       109        1%
```

`Size` counts the addresses of the pool's ranges, with excluded
addresses left out.

## show dhcp server static-mappings

The static mappings Kea is serving, whether or not the client holds a
lease right now:

```console
$ show dhcp server static-mappings
Pool  Subnet       Hostname  IP Address  MAC Address        DUID  Description
----  -----------  --------  ----------  -----------------  ----  -----------
LAN   10.1.0.0/24  printer   10.1.0.10   02:00:00:00:00:01  N/A   lobby
```

## show dhcpv6 server

The same three views for DHCPv6. Leases have a `Type` column: `IA_NA`
for an address, `IA_PD` for a delegated prefix, which is shown with its
length.

```console
$ show dhcpv6 server leases
IPv6 address        MAC address        State   Last communication   Lease expiration     Remaining  Pool  Hostname  Type   DUID
------------------  -----------------  ------  -------------------  -------------------  ---------  ----  --------  -----  -----------------------------
2001:db8:1::10      02:00:00:00:00:01  active  2026-11-09 08:20:11  2026-11-10 08:20:11  23:59:48   LAN   -         IA_NA  00:03:00:01:02:00:00:00:00:01
2001:db8:2::100     02:00:00:00:00:02  active  2026-11-09 08:20:15  2026-11-10 08:20:15  23:59:52   PD    -         IA_NA  00:03:00:01:02:00:00:00:00:02
2001:db8:8000::/56  02:00:00:00:00:02  active  2026-11-09 08:20:15  2026-11-10 08:20:15  23:59:52   PD    -         IA_PD  00:03:00:01:02:00:00:00:00:02
```

## What the server views say when there is nothing to show

| Output | Meaning |
|---|---|
| `DHCP server is not configured` | No `service dhcp-server` configuration (for that VRF) |
| `DHCP server is disabled` | The tree has `disable` set |
| `DHCP server is not running` | Kea does not answer on its control socket |
| `DHCP pool "X" does not exist` | No shared network of that name |

The DHCPv6 views say `DHCPv6 server …`, and the VRF views add
`for VRF <name>`.

If Kea refused the latest configuration, every server view starts with
Kea's reason, and the rows below it are those of the configuration Kea
is still running. See
[When Kea refuses a
configuration](ch-06-05-kea-and-insomnia.md#when-kea-refuses-a-configuration).

## show dhcp relay statistics

One row per interface that has received DHCP traffic, in every VRF,
counted since the relay agent started:

```console
$ show dhcp relay statistics
VRF      Interface  Received  Forwarded  Dropped  Send errors  No option 82
-------  ---------  --------  ---------  -------  -----------  ------------
default  lan1       6         6          0        0            0
default  lan2       4         4          0        0            0
default  wan1       11        10         1        0            0

VRF      Interface  Dropped         Count
-------  ---------  --------------  -----
default  wan1       wrong-upstream  1
```

- A packet is counted on the interface it arrived on: a request on its
  listen interface, a reply on the upstream interface. Every received
  packet ends as `Forwarded` or `Dropped`.
- `Send errors` counts failed sends, one per server a request could not
  be sent to.
- `No option 82` counts DHCPv4 requests forwarded without the relay's
  option 82 because adding it would have exceeded `max-size`.
- The second table breaks `Dropped` down by reason and appears only
  when something was dropped.

`show dhcp relay vrf red statistics` keeps one VRF's rows. With no
traffic yet the output is `No relay traffic`.

| Drop reason | Meaning |
|---|---|
| `wrong-upstream` | A reply arrived on an interface that is not an upstream interface |
| `unknown-server` | A reply on a listen interface from a sender that is not a configured server |
| `hop-limit` | The message had already passed `hop-count` / `max-hop-count` relays |
| `no-binding` | A reply that names no listen interface of this relay |
| `own-giaddr` | A DHCPv4 request carrying one of this router's addresses as its gateway address: a loop |
| `agent-option-present` | A DHCPv4 request that already had option 82, dropped by `relay-agents-packets discard` |
| `no-address` | The DHCPv4 listen interface has no IPv4 address to relay from |
| `no-link-address` | The DHCPv6 listen interface has no global address and no `address` leaf |
| `unexpected-type` | A DHCPv6 message of the wrong type for its direction: a server's message on the client side, or anything but a Relay-reply on the server side |
| `too-long` | A DHCPv6 message too long to wrap in a Relay-forward |
| `interface-down` | The interface the packet belongs to is down or gone |
| `malformed` | Not a well-formed DHCP message |

`show dhcpv6 relay statistics` is the same view for DHCPv6, without the
`No option 82` column.

## show process

The daemons insomnia drives, DHCP's among them. See
[Processes](ch-06-05-kea-and-insomnia.md#processes-show-process-start-stop-restart).

```console
$ show process
Name               VRF      State    Admin  PID   Uptime   Restarts  Last error
-----------------  -------  -------  -----  ----  -------  --------  ----------
dhcp-relay         -        running  up     1412  2h13m5s  0
kea-dhcp4@default  default  running  up     1398  2h13m6s  0
kea-dhcp4@red      red      running  up     1405  2h13m6s  0
```

## Reading the views together

- Committed and accepted? The insomnia log shows
  `kea-dhcp4 default: config-reload: …` with the interfaces Kea listens
  on. An interface missing from that list is why its clients get no
  answer.
- Is Kea running? `show process` shows `kea-dhcp4@<vrf>` as `running`.
- Are addresses left? `show dhcp server statistics`.
- Relayed clients get nothing? `show dhcp relay statistics`: `Received`
  growing on the listen interface with nothing `Forwarded` points at
  the relay's configuration; requests forwarded but no replies received
  on the upstream interface points at the server or the route back to
  the relay.
