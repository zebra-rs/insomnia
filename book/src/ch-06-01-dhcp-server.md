# DHCPv4 Server

`service dhcp-server` describes the DHCPv4 service of the default
routing table. A server in a VRF uses the same leaves under
`service dhcp-server vrf <name>`; see
[DHCP in a VRF](ch-06-04-dhcp-in-a-vrf.md).

## A first server

One LAN, one range, a default router and a DNS server:

```console
set interface lan1 ipv4 address 10.1.0.1/24
set service dhcp-server shared-network-name LAN subnet 10.1.0.0/24 subnet-id 1
set service dhcp-server shared-network-name LAN subnet 10.1.0.0/24 option default-router 10.1.0.1
set service dhcp-server shared-network-name LAN subnet 10.1.0.0/24 option name-server 192.0.2.53
set service dhcp-server shared-network-name LAN subnet 10.1.0.0/24 range 0 start 10.1.0.100
set service dhcp-server shared-network-name LAN subnet 10.1.0.0/24 range 0 stop 10.1.0.199
commit
```

insomnia's log confirms what Kea is now serving:

```
kea-dhcp4 default: started: 1 shared networks, 1 subnets, interfaces [lan1]
```

`lan1` is in the list because it carries an address inside the subnet;
nothing in the configuration names it. [Where the server
listens](#where-the-server-listens) explains the rule.

## Shared networks and subnets

A **shared network** is one physical network: a LAN, or a group of
subnets that share a wire. Its name is yours to choose, and it is the
*pool* the show commands report on. A shared network holds one or more
**subnets**.

Every subnet needs a `subnet-id`: a number, unique across the server,
that Kea writes into its lease file. Keep it stable. Renumbering a
subnet's id detaches the leases already granted from it.

| Leaf (under `shared-network-name <name>`) | Meaning |
|---|---|
| `authoritative` | Answer a request for an address this network does not know with a NAK, so a client that moved here asks again at once |
| `description` | Free text |
| `disable` | Stop serving this shared network |
| `option …` | Options for every subnet in it |

| Leaf (under `subnet <prefix>`) | Meaning |
|---|---|
| `subnet-id` | Required. 1..4294967294, unique |
| `range <name> start <a> stop <b>` | An address range to lease from. Several are allowed |
| `exclude <address>` | An address inside a range that is never leased. Repeatable |
| `lease` | Lease time in seconds. Default 86400 (one day) |
| `static-mapping <name>` | A fixed address for one client |
| `client-class <name>` | Serve this subnet only to clients in the class |
| `ignore-client-id` | Identify clients by MAC address only, ignoring the client identifier |
| `option …` | Options for this subnet, overriding the shared network's |
| `description`, `disable` | As above |

A range may carry its own `client-class` and `option` leaves too.

`exclude` cuts the ranges around the address: with a range
`10.1.0.100`–`10.1.0.199` and `exclude 10.1.0.100`, Kea is given
`10.1.0.101`–`10.1.0.199`.

## Options

`option` exists at four levels: shared network, subnet, range and static
mapping. The most specific one wins. The leaves are VyOS's.

| Leaf | DHCP option |
|---|---|
| `default-router` | Router (3) |
| `name-server` | DNS servers (6). Repeatable |
| `domain-name` | Domain name (15) |
| `domain-search` | Domain search list (119). Repeatable |
| `ntp-server` | NTP servers (42). Repeatable |
| `time-server` | Time servers (4). Repeatable |
| `time-offset` | Offset from UTC in seconds (2) |
| `time-zone` | Time zone, by name (`Europe/Berlin`), as options 100 and 101 |
| `static-route <prefix> next-hop <address>` | Classless static routes (121) |
| `client-prefix-length` | Subnet mask (1). The subnet's own when unset |
| `interface-mtu` | Interface MTU (26) |
| `ip-forwarding` | IP forwarding on the client (19) |
| `server-identifier` | Server identifier (54) |
| `bootfile-name`, `bootfile-server`, `bootfile-size` | Network boot |
| `tftp-server-name` | TFTP server name (66) |
| `captive-portal` | Captive portal URL (114) |
| `ipv6-only-preferred` | IPv6-only preferred (108, RFC 8925), in seconds |
| `wpad-url` | Web proxy autodiscovery (252) |
| `wins-server`, `pop-server`, `smtp-server` | NetBIOS, POP3 and SMTP servers. Repeatable |
| `capwap-controller` | CAPWAP access controller (138) |
| `vendor-option ubiquiti unifi-controller` | UniFi controller address |

Two details worth knowing:

- **Classless static routes and the default router.** A client that
  receives option 121 ignores the router option (RFC 3442). So when you
  configure `static-route`, insomnia adds `default-router` to option 121
  as a `0.0.0.0/0` route, as VyOS does, and the client keeps its default
  route.
- **`bootfile-server`** becomes the boot server address only when it is
  an IPv4 address, which is all Kea accepts there.

## Static mappings

A static mapping reserves an address for one client, identified by its
MAC address or by its DUID (one of the two, not both):

```console
set service dhcp-server shared-network-name LAN subnet 10.1.0.0/24 static-mapping printer mac 02:00:00:00:00:01
set service dhcp-server shared-network-name LAN subnet 10.1.0.0/24 static-mapping printer ip-address 10.1.0.10
set service dhcp-server shared-network-name LAN subnet 10.1.0.0/24 static-mapping printer description lobby
```

The address must lie inside the subnet. It does not have to be inside a
range, and usually is not. A mapping can carry its own `option` leaves
and can be switched off with `disable`.

## Client classes

A client class groups clients by what they send, and a range or a
subnet can then be reserved for the class.

```console
set service dhcp-server client-class VOIP vendor-class-id value voip
set service dhcp-server shared-network-name LAN2 subnet 10.2.0.0/24 range voip start 10.2.0.50
set service dhcp-server shared-network-name LAN2 subnet 10.2.0.0/24 range voip stop 10.2.0.59
set service dhcp-server shared-network-name LAN2 subnet 10.2.0.0/24 range voip client-class VOIP
```

Phones that send the vendor class `voip` get an address from
`10.2.0.50`–`10.2.0.59`. Other clients on that subnet are served from
its other ranges.

| Match (under `client-class <name>`) | Compares |
|---|---|
| `vendor-class-id value <v>` | Option 60 |
| `hostname value <v>` | Option 12 |
| `relay-agent-information circuit-id <v>` | Option 82, circuit ID: which relay interface the client is behind |
| `relay-agent-information remote-id <v>` | Option 82, remote ID |

- A value is compared whole: it is text, or hex written as `0x…`.
- Several matches in one class must all hold.
- A class can carry `option` leaves, which its members receive.
- A range or subnet that names a class which is missing, disabled or
  has no usable match is skipped, with a warning. It is never served
  to everyone instead.

Matching on the circuit ID is how one server gives each relayed LAN its
own range; the
[relay sample](ch-06-06-sample-configurations.md#4-a-relay-and-a-central-server)
shows it.

## Where the server listens

Kea is never told to listen everywhere. insomnia works out the
interfaces, in this order:

1. **`listen-address <address>`**: Kea opens an ordinary UDP socket on
   each listed address that is assigned to an interface. Such a socket
   only hears relayed requests, so use it for a central server that no
   client reaches directly.
2. **`listen-interface <name>`**: Kea listens on those interfaces for
   directly connected clients and for relays.
3. **Neither**: every interface that carries an address inside a
   configured subnet.

If both `listen-address` and `listen-interface` are set,
`listen-address` is used and a warning says so. When nothing is left
to listen on, nothing is served, and the log says why.

The set follows the interfaces. Add an address on a new LAN and the
next link event re-renders the configuration; an unchanged result is
not reloaded.

## Other leaves

| Leaf | Meaning |
|---|---|
| `disable` | Stop the DHCPv4 server without deleting its configuration |
| `log-level` | Kea's log level: `fatal`, `error`, `warn`, `info` (default), `debug` |

## What is checked when rendering

Each of these is skipped with a warning naming it; everything else is
served.

- A subnet that is not a network prefix (host bits set), that overlaps
  another subnet, that reuses a `subnet-id`, or that has neither a
  usable range nor an enabled static mapping.
- A range that lies outside its subnet, whose `stop` is below its
  `start`, or that overlaps another range.
- A static mapping without a MAC address or DUID, with an address
  outside the subnet, or that reuses another mapping's address, MAC
  address or DUID.
- A client class with no match, or with a value that is neither text
  nor `0x` hex.
- A `time-zone` that does not exist, and a malformed `static-route`.

## Differences from VyOS

- Kea is reloaded in place on a commit, never restarted (see
  [How insomnia Drives Kea and the Relay
  Agent](ch-06-05-kea-and-insomnia.md)).
- Kea never listens on every interface.
- No `ping-check`, dynamic DNS, `hostfile-update` or high availability.
- A range cut by `exclude` keeps its client class. VyOS's pieces keep
  only the options.
- VyOS's commit-time errors are render-time warnings, so one bad range
  does not block a commit.
- `show dhcp server statistics` reads Kea's own counters.
