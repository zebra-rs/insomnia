# DHCPv6 Server

`service dhcpv6-server` describes the DHCPv6 service of the default
routing table: addresses, options, and delegated prefixes. A server in a
VRF uses the same leaves under `service dhcpv6-server vrf <name>`; see
[DHCP in a VRF](ch-06-04-dhcp-in-a-vrf.md).

DHCPv6 hands out addresses and prefixes, not routes: a client takes its
default router from router advertisements, not from this server.

## A first server

```console
set interface lan1 ipv6 address 2001:db8:1::1/64
set service dhcpv6-server global-parameters name-server 2001:db8::53
set service dhcpv6-server shared-network-name LAN subnet 2001:db8:1::/64 subnet-id 1
set service dhcpv6-server shared-network-name LAN subnet 2001:db8:1::/64 range 0 start 2001:db8:1::100
set service dhcpv6-server shared-network-name LAN subnet 2001:db8:1::/64 range 0 stop 2001:db8:1::1ff
commit
```

```
kea-dhcp6 default: started: 1 shared networks, 1 subnets, interfaces [lan1]
```

## Shared networks and subnets

The structure is the DHCPv4 server's: shared networks hold subnets, and
every subnet needs a unique `subnet-id`.

| Leaf (under `subnet <prefix>`) | Meaning |
|---|---|
| `subnet-id` | Required. 1..4294967294, unique |
| `range <name> start <a> stop <b>` | Addresses to lease, as a first and a last address |
| `range <name> prefix <prefix>` | Addresses to lease, as a prefix inside the subnet |
| `interface <name>` | The interface this subnet's clients are directly connected to |
| `lease-time default \| maximum \| minimum` | Valid lifetime in seconds, and the bounds a client's request is held to |
| `prefix-delegation prefix <address> …` | A pool of prefixes to delegate |
| `static-mapping <name>` | Fixed addresses or prefixes for one client |
| `option …` | Options for this subnet |

A shared network takes `description`, `disable`, `interface` and
`option`.

### The `interface` leaf

Kea chooses the subnet for a directly connected client by the interface
the request arrived on, so each directly served subnet needs one.

You rarely have to set it. A subnet with no `interface` of its own or
of its shared network gets the interface that carries an address inside
it. Set `interface` when no interface has such an address, or to say
which one you mean. An `interface` that does not exist is dropped with
a warning; Kea would refuse the whole configuration otherwise.

Relayed requests are matched by the relay's link address and need no
`interface`.

## Options

| Leaf | DHCPv6 option |
|---|---|
| `name-server` | DNS servers (23). Repeatable |
| `domain-search` | Domain search list (24). Repeatable |
| `sntp-server` | SNTP servers (31). Repeatable |
| `sip-server` | SIP servers, by address or name. Repeatable |
| `nis-domain`, `nis-server` | NIS domain and servers |
| `nisplus-domain`, `nisplus-server` | NIS+ domain and servers |
| `info-refresh-time` | How long a stateless client waits before asking again (32) |
| `time-zone` | Time zone, by name, as options 41 and 42 |
| `captive-portal` | Captive portal URL (103) |
| `capwap-controller` | CAPWAP access controller (52) |
| `vendor-option cisco tftp-server` | Cisco TFTP servers. Repeatable |

`option` exists on the shared network, the subnet, the range and the
static mapping. `global-parameters name-server` sets the DNS servers
for the whole server.

## Static mappings

A mapping identifies a client by DUID or MAC address (one of the two)
and gives it addresses, prefixes, or both:

```console
set service dhcpv6-server shared-network-name LAN subnet 2001:db8:1::/64 static-mapping c1 duid 00:03:00:01:02:00:00:00:00:01
set service dhcpv6-server shared-network-name LAN subnet 2001:db8:1::/64 static-mapping c1 ipv6-address 2001:db8:1::10
```

`ipv6-address` and `ipv6-prefix` are both repeatable. A mapping needs
at least one of them, and an address must lie inside the subnet.

## Prefix delegation

A router on the LAN can ask for a whole prefix for the networks behind
it. Give the subnet a pool to delegate from:

```console
set service dhcpv6-server shared-network-name PD subnet 2001:db8:2::/64 subnet-id 2
set service dhcpv6-server shared-network-name PD subnet 2001:db8:2::/64 prefix-delegation prefix 2001:db8:8000:: prefix-length 48
set service dhcpv6-server shared-network-name PD subnet 2001:db8:2::/64 prefix-delegation prefix 2001:db8:8000:: delegated-length 56
```

This delegates /56 prefixes out of `2001:db8:8000::/48`: 256 of them.

| Leaf (under `prefix-delegation prefix <address>`) | Meaning |
|---|---|
| `prefix-length` | Required. Length of the pool, 32..64 |
| `delegated-length` | Required. Length of each delegated prefix, 32..96. Not shorter than `prefix-length` |
| `excluded-prefix`, `excluded-prefix-length` | A prefix inside the pool the requesting router must keep for its own link to this router (RFC 6603) |

### Routes for delegated prefixes

A delegated prefix is useless until this router knows where to send its
traffic. insomnia installs that route itself:

```
2001:db8:8000::/56 via fe80::ff:fe00:2 dev lan2 proto dhcp
```

- The next hop is the requesting router's link-local address, on the
  interface its request arrived on.
- zebra-rs shows the route as a `D` route in `show ipv6 route`, in the
  server's VRF, and can redistribute it.
- The route is installed when Kea confirms the lease, and removed when
  the prefix is released, expires or is declined. A sweep at startup
  and every minute removes any that no lease backs.
- insomnia only ever touches `proto dhcp` routes inside your configured
  `prefix-delegation` pools.

`disable-route-autoinstall` turns this off, for when a routing protocol
or static routes already cover the delegated space.

## Where the server listens

As for DHCPv4, Kea is never told to listen everywhere:

1. **`listen-interface <name>`**: those interfaces.
2. **Otherwise**: the `interface` leaves of the shared networks and
   subnets, plus every interface that carries an address inside a
   configured subnet.

An interface joins only when its link-local address is ready (duplicate
address detection has finished). Kea needs that address to join the
DHCPv6 multicast group, and does not try again if it is not there. The
address event that ends detection re-renders the configuration and adds
the interface, so on a fresh link the server can start serving a second
or two after the commit.

## Other leaves

| Leaf | Meaning |
|---|---|
| `disable` | Stop the DHCPv6 server without deleting its configuration |
| `preference` | Server preference, 0..255. Clients pick the highest among the servers that answer |
| `log-level` | Kea's log level |

## The server's DUID

The server identifies itself with a DUID that insomnia has Kea generate
once and keep in the instance's state directory
(`/var/lib/insomnia/kea/<vrf>/`). It survives restarts and upgrades, so
clients keep recognising the server.

## What is checked when rendering

Each of these is skipped with a warning naming it:

- A subnet that overlaps another, or reuses a `subnet-id`.
- A range that has neither a `prefix` nor both `start` and `stop`, lies
  outside its subnet, or overlaps another range.
- A delegation pool whose `prefix-length` is longer than its
  `delegated-length`, that is not a network prefix, or that overlaps
  another pool; an excluded prefix outside the pool or not longer than
  the delegated length.
- A static mapping without a DUID or MAC address, without an address or
  prefix, with an address outside the subnet, or that reuses another
  mapping's address, prefix, DUID or MAC address.

## Differences from VyOS

- Kea is reloaded in place on a commit, never restarted.
- Kea never listens on every interface, and a subnet's `interface` is
  filled in when it can be worked out.
- Delegated-prefix routes are `proto dhcp`, installed by insomnia after
  it has confirmed the lease with Kea. VyOS has Kea's hook run
  `sudo ip route` and tags the route `static`.
- `vendor-option cisco tftp-server` is rendered. VyOS accepts the leaf
  and never renders it.
- No dynamic DNS or high availability.
