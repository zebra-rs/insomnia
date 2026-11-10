# Sample Configurations

Five configurations, from one LAN to tenants in VRFs. Each is taken
from insomnia's integration tests, where it is applied to a real
zebra-rs, insomnia and Kea and clients lease from it
(`bdd/tests/configs/dhcp_*`). Interface names are the tests'; use your
own.

All samples assume `zebra-rs --feature insomnia`, and Kea installed for
the server samples.

## 1. Two LANs, a printer and a phone range

A router serving two LANs directly. `LAN` has a reserved address for a
printer and one address kept out of its range; `LAN2` has a range of
its own for phones.

```
   lan1 10.1.0.1/24 ── clients, printer
   lan2 10.2.0.1/24 ── clients, phones (vendor class "voip")
```

```console
set interface lan1 ipv4 address 10.1.0.1/24
set interface lan2 ipv4 address 10.2.0.1/24

set service dhcp-server client-class VOIP vendor-class-id value voip

set service dhcp-server shared-network-name LAN authoritative
set service dhcp-server shared-network-name LAN option domain-name example.com
set service dhcp-server shared-network-name LAN option name-server 192.0.2.53
set service dhcp-server shared-network-name LAN subnet 10.1.0.0/24 subnet-id 1
set service dhcp-server shared-network-name LAN subnet 10.1.0.0/24 option default-router 10.1.0.1
set service dhcp-server shared-network-name LAN subnet 10.1.0.0/24 option ntp-server 192.0.2.123
set service dhcp-server shared-network-name LAN subnet 10.1.0.0/24 option static-route 198.51.100.0/24 next-hop 10.1.0.1
set service dhcp-server shared-network-name LAN subnet 10.1.0.0/24 exclude 10.1.0.100
set service dhcp-server shared-network-name LAN subnet 10.1.0.0/24 range 0 start 10.1.0.100
set service dhcp-server shared-network-name LAN subnet 10.1.0.0/24 range 0 stop 10.1.0.199
set service dhcp-server shared-network-name LAN subnet 10.1.0.0/24 static-mapping printer ip-address 10.1.0.10
set service dhcp-server shared-network-name LAN subnet 10.1.0.0/24 static-mapping printer mac 02:00:00:00:00:01
set service dhcp-server shared-network-name LAN subnet 10.1.0.0/24 static-mapping printer description lobby

set service dhcp-server shared-network-name LAN2 subnet 10.2.0.0/24 subnet-id 2
set service dhcp-server shared-network-name LAN2 subnet 10.2.0.0/24 option default-router 10.2.0.1
set service dhcp-server shared-network-name LAN2 subnet 10.2.0.0/24 range voip start 10.2.0.50
set service dhcp-server shared-network-name LAN2 subnet 10.2.0.0/24 range voip stop 10.2.0.59
set service dhcp-server shared-network-name LAN2 subnet 10.2.0.0/24 range voip client-class VOIP
set service dhcp-server shared-network-name LAN2 subnet 10.2.0.0/24 range 0 start 10.2.0.100
set service dhcp-server shared-network-name LAN2 subnet 10.2.0.0/24 range 0 stop 10.2.0.199
commit
```

What clients get:

- The printer (`02:00:00:00:00:01`) always gets `10.1.0.10`, with the
  domain name and DNS server of `LAN` and the router, NTP server and
  static route of its subnet.
- The first other client on `lan1` gets `10.1.0.101`: `10.1.0.100` is
  excluded. The pool has 99 addresses.
- A phone on `lan2` that sends the vendor class `voip` gets an address
  from `10.2.0.50`–`10.2.0.59`; any other client there gets one from
  `10.2.0.100`–`10.2.0.199`.
- Kea listens on `lan1` and `lan2` and on no other interface, because
  only they carry an address inside a configured subnet.

```
kea-dhcp4 default: started: 2 shared networks, 2 subnets, interfaces [lan1 lan2]
```

## 2. DHCPv6 with a static mapping

```console
set interface lan1 ipv6 address 2001:db8:1::1/64

set service dhcpv6-server global-parameters name-server 2001:db8::53
set service dhcpv6-server shared-network-name LAN option domain-search example.com
set service dhcpv6-server shared-network-name LAN subnet 2001:db8:1::/64 subnet-id 1
set service dhcpv6-server shared-network-name LAN subnet 2001:db8:1::/64 range 0 start 2001:db8:1::100
set service dhcpv6-server shared-network-name LAN subnet 2001:db8:1::/64 range 0 stop 2001:db8:1::1ff
set service dhcpv6-server shared-network-name LAN subnet 2001:db8:1::/64 static-mapping c1 duid 00:03:00:01:02:00:00:00:00:01
set service dhcpv6-server shared-network-name LAN subnet 2001:db8:1::/64 static-mapping c1 ipv6-address 2001:db8:1::10
commit
```

The client with that DUID gets `2001:db8:1::10`; others get an address
from the 256 in the range. The subnet has no `interface` leaf: insomnia
fills in `lan1`, the interface with an address inside it.

## 3. Prefix delegation to downstream routers

Routers on `lan2` ask for a prefix for the networks behind them. Each
gets an address on the link and a /56 out of `2001:db8:8000::/48`.

```console
set interface lan2 ipv6 address 2001:db8:2::1/64

set service dhcpv6-server shared-network-name PD subnet 2001:db8:2::/64 subnet-id 2
set service dhcpv6-server shared-network-name PD subnet 2001:db8:2::/64 range 0 start 2001:db8:2::100
set service dhcpv6-server shared-network-name PD subnet 2001:db8:2::/64 range 0 stop 2001:db8:2::1ff
set service dhcpv6-server shared-network-name PD subnet 2001:db8:2::/64 prefix-delegation prefix 2001:db8:8000:: prefix-length 48
set service dhcpv6-server shared-network-name PD subnet 2001:db8:2::/64 prefix-delegation prefix 2001:db8:8000:: delegated-length 56
commit
```

When a router takes a prefix, insomnia installs the route to it through
that router:

```console
$ ip -6 route show proto dhcp
2001:db8:8000::/56 via fe80::ff:fe00:2 dev lan2 metric 1024 pref medium
```

zebra-rs lists the same route in `show ipv6 route`, marked `D`. The
route goes away when the router releases the prefix or its lease
expires.

## 4. A relay and a central server

Two routers. `r1` has the client LANs and relays; `r2` is the server
and is not connected to any client LAN.

```
   lan1 10.1.0.1/24 ┐
                    r1 ── wan1 192.0.2.1/24 ──── wan1 192.0.2.2/24 ── r2 (server)
   lan2 10.2.0.1/24 ┘        2001:db8::1/64        2001:db8::2/64
```

### r1, the relay

```console
set service dhcp-relay listen-interface lan1
set service dhcp-relay listen-interface lan2
set service dhcp-relay upstream-interface wan1
set service dhcp-relay server 192.0.2.2

set service dhcpv6-relay listen-interface lan1
set service dhcpv6-relay listen-interface lan2
set service dhcpv6-relay upstream-interface wan1 address ff02::1:2
set service dhcpv6-relay use-interface-id-option
commit
```

The DHCPv6 relay sends to `ff02::1:2`, the address every DHCPv6 server
on the upstream link listens on, so `r1` does not need to know `r2`'s
address.

### r2, the server

```console
set service dhcp-server listen-address 192.0.2.2
set service dhcp-server client-class CIRCUIT1 relay-agent-information circuit-id lan1
set service dhcp-server shared-network-name SITE option name-server 192.0.2.53
set service dhcp-server shared-network-name SITE subnet 10.1.0.0/24 subnet-id 1
set service dhcp-server shared-network-name SITE subnet 10.1.0.0/24 option default-router 10.1.0.1
set service dhcp-server shared-network-name SITE subnet 10.1.0.0/24 range lan1 start 10.1.0.50
set service dhcp-server shared-network-name SITE subnet 10.1.0.0/24 range lan1 stop 10.1.0.59
set service dhcp-server shared-network-name SITE subnet 10.1.0.0/24 range lan1 client-class CIRCUIT1
set service dhcp-server shared-network-name SITE subnet 10.2.0.0/24 subnet-id 2
set service dhcp-server shared-network-name SITE subnet 10.2.0.0/24 option default-router 10.2.0.1
set service dhcp-server shared-network-name SITE subnet 10.2.0.0/24 range 0 start 10.2.0.100
set service dhcp-server shared-network-name SITE subnet 10.2.0.0/24 range 0 stop 10.2.0.199

set service dhcpv6-server listen-interface wan1
set service dhcpv6-server shared-network-name LAN1 subnet 2001:db8:1::/64 subnet-id 1
set service dhcpv6-server shared-network-name LAN1 subnet 2001:db8:1::/64 range 0 start 2001:db8:1::100
set service dhcpv6-server shared-network-name LAN1 subnet 2001:db8:1::/64 range 0 stop 2001:db8:1::1ff
set service dhcpv6-server shared-network-name LAN2 subnet 2001:db8:2::/64 subnet-id 2
set service dhcpv6-server shared-network-name LAN2 subnet 2001:db8:2::/64 range 0 start 2001:db8:2::100
set service dhcpv6-server shared-network-name LAN2 subnet 2001:db8:2::/64 range 0 stop 2001:db8:2::1ff
commit
```

Points to note:

- **`r2` has no address in the client subnets**, so the server must be
  told where to listen: `listen-address` for DHCPv4 (relayed requests
  only), `listen-interface` for DHCPv6.
- **The server picks the subnet from the relay.** For DHCPv4 that is
  the gateway address `r1` writes into the request (`10.1.0.1` or
  `10.2.0.1`); for DHCPv6 the relay's link address.
- **`r2` needs routes back to `10.1.0.0/24` and `10.2.0.0/24`**, since
  it answers to the relay's address on the client LAN.
- **The class `CIRCUIT1` matches the relay's option 82.** `r1` puts the
  listen interface's name in the circuit ID, so the range `lan1` is
  only given to clients behind `r1`'s `lan1`.

## 5. Tenants in VRFs with the same addresses

Two tenants, each in a VRF, each using `10.1.0.0/24` and
`2001:db8:1::/64`, beside a network in the default table.

```console
set vrf red
set vrf blue
set interface lanred vrf red
set interface lanblue vrf blue
set interface lanred ipv4 address 10.1.0.1/24
set interface lanred ipv6 address 2001:db8:1::1/64
set interface lanblue ipv4 address 10.1.0.1/24
set interface lanblue ipv6 address 2001:db8:1::1/64
set interface lan9 ipv4 address 10.9.0.1/24

set service dhcp-server shared-network-name LAN9 subnet 10.9.0.0/24 subnet-id 9
set service dhcp-server shared-network-name LAN9 subnet 10.9.0.0/24 range 0 start 10.9.0.100
set service dhcp-server shared-network-name LAN9 subnet 10.9.0.0/24 range 0 stop 10.9.0.199

set service dhcp-server vrf red shared-network-name TENANT subnet 10.1.0.0/24 subnet-id 1
set service dhcp-server vrf red shared-network-name TENANT subnet 10.1.0.0/24 range 0 start 10.1.0.100
set service dhcp-server vrf red shared-network-name TENANT subnet 10.1.0.0/24 range 0 stop 10.1.0.149

set service dhcp-server vrf blue shared-network-name TENANT subnet 10.1.0.0/24 subnet-id 1
set service dhcp-server vrf blue shared-network-name TENANT subnet 10.1.0.0/24 range 0 start 10.1.0.150
set service dhcp-server vrf blue shared-network-name TENANT subnet 10.1.0.0/24 range 0 stop 10.1.0.199

set service dhcpv6-server vrf red shared-network-name TENANT subnet 2001:db8:1::/64 subnet-id 1
set service dhcpv6-server vrf red shared-network-name TENANT subnet 2001:db8:1::/64 range 0 start 2001:db8:1::100
set service dhcpv6-server vrf red shared-network-name TENANT subnet 2001:db8:1::/64 range 0 stop 2001:db8:1::14f
set service dhcpv6-server vrf red shared-network-name TENANT subnet 2001:db8:1::/64 prefix-delegation prefix 2001:db8:8000:: prefix-length 48
set service dhcpv6-server vrf red shared-network-name TENANT subnet 2001:db8:1::/64 prefix-delegation prefix 2001:db8:8000:: delegated-length 56
commit
```

Three DHCPv4 servers and one DHCPv6 server now run, each in its own
routing table:

```
kea-dhcp4 default: started: 1 shared networks, 1 subnets, interfaces [lan9]
kea-dhcp4 red: started: 1 shared networks, 1 subnets, interfaces [lanred]
kea-dhcp4 blue: started: 1 shared networks, 1 subnets, interfaces [lanblue]
kea-dhcp6 red: started: 1 shared networks, 1 subnets, interfaces [lanred]
```

A client on `lanred` leases from `red`'s range, one on `lanblue` from
`blue`'s, although both servers serve the same subnet under the same
shared-network name and `subnet-id`. A prefix delegated in `red` is
routed in `red`'s table.

A relay in a VRF is configured the same way:

```console
set service dhcp-relay vrf red listen-interface lanred
set service dhcp-relay vrf red upstream-interface wanred
set service dhcp-relay vrf red server 192.0.2.10
```

Both interfaces must be in VRF `red`, and the server is reached through
`red`'s routing table.
