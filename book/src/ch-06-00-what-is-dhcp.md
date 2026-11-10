# DHCP

zebra-rs provides VyOS-derived DHCP server and relay configuration under
`service`. On every commit insomnia renders it for two engines:

- `service dhcp-server` and `service dhcpv6-server` become complete
  [Kea](https://www.isc.org/kea/) configurations, one `kea-dhcp4` and one
  `kea-dhcp6` per VRF;
- `service dhcp-relay` and `service dhcpv6-relay` become the
  configuration of `insomnia-dhcp-relay`, insomnia's own relay agent.

Loading is declarative, as for the firewall and VRRP: what you removed
from the configuration is gone from the daemon after the same commit.

The four trees are VyOS's, leaf for leaf, so a VyOS
`set service dhcp-server …` line ports unchanged.

This section is about serving and relaying DHCP. Leasing an address
*for* a router interface (`interface <name> ipv4 address dhcp`) is
zebra-rs's own DHCP client and is described in the zebra-rs book.

DHCP support is part of the optional insomnia feature set. Start
zebra-rs with the feature enabled:

```console
$ zebra-rs --feature insomnia
```

Without it the whole `service` subtree is absent from the schema: the
commands do not complete and do not parse.

## Prerequisites

**The servers need Kea.** The insomnia package recommends it; on a
minimal install add it by hand:

```console
$ sudo apt install kea-dhcp4-server kea-dhcp6-server
```

insomnia is tested with Kea 2.4.1, the version in Ubuntu 24.04. It
starts Kea through its own systemd template units,
`insomnia-kea-dhcp4@<vrf>.service` and
`insomnia-kea-dhcp6@<vrf>.service`, when there is something to serve,
and stops them when there is not. Nothing needs to be enabled by hand.

The distribution's own `kea-dhcp4-server.service`,
`kea-dhcp6-server.service` and `/etc/kea` are never touched. Their
lease files and control sockets are at other paths, so the two sets
cannot collide; if you do not use the stock services you may disable
them.

**The relay needs nothing extra.** `insomnia-dhcp-relay` ships in the
insomnia package with its unit, `insomnia-dhcp-relay.service`, which
insomnia starts on the first relay configuration.

## What is supported

- **DHCPv4 server**: shared networks, subnets, address ranges with
  excluded addresses, static mappings by MAC address or DUID, the
  common options (routers, DNS, NTP, domain search, classless static
  routes, boot files, …) at every level, and client classes that match
  on the vendor class, the host name or the relay agent information.
- **DHCPv6 server**: subnets, address ranges, static mappings, options,
  and prefix delegation with a route installed for every delegated
  prefix.
- **DHCPv4 and DHCPv6 relay**: listen and upstream interfaces, the
  relay agent information option (option 82), hop limits, the
  DHCPv6 Interface-ID option.
- **VRFs**: every tree has a `vrf <name>` list for a server or a relay
  inside a VRF, with its own leases.
- **Operational visibility**: `show dhcp server leases`, `statistics`
  and `static-mappings`, their `dhcpv6` twins, `show dhcp relay
  statistics`, and `show process` with `start`, `stop` and `restart` for
  the daemons.

A configuration change never restarts Kea. insomnia has Kea check the
new configuration first and then reload it in place, so leases are
kept, no request is lost to a restart, and a configuration Kea refuses
leaves the previous one serving.

## What is not

These VyOS leaves are not in the schema, because insomnia cannot apply
them. `set` fails on them; nothing is stored and silently ignored.

| VyOS leaf | Why not |
|---|---|
| `dynamic-dns-update`, `hostfile-update` | need a DNS server on the router |
| `ping-check` | Kea 2.4.1 has no ping-check hook |
| `high-availability` | the peers must authenticate each other, which needs `pki` |
| client-class `substring` matches | Kea 2.4.1 cannot express a case-insensitive "contains" |
| `service dhcp-relay interface` | VyOS deprecates it for `listen-interface` and `upstream-interface` |

## The configuration trees at a glance

```
service
├── dhcp-server
│   ├── disable
│   ├── listen-interface … | listen-address …
│   ├── log-level
│   ├── client-class <name>            match a group of clients
│   ├── shared-network-name <name>
│   │   ├── authoritative, description, disable
│   │   ├── option …                   for every subnet below
│   │   └── subnet <prefix>
│   │       ├── subnet-id              required, unique
│   │       ├── range <name> start … stop …
│   │       ├── exclude …              addresses kept out of the ranges
│   │       ├── static-mapping <name>  fixed address by mac | duid
│   │       ├── lease                  seconds
│   │       ├── client-class, ignore-client-id
│   │       └── option …
│   └── vrf <name> …                   the same tree, inside a VRF
├── dhcpv6-server
│   ├── disable, listen-interface …, log-level, preference
│   ├── disable-route-autoinstall      no routes for delegated prefixes
│   ├── global-parameters name-server …
│   ├── shared-network-name <name>
│   │   ├── description, disable, interface, option …
│   │   └── subnet <prefix>
│   │       ├── subnet-id, interface, option …
│   │       ├── range <name> start … stop … | prefix …
│   │       ├── prefix-delegation prefix <address> …
│   │       ├── static-mapping <name>
│   │       └── lease-time default | maximum | minimum
│   └── vrf <name> …
├── dhcp-relay
│   ├── disable
│   ├── listen-interface …             where clients are
│   ├── upstream-interface …           where servers are
│   ├── server …
│   ├── relay-options hop-count | max-size | relay-agents-packets
│   └── vrf <name> …
└── dhcpv6-relay
    ├── disable
    ├── listen-interface <name> [address …]
    ├── upstream-interface <name> address …
    ├── max-hop-count
    ├── use-interface-id-option
    └── vrf <name> …
```

The smallest working server is one shared network with one subnet: a
`subnet-id` and a range. The smallest relay is a listen interface, an
upstream interface and a server. The next chapters build both;
[Sample Configurations](ch-06-06-sample-configurations.md) collects
complete setups.

## Checks at commit time and afterwards

zebra-rs refuses what the schema can refuse: a subnet without a
`subnet-id`, a range without `start` and `stop`, a delegated prefix
without its lengths. Everything else VyOS checks at commit (a range
outside its subnet, two subnets with one id, a client class that does
not exist, …) insomnia checks when it renders. What fails a check is
skipped with a warning in insomnia's log that names it and says why;
the rest of the configuration is served.

```
dhcp-server: service dhcp-server shared-network-name LAN subnet 10.1.0.0/24 range bad skipped: not inside the subnet
```

Skipping never widens who is served. A range that names a missing
client class is skipped; it is not opened to every client.
