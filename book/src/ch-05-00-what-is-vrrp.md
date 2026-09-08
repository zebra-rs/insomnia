# VRRP

zebra-rs provides VyOS-derived VRRP configuration. You describe virtual
routers with the `set vrrp …` command tree; on every commit insomnia
renders a complete keepalived configuration and reloads the running
keepalived. Loading is declarative: a group you removed from the
configuration is withdrawn by keepalived in the same reload, so there is
never a drift between the config tree and the daemon.

The tree is VyOS's `high-availability vrrp` with the `high-availability`
wrapper dropped: every leaf below `vrrp` keeps its VyOS name, so a VyOS
configuration ports by deleting that one prefix.

VRRP support is part of the optional ISO feature set. Start the daemon
with the feature enabled:

```console
$ zebra-rs --feature iso
```

Without `--feature iso` the whole `vrrp` subtree is absent from the
schema — the commands do not complete and do not parse.

## Prerequisites

insomnia drives keepalived through a dedicated systemd template unit,
`insomnia-keepalived@<vrf>.service`, that it starts on the first
configured group and stops when the last one goes away. keepalived must
be installed; nothing needs to be enabled by hand:

```console
$ sudo apt install keepalived
```

The distribution's own `keepalived.service` and
`/etc/keepalived/keepalived.conf` are never touched. Each instance lives
under `/run/insomnia/vrrp/<vrf>/` — `default` for the global routing
table — with its rendered `keepalived.conf`, pid files and the dump
files `show vrrp` reads.

If keepalived is not installed, configuration is still validated,
rendered and written to that directory — a warning is logged and the
file is picked up by the first reload after keepalived appears.

## What is supported

- **VRRP groups** on any interface: virtual addresses with optional
  per-address device, priority, advertisement interval, preemption with
  delay, VRRPv2 and VRRPv3, IPv4 and IPv6 (one family per group).
- **Unicast VRRP** with peer addresses and a hello source address, and
  the RFC 3768 virtual-MAC mode (`rfc3768-compatibility`).
- **Authentication** for VRRPv2 (plaintext or AH), as in VyOS.
- **Health checks** (script or ping), tracked interfaces, gratuitous
  ARP tuning, and transition scripts on master/backup/fault/stop.
- **Sync groups** that fail over a set of groups together.
- **Operational visibility**: `show vrrp`, `show vrrp detail`,
  `show vrrp statistics` — live state read from keepalived.

Three knobs go beyond VyOS because keepalived supports them: a
per-group `version`, `v3-checksum-as-v2` for peers that compute the
VRRPv3 IPv4 checksum without the pseudo-header, and a fractional
`advertise-interval` for VRRPv3 groups.

## The configuration tree at a glance

```
vrrp
├── disable                        stop keepalived entirely
├── global-parameters
│   ├── garp …                     gratuitous ARP defaults
│   ├── startup-delay              seconds before the first election
│   └── version                    2 | 3, the default for every group
├── group <name>
│   ├── interface                  where advertisements are sent
│   ├── vrid                       1-255, shared by the routers of one virtual router
│   ├── address <ip[/len]>         virtual addresses (optional `interface`)
│   ├── priority                   1-255, highest wins
│   ├── advertise-interval         seconds
│   ├── no-preempt | preempt-delay
│   ├── peer-address …             unicast peers
│   ├── hello-source-address
│   ├── authentication             password + type (VRRPv2)
│   ├── rfc3768-compatibility      virtual MAC on a macvlan
│   ├── health-check               script | ping, interval, failure-count
│   ├── track interface …          fault when a tracked link drops
│   ├── transition-script          master | backup | fault | stop
│   ├── garp …                     per-group gratuitous ARP tuning
│   ├── version, v3-checksum-as-v2 extensions
│   └── disable
└── sync-group <name>
    ├── member …                   groups that fail over together
    ├── health-check
    └── transition-script
```

A minimal working configuration is one group: an interface, a VRID and
a virtual address. The next chapter builds exactly that on a pair of
routers; [Sample Configurations](ch-05-05-sample-configurations.md)
collects five complete setups, from that pair to an edge router with a
sync group, each with the keepalived configuration insomnia renders.
