# VRRP Groups

A group is one virtual router as seen from one physical router. The
routers that back the same virtual address configure the same VRID on
the same segment; the one with the highest priority becomes master and
owns the address.

## A master/backup pair

On the first router:

```console
set vrrp group LAN interface eth0
set vrrp group LAN vrid 10
set vrrp group LAN priority 200
set vrrp group LAN address 192.0.2.254/24
set vrrp group LAN description primary router
commit
```

On the second, the same group with a lower priority:

```console
set vrrp group LAN interface eth0
set vrrp group LAN vrid 10
set vrrp group LAN priority 100
set vrrp group LAN address 192.0.2.254/24
commit
```

Both routers start in BACKUP and elect; the higher priority takes
MASTER within a few advertisement intervals and adds `192.0.2.254/24`
to `eth0`. When it loses the link or its keepalived stops, the other
router takes over and the address moves.

Three leaves are required: `interface`, `vrid` and at least one
`address`. A group missing any of them is skipped with a warning in
the insomnia log and never reaches keepalived; the other groups are
unaffected.

## Addresses

`address` takes an IPv4 or IPv6 address, with or without a prefix
length, and may repeat. An address is added to the group's interface
unless it names its own device:

```console
set vrrp group LAN address 192.0.2.254/24
set vrrp group LAN address 198.51.100.1/24 interface eth1
```

`excluded-address` works the same way but is excluded from the VRRP
advertisement itself — use it when the address list would not fit the
packet, or for addresses that must not take part in the election.

One group carries one address family. Put IPv4 and IPv6 virtual
addresses in separate groups; keepalived cannot mix them, and a mixed
group is skipped.

## Priority and preemption

`priority` (default 100) decides the election; the master advertises
its priority and a backup with a higher one preempts it. `no-preempt`
lets a lower-priority master keep the role until it fails, and
`preempt-delay` waits the given seconds before a higher-priority
router takes over — useful to let routing converge after a reboot.

```console
set vrrp group LAN priority 200
set vrrp group LAN preempt-delay 30
```

## Timers and protocol version

`advertise-interval` is in seconds (default 1). VRRPv2 uses whole
seconds; a VRRPv3 group accepts fractions down to `0.01` and up to
`40.95`:

```console
set vrrp global-parameters version 3
set vrrp group LAN advertise-interval 0.5
```

The global version applies to every group; IPv6 groups always run
VRRPv3. A single group may override it with `version`, which VyOS
does not offer:

```console
set vrrp group LAN version 3
```

## Disabling a group

`disable` removes the group from keepalived without deleting its
configuration. `show vrrp` keeps listing it as `DISABLED`:

```console
set vrrp group LAN disable
```

`set vrrp disable` at the top stops keepalived entirely.
