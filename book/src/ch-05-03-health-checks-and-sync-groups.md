# Health Checks, Tracking and Sync Groups

Priority alone only reacts to the router going away. Health checks
and tracked interfaces let a master step down while it is still up but
no longer useful.

## Health checks

A health check runs a script or a ping on an interval. When it fails
`failure-count` times in a row the group enters FAULT and a backup
takes over; one success brings it back:

```console
set vrrp group LAN health-check ping 192.0.2.1
set vrrp group LAN health-check interval 5
set vrrp group LAN health-check failure-count 3
```

or

```console
set vrrp group LAN health-check script /usr/local/bin/check-uplink
set vrrp group LAN health-check interval 10
set vrrp group LAN health-check timeout 8
```

Exactly one of `script` and `ping` must be set; otherwise the check is
dropped with a warning and the group runs unchecked. A `timeout`
shorter than the interval is accepted but warned about, since the
script may be killed before it finishes. Scripts run as root.

## Tracked interfaces

The group's own interface is always tracked: if it goes down the group
enters FAULT. Add other interfaces whose loss should trigger a failover
too, typically the uplink behind a LAN-facing virtual address:

```console
set vrrp group LAN track interface eth1
set vrrp group LAN track exclude-vrrp-interface
```

`exclude-vrrp-interface` stops tracking the VRRP interface itself
(keepalived `dont_track_primary`), for setups where that link flapping
must not move the address.

## Transition scripts

Run a command when the group changes state:

```console
set vrrp group LAN transition-script master /usr/local/bin/on-master
set vrrp group LAN transition-script backup /usr/local/bin/on-backup
set vrrp group LAN transition-script fault  /usr/local/bin/on-fault
set vrrp group LAN transition-script stop   /usr/local/bin/on-stop
```

insomnia renders these as keepalived's native `notify_master`,
`notify_backup`, `notify_fault` and `notify_stop` lines. VyOS routes
them through a FIFO and a Python dispatcher; the effect is the same,
the scripts receive keepalived's standard arguments.

## Sync groups

Two groups on one router — say the LAN side and the WAN side — must
fail over together, or traffic ends up entering through one router and
leaving through the other. A sync group ties them:

```console
set vrrp sync-group PAIR member LAN
set vrrp sync-group PAIR member WAN
set vrrp sync-group PAIR health-check ping 203.0.113.1
```

When any member enters FAULT the whole sync group steps down. The sync
group carries its own health check and transition scripts; a member's
own `health-check` is ignored while it belongs to a sync group (VyOS
refuses that commit, insomnia warns and uses the sync group's). A
member must name an existing, enabled group.

## Gratuitous ARP

On becoming master keepalived sends gratuitous ARPs so switches and
hosts learn the new location of the virtual address. The defaults suit
most segments; tune them per group or for every group:

```console
set vrrp group LAN garp master-repeat 3
set vrrp group LAN garp master-refresh 30
set vrrp global-parameters garp master-delay 10
```

`interval` is the gap between the packets, `master-delay` the wait
before a second burst after the transition, `master-repeat` the burst
size, and `master-refresh` / `master-refresh-repeat` a periodic refresh
while master (0 disables it).

## Startup delay

`global-parameters startup-delay` holds every group in INIT for the
given seconds after keepalived starts, so a rebooting router does not
grab mastership before its routing has converged:

```console
set vrrp global-parameters startup-delay 30
```
