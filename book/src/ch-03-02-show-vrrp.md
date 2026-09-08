# Show VRRP

Three operational views, all answered from the running keepalived: on
request insomnia sends keepalived its JSON signal, reads the dump it
writes, and renders it in the VyOS layouts. When keepalived is not
running, or no group is active, the views answer
`VRRP data is not available (process not running or no active groups)`;
the summary then still lists disabled groups.

For machine-readable output request JSON through `vtyctl`, e.g.
`vtyctl show --json "show vrrp"` — the raw dump, one object per group
with `data` and `stats`.

## show vrrp

One row per group with its live state:

```console
$ show vrrp
Name  Interface  VRID  State   Priority  Last Transition
----  ---------  ----  ------  --------  ---------------
LAN   eth0       10    MASTER  200       2m14s
WAN   eth1       20    BACKUP  100       2m13s
OLD   eth2       30    DISABLED
```

`State` is `INIT`, `BACKUP`, `MASTER` or `FAULT` — the last one when
the interface is down, a tracked interface dropped or a health check
failed. `Priority` is the effective priority after tracking
adjustments. Groups carrying `disable` are appended as `DISABLED` from
the committed configuration.

## show vrrp detail

Everything keepalived knows about a group, optionally for one group:

```console
$ show vrrp detail group LAN
 VRRP Instance: LAN
   VRRP Version: 2
   State: MASTER
   Wantstate: MASTER
   Last transition: 1788833808.966043
   Interface: eth0
   Gratuitous ARP delay: 5
   Gratuitous ARP repeat: 5
   Gratuitous ARP refresh: 0
   Gratuitous ARP refresh repeat: 1
   Gratuitous ARP lower priority delay: 5
   Gratuitous ARP lower priority repeat: 5
   Send advert after receive lower priority advert: true
   Send advert after receive higher priority advert: false
   Virtual Router ID: 10
   Priority: 200
   Effective priority: 200
   Advert interval: 1 sec
   Accept: Enabled
   Preempt: Enabled
   Promote secondaries: Disabled
   Authentication type: NONE
   Virtual IP (1):
       192.0.2.254/24 dev eth0 scope global set
   Using smtp notification: no
   Notify deleted: Fault
```

A backup additionally shows `Master priority`, the priority in the
advertisements it is receiving, and for VRRPv3 the master's
advertisement interval.

## show vrrp statistics

Counters since keepalived started, optionally for one group:

```console
$ show vrrp statistics group LAN

VRRP Instance: LAN
  Advertisements:
    Received: 0
    Sent: 134
  Became master: 1
  Released master: 0
  Packet Errors:
    Length: 0
    TTL: 0
    Invalid Type: 0
    Advertisement Interval: 0
    Address List: 0
  Authentication Errors:
    Invalid Type: 0
    Type Mismatch: 0
    Failure: 0
  Priority Zero:
    Received: 0
    Sent: 0
```

The error counters are the first place to look when two routers both
claim MASTER: `Advertisement Interval` and `Address List` errors mean
the routers disagree on the group's configuration, `Authentication`
errors that one side has a password the other lacks, `TTL` that a
router in between forwarded the advertisement.

## Reading the views together

- config committed? → insomnia log shows
  `vrrp: keepalived configuration loaded`.
- keepalived accepted it? → `show vrrp` lists the group.
- election settled? → exactly one router shows `MASTER` for the VRID,
  and `ip addr` on it carries the virtual address.
- advertisements flow? → `Received` grows on the backup,
  `Sent` on the master.
