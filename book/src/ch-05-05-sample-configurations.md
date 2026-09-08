# Sample Configurations

Five complete configurations, from the smallest useful pair to an
edge router with a sync group. Every `set` block below was applied to
zebra-rs as written, and every `keepalived.conf` shown is what insomnia
rendered from it into `/run/insomnia/vrrp/default/keepalived.conf` —
so the pairs are a faithful guide to what reaches keepalived.

All samples assume `zebra-rs --feature iso` and keepalived installed.

## 1. A master/backup pair

The classic first-hop redundancy setup: two routers on one segment,
one virtual gateway address, hosts point their default route at it.

```
   hosts ── default gateway 192.0.2.254
              │
     ┌────────┴────────┐
   r1 eth0            r2 eth0
   192.0.2.1          192.0.2.2
   priority 200       priority 100         VRID 10, VIP 192.0.2.254/24
```

### r1

```console
set vrrp group LAN interface eth0
set vrrp group LAN vrid 10
set vrrp group LAN priority 200
set vrrp group LAN address 192.0.2.254/24
set vrrp group LAN description LAN gateway, primary
```

### r2

The same group with a lower priority:

```console
set vrrp group LAN interface eth0
set vrrp group LAN vrid 10
set vrrp group LAN priority 100
set vrrp group LAN address 192.0.2.254/24
set vrrp group LAN description LAN gateway, backup
```

### What insomnia renders (r1)

```
global_defs {
    dynamic_interfaces
    script_user root
}

vrrp_instance LAN {
    # LAN gateway, primary
    state BACKUP
    interface eth0
    virtual_router_id 10
    priority 200
    advert_int 1
    preempt_delay 0
    virtual_ipaddress {
        192.0.2.254/24
    }
}
```

Every instance starts in `BACKUP` and elects; the defaults you did not
set (`advert_int 1`, `preempt_delay 0`, meaning preempt immediately)
are filled in by insomnia. The description becomes a comment.

### Verify

```console
r1$ show vrrp
Name  Interface  VRID  State   Priority  Last Transition
----  ---------  ----  ------  --------  ---------------
LAN   eth0       10    MASTER  200       2m14s

r2$ show vrrp
Name  Interface  VRID  State   Priority  Last Transition
----  ---------  ----  ------  --------  ---------------
LAN   eth0       10    BACKUP  100       2m13s
```

`ip -4 addr show dev eth0` on r1 lists `192.0.2.254/24` as a secondary
address; on r2 it does not. Pull r1's cable and both facts swap within
about three seconds; plug it back and r1 preempts.

## 2. Dual-stack: IPv4 and IPv6 gateways

keepalived runs one address family per instance, so a dual-stack
gateway is two groups. They may share the VRID: the virtual MACs
differ per family (`00:00:5e:00:01:0a` for IPv4, `00:00:5e:00:02:0a`
for IPv6), and so do the advertisement channels. VRRPv3 is required
for IPv6; setting it globally keeps both groups on the same protocol
and allows the sub-second advertisement interval.

### r1

```console
set vrrp global-parameters version 3
set vrrp group LAN4 interface eth0
set vrrp group LAN4 vrid 10
set vrrp group LAN4 priority 200
set vrrp group LAN4 advertise-interval 0.5
set vrrp group LAN4 address 192.0.2.254/24
set vrrp group LAN6 interface eth0
set vrrp group LAN6 vrid 10
set vrrp group LAN6 priority 200
set vrrp group LAN6 advertise-interval 0.5
set vrrp group LAN6 address 2001:db8:0:1::ffff/64
```

r2 is identical with `priority 100` in both groups.

### What insomnia renders (r1)

```
global_defs {
    dynamic_interfaces
    script_user root
    vrrp_version 3
}

vrrp_instance LAN4 {
    state BACKUP
    interface eth0
    virtual_router_id 10
    priority 200
    advert_int 0.5
    preempt_delay 0
    virtual_ipaddress {
        192.0.2.254/24
    }
}

vrrp_instance LAN6 {
    state BACKUP
    interface eth0
    virtual_router_id 10
    priority 200
    advert_int 0.5
    preempt_delay 0
    virtual_ipaddress {
        2001:db8:0:1::ffff/64
    }
}
```

The two instances are independent state machines: it is possible, and
harmless, for r1 to be MASTER for IPv4 while r2 is MASTER for IPv6,
for example after a one-sided health-check failure. Put both in a sync
group (sample 5) if the families must move together.

## 3. Unicast VRRP with a virtual MAC and authentication

For segments that do not carry multicast — most cloud networks — the
routers address each other directly. This sample also switches on the
RFC 3768 virtual MAC, so hosts never see the gateway's MAC change, and
a VRRPv2 password.

### r1

```console
set vrrp group LAN interface eth0
set vrrp group LAN vrid 10
set vrrp group LAN priority 200
set vrrp group LAN address 192.0.2.254/24
set vrrp group LAN hello-source-address 192.0.2.1
set vrrp group LAN peer-address 192.0.2.2
set vrrp group LAN rfc3768-compatibility
set vrrp group LAN authentication type plaintext-password
set vrrp group LAN authentication password Zebra1
```

r2 mirrors it: `hello-source-address 192.0.2.2`,
`peer-address 192.0.2.1`, `priority 100`, the same password. With more
than two routers, list every other router as a `peer-address`.

### What insomnia renders (r1)

```
global_defs {
    dynamic_interfaces
    script_user root
}

vrrp_instance LAN {
    state BACKUP
    interface eth0
    virtual_router_id 10
    priority 200
    advert_int 1
    preempt_delay 0
    unicast_peer {
        192.0.2.2
    }
    unicast_src_ip 192.0.2.1
    use_vmac eth0v10v4
    vmac_xmit_base
    authentication {
        auth_pass "Zebra1"
        auth_type PASS
    }
    virtual_ipaddress {
        192.0.2.254/24
    }
}
```

keepalived creates the macvlan `eth0v10v4` with the virtual MAC and
puts `192.0.2.254/24` on it while master; `vmac_xmit_base` sends the
unicast advertisements from `eth0` itself, which is what VyOS does for
unicast with a VMAC. Note that cloud networks which filter unknown
source MACs may need the virtual MAC allowed on the port.

## 4. Active/active: two virtual routers

Both routers forward at once by running two virtual routers with
opposite priorities. Half the hosts use `192.0.2.253` as their
gateway, the other half `192.0.2.254`; when one router fails, the
survivor takes both addresses.

```
   hosts A ── gw 192.0.2.253 (VRID 10)     hosts B ── gw 192.0.2.254 (VRID 20)
                    │                                        │
              r1: master of VRID 10                    r2: master of VRID 20
                  backup for VRID 20                       backup for VRID 10
```

### r1

```console
set vrrp group LAN-A interface eth0
set vrrp group LAN-A vrid 10
set vrrp group LAN-A priority 200
set vrrp group LAN-A address 192.0.2.253/24
set vrrp group LAN-B interface eth0
set vrrp group LAN-B vrid 20
set vrrp group LAN-B priority 100
set vrrp group LAN-B address 192.0.2.254/24
```

### r2

```console
set vrrp group LAN-A interface eth0
set vrrp group LAN-A vrid 10
set vrrp group LAN-A priority 100
set vrrp group LAN-A address 192.0.2.253/24
set vrrp group LAN-B interface eth0
set vrrp group LAN-B vrid 20
set vrrp group LAN-B priority 200
set vrrp group LAN-B address 192.0.2.254/24
```

### What insomnia renders (r1)

```
global_defs {
    dynamic_interfaces
    script_user root
}

vrrp_instance LAN-A {
    state BACKUP
    interface eth0
    virtual_router_id 10
    priority 200
    advert_int 1
    preempt_delay 0
    virtual_ipaddress {
        192.0.2.253/24
    }
}

vrrp_instance LAN-B {
    state BACKUP
    interface eth0
    virtual_router_id 20
    priority 100
    advert_int 1
    preempt_delay 0
    virtual_ipaddress {
        192.0.2.254/24
    }
}
```

### Verify

```console
r1$ show vrrp
Name   Interface  VRID  State   Priority  Last Transition
-----  ---------  ----  ------  --------  ---------------
LAN-A  eth0       10    MASTER  200       5m2s
LAN-B  eth0       20    BACKUP  100       5m1s

r2$ show vrrp
Name   Interface  VRID  State   Priority  Last Transition
-----  ---------  ----  ------  --------  ---------------
LAN-A  eth0       10    BACKUP  100       5m2s
LAN-B  eth0       20    MASTER  200       5m1s
```

Two VRIDs on one interface are fine as long as each VRID is used once
per interface and address family; a repeated pair is skipped with a
warning in the insomnia log.

## 5. An edge router pair with a sync group

An edge router has a LAN side and a WAN side. If only one side fails
over, traffic enters through one router and tries to leave through the
other. The sync group moves both together, a health check on the
upstream gateway fails the whole edge over when the WAN goes dark, and
each side tracks the other interface. A startup delay and a preempt
delay keep a rebooting router from grabbing mastership before its
routing has converged.

```
   LAN 192.0.2.0/24 ── VIP .254 ── r1 / r2 ── VIP 203.0.113.10 ── WAN, upstream 203.0.113.1
                       (VRID 10)   eth0 eth1  (VRID 20)
```

### r1

```console
set vrrp global-parameters startup-delay 30
set vrrp group LAN interface eth0
set vrrp group LAN vrid 10
set vrrp group LAN priority 200
set vrrp group LAN preempt-delay 30
set vrrp group LAN address 192.0.2.254/24
set vrrp group LAN track interface eth1
set vrrp group WAN interface eth1
set vrrp group WAN vrid 20
set vrrp group WAN priority 200
set vrrp group WAN preempt-delay 30
set vrrp group WAN address 203.0.113.10/28
set vrrp group WAN track interface eth0
set vrrp sync-group EDGE member LAN
set vrrp sync-group EDGE member WAN
set vrrp sync-group EDGE health-check ping 203.0.113.1
set vrrp sync-group EDGE health-check interval 5
set vrrp sync-group EDGE health-check failure-count 3
set vrrp sync-group EDGE transition-script master /usr/local/bin/edge-master
set vrrp sync-group EDGE transition-script backup /usr/local/bin/edge-backup
```

r2 is identical with `priority 100` in both groups.

### What insomnia renders (r1)

```
global_defs {
    dynamic_interfaces
    script_user root
    vrrp_startup_delay 30
}

vrrp_script healthcheck_sg_EDGE {
    script "/usr/bin/ping -c1 203.0.113.1"
    interval 5
    fall 3
    rise 1
}

vrrp_instance LAN {
    state BACKUP
    interface eth0
    virtual_router_id 10
    priority 200
    advert_int 1
    preempt_delay 30
    virtual_ipaddress {
        192.0.2.254/24
    }
    track_interface {
        eth1
    }
}

vrrp_instance WAN {
    state BACKUP
    interface eth1
    virtual_router_id 20
    priority 200
    advert_int 1
    preempt_delay 30
    virtual_ipaddress {
        203.0.113.10/28
    }
    track_interface {
        eth0
    }
}

vrrp_sync_group EDGE {
    group {
        LAN
        WAN
    }
    track_script {
        healthcheck_sg_EDGE
    }
    notify_master "/usr/local/bin/edge-master"
    notify_backup "/usr/local/bin/edge-backup"
}
```

The health check lives on the sync group, so its `vrrp_script` and
`track_script` are attached there. Had `LAN` or `WAN` carried a
`health-check` of its own, insomnia would ignore it with a warning:
only the sync group's check decides. The transition scripts run with
keepalived's standard arguments (`GROUP`, `EDGE`, the new state, the
priority) whenever the whole edge changes role.

## Applying and checking

After each `commit` the insomnia log shows one of:

```
vrrp: keepalived configuration loaded
vrrp: keepalived configuration unchanged
vrrp: keepalived stopped (no configuration)
```

followed by any `vrrp: group …; skipped` warnings. Then `show vrrp`
lists the groups keepalived is running, and `show vrrp detail` shows
the negotiated parameters; see [Show VRRP](ch-03-02-show-vrrp.md).
