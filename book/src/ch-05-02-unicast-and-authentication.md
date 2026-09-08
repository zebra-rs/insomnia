# Unicast VRRP, Virtual MAC and Authentication

## Unicast peers

VRRP advertisements are multicast to 224.0.0.18 (ff02::12 for IPv6).
Where multicast does not cross the segment — many cloud networks, some
L2 fabrics — list the peers explicitly and keepalived exchanges
advertisements as unicast:

```console
set vrrp group LAN peer-address 192.0.2.2
set vrrp group LAN hello-source-address 192.0.2.1
```

`hello-source-address` is the source of the advertisements. With peers
it becomes the unicast source; without peers it is the source of the
multicast advertisements. Peers and the source must be in the group's
address family, or the group is skipped.

## Virtual MAC (RFC 3768 compatibility)

By default the virtual address is added to the interface and answers
ARP with the interface's own MAC. `rfc3768-compatibility` makes
keepalived create a macvlan named `<interface>v<vrid>v4` (or `v6`) with
the RFC virtual MAC `00:00:5e:00:01:<vrid>`, and moves the virtual
address there. Hosts then never see the MAC change on failover:

```console
set vrrp group LAN rfc3768-compatibility
```

With unicast peers keepalived transmits from the base interface
(`vmac_xmit_base`), exactly as VyOS renders it.

## Authentication

VRRPv2 carries an optional password, either in the clear or as an AH
header. RFC 5798 removed authentication from VRRPv3, and it adds no
real security, but it keeps a mixed fleet consistent:

```console
set vrrp group LAN authentication type plaintext-password
set vrrp group LAN authentication password s3cret
```

Both leaves are required together. keepalived uses at most eight
characters of the password; a longer one is truncated with a warning.

## Checksum interoperability

Some vendors compute the VRRPv3 checksum for IPv4 without the
pseudo-header. If such a peer ignores this router's advertisements, or
this router ignores theirs, set the keepalived option directly:

```console
set vrrp group LAN v3-checksum-as-v2
```

This is the same fix FRR exposes as `no checksum-with-ipv4-pseudoheader`.
