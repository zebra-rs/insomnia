# DHCP in a VRF

Each of the four DHCP trees has a `vrf <name>` list. The leaves under
it are the ones described in the previous chapters; they configure the
same service inside that VRF.

```console
set vrf red
set interface lanred vrf red
set interface lanred ipv4 address 10.1.0.1/24
set service dhcp-server vrf red shared-network-name TENANT subnet 10.1.0.0/24 subnet-id 1
set service dhcp-server vrf red shared-network-name TENANT subnet 10.1.0.0/24 range 0 start 10.1.0.100
set service dhcp-server vrf red shared-network-name TENANT subnet 10.1.0.0/24 range 0 stop 10.1.0.149
commit
```

The top-level leaves (`service dhcp-server shared-network-name …`)
remain the service of the default routing table. zebra-rs refuses
`vrf default` at commit: the default table is configured at the top
level.

## One instance per VRF

A VRF entry is a server or a relay of its own, not a view of the
default one.

- **Servers.** Each VRF gets its own Kea processes, shown by
  `show process` as `kea-dhcp4@<vrf>` and `kea-dhcp6@<vrf>`, with their
  own configuration and their own lease file under
  `/var/lib/insomnia/kea/<vrf>/`.
- **Overlapping addresses are fine.** VRF `red` and VRF `blue` can both
  serve `10.1.0.0/24`, and both can use `subnet-id 1`. Shared-network
  names, subnet ids and leases are per instance.
- **Relays.** One `insomnia-dhcp-relay` process relays for every VRF. A
  VRF instance's sockets are bound to that VRF, so its servers are
  reached through the VRF's routing table.
- **Delegated-prefix routes** go into the VRF's table.

## Rules every VRF instance follows

1. **An interface it names must be in that VRF.** A `listen-interface`,
   `upstream-interface` or DHCPv6 `interface` that is in another VRF, or
   does not exist, is skipped with a warning:

   ```
   dhcp-relay: service dhcpv6-relay vrf red: listen-interface lan9 is in VRF default, not red; skipped
   ```

   Without this rule a VRF instance could take a request from one
   tenant's LAN and answer it from another tenant's server.

2. **The VRF must exist.** An instance whose VRF is not configured is
   not started:

   ```
   dhcp-relay: service dhcp-relay vrf blue: VRF blue does not exist; not started
   ```

   It starts as soon as the VRF appears. No commit to the DHCP tree is
   needed.

3. **A server listens only inside its VRF.** With no `listen-interface`
   or `listen-address`, its listen set is the interfaces of that VRF
   that carry an address inside one of its subnets.

Interfaces can move. When one is put into a VRF, or taken out, the
instances on both sides are re-rendered from the new membership.

## Show commands

The VRF comes right after the feature, before the view:

```console
$ show dhcp server vrf red leases
$ show dhcp server vrf red statistics pool TENANT
$ show dhcpv6 server vrf red leases
$ show dhcp relay vrf red statistics
```

Without `vrf <name>`, the server views show the default table's server.
The relay views show every VRF, with a `VRF` column.

```console
$ show dhcp server vrf green leases
DHCP server is not configured for VRF green
```

## How a Kea instance is tied to its VRF

Kea knows nothing about VRFs. insomnia loads a small socket program
for each VRF and pins it at `/sys/fs/bpf/insomnia/vrf/<vrf>`; the
template unit attaches it (`BPFProgram=sock_create:…`), and from then on
every socket that Kea instance opens belongs to the VRF.

The unit refuses to start without the pinned program, so a Kea can
never come up unbound and serve the wrong routing table. When a VRF is
deleted and created again, insomnia pins the program for the new device
and restarts the instance.

This applies under systemd. Where you start Kea yourself
(`--kea-control socket`), start a VRF's instance with
`ip vrf exec <vrf>`, as the integration tests do.

## Differences from VyOS

- VyOS spells the server `vrf name <n> service dhcp-server`; here it is
  `service dhcp-server vrf <n>`, zebra-rs's order for every per-VRF
  feature.
- VyOS has no relay in a VRF.
- VyOS runs a VRF's Kea under `ip vrf exec`. insomnia binds the systemd
  unit itself, which also holds across restarts of the unit.
