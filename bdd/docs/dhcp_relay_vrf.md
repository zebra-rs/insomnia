# DHCPv4 and DHCPv6 relay in VRFs with overlapping tenants (service dhcp-relay vrf, insomnia feature)

## Overview

zebra-rs owns `service dhcp-relay` / `service dhcpv6-relay` and their
per-VRF `vrf <name>` lists, and the VRFs, members and addresses
themselves; insomnia renders one relay.json binding per listen
interface, each tagged with its VRF, and the insomnia-dhcp-relay agent
binds its sockets per VRF (VyOS has no per-VRF relay).

Topology: the relay r1 carries two tenants, `red` and `blue`, that use
the SAME addresses on both sides, plus a default-VRF LAN. Each tenant
has its own standalone server; the two serve the same subnets from
disjoint pools, so the address a client gets proves which server
answered, and that the tenants never cross.

IPv6 is the same picture: 2001:db8:1::/64 on both tenant LANs,
2001:db8::/64 on both tenant server links, 2001:db8:9::/64 and
2001:db8:99::/64 in the default VRF.

Every interface a `vrf <name>` instance names must be a member of that
VRF; insomnia skips any other with a warning (the agent checks again per
request), so a client of one VRF is never relayed to another's servers.

r1 runs the agent, zebra-rs and insomnia (tests/scripts/dhcp_node.sh);
every server runs kea-dhcp4 and kea-dhcp6 (tests/scripts/kea_server.sh).
Requires the same host tools as dhcp_relay.feature.

## Config Files

- r1.conf: `vrf red`, `vrf blue`, the members and all addresses, the
  default-VRF relay on lan9 → wan9, and `vrf red` / `vrf blue` relays
  for both families.
- sred-, sblue-, s9-kea4.json / -kea6.json: one subnet each.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup the relay, the VRFs and the three servers | |
| Each tenant's client gets its lease from its own server | |
| The counters are kept per VRF | |
| The tenants' server-side routes live only in their VRF tables | |
| An interface outside the instance's VRF is not relayed | |
| The relay statistics of one VRF | |
| A reply forged inside a tenant is dropped | |
| Removing one tenant's relay leaves the other alone | |
| A VRF that is deleted and re-created comes back | |
| Teardown topology | |
