# DHCP servers per VRF with overlapping tenants (service dhcp-server vrf, insomnia feature)

## Overview

`service dhcp-server vrf <name>` and `service dhcpv6-server vrf <name>`
give each VRF its own Kea pair (design/dhcp.md §19); insomnia renders one
configuration per family per VRF from that VRF's interfaces only, so two
tenants can serve the same subnet. `red` and `blue` both serve
10.1.0.0/24 and 2001:db8:1::/64 on interfaces with the same addresses,
from disjoint pools, so the address a client gets proves which instance
answered. The default VRF serves its own LAN.

r1 runs zebra-rs, insomnia and the default VRF's Kea
(tests/scripts/dhcp_node.sh … kea); once zebra-rs has created the VRFs,
`dhcp_node.sh … kea-vrf <vrf>` starts that VRF's pair under
`ip vrf exec <vrf>`, the kernel hook the units' `BPFProgram=` binding
uses (design/process.md §4). insomnia drives every instance over its
control socket (`--kea-control socket`).

## Config Files

- vrfs.conf: `vrf red`, `vrf blue`, the members and all addresses.
- r1.conf: the default VRF's LAN9 (10.9.0.0/24, 2001:db8:9::/64); in red
  and in blue, TENANT 10.1.0.0/24 (red .100–.149, blue .150–.199) and
  2001:db8:1::/64 (red ::100–::14f with /56 delegations out of
  2001:db8:8000::/48, blue ::150–::19f).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup the router, its VRFs and the three Kea pairs | |
| Each tenant's client gets its lease from its own instance | |
| Show is per VRF | |
| show process lists every instance, and the actions belong to the harness | |
| A delegated prefix is routed in its VRF's table only | |
| Removing one tenant's server leaves the other alone | |
| Teardown topology | |
