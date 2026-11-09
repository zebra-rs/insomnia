# DHCPv4 server with Kea (service dhcp-server, insomnia feature)

## Overview

zebra-rs owns the VyOS-derived `service dhcp-server` config subtree
(enabled with `--feature insomnia`); insomnia renders it into a complete
kea-dhcp4 configuration, loads it with `config-test` and
`config-reload` over Kea's control socket, and answers
`show dhcp server leases|statistics|static-mappings` from Kea's
lease_cmds and stat_cmds.

Topology: three client LANs on the router r1. lan1 and lan2 carry a
configured subnet each; lan3 has an address but no subnet, so Kea must
not listen there (DH8: never "*").

r1 runs zebra-rs, insomnia and Kea inside a private mount namespace
(tests/scripts/dhcp_node.sh … kea): the script starts kea-dhcp4 on a
bootstrap configuration at the path insomnia renders to, and insomnia
(`--kea-control socket`) replaces it. Each lease is one dhcpcd run
(tests/scripts/dhcp_client.sh). c1's MAC address is pinned so the
static mapping matches it; changing it makes c1 a new client.
Requires Kea (kea-dhcp4-server, or `make stage KEA_PREFIX=…`) and dhcpcd.

## Config Files

- bad-range.conf: a range outside its subnet, for the skip scenario.
- r1.conf: the three interface addresses; shared network LAN with
  10.1.0.0/24 (range .100–.199 minus `exclude 10.1.0.100`, options
  default-router, name-server, domain-name, ntp-server and a
  static-route sent as raw option 121, a static mapping `printer` for
  02:00:00:00:00:01 → 10.1.0.10); shared network LAN2 with 10.2.0.0/24
  (range .50–.59 for client class VOIP, matched on vendor-class-id
  `voip`, and range .100–.199 for everyone else).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup the server | |
| The static mapping, with every option of its subnet and shared network | |
| A new client gets the first address of the range, past the excluded one | |
| A client class selects its own range | |
| Kea does not listen on an interface without a subnet | |
| Show commands | |
| A configuration change is a reload that keeps the leases | |
| Kea keeps serving while insomnia is stopped, and is not reloaded when it returns | |
| What fails a check is skipped with a warning, the rest is served | |
| disable, then delete, stop serving | |
| Teardown topology | |
