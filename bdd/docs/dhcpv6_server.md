# DHCPv6 server with Kea and delegated-prefix routes (service dhcpv6-server, insomnia feature)

## Overview

zebra-rs owns the VyOS-derived `service dhcpv6-server` config subtree
(enabled with `--feature insomnia`); insomnia renders it into a complete
kea-dhcp6 configuration, loads it over Kea's control socket, answers
`show dhcpv6 server …`, and installs a `proto dhcp` route for every
delegated prefix (design/dhcp.md §7.5, DH9): Kea's run_script hook runs
kea-notify, which tells insomnia, which confirms the lease with
`lease6-get` before it touches the routing table.

Topology: two client LANs on the router r1. LAN serves addresses and a
static mapping by DUID; PD serves addresses and /56 prefixes out of
2001:db8:8000::/48, with a 20-second lease so that expiry can be seen.

r1 runs zebra-rs, insomnia and Kea inside a private mount namespace
(tests/scripts/dhcp_node.sh … kea). Each lease is one dhcpcd run
(tests/scripts/dhcp_client.sh) with a DUID-LL; c1's MAC address is
pinned, so its DUID matches the static mapping. Requires Kea
(kea-dhcp6-server, or `make stage KEA_PREFIX=…`) and dhcpcd.

## Config Files

- r1.conf: the interface addresses; global name-server; shared network
  LAN (2001:db8:1::/64, range ::100–::1ff, domain-search, static mapping
  `c1` for DUID 00:03:00:01:02:00:00:00:00:01 → 2001:db8:1::10); shared
  network PD (2001:db8:2::/64, range ::100–::1ff, prefix-delegation
  2001:db8:8000::/48 in /56s, lease-time 20 s).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup the server | |
| The static mapping by DUID, with the global and shared-network options | |
| Another client gets an address from the range | |
| A delegated prefix is routed to the requesting router | |
| The route goes when the lease expires | |
| disable-route-autoinstall delegates without routing | |
| Show commands | |
| delete stops serving | |
| Teardown topology | |
