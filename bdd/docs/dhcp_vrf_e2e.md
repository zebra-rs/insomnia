# Relay per VRF to server per VRF, overlapping tenants end to end (insomnia feature)

## Overview

The whole chain in VRFs: r1 relays each tenant with
`service dhcp-relay vrf <name>` / `service dhcpv6-relay vrf <name>`, and r2
serves each tenant with `service dhcp-server vrf <name>` /
`service dhcpv6-server vrf <name>`. Both tenants use the same addresses on
every link, each on its own pair of interfaces between the routers, and
r2's two instances serve the same subnets from disjoint pools.

r2's instances listen only for relayed traffic: `listen-address
192.0.2.2` in each VRF (two UDP sockets on the same address and port,
each bound to its VRF) and `listen-interface wan<vrf>` for DHCPv6, so r1
relays DHCPv6 to ff02::1:2 (see dhcp_server_relay.feature). r2's Kea
pairs are started under `ip vrf exec <vrf>` by
`dhcp_node.sh … kea-vrf <vrf>` once zebra-rs has created the VRFs.

## Config Files

- r1.conf: both VRFs, members and addresses, and the per-VRF relays.
- vrfs.conf: r2's VRFs, members and addresses.
- r2.conf: the per-VRF servers (red .100–.149 and ::100–::14f, blue
  .150–.199 and ::150–::19f).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup both routers | |
| Each tenant gets its lease from its own instance, through its own relay | |
| The relay counters and the server leases line up per VRF | |
| Teardown topology | |
