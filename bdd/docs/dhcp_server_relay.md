# Our relay in front of our server (service dhcp-relay → service dhcp-server, insomnia feature)

## Overview

Both ends are insomnia: r1 relays with insomnia-dhcp-relay, r2 serves with
an insomnia-driven Kea that listens only for relayed traffic. The server
selects the subnet by giaddr (DHCPv4) or link-address (DHCPv6), and puts a
client whose option 82 carries circuit-id `lan1` (the relay's listen
interface) in a class with its own range.

r2 listens with `listen-address 192.0.2.2` (Kea's UDP socket: relayed
DHCPv4 only, design/dhcp.md DH8) and `listen-interface wan1` (DHCPv6).
Kea 2.4 receives DHCPv6 on a link-local and the ff02::1:2 socket per
interface, and `listen-interface` cannot name a unicast address, so r1
relays DHCPv6 to ff02::1:2 on wan1.

## Config Files

- r1.conf: the LAN and WAN addresses; `service dhcp-relay` lan1, lan2 →
  wan1, server 192.0.2.2; `service dhcpv6-relay` lan1, lan2 → wan1
  address ff02::1:2, with the Interface-ID option.
- r2.conf: wan1's addresses; shared network SITE with 10.1.0.0/24 (range
  .50–.59 for class CIRCUIT1, circuit-id lan1) and 10.2.0.0/24 (.100–.199);
  shared networks LAN1 (2001:db8:1::/64) and LAN2 (2001:db8:2::/64). A
  shared network is one link to Kea: giaddr or link-address picks the
  network, then any of its subnets may serve. SITE's 10.1.0.0/24 has only
  the class range, so c2 (no circuit-id lan1) can only get 10.2.0.0/24;
  the DHCPv6 subnets have plain ranges and so need a network each.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup the relay and the server | |
| DHCPv4: the subnet by giaddr, the class by circuit-id | |
| DHCPv6: the subnet by link-address | |
| The counters on both routers line up | |
| Teardown topology | |
