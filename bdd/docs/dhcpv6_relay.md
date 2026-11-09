# DHCPv6 relay with insomnia-dhcp-relay (service dhcpv6-relay, insomnia feature)

## Overview

zebra-rs owns the VyOS-derived `service dhcpv6-relay` config subtree
(enabled with `--feature insomnia`); insomnia renders it into the
relay agent's relay.json, SIGHUPs insomnia-dhcp-relay, and answers
`show dhcpv6 relay statistics` from the agent's control socket.

Topology: one client LAN on the relay r1, and a standalone Kea on the
server side, listening on its unicast address. The server selects the
subnet by the Relay-forw link-address, and puts a client whose
Relay-forw carries Interface-ID `lan1` in a class with its own range,
which is how the scenarios see the Interface-ID option arrive.

r1 runs the agent, zebra-rs and insomnia inside a private mount
namespace (tests/scripts/dhcp_node.sh); s1's Kea comes from
tests/scripts/kea_server.sh; each lease is one dhcpcd run
(tests/scripts/dhcp_client.sh) with a DUID-LL. Requires the same host
tools as dhcp_relay.feature.

## Config Files

- r1.conf: the two interface addresses; listen-interface lan1,
  upstream-interface wan1 address 2001:db8::10.
- s1-kea6.json: 2001:db8:1::/64 (class ifid-lan1 → 2001:db8:1::50–5f,
  others → 2001:db8:1::100–1ff).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup the relay and its server | |
| An address through the relay, chosen by link-address | |
| With the Interface-ID option the server sees the listen interface | |
| An explicit link-address selects the subnet | |
| A Relay-repl forged by a client is dropped and counted | |
| The relay counts per interface | |
| A multicast server address | |
| delete stops relaying declaratively | |
| Teardown topology | |
