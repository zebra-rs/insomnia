# DHCPv4 relay with insomnia-dhcp-relay (service dhcp-relay, insomnia feature)

## Overview

zebra-rs owns the VyOS-derived `service dhcp-relay` config subtree
(enabled with `--feature insomnia`); insomnia subscribes to it over the
zebra.config.v1 gRPC API, renders relay.json for its relay agent,
insomnia-dhcp-relay, and SIGHUPs it, and answers
`show dhcp relay statistics` on the zebra-rs CLI as the zebra.show.v1
provider from the agent's control socket.

Topology: two client LANs on the relay r1, and a standalone Kea on the
server side. The server is not under test: it serves both LANs by the
relay's giaddr, and puts a client whose relay agent information carries
circuit-id `lan1` in a class with its own range, which is how the
scenarios see option 82 arrive.

r1 runs the agent, zebra-rs and insomnia inside a private mount
namespace (tests/scripts/dhcp_node.sh); insomnia is in signal mode and
the agent logs every packet decision (RUST_LOG=debug) to
logs/<ns>.relay.log. s1's Kea comes from tests/scripts/kea_server.sh.
Each client lease is one dhcpcd run (tests/scripts/dhcp_client.sh).
Requires Kea (apt install kea-dhcp4-server, or
`make -C bdd stage KEA_PREFIX=<unpacked packages>`), dhcpcd, and a
zebra-rs toolchain with the `service` trees staged next to insomnia.

## Config Files

- r1.conf: the three interface addresses; listen-interface lan1 and
  lan2, upstream-interface wan1, server 192.0.2.10.
- s1-kea4.json: 10.1.0.0/24 (class circuit-lan1 → 10.1.0.50–59, others
  → 10.1.0.100–199) and 10.2.0.0/24 (10.2.0.100–199), with routers.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup the relay and its server | |
| A lease through the relay, with option 82 and a unicast reply | |
| A client that asks for broadcast gets a broadcast reply | |
| The relay counts per interface | |
| A reply forged by a client is dropped and counted | |
| A request at the hop limit is dropped | |
| Removing a listen interface leaves the others relaying | |
| disable and delete stop relaying declaratively | |
| Teardown topology | |
