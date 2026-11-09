@serial
@dhcp_relay
@dhcp
Feature: DHCPv4 relay with insomnia-dhcp-relay (service dhcp-relay, insomnia feature)

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

      c1 (c0) ── lan1 10.1.0.1 ─┐
                                r1 ── wan1 192.0.2.1 ── (s0) 192.0.2.10 s1  kea-dhcp4
      c2 (c0) ── lan2 10.2.0.1 ─┘

  r1 runs the agent, zebra-rs and insomnia inside a private mount
  namespace (tests/scripts/dhcp_node.sh); insomnia is in signal mode and
  the agent logs every packet decision (RUST_LOG=debug) to
  logs/<ns>.relay.log. s1's Kea comes from tests/scripts/kea_server.sh.
  Each client lease is one dhcpcd run (tests/scripts/dhcp_client.sh).
  Requires Kea (apt install kea-dhcp4-server, or
  `make -C bdd stage KEA_PREFIX=<unpacked packages>`), dhcpcd, and a
  zebra-rs toolchain with the `service` trees staged next to insomnia.

  Config files:
  - r1.conf: the three interface addresses; listen-interface lan1 and
    lan2, upstream-interface wan1, server 192.0.2.10.
  - s1-kea4.json: 10.1.0.0/24 (class circuit-lan1 → 10.1.0.50–59, others
    → 10.1.0.100–199) and 10.2.0.0/24 (10.2.0.100–199), with routers.

  Scenario: Setup the relay and its server
    Given a clean test environment
    When I create namespace "r1"
    And I create namespace "s1"
    And I create namespace "c1"
    And I create namespace "c2"
    And I connect namespace "c1" interface "c0" to namespace "r1" interface "lan1"
    And I connect namespace "c2" interface "c0" to namespace "r1" interface "lan2"
    And I connect namespace "r1" interface "wan1" to namespace "s1" interface "s0"
    And I add address "192.0.2.10/24" to interface "s0" in namespace "s1"
    And I add route "10.0.0.0/8" via "192.0.2.1" in namespace "s1"
    And I spawn "tests/scripts/kea_server.sh dhcp_relay_s1 4 tests/configs/dhcp_relay/s1-kea4.json" in namespace "s1"
    And I spawn "tests/scripts/dhcp_node.sh dhcp_relay_r1" in namespace "r1"
    Then log "kea4" in namespace "s1" should eventually contain "DHCP4_STARTED"
    And insomnia log in namespace "r1" should eventually contain "show provider registered"
    And show command "show interface" in namespace "r1" should eventually contain "lan1"
    When I apply config "r1.conf" to namespace "r1"
    Then insomnia log in namespace "r1" should eventually contain "relay agent loaded 2 DHCPv4"
    And log "relay" in namespace "r1" should eventually contain "dhcp4 listen lan1: open"
    And log "relay" in namespace "r1" should eventually contain "dhcp4 vrf default address 10.1.0.1: open"

  Scenario: A lease through the relay, with option 82 and a unicast reply
    Given the test topology exists
    Then DHCPv4 client on interface "c0" in namespace "c1" should obtain an address in "10.1.0.50-10.1.0.59"
    And the DHCPv4 lease on interface "c0" in namespace "c1" should have "routers" "10.1.0.1"
    And log "relay" in namespace "r1" should eventually contain "reply relayed to lan1 (unicast)"

  Scenario: A client that asks for broadcast gets a broadcast reply
    Given the test topology exists
    Then DHCPv4 client with "broadcast" on interface "c0" in namespace "c2" should obtain an address in "10.2.0.100-10.2.0.199"
    And the DHCPv4 lease on interface "c0" in namespace "c2" should have "routers" "10.2.0.1"
    And log "relay" in namespace "r1" should eventually contain "reply relayed to lan2 (broadcast)"

  Scenario: The relay counts per interface
    Given the test topology exists
    Then show command "show dhcp relay statistics" in namespace "r1" should contain "lan1"
    And show command "show dhcp relay statistics" in namespace "r1" should contain "lan2"
    And show command "show dhcp relay statistics" in namespace "r1" should contain "wan1"
    And show command "show dhcp relay statistics" in namespace "r1" should contain "No option 82"

  Scenario: A reply forged by a client is dropped and counted
    Given the test topology exists
    When I execute "python3 -I tests/scripts/dhcp_forge.py bootreply 10.1.0.1 10.2.0.1" in namespace "c1"
    Then log "relay" in namespace "r1" should eventually contain "dropped: wrong-upstream"
    And show command "show dhcp relay statistics" in namespace "r1" should eventually contain "wrong-upstream"

  Scenario: A request at the hop limit is dropped
    Given the test topology exists
    When I apply command "set service dhcp-relay relay-options hop-count 2" in namespace "r1"
    And I wait 2 seconds
    And I execute "python3 -I tests/scripts/dhcp_forge.py bootrequest 10.1.0.1 2" in namespace "c1"
    Then log "relay" in namespace "r1" should eventually contain "request dropped: hop-limit"
    When I apply command "delete service dhcp-relay relay-options hop-count" in namespace "r1"
    Then DHCPv4 client on interface "c0" in namespace "c1" should obtain an address in "10.1.0.50-10.1.0.59"

  Scenario: Removing a listen interface leaves the others relaying
    Given the test topology exists
    When I apply command "delete service dhcp-relay listen-interface lan2" in namespace "r1"
    And I wait 2 seconds
    Then DHCPv4 client on interface "c0" in namespace "c2" should not obtain an address
    And DHCPv4 client on interface "c0" in namespace "c1" should obtain an address in "10.1.0.50-10.1.0.59"
    When I apply command "set service dhcp-relay listen-interface lan2" in namespace "r1"
    Then DHCPv4 client on interface "c0" in namespace "c2" should obtain an address in "10.2.0.100-10.2.0.199"

  Scenario: disable and delete stop relaying declaratively
    Given the test topology exists
    When I apply command "set service dhcp-relay disable" in namespace "r1"
    Then command "ss -ulpn" in namespace "r1" should eventually not contain "insomnia-dhcp"
    And DHCPv4 client on interface "c0" in namespace "c1" should not obtain an address
    When I apply command "delete service dhcp-relay disable" in namespace "r1"
    Then DHCPv4 client on interface "c0" in namespace "c1" should obtain an address in "10.1.0.50-10.1.0.59"
    When I apply command "delete service dhcp-relay" in namespace "r1"
    Then command "ss -ulpn" in namespace "r1" should eventually not contain "insomnia-dhcp"
    And DHCPv4 client on interface "c0" in namespace "c1" should not obtain an address

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I execute "tests/scripts/dhcp_node_stop.sh dhcp_relay_r1" in namespace "r1"
    And I execute "tests/scripts/dhcp_node_stop.sh dhcp_relay_s1" in namespace "s1"
    And I delete namespace "r1"
    And I delete namespace "s1"
    And I delete namespace "c1"
    And I delete namespace "c2"
    Then the test environment should be clean
