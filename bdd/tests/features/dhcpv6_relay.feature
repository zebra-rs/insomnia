@serial
@dhcpv6_relay
@dhcp
Feature: DHCPv6 relay with insomnia-dhcp-relay (service dhcpv6-relay, insomnia feature)

  zebra-rs owns the VyOS-derived `service dhcpv6-relay` config subtree
  (enabled with `--feature insomnia`); insomnia renders it into the
  relay agent's relay.json, SIGHUPs insomnia-dhcp-relay, and answers
  `show dhcpv6 relay statistics` from the agent's control socket.

  Topology: one client LAN on the relay r1, and a standalone Kea on the
  server side, listening on its unicast address. The server selects the
  subnet by the Relay-forw link-address, and puts a client whose
  Relay-forw carries Interface-ID `lan1` in a class with its own range,
  which is how the scenarios see the Interface-ID option arrive.

      c1 (c0) ── lan1 2001:db8:1::1 ── r1 ── wan1 2001:db8::1 ── (s0) 2001:db8::10 s1  kea-dhcp6

  r1 runs the agent, zebra-rs and insomnia inside a private mount
  namespace (tests/scripts/dhcp_node.sh); s1's Kea comes from
  tests/scripts/kea_server.sh; each lease is one dhcpcd run
  (tests/scripts/dhcp_client.sh) with a DUID-LL. Requires the same host
  tools as dhcp_relay.feature.

  Config files:
  - r1.conf: the two interface addresses; listen-interface lan1,
    upstream-interface wan1 address 2001:db8::10.
  - s1-kea6.json: 2001:db8:1::/64 (class ifid-lan1 → 2001:db8:1::50–5f,
    others → 2001:db8:1::100–1ff).

  Scenario: Setup the relay and its server
    Given a clean test environment
    When I create namespace "r1"
    And I create namespace "s1"
    And I create namespace "c1"
    And I connect namespace "c1" interface "c0" to namespace "r1" interface "lan1"
    And I connect namespace "r1" interface "wan1" to namespace "s1" interface "s0"
    And I execute "ip -6 addr add 2001:db8::10/64 dev s0 nodad" in namespace "s1"
    And I spawn "tests/scripts/kea_server.sh dhcpv6_relay_s1 6 tests/configs/dhcpv6_relay/s1-kea6.json" in namespace "s1"
    And I spawn "tests/scripts/dhcp_node.sh dhcpv6_relay_r1" in namespace "r1"
    Then log "kea6" in namespace "s1" should eventually contain "DHCP6_STARTED"
    And insomnia log in namespace "r1" should eventually contain "show provider registered"
    And show command "show interface" in namespace "r1" should eventually contain "lan1"
    When I apply config "r1.conf" to namespace "r1"
    Then insomnia log in namespace "r1" should eventually contain "relay agent loaded 0 DHCPv4 and 1 DHCPv6"
    And log "relay" in namespace "r1" should eventually contain "dhcp6 listen lan1: open"
    And log "relay" in namespace "r1" should eventually contain "dhcp6 server vrf default: open"

  Scenario: An address through the relay, chosen by link-address
    Given the test topology exists
    Then DHCPv6 client on interface "c0" in namespace "c1" should obtain an address in "2001:db8:1::100-2001:db8:1::1ff"
    And log "relay" in namespace "r1" should eventually contain "relay-reply delivered to"

  Scenario: With the Interface-ID option the server sees the listen interface
    Given the test topology exists
    When I apply command "set service dhcpv6-relay use-interface-id-option" in namespace "r1"
    And I wait 2 seconds
    Then DHCPv6 client with "duid 00:03:00:01:02:00:00:00:01:99" on interface "c0" in namespace "c1" should obtain an address in "2001:db8:1::50-2001:db8:1::5f"
    When I apply command "delete service dhcpv6-relay use-interface-id-option" in namespace "r1"
    And I wait 2 seconds

  Scenario: An explicit link-address selects the subnet
    Given the test topology exists
    When I apply command "set service dhcpv6-relay listen-interface lan1 address 2001:db8:7::1" in namespace "r1"
    And I wait 2 seconds
    Then DHCPv6 client on interface "c0" in namespace "c1" should not obtain an address
    When I apply command "set service dhcpv6-relay listen-interface lan1 address 2001:db8:1::1" in namespace "r1"
    And I wait 2 seconds
    Then DHCPv6 client on interface "c0" in namespace "c1" should obtain an address in "2001:db8:1::100-2001:db8:1::1ff"

  Scenario: A Relay-repl forged by a client is dropped and counted
    Given the test topology exists
    When I execute "python3 -I tests/scripts/dhcp_forge.py relayrepl c0 2001:db8:1::1" in namespace "c1"
    Then log "relay" in namespace "r1" should eventually contain "dropped: unknown-server"
    And show command "show dhcpv6 relay statistics" in namespace "r1" should eventually contain "unknown-server"

  Scenario: The relay counts per interface
    Given the test topology exists
    Then show command "show dhcpv6 relay statistics" in namespace "r1" should contain "lan1"
    And show command "show dhcpv6 relay statistics" in namespace "r1" should contain "wan1"

  Scenario: A multicast server address
    Given the test topology exists
    When I apply command "delete service dhcpv6-relay upstream-interface wan1 address 2001:db8::10" in namespace "r1"
    And I apply command "set service dhcpv6-relay upstream-interface wan1 address ff02::1:2" in namespace "r1"
    And I wait 2 seconds
    Then DHCPv6 client on interface "c0" in namespace "c1" should obtain an address in "2001:db8:1::100-2001:db8:1::1ff"

  Scenario: delete stops relaying declaratively
    Given the test topology exists
    When I apply command "delete service dhcpv6-relay" in namespace "r1"
    Then command "ss -ulpn" in namespace "r1" should eventually not contain "insomnia-dhcp"
    And DHCPv6 client on interface "c0" in namespace "c1" should not obtain an address

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I execute "tests/scripts/dhcp_node_stop.sh dhcpv6_relay_r1" in namespace "r1"
    And I execute "tests/scripts/dhcp_node_stop.sh dhcpv6_relay_s1" in namespace "s1"
    And I delete namespace "r1"
    And I delete namespace "s1"
    And I delete namespace "c1"
    Then the test environment should be clean
