@serial
@dhcp_server_relay
@dhcp
Feature: Our relay in front of our server (service dhcp-relay → service dhcp-server, insomnia feature)

  Both ends are insomnia: r1 relays with insomnia-dhcp-relay, r2 serves with
  an insomnia-driven Kea that listens only for relayed traffic. The server
  selects the subnet by giaddr (DHCPv4) or link-address (DHCPv6), and puts a
  client whose option 82 carries circuit-id `lan1` (the relay's listen
  interface) in a class with its own range.

      c1 (c0) ── lan1 10.1.0.1 ─┐
      c2 (c0) ── lan2 10.2.0.1 ─┴─ r1 ── wan1 192.0.2.1 ── (wan1) 192.0.2.2 r2
                                   relay                        kea-dhcp4 / kea-dhcp6

  r2 listens with `listen-address 192.0.2.2` (Kea's UDP socket: relayed
  DHCPv4 only, design/dhcp.md DH8) and `listen-interface wan1` (DHCPv6).
  Kea 2.4 receives DHCPv6 on a link-local and the ff02::1:2 socket per
  interface, and `listen-interface` cannot name a unicast address, so r1
  relays DHCPv6 to ff02::1:2 on wan1.

  Config files:
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

  Scenario: Setup the relay and the server
    Given a clean test environment
    When I create namespace "r1"
    And I create namespace "r2"
    And I create namespace "c1"
    And I create namespace "c2"
    And I connect namespace "c1" interface "c0" to namespace "r1" interface "lan1"
    And I connect namespace "c2" interface "c0" to namespace "r1" interface "lan2"
    And I connect namespace "r1" interface "wan1" to namespace "r2" interface "wan1"
    And I spawn "tests/scripts/dhcp_node.sh dhcp_server_relay_r1" in namespace "r1"
    And I spawn "tests/scripts/dhcp_node.sh dhcp_server_relay_r2 kea" in namespace "r2"
    Then log "kea6" in namespace "r2" should eventually contain "DHCP6_STARTED"
    And insomnia log in namespace "r1" should eventually contain "show provider registered"
    And insomnia log in namespace "r2" should eventually contain "show provider registered"
    And show command "show interface" in namespace "r1" should eventually contain "wan1"
    And show command "show interface" in namespace "r2" should eventually contain "wan1"
    When I apply config "r2.conf" to namespace "r2"
    And I add route "10.0.0.0/8" via "192.0.2.1" in namespace "r2"
    Then insomnia log in namespace "r2" should eventually contain "kea-dhcp4 default: config-reload: 1 shared networks, 2 subnets, interfaces [wan1/192.0.2.2]"
    And insomnia log in namespace "r2" should eventually contain "kea-dhcp6 default: config-reload: 2 shared networks, 2 subnets, interfaces [wan1]"
    When I apply config "r1.conf" to namespace "r1"
    Then insomnia log in namespace "r1" should eventually contain "relay agent loaded 2 DHCPv4 and 2 DHCPv6"

  Scenario: DHCPv4: the subnet by giaddr, the class by circuit-id
    Given the test topology exists
    Then DHCPv4 client with "option routers" on interface "c0" in namespace "c1" should obtain an address in "10.1.0.50-10.1.0.59"
    And the DHCPv4 lease on interface "c0" in namespace "c1" should have "routers" "10.1.0.1"
    And DHCPv4 client on interface "c0" in namespace "c2" should obtain an address in "10.2.0.100-10.2.0.199"

  Scenario: DHCPv6: the subnet by link-address
    Given the test topology exists
    Then DHCPv6 client on interface "c0" in namespace "c1" should obtain an address in "2001:db8:1::100-2001:db8:1::1ff"
    And DHCPv6 client on interface "c0" in namespace "c2" should obtain an address in "2001:db8:2::100-2001:db8:2::1ff"

  Scenario: The counters on both routers line up
    Given the test topology exists
    Then show command "show dhcp relay statistics" in namespace "r1" should contain "lan1"
    And show command "show dhcpv6 relay statistics" in namespace "r1" should contain "lan2"
    And show command "show dhcp server statistics" in namespace "r2" should contain "SITE  110   2       108        2%"
    And show command "show dhcp server leases" in namespace "r2" should contain "10.1.0.5"
    And show command "show dhcp server leases" in namespace "r2" should contain "10.2.0.1"
    And show command "show dhcpv6 server leases" in namespace "r2" should contain "2001:db8:2::1"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I execute "tests/scripts/dhcp_node_stop.sh dhcp_server_relay_r1" in namespace "r1"
    And I execute "tests/scripts/dhcp_node_stop.sh dhcp_server_relay_r2" in namespace "r2"
    And I delete namespace "r1"
    And I delete namespace "r2"
    And I delete namespace "c1"
    And I delete namespace "c2"
    Then the test environment should be clean
