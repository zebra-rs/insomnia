@serial
@dhcpv6_server
@dhcp
Feature: DHCPv6 server with Kea and delegated-prefix routes (service dhcpv6-server, insomnia feature)

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

      c1 (c0) ── lan1 2001:db8:1::1/64 ─┐
      c2 (c0) ── lan2 2001:db8:2::1/64 ─┴─ r1   zebra-rs + insomnia + kea-dhcp6

  r1 runs zebra-rs, insomnia and Kea inside a private mount namespace
  (tests/scripts/dhcp_node.sh … kea). Each lease is one dhcpcd run
  (tests/scripts/dhcp_client.sh) with a DUID-LL; c1's MAC address is
  pinned, so its DUID matches the static mapping. Requires Kea
  (kea-dhcp6-server, or `make stage KEA_PREFIX=…`) and dhcpcd.

  Config files:
  - r1.conf: the interface addresses; global name-server; shared network
    LAN (2001:db8:1::/64, range ::100–::1ff, domain-search, static mapping
    `c1` for DUID 00:03:00:01:02:00:00:00:00:01 → 2001:db8:1::10); shared
    network PD (2001:db8:2::/64, range ::100–::1ff, prefix-delegation
    2001:db8:8000::/48 in /56s, lease-time 20 s).

  Scenario: Setup the server
    Given a clean test environment
    When I create namespace "r1"
    And I create namespace "c1"
    And I create namespace "c2"
    And I connect namespace "c1" interface "c0" to namespace "r1" interface "lan1"
    And I connect namespace "c2" interface "c0" to namespace "r1" interface "lan2"
    And I execute "ip link set c0 address 02:00:00:00:00:01" in namespace "c1"
    And I spawn "tests/scripts/dhcp_node.sh dhcpv6_server_r1 kea" in namespace "r1"
    Then log "kea6" in namespace "r1" should eventually contain "DHCP6_STARTED"
    And insomnia log in namespace "r1" should eventually contain "show provider registered"
    And show command "show interface" in namespace "r1" should eventually contain "lan2"
    When I apply config "r1.conf" to namespace "r1"
    Then insomnia log in namespace "r1" should eventually contain "kea-dhcp6 default: config-reload: 2 shared networks, 2 subnets, interfaces [lan1 lan2]"

  Scenario: The static mapping by DUID, with the global and shared-network options
    Given the test topology exists
    Then DHCPv6 client with "option dhcp6_name_servers;option dhcp6_domain_search" on interface "c0" in namespace "c1" should obtain an address in "2001:db8:1::10-2001:db8:1::10"
    And the DHCPv6 lease on interface "c0" in namespace "c1" should have "dhcp6_name_servers" "2001:db8::53"
    And the DHCPv6 lease on interface "c0" in namespace "c1" should have "dhcp6_domain_search" "example.com"

  Scenario: Another client gets an address from the range
    Given the test topology exists
    When I execute "ip link set c0 address 02:00:00:00:00:02" in namespace "c1"
    Then DHCPv6 client on interface "c0" in namespace "c1" should obtain an address in "2001:db8:1::100-2001:db8:1::1ff"
    When I execute "ip link set c0 address 02:00:00:00:00:01" in namespace "c1"

  Scenario: A delegated prefix is routed to the requesting router
    Given the test topology exists
    Then DHCPv6 client on interface "c0" in namespace "c2" should obtain a prefix in "2001:db8:8000::/48"
    And command "ip -6 route show proto dhcp" in namespace "r1" should eventually contain "2001:db8:8000:"
    And command "ip -6 route show proto dhcp" in namespace "r1" should eventually contain "via fe80::"
    And insomnia log in namespace "r1" should eventually contain "proto dhcp installed"
    And show command "show ipv6 route" in namespace "r1" should eventually contain "2001:db8:8000:"

  Scenario: The route goes when the lease expires
    Given the test topology exists
    When I wait 15 seconds
    Then command "ip -6 route show proto dhcp" in namespace "r1" should eventually not contain "2001:db8:8000:"
    And insomnia log in namespace "r1" should eventually contain "removed (no active lease)"

  Scenario: disable-route-autoinstall delegates without routing
    Given the test topology exists
    When I apply command "set service dhcpv6-server disable-route-autoinstall" in namespace "r1"
    And I wait 2 seconds
    Then DHCPv6 client on interface "c0" in namespace "c2" should obtain a prefix in "2001:db8:8000::/48"
    When I wait 3 seconds
    Then command "ip -6 route show proto dhcp" in namespace "r1" should not contain "2001:db8:8000:"
    When I apply command "delete service dhcpv6-server disable-route-autoinstall" in namespace "r1"

  Scenario: Show commands
    Given the test topology exists
    Then show command "show dhcpv6 server leases" in namespace "r1" should contain "2001:db8:1::10"
    And show command "show dhcpv6 server leases pool LAN" in namespace "r1" should contain "IA_NA"
    And show command "show dhcpv6 server statistics pool LAN" in namespace "r1" should contain "LAN   256   2       254        1%"
    And show command "show dhcpv6 server static-mappings" in namespace "r1" should contain "00:03:00:01:02:00:00:00:00:01"

  Scenario: delete stops serving
    Given the test topology exists
    When I apply command "delete service dhcpv6-server" in namespace "r1"
    Then show command "show dhcpv6 server leases" in namespace "r1" should eventually contain "DHCPv6 server is not configured"
    And DHCPv6 client on interface "c0" in namespace "c1" should not obtain an address

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I execute "tests/scripts/dhcp_node_stop.sh dhcpv6_server_r1" in namespace "r1"
    And I delete namespace "r1"
    And I delete namespace "c1"
    And I delete namespace "c2"
    Then the test environment should be clean
