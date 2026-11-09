@serial
@dhcp_server
@dhcp
Feature: DHCPv4 server with Kea (service dhcp-server, insomnia feature)

  zebra-rs owns the VyOS-derived `service dhcp-server` config subtree
  (enabled with `--feature insomnia`); insomnia renders it into a complete
  kea-dhcp4 configuration, loads it with `config-test` and
  `config-reload` over Kea's control socket, and answers
  `show dhcp server leases|statistics|static-mappings` from Kea's
  lease_cmds and stat_cmds.

  Topology: three client LANs on the router r1. lan1 and lan2 carry a
  configured subnet each; lan3 has an address but no subnet, so Kea must
  not listen there (DH8: never "*").

      c1 (c0) ── lan1 10.1.0.1/24 ─┐
      c2 (c0) ── lan2 10.2.0.1/24 ─┼─ r1   zebra-rs + insomnia + kea-dhcp4
      c3 (c0) ── lan3 10.3.0.1/24 ─┘

  r1 runs zebra-rs, insomnia and Kea inside a private mount namespace
  (tests/scripts/dhcp_node.sh … kea): the script starts kea-dhcp4 on a
  bootstrap configuration at the path insomnia renders to, and insomnia
  (`--kea-control socket`) replaces it. Each lease is one dhcpcd run
  (tests/scripts/dhcp_client.sh). c1's MAC address is pinned so the
  static mapping matches it; changing it makes c1 a new client.
  Requires Kea (kea-dhcp4-server, or `make stage KEA_PREFIX=…`) and dhcpcd.

  Config files:
  - bad-range.conf: a range outside its subnet, for the skip scenario.
  - r1.conf: the three interface addresses; shared network LAN with
    10.1.0.0/24 (range .100–.199 minus `exclude 10.1.0.100`, options
    default-router, name-server, domain-name, ntp-server and a
    static-route sent as raw option 121, a static mapping `printer` for
    02:00:00:00:00:01 → 10.1.0.10); shared network LAN2 with 10.2.0.0/24
    (range .50–.59 for client class VOIP, matched on vendor-class-id
    `voip`, and range .100–.199 for everyone else).

  Scenario: Setup the server
    Given a clean test environment
    When I create namespace "r1"
    And I create namespace "c1"
    And I create namespace "c2"
    And I create namespace "c3"
    And I connect namespace "c1" interface "c0" to namespace "r1" interface "lan1"
    And I connect namespace "c2" interface "c0" to namespace "r1" interface "lan2"
    And I connect namespace "c3" interface "c0" to namespace "r1" interface "lan3"
    And I execute "ip link set c0 address 02:00:00:00:00:01" in namespace "c1"
    And I spawn "tests/scripts/dhcp_node.sh dhcp_server_r1 kea" in namespace "r1"
    Then log "kea4" in namespace "r1" should eventually contain "DHCP4_STARTED"
    And insomnia log in namespace "r1" should eventually contain "show provider registered"
    And show command "show interface" in namespace "r1" should eventually contain "lan3"
    When I apply config "r1.conf" to namespace "r1"
    Then insomnia log in namespace "r1" should eventually contain "kea-dhcp4 default: config-reload: 2 shared networks, 2 subnets, interfaces [lan1 lan2]"

  Scenario: The static mapping, with every option of its subnet and shared network
    Given the test topology exists
    Then DHCPv4 client with "option routers;option domain_name_servers;option domain_name;option ntp_servers;option classless_static_routes" on interface "c0" in namespace "c1" should obtain an address in "10.1.0.10-10.1.0.10"
    And the DHCPv4 lease on interface "c0" in namespace "c1" should have "routers" "10.1.0.1"
    And the DHCPv4 lease on interface "c0" in namespace "c1" should have "domain_name_servers" "192.0.2.53"
    And the DHCPv4 lease on interface "c0" in namespace "c1" should have "domain_name" "example.com"
    And the DHCPv4 lease on interface "c0" in namespace "c1" should have "ntp_servers" "192.0.2.123"
    And the DHCPv4 lease on interface "c0" in namespace "c1" should have "classless_static_routes" "198.51.100.0/24 10.1.0.1 0.0.0.0/0 10.1.0.1"

  Scenario: A new client gets the first address of the range, past the excluded one
    Given the test topology exists
    When I execute "ip link set c0 address 02:00:00:00:00:02" in namespace "c1"
    Then DHCPv4 client on interface "c0" in namespace "c1" should obtain an address in "10.1.0.101-10.1.0.101"
    When I execute "ip link set c0 address 02:00:00:00:00:01" in namespace "c1"

  Scenario: A client class selects its own range
    Given the test topology exists
    Then DHCPv4 client with "vendorclassid voip" on interface "c0" in namespace "c2" should obtain an address in "10.2.0.50-10.2.0.59"
    And the DHCPv4 lease on interface "c0" in namespace "c2" should have "routers" "10.2.0.1"

  Scenario: Kea does not listen on an interface without a subnet
    Given the test topology exists
    Then DHCPv4 client on interface "c0" in namespace "c3" should not obtain an address
    And command "ss -lnp --packet" in namespace "r1" should not contain "lan3"

  Scenario: Show commands
    Given the test topology exists
    Then show command "show dhcp server leases" in namespace "r1" should contain "10.1.0.10"
    And show command "show dhcp server leases" in namespace "r1" should contain "10.1.0.101"
    And show command "show dhcp server leases" in namespace "r1" should contain "02:00:00:00:00:02"
    And show command "show dhcp server leases pool LAN2" in namespace "r1" should contain "10.2.0.5"
    And show command "show dhcp server leases pool LAN2" in namespace "r1" should not contain "10.1.0.10"
    And show command "show dhcp server statistics" in namespace "r1" should contain "LAN   99    2       97         2%"
    And show command "show dhcp server statistics pool LAN2" in namespace "r1" should contain "LAN2  110   1       109        1%"
    And show command "show dhcp server static-mappings" in namespace "r1" should contain "LAN   10.1.0.0/24  printer   10.1.0.10   02:00:00:00:00:01  N/A   lobby"
    And show command "show dhcp server leases pool NOPE" in namespace "r1" should contain "does not exist"

  Scenario: A configuration change is a reload that keeps the leases
    Given the test topology exists
    When I apply command "set service dhcp-server shared-network-name LAN option time-zone Asia/Tokyo" in namespace "r1"
    Then DHCPv4 client with "option tzdb_timezone" on interface "c0" in namespace "c1" should obtain an address in "10.1.0.10-10.1.0.10"
    And the DHCPv4 lease on interface "c0" in namespace "c1" should have "tzdb_timezone" "Asia/Tokyo"
    And show command "show dhcp server leases" in namespace "r1" should contain "10.1.0.101"

  Scenario: Kea keeps serving while insomnia is stopped, and is not reloaded when it returns
    Given the test topology exists
    When I execute "tests/scripts/dhcp_node.sh dhcp_server_r1 stop-insomnia" in namespace "r1"
    Then DHCPv4 client with "vendorclassid voip" on interface "c0" in namespace "c2" should obtain an address in "10.2.0.50-10.2.0.59"
    When I execute "tests/scripts/dhcp_node.sh dhcp_server_r1 start-insomnia" in namespace "r1"
    Then insomnia log in namespace "r1" should eventually contain "kea-dhcp4 default: configuration unchanged"

  Scenario: What fails a check is skipped with a warning, the rest is served
    Given the test topology exists
    When I apply config "bad-range.conf" to namespace "r1"
    Then insomnia log in namespace "r1" should eventually contain "subnet 10.1.0.0/24 range bad skipped: not inside the subnet"
    And DHCPv4 client on interface "c0" in namespace "c1" should obtain an address in "10.1.0.10-10.1.0.10"
    When I apply command "delete service dhcp-server shared-network-name LAN subnet 10.1.0.0/24 range bad" in namespace "r1"

  Scenario: disable, then delete, stop serving
    Given the test topology exists
    When I apply command "set service dhcp-server disable" in namespace "r1"
    Then insomnia log in namespace "r1" should eventually contain "kea-dhcp4 default: config-reload: idle (nothing to serve)"
    And show command "show dhcp server leases" in namespace "r1" should contain "DHCP server is disabled"
    And DHCPv4 client on interface "c0" in namespace "c1" should not obtain an address
    When I apply command "delete service dhcp-server" in namespace "r1"
    Then show command "show dhcp server leases" in namespace "r1" should eventually contain "DHCP server is not configured"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I execute "tests/scripts/dhcp_node_stop.sh dhcp_server_r1" in namespace "r1"
    And I delete namespace "r1"
    And I delete namespace "c1"
    And I delete namespace "c2"
    And I delete namespace "c3"
    Then the test environment should be clean
