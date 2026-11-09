@serial
@dhcp_server_vrf
@dhcp
Feature: DHCP servers per VRF with overlapping tenants (service dhcp-server vrf, insomnia feature)

  `service dhcp-server vrf <name>` and `service dhcpv6-server vrf <name>`
  give each VRF its own Kea pair (design/dhcp.md §19); insomnia renders one
  configuration per family per VRF from that VRF's interfaces only, so two
  tenants can serve the same subnet. `red` and `blue` both serve
  10.1.0.0/24 and 2001:db8:1::/64 on interfaces with the same addresses,
  from disjoint pools, so the address a client gets proves which instance
  answered. The default VRF serves its own LAN.

      c1 (c0) ── lanred  10.1.0.1  (red)     ─┐
      c2 (c0) ── lanblue 10.1.0.1  (blue)    ─┼─ r1   Kea default, red, blue
      c9 (c0) ── lan9    10.9.0.1  (default) ─┘        (kea-dhcp4 + kea-dhcp6 each)

  r1 runs zebra-rs, insomnia and the default VRF's Kea
  (tests/scripts/dhcp_node.sh … kea); once zebra-rs has created the VRFs,
  `dhcp_node.sh … kea-vrf <vrf>` starts that VRF's pair under
  `ip vrf exec <vrf>`, the kernel hook the units' `BPFProgram=` binding
  uses (design/process.md §4). insomnia drives every instance over its
  control socket (`--kea-control socket`).

  Config files:
  - vrfs.conf: `vrf red`, `vrf blue`, the members and all addresses.
  - r1.conf: the default VRF's LAN9 (10.9.0.0/24, 2001:db8:9::/64); in red
    and in blue, TENANT 10.1.0.0/24 (red .100–.149, blue .150–.199) and
    2001:db8:1::/64 (red ::100–::14f with /56 delegations out of
    2001:db8:8000::/48, blue ::150–::19f).

  Scenario: Setup the router, its VRFs and the three Kea pairs
    Given a clean test environment
    When I create namespace "r1"
    And I create namespace "c1"
    And I create namespace "c2"
    And I create namespace "c9"
    And I connect namespace "c1" interface "c0" to namespace "r1" interface "lanred"
    And I connect namespace "c2" interface "c0" to namespace "r1" interface "lanblue"
    And I connect namespace "c9" interface "c0" to namespace "r1" interface "lan9"
    And I spawn "tests/scripts/dhcp_node.sh dhcp_server_vrf_r1 kea" in namespace "r1"
    Then log "kea6" in namespace "r1" should eventually contain "DHCP6_STARTED"
    And insomnia log in namespace "r1" should eventually contain "show provider registered"
    And show command "show interface" in namespace "r1" should eventually contain "lanblue"
    When I apply config "vrfs.conf" to namespace "r1"
    Then command "ip -br link show type vrf" in namespace "r1" should eventually contain "blue"
    When I execute "tests/scripts/dhcp_node.sh dhcp_server_vrf_r1 kea-vrf red" in namespace "r1"
    And I execute "tests/scripts/dhcp_node.sh dhcp_server_vrf_r1 kea-vrf blue" in namespace "r1"
    Then log "kea6-blue" in namespace "r1" should eventually contain "DHCP6_STARTED"
    When I apply config "r1.conf" to namespace "r1"
    Then insomnia log in namespace "r1" should eventually contain "kea-dhcp4 red: config-reload: 1 shared networks, 1 subnets, interfaces [lanred]"
    And insomnia log in namespace "r1" should eventually contain "kea-dhcp4 blue: config-reload: 1 shared networks, 1 subnets, interfaces [lanblue]"
    And insomnia log in namespace "r1" should eventually contain "kea-dhcp4 default: config-reload: 1 shared networks, 1 subnets, interfaces [lan9]"
    And insomnia log in namespace "r1" should eventually contain "kea-dhcp6 red: config-reload: 1 shared networks, 1 subnets, interfaces [lanred]"
    And insomnia log in namespace "r1" should eventually contain "kea-dhcp6 blue: config-reload: 1 shared networks, 1 subnets, interfaces [lanblue]"
    And insomnia log in namespace "r1" should eventually contain "kea-dhcp6 default: config-reload: 1 shared networks, 1 subnets, interfaces [lan9]"

  Scenario: Each tenant's client gets its lease from its own instance
    Given the test topology exists
    Then DHCPv4 client on interface "c0" in namespace "c1" should obtain an address in "10.1.0.100-10.1.0.149"
    And DHCPv4 client on interface "c0" in namespace "c2" should obtain an address in "10.1.0.150-10.1.0.199"
    And DHCPv4 client on interface "c0" in namespace "c9" should obtain an address in "10.9.0.100-10.9.0.199"
    And DHCPv6 client on interface "c0" in namespace "c1" should obtain an address in "2001:db8:1::100-2001:db8:1::14f"
    And DHCPv6 client on interface "c0" in namespace "c2" should obtain an address in "2001:db8:1::150-2001:db8:1::19f"
    And DHCPv6 client on interface "c0" in namespace "c9" should obtain an address in "2001:db8:9::100-2001:db8:9::1ff"

  Scenario: Show is per VRF
    Given the test topology exists
    Then show command "show dhcp server leases vrf red" in namespace "r1" should contain "10.1.0.100"
    And show command "show dhcp server leases vrf red" in namespace "r1" should not contain "10.1.0.150"
    And show command "show dhcp server leases vrf blue" in namespace "r1" should contain "10.1.0.150"
    And show command "show dhcp server leases" in namespace "r1" should contain "10.9.0.100"
    And show command "show dhcp server leases" in namespace "r1" should not contain "10.1.0."
    And show command "show dhcp server statistics vrf blue pool TENANT" in namespace "r1" should contain "TENANT  50    1       49         2%"
    And show command "show dhcpv6 server leases vrf red" in namespace "r1" should contain "2001:db8:1::100"
    And show command "show dhcp server leases vrf green" in namespace "r1" should contain "DHCP server is not configured for VRF green"

  Scenario: show process lists every instance, and the actions belong to the harness
    Given the test topology exists
    Then show command "show process kea-dhcp4@red" in namespace "r1" should contain "kea-dhcp4@red  red  running  up"
    And show command "show process kea-dhcp6@blue" in namespace "r1" should contain "kea-dhcp6@blue  blue  running  up"
    And show command "show process kea-dhcp4@default" in namespace "r1" should contain "kea-dhcp4@default  default  running  up"
    And show command "show process" in namespace "r1" should contain "dhcp-relay"
    And show command "show process" in namespace "r1" should contain "keepalived@default"
    And show command "stop process kea-dhcp4@red" in namespace "r1" should contain "Not supported in signal mode"
    And show command "show process kea-dhcp4@green" in namespace "r1" should contain "No process"

  Scenario: A delegated prefix is routed in its VRF's table only
    Given the test topology exists
    Then DHCPv6 client on interface "c0" in namespace "c1" should obtain a prefix in "2001:db8:8000::/48"
    And command "ip -6 route show vrf red proto dhcp" in namespace "r1" should eventually contain "2001:db8:8000:"
    And command "ip -6 route show table main proto dhcp" in namespace "r1" should not contain "2001:db8:8000:"

  Scenario: Removing one tenant's server leaves the other alone
    Given the test topology exists
    When I apply command "delete service dhcp-server vrf blue" in namespace "r1"
    Then insomnia log in namespace "r1" should eventually contain "kea-dhcp4 blue: config-reload: idle (nothing to serve)"
    And DHCPv4 client on interface "c0" in namespace "c2" should not obtain an address
    And DHCPv4 client on interface "c0" in namespace "c1" should obtain an address in "10.1.0.100-10.1.0.149"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I execute "tests/scripts/dhcp_node_stop.sh dhcp_server_vrf_r1" in namespace "r1"
    And I delete namespace "r1"
    And I delete namespace "c1"
    And I delete namespace "c2"
    And I delete namespace "c9"
    Then the test environment should be clean
