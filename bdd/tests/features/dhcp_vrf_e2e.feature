@serial
@dhcp_vrf_e2e
@dhcp
Feature: Relay per VRF to server per VRF, overlapping tenants end to end (insomnia feature)

  The whole chain in VRFs: r1 relays each tenant with
  `service dhcp-relay vrf <name>` / `service dhcpv6-relay vrf <name>`, and r2
  serves each tenant with `service dhcp-server vrf <name>` /
  `service dhcpv6-server vrf <name>`. Both tenants use the same addresses on
  every link, each on its own pair of interfaces between the routers, and
  r2's two instances serve the same subnets from disjoint pools.

      c1 (c0) ── lanred  10.1.0.1 ─┐            ┌─ wanred  192.0.2.1 ── 192.0.2.2 wanred  ─┐
                                   r1 (relay)                                              r2 (Kea red, blue)
      c2 (c0) ── lanblue 10.1.0.1 ─┘            └─ wanblue 192.0.2.1 ── 192.0.2.2 wanblue ─┘

  r2's instances listen only for relayed traffic: `listen-address
  192.0.2.2` in each VRF (two UDP sockets on the same address and port,
  each bound to its VRF) and `listen-interface wan<vrf>` for DHCPv6, so r1
  relays DHCPv6 to ff02::1:2 (see dhcp_server_relay.feature). r2's Kea
  pairs are started under `ip vrf exec <vrf>` by
  `dhcp_node.sh … kea-vrf <vrf>` once zebra-rs has created the VRFs.

  Config files:
  - r1.conf: both VRFs, members and addresses, and the per-VRF relays.
  - vrfs.conf: r2's VRFs, members and addresses.
  - r2.conf: the per-VRF servers (red .100–.149 and ::100–::14f, blue
    .150–.199 and ::150–::19f).

  Scenario: Setup both routers
    Given a clean test environment
    When I create namespace "r1"
    And I create namespace "r2"
    And I create namespace "c1"
    And I create namespace "c2"
    And I connect namespace "c1" interface "c0" to namespace "r1" interface "lanred"
    And I connect namespace "c2" interface "c0" to namespace "r1" interface "lanblue"
    And I connect namespace "r1" interface "wanred" to namespace "r2" interface "wanred"
    And I connect namespace "r1" interface "wanblue" to namespace "r2" interface "wanblue"
    And I spawn "tests/scripts/dhcp_node.sh dhcp_vrf_e2e_r1" in namespace "r1"
    And I spawn "tests/scripts/dhcp_node.sh dhcp_vrf_e2e_r2" in namespace "r2"
    Then insomnia log in namespace "r1" should eventually contain "show provider registered"
    And insomnia log in namespace "r2" should eventually contain "show provider registered"
    And show command "show interface" in namespace "r1" should eventually contain "wanblue"
    And show command "show interface" in namespace "r2" should eventually contain "wanblue"
    When I apply config "vrfs.conf" to namespace "r2"
    Then command "ip -br link show type vrf" in namespace "r2" should eventually contain "blue"
    When I execute "tests/scripts/dhcp_node.sh dhcp_vrf_e2e_r2 kea-vrf red" in namespace "r2"
    And I execute "tests/scripts/dhcp_node.sh dhcp_vrf_e2e_r2 kea-vrf blue" in namespace "r2"
    And I execute "ip route add 10.1.0.0/24 via 192.0.2.1 vrf red" in namespace "r2"
    And I execute "ip route add 10.1.0.0/24 via 192.0.2.1 vrf blue" in namespace "r2"
    And I apply config "r2.conf" to namespace "r2"
    Then insomnia log in namespace "r2" should eventually contain "kea-dhcp4 red: config-reload: 1 shared networks, 1 subnets, interfaces [wanred/192.0.2.2]"
    And insomnia log in namespace "r2" should eventually contain "kea-dhcp4 blue: config-reload: 1 shared networks, 1 subnets, interfaces [wanblue/192.0.2.2]"
    And insomnia log in namespace "r2" should eventually contain "kea-dhcp6 red: config-reload: 1 shared networks, 1 subnets, interfaces [wanred]"
    And insomnia log in namespace "r2" should eventually contain "kea-dhcp6 blue: config-reload: 1 shared networks, 1 subnets, interfaces [wanblue]"
    When I apply config "r1.conf" to namespace "r1"
    Then insomnia log in namespace "r1" should eventually contain "relay agent loaded 2 DHCPv4 and 2 DHCPv6"
    And log "relay" in namespace "r1" should eventually contain "dhcp4 vrf blue address 10.1.0.1: open"

  Scenario: Each tenant gets its lease from its own instance, through its own relay
    Given the test topology exists
    Then DHCPv4 client on interface "c0" in namespace "c1" should obtain an address in "10.1.0.100-10.1.0.149"
    And DHCPv4 client on interface "c0" in namespace "c2" should obtain an address in "10.1.0.150-10.1.0.199"
    And DHCPv6 client on interface "c0" in namespace "c1" should obtain an address in "2001:db8:1::100-2001:db8:1::14f"
    And DHCPv6 client on interface "c0" in namespace "c2" should obtain an address in "2001:db8:1::150-2001:db8:1::19f"

  Scenario: The relay counters and the server leases line up per VRF
    Given the test topology exists
    Then show command "show dhcp relay statistics" in namespace "r1" should contain "red   lanred     2         2"
    And show command "show dhcp relay statistics" in namespace "r1" should contain "blue  lanblue    2         2"
    And show command "show dhcp server leases vrf red" in namespace "r2" should contain "10.1.0.100"
    And show command "show dhcp server leases vrf red" in namespace "r2" should not contain "10.1.0.150"
    And show command "show dhcp server leases vrf blue" in namespace "r2" should contain "10.1.0.150"
    And show command "show dhcpv6 server leases vrf blue" in namespace "r2" should contain "2001:db8:1::150"
    And show command "show dhcpv6 server leases vrf blue" in namespace "r2" should not contain "2001:db8:1::100"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I execute "tests/scripts/dhcp_node_stop.sh dhcp_vrf_e2e_r1" in namespace "r1"
    And I execute "tests/scripts/dhcp_node_stop.sh dhcp_vrf_e2e_r2" in namespace "r2"
    And I delete namespace "r1"
    And I delete namespace "r2"
    And I delete namespace "c1"
    And I delete namespace "c2"
    Then the test environment should be clean
