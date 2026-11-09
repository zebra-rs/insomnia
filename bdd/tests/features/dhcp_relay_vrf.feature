@serial
@dhcp_relay_vrf
@dhcp
Feature: DHCPv4 and DHCPv6 relay in VRFs with overlapping tenants (service dhcp-relay vrf, insomnia feature)

  zebra-rs owns `service dhcp-relay` / `service dhcpv6-relay` and their
  per-VRF `vrf <name>` lists, and the VRFs, members and addresses
  themselves; insomnia renders one relay.json binding per listen
  interface, each tagged with its VRF, and the insomnia-dhcp-relay agent
  binds its sockets per VRF (VyOS has no per-VRF relay).

  Topology: the relay r1 carries two tenants, `red` and `blue`, that use
  the SAME addresses on both sides, plus a default-VRF LAN. Each tenant
  has its own standalone server; the two serve the same subnets from
  disjoint pools, so the address a client gets proves which server
  answered, and that the tenants never cross.

      c1 (c0) ── lanred  10.1.0.1  ─┐                ┌─ wanred  192.0.2.1 ── (s0) 192.0.2.10 sred   pools .100–149
      c2 (c0) ── lanblue 10.1.0.1  ─┼─ r1 (red,blue) ─┼─ wanblue 192.0.2.1 ── (s0) 192.0.2.10 sblue  pools .150–199
      c9 (c0) ── lan9    10.9.0.1  ─┘   (default)    └─ wan9    198.51.100.1 ─ (s0) 198.51.100.10 s9

  IPv6 is the same picture: 2001:db8:1::/64 on both tenant LANs,
  2001:db8::/64 on both tenant server links, 2001:db8:9::/64 and
  2001:db8:99::/64 in the default VRF.

  r1 runs the agent, zebra-rs and insomnia (tests/scripts/dhcp_node.sh);
  every server runs kea-dhcp4 and kea-dhcp6 (tests/scripts/kea_server.sh).
  Requires the same host tools as dhcp_relay.feature.

  Config files:
  - r1.conf: `vrf red`, `vrf blue`, the members and all addresses, the
    default-VRF relay on lan9 → wan9, and `vrf red` / `vrf blue` relays
    for both families.
  - sred-, sblue-, s9-kea4.json / -kea6.json: one subnet each.

  Scenario: Setup the relay, the VRFs and the three servers
    Given a clean test environment
    When I create namespace "r1"
    And I create namespace "sred"
    And I create namespace "sblue"
    And I create namespace "s9"
    And I create namespace "c1"
    And I create namespace "c2"
    And I create namespace "c9"
    And I connect namespace "c1" interface "c0" to namespace "r1" interface "lanred"
    And I connect namespace "c2" interface "c0" to namespace "r1" interface "lanblue"
    And I connect namespace "c9" interface "c0" to namespace "r1" interface "lan9"
    And I connect namespace "r1" interface "wanred" to namespace "sred" interface "s0"
    And I connect namespace "r1" interface "wanblue" to namespace "sblue" interface "s0"
    And I connect namespace "r1" interface "wan9" to namespace "s9" interface "s0"
    And I add address "192.0.2.10/24" to interface "s0" in namespace "sred"
    And I add address "192.0.2.10/24" to interface "s0" in namespace "sblue"
    And I add address "198.51.100.10/24" to interface "s0" in namespace "s9"
    And I execute "ip -6 addr add 2001:db8::10/64 dev s0 nodad" in namespace "sred"
    And I execute "ip -6 addr add 2001:db8::10/64 dev s0 nodad" in namespace "sblue"
    And I execute "ip -6 addr add 2001:db8:99::10/64 dev s0 nodad" in namespace "s9"
    And I add route "10.0.0.0/8" via "192.0.2.1" in namespace "sred"
    And I add route "10.0.0.0/8" via "192.0.2.1" in namespace "sblue"
    And I add route "10.0.0.0/8" via "198.51.100.1" in namespace "s9"
    And I add route "2001:db8:9::/64" via "2001:db8:99::1" in namespace "s9"
    And I spawn "tests/scripts/kea_server.sh dhcp_relay_vrf_sred 4 tests/configs/dhcp_relay_vrf/sred-kea4.json" in namespace "sred"
    And I spawn "tests/scripts/kea_server.sh dhcp_relay_vrf_sred 6 tests/configs/dhcp_relay_vrf/sred-kea6.json" in namespace "sred"
    And I spawn "tests/scripts/kea_server.sh dhcp_relay_vrf_sblue 4 tests/configs/dhcp_relay_vrf/sblue-kea4.json" in namespace "sblue"
    And I spawn "tests/scripts/kea_server.sh dhcp_relay_vrf_sblue 6 tests/configs/dhcp_relay_vrf/sblue-kea6.json" in namespace "sblue"
    And I spawn "tests/scripts/kea_server.sh dhcp_relay_vrf_s9 4 tests/configs/dhcp_relay_vrf/s9-kea4.json" in namespace "s9"
    And I spawn "tests/scripts/kea_server.sh dhcp_relay_vrf_s9 6 tests/configs/dhcp_relay_vrf/s9-kea6.json" in namespace "s9"
    And I spawn "tests/scripts/dhcp_node.sh dhcp_relay_vrf_r1" in namespace "r1"
    Then log "kea6" in namespace "sred" should eventually contain "DHCP6_STARTED"
    And log "kea6" in namespace "sblue" should eventually contain "DHCP6_STARTED"
    And log "kea6" in namespace "s9" should eventually contain "DHCP6_STARTED"
    And insomnia log in namespace "r1" should eventually contain "show provider registered"
    And show command "show interface" in namespace "r1" should eventually contain "lanblue"
    When I apply config "r1.conf" to namespace "r1"
    Then insomnia log in namespace "r1" should eventually contain "relay agent loaded 3 DHCPv4 and 3 DHCPv6"
    And log "relay" in namespace "r1" should eventually contain "dhcp4 vrf red address 10.1.0.1: open"
    And log "relay" in namespace "r1" should eventually contain "dhcp4 vrf blue address 10.1.0.1: open"
    And log "relay" in namespace "r1" should eventually contain "dhcp6 server vrf red: open"
    And log "relay" in namespace "r1" should eventually contain "dhcp6 server vrf blue: open"

  Scenario: Each tenant's client gets its lease from its own server
    Given the test topology exists
    Then DHCPv4 client on interface "c0" in namespace "c1" should obtain an address in "10.1.0.100-10.1.0.149"
    And DHCPv4 client on interface "c0" in namespace "c2" should obtain an address in "10.1.0.150-10.1.0.199"
    And DHCPv4 client on interface "c0" in namespace "c9" should obtain an address in "10.9.0.100-10.9.0.199"
    And DHCPv6 client on interface "c0" in namespace "c1" should obtain an address in "2001:db8:1::100-2001:db8:1::14f"
    And DHCPv6 client on interface "c0" in namespace "c2" should obtain an address in "2001:db8:1::150-2001:db8:1::19f"
    And DHCPv6 client on interface "c0" in namespace "c9" should obtain an address in "2001:db8:9::100-2001:db8:9::1ff"

  Scenario: The counters are kept per VRF
    Given the test topology exists
    Then show command "show dhcp relay statistics" in namespace "r1" should contain "red      lanred"
    And show command "show dhcp relay statistics" in namespace "r1" should contain "blue     lanblue"
    And show command "show dhcp relay statistics" in namespace "r1" should contain "default  lan9"
    And show command "show dhcpv6 relay statistics" in namespace "r1" should contain "red      wanred"
    And show command "show dhcpv6 relay statistics" in namespace "r1" should contain "blue     wanblue"

  Scenario: The tenants' server-side routes live only in their VRF tables
    Given the test topology exists
    Then command "ip route show vrf red" in namespace "r1" should eventually contain "192.0.2.0/24"
    And command "ip route show vrf blue" in namespace "r1" should eventually contain "192.0.2.0/24"
    And command "ip route show table main" in namespace "r1" should not contain "192.0.2.0/24"
    And ping from "r1" to "192.0.2.10" should fail
    And command "ip vrf exec red ping -c 1 -W 2 192.0.2.10" in namespace "r1" should eventually contain "1 received"

  Scenario: A reply forged inside a tenant is dropped
    Given the test topology exists
    When I execute "python3 -I tests/scripts/dhcp_forge.py bootreply 10.1.0.1 10.1.0.1" in namespace "c1"
    Then log "relay" in namespace "r1" should eventually contain "dropped: wrong-upstream"
    And show command "show dhcp relay statistics" in namespace "r1" should eventually contain "wrong-upstream"

  Scenario: Removing one tenant's relay leaves the other alone
    Given the test topology exists
    When I apply command "delete service dhcp-relay vrf blue" in namespace "r1"
    And I wait 2 seconds
    Then DHCPv4 client on interface "c0" in namespace "c2" should not obtain an address
    And DHCPv4 client on interface "c0" in namespace "c1" should obtain an address in "10.1.0.100-10.1.0.149"
    When I apply config "r1.conf" to namespace "r1"
    Then DHCPv4 client on interface "c0" in namespace "c2" should obtain an address in "10.1.0.150-10.1.0.199"

  Scenario: A VRF that is deleted and re-created comes back
    Given the test topology exists
    When I apply command "delete interface lanblue vrf" in namespace "r1"
    And I apply command "delete interface wanblue vrf" in namespace "r1"
    And I apply command "delete vrf blue" in namespace "r1"
    Then command "ip -br link show type vrf" in namespace "r1" should eventually not contain "blue"
    And log "relay" in namespace "r1" should eventually contain "server vrf blue: no interface blue; waiting for it"
    And DHCPv4 client on interface "c0" in namespace "c1" should obtain an address in "10.1.0.100-10.1.0.149"
    When I apply config "r1.conf" to namespace "r1"
    Then command "ip -br link show type vrf" in namespace "r1" should eventually contain "blue"
    And DHCPv4 client on interface "c0" in namespace "c2" should obtain an address in "10.1.0.150-10.1.0.199"
    And DHCPv6 client on interface "c0" in namespace "c2" should obtain an address in "2001:db8:1::150-2001:db8:1::19f"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I execute "tests/scripts/dhcp_node_stop.sh dhcp_relay_vrf_r1" in namespace "r1"
    And I execute "tests/scripts/dhcp_node_stop.sh dhcp_relay_vrf_sred" in namespace "sred"
    And I execute "tests/scripts/dhcp_node_stop.sh dhcp_relay_vrf_sblue" in namespace "sblue"
    And I execute "tests/scripts/dhcp_node_stop.sh dhcp_relay_vrf_s9" in namespace "s9"
    And I delete namespace "r1"
    And I delete namespace "sred"
    And I delete namespace "sblue"
    And I delete namespace "s9"
    And I delete namespace "c1"
    And I delete namespace "c2"
    And I delete namespace "c9"
    Then the test environment should be clean
