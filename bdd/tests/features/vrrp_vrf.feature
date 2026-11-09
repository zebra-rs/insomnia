@serial
@vrrp_vrf
Feature: VRRP in a VRF beside the global table (vrrp vrf, insomnia feature)

  `vrrp vrf <name> …` is the `vrrp` tree for a VRF (zebra-rs's
  `<feature> vrf <name>` convention; VyOS has no per-VRF VRRP). insomnia
  renders one keepalived instance per VRF, `keepalived@<vrf>`, bound to
  its VRF (`BPFProgram=` under systemd, `ip vrf exec` here), and follows
  the per-VRF rules of design/process.md §4.9: every interface a group
  names must be a member of the instance's VRF.

  Topology: two routers run two VRRP groups side by side. LAN is in VRF
  red, on the bridge the client h1 shares (the routers' bridge veths are
  enslaved to red); WAN is in the global table, on a direct link.

      h1 192.0.2.100 (vh1ns) ──┐
                               br ── (vr1ns, red) 192.0.2.1 r1  priority 200 ┐  LAN: vrid 10, VIP 192.0.2.254
                               └──── (vr2ns, red) 192.0.2.2 r2  priority 100 ┘       (vrrp vrf red)
      r1 (d1) 198.51.100.1 ────────── (d2) 198.51.100.2 r2                       WAN: vrid 20, VIP 198.51.100.254
                                                                                      (vrrp, global table)

  Each router runs zebra-rs, insomnia (signal mode) and the global
  table's keepalived in a private mount namespace
  (tests/scripts/vrrp_node.sh); once zebra-rs has created VRF red,
  `vrrp_node.sh … keepalived-vrf red` starts red's keepalived under
  `ip vrf exec red`. Requires keepalived on the host.

  Config files:
  - r1-vrfs.conf, r2-vrfs.conf: VRF red, the bridge veth enslaved to it,
    and both interfaces' addresses.
  - r1.conf, r2.conf: group WAN on d1/d2 (global table) and group LAN on
    the bridge veth under `vrrp vrf red`, priority 200 / 100.
  - bad.conf: a group in red on d1, which is in the global table.

  Scenario: Setup two routers with a VRRP group in VRF red and one in the global table
    Given a clean test environment
    When I create bridge "br"
    And I create namespace "r1" with IP "192.0.2.1/24" on bridge "br"
    And I create namespace "r2" with IP "192.0.2.2/24" on bridge "br"
    And I create namespace "h1" with IP "192.0.2.100/24" on bridge "br"
    And I connect namespace "r1" interface "d1" to namespace "r2" interface "d2"
    And I spawn "tests/scripts/vrrp_node.sh vrrp_vrf_r1" in namespace "r1"
    And I spawn "tests/scripts/vrrp_node.sh vrrp_vrf_r2" in namespace "r2"
    Then insomnia log in namespace "r1" should eventually contain "show provider registered"
    And insomnia log in namespace "r2" should eventually contain "show provider registered"
    And show command "show interface" in namespace "r1" should eventually contain "d1"
    And show command "show interface" in namespace "r2" should eventually contain "d2"
    When I apply config "r1-vrfs.conf" to namespace "r1"
    And I apply config "r2-vrfs.conf" to namespace "r2"
    Then command "ip -br link show type vrf" in namespace "r1" should eventually contain "red"
    And command "ip -br link show type vrf" in namespace "r2" should eventually contain "red"
    When I execute "tests/scripts/vrrp_node.sh vrrp_vrf_r1 keepalived-vrf red" in namespace "r1"
    And I execute "tests/scripts/vrrp_node.sh vrrp_vrf_r2 keepalived-vrf red" in namespace "r2"
    And I apply config "r1.conf" to namespace "r1"
    And I apply config "r2.conf" to namespace "r2"
    Then insomnia log in namespace "r1" should eventually contain "vrrp vrf red: keepalived configuration loaded"
    And insomnia log in namespace "r1" should eventually contain "vrrp: keepalived configuration loaded"
    And show command "show vrrp vrf red" in namespace "r1" should eventually contain "MASTER"
    And show command "show vrrp vrf red" in namespace "r2" should eventually contain "BACKUP"
    And show command "show vrrp" in namespace "r1" should eventually contain "MASTER"
    And show command "show vrrp" in namespace "r2" should eventually contain "BACKUP"

  Scenario: The VRF's virtual address lives in the VRF
    Given the test topology exists
    Then ping from "h1" to "192.0.2.254" should eventually succeed
    And command "ip -4 addr show dev vr1ns" in namespace "r1" should eventually contain "192.0.2.254"
    And command "ip -4 route show vrf red" in namespace "r1" should eventually contain "192.0.2.0/24"
    And command "ip -4 route show table main" in namespace "r1" should not contain "192.0.2.0/24"
    And command "ip -4 addr show dev d1" in namespace "r1" should eventually contain "198.51.100.254"
    And command "ip -4 route show table main" in namespace "r1" should eventually contain "198.51.100.0/24"

  Scenario: Show is per instance
    Given the test topology exists
    Then show command "show vrrp vrf red detail group LAN" in namespace "r1" should contain "State: MASTER"
    And show command "show vrrp vrf red" in namespace "r1" should not contain "WAN"
    And show command "show vrrp" in namespace "r1" should contain "WAN"
    And show command "show vrrp" in namespace "r1" should not contain "LAN"
    And show command "show vrrp vrf red statistics" in namespace "r2" should contain "Received:"
    And show command "show vrrp vrf blue" in namespace "r1" should contain "VRRP is not configured for VRF blue"
    And show command "show process keepalived@red" in namespace "r1" should contain "keepalived@red  red  running  up"
    And show command "show process keepalived@default" in namespace "r1" should contain "keepalived@default  default  running  up"

  Scenario: Failover inside the VRF leaves the global table's group alone
    Given the test topology exists
    When I bring link down in namespace "r1"
    Then show command "show vrrp vrf red" in namespace "r2" should eventually contain "MASTER"
    And ping from "h1" to "192.0.2.254" should eventually succeed
    And show command "show vrrp" in namespace "r1" should contain "MASTER"
    When I bring link up in namespace "r1"
    Then show command "show vrrp vrf red" in namespace "r1" should eventually contain "MASTER"
    And show command "show vrrp vrf red" in namespace "r2" should eventually contain "BACKUP"

  Scenario: A group on an interface outside the VRF is skipped
    Given the test topology exists
    When I apply config "bad.conf" to namespace "r1"
    Then insomnia log in namespace "r1" should eventually contain "vrrp vrf red: group BAD: interface d1 is in VRF default, not red; skipped"
    And show command "show vrrp vrf red" in namespace "r1" should not contain "BAD"
    And command "ip -4 addr show dev d1" in namespace "r1" should not contain "203.0.113.254"
    When I apply command "delete vrrp vrf red group BAD" in namespace "r1"

  Scenario: Deleting the VRF's tree stops its instance only
    Given the test topology exists
    When I apply command "delete vrrp vrf red" in namespace "r1"
    Then insomnia log in namespace "r1" should eventually contain "vrrp vrf red: keepalived stopped (no configuration)"
    And command "ip -4 addr show dev vr1ns" in namespace "r1" should eventually not contain "192.0.2.254"
    And show command "show vrrp vrf red" in namespace "r2" should eventually contain "MASTER"
    And ping from "h1" to "192.0.2.254" should eventually succeed
    And show command "show vrrp" in namespace "r1" should contain "MASTER"
    And show command "show vrrp vrf red" in namespace "r1" should contain "VRRP is not configured for VRF red"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I execute "tests/scripts/vrrp_node_stop.sh vrrp_vrf_r1" in namespace "r1"
    And I execute "tests/scripts/vrrp_node_stop.sh vrrp_vrf_r2" in namespace "r2"
    And I delete namespace "r1"
    And I delete namespace "r2"
    And I delete namespace "h1"
    And I delete bridge "br"
    Then the test environment should be clean
