@serial
@vrrp_pair
Feature: VRRP master/backup pair with keepalived (vrrp, ISO feature)

  zebra-rs owns the VyOS-derived `vrrp` config subtree (enabled with
  `--feature iso`); insomnia subscribes to it over the zebra.config.v1
  gRPC API, renders keepalived.conf, reloads keepalived, and answers
  `show vrrp` on the zebra-rs CLI as the zebra.show.v1 provider — live
  state read back from keepalived's JSON dump.

  Topology: two routers and one host on a bridge. r1 (priority 200) and
  r2 (priority 100) share VRID 10 and the virtual address 192.0.2.254;
  h1 is the client that follows the virtual address.

      h1 192.0.2.100 (vh1ns) ──┐
                               br ── (vr1ns) 192.0.2.1 r1  priority 200 ┐  VIP 192.0.2.254/24
                               └──── (vr2ns) 192.0.2.2 r2  priority 100 ┘  vrid 10

  Each router runs keepalived + zebra-rs + insomnia inside a private
  mount namespace (tests/scripts/vrrp_node.sh) so both use the stock
  /run/insomnia/vrrp/default instance directory without colliding on the
  shared filesystem, and without touching any keepalived service the host
  itself runs. keepalived is started on an empty config and insomnia runs
  in signal mode, SIGHUPing it on every render. Requires keepalived
  installed on the host, and a zebra-rs toolchain staged next to insomnia
  (`make -C bdd stage`).

  Config files (set-format):
  - r1.conf, r2.conf: one group LAN on the bridge veth, vrid 10, virtual
    address 192.0.2.254/24, priority 200 / 100, advertise-interval 1.

  Scenario: Setup two VRRP routers and elect the master
    Given a clean test environment
    When I create bridge "br"
    And I create namespace "r1" with IP "192.0.2.1/24" on bridge "br"
    And I create namespace "r2" with IP "192.0.2.2/24" on bridge "br"
    And I create namespace "h1" with IP "192.0.2.100/24" on bridge "br"
    And I spawn "tests/scripts/vrrp_node.sh vrrp_pair_r1" in namespace "r1"
    And I spawn "tests/scripts/vrrp_node.sh vrrp_pair_r2" in namespace "r2"
    Then show command "show interface" in namespace "r1" should eventually contain "vr1ns"
    And show command "show interface" in namespace "r2" should eventually contain "vr2ns"
    When I apply config "r1.conf" to namespace "r1"
    And I apply config "r2.conf" to namespace "r2"
    Then insomnia log in namespace "r1" should eventually contain "keepalived configuration loaded"
    And insomnia log in namespace "r2" should eventually contain "keepalived configuration loaded"
    And show command "show vrrp" in namespace "r1" should eventually contain "MASTER"
    And show command "show vrrp" in namespace "r2" should eventually contain "BACKUP"
    And command "ip -4 addr show dev vr1ns" in namespace "r1" should eventually contain "192.0.2.254"
    And command "ip -4 addr show dev vr2ns" in namespace "r2" should not contain "192.0.2.254"

  Scenario: The virtual address answers from the master
    Given the test topology exists
    Then ping from "h1" to "192.0.2.254" should eventually succeed
    And show command "show vrrp detail" in namespace "r1" should contain "State: MASTER"
    And show command "show vrrp detail group LAN" in namespace "r2" should contain "State: BACKUP"
    And show command "show vrrp statistics" in namespace "r2" should contain "Received:"

  Scenario: Failover when the master loses its link, preemption when it returns
    Given the test topology exists
    When I bring link down in namespace "r1"
    Then show command "show vrrp" in namespace "r2" should eventually contain "MASTER"
    And command "ip -4 addr show dev vr2ns" in namespace "r2" should eventually contain "192.0.2.254"
    And ping from "h1" to "192.0.2.254" should eventually succeed
    When I bring link up in namespace "r1"
    Then show command "show vrrp" in namespace "r1" should eventually contain "MASTER"
    And show command "show vrrp" in namespace "r2" should eventually contain "BACKUP"
    And command "ip -4 addr show dev vr2ns" in namespace "r2" should eventually not contain "192.0.2.254"

  Scenario: Deleting the config withdraws the virtual address declaratively
    Given the test topology exists
    When I apply command "delete vrrp" in namespace "r1"
    Then insomnia log in namespace "r1" should eventually contain "keepalived stopped (no configuration)"
    And command "ip -4 addr show dev vr1ns" in namespace "r1" should eventually not contain "192.0.2.254"
    And show command "show vrrp" in namespace "r2" should eventually contain "MASTER"
    And ping from "h1" to "192.0.2.254" should eventually succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I execute "tests/scripts/vrrp_node_stop.sh vrrp_pair_r1" in namespace "r1"
    And I execute "tests/scripts/vrrp_node_stop.sh vrrp_pair_r2" in namespace "r2"
    And I delete namespace "r1"
    And I delete namespace "r2"
    And I delete namespace "h1"
    And I delete bridge "br"
    Then the test environment should be clean
