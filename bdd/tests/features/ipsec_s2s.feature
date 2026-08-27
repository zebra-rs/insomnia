@serial
@ipsec_s2s
Feature: Site-to-site IPsec with strongSwan (vpn ipsec, ISO feature)

  zebra-rs owns the VyOS-style `vpn ipsec` config subtree (enabled
  with `--feature iso`); insomnia subscribes to it over the
  zebra.config.v1 gRPC API, renders strongSwan swanctl configuration
  and loads it into charon over the vici socket, and answers
  `show vpn ipsec` on the zebra-rs CLI as the zebra.show.v1 provider —
  live SA state read back over the same socket (sa/connections) and
  from the kernel (state/policy).

  Topology: two nodes, IKEv2 with a pre-shared key, one policy-based
  tunnel between dummy-anchored subnets.

      z1 192.0.2.1 (i1) <----------------> (i1) 192.0.2.9 z2
      d1 10.0.1.1/24        ESP tunnel          d1 10.0.2.1/24
                     10.0.1.0/24 <-> 10.0.2.0/24

  Each node runs charon-systemd + zebra-rs + insomnia inside a private
  mount namespace (tests/scripts/ipsec_node.sh) so both instances use
  the stock /etc/swanctl and /run/charon.vici paths without colliding
  on the shared filesystem — see the script header. Requires
  charon-systemd and strongswan-swanctl installed on the host, and a
  zebra-rs toolchain staged next to insomnia (`make -C bdd stage`).

  The responder is configured — and its insomnia has loaded charon —
  before the initiator: insomnia applies each node's config
  asynchronously (it subscribes to zebra-rs and loads swanctl on its
  own schedule), and a `connection-type initiate` child fires the
  moment it is loaded. If the responder's charon has no config yet it
  answers NO_PROPOSAL_CHOSEN, and charon does not retry an IKE_SA that
  failed on an error notify (`keyingtries = 0` only covers timeouts),
  so the tunnel would stay down. The in-process backend loaded inside
  the commit and hid this ordering; between two real hosts it is the
  same rule — bring the responder up first.

  Config files (set-format; z1 initiates, z2 responds):
  - z1.conf, z2.conf: psk table with both endpoint ids, esp/ike
    groups (AES-256-GCM, DH group 19), one site-to-site peer with
    tunnel 1 between the dummy subnets.

  Scenario: Setup two IPsec nodes and establish the tunnel
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "i1" to namespace "z2" interface "i1"
    And I add address "192.0.2.1/24" to interface "i1" in namespace "z1"
    And I add address "192.0.2.9/24" to interface "i1" in namespace "z2"
    And I create dummy interface "d1" with address "10.0.1.1/24" in namespace "z1"
    And I create dummy interface "d1" with address "10.0.2.1/24" in namespace "z2"
    And I spawn "tests/scripts/ipsec_node.sh ipsec_s2s_z1" in namespace "z1"
    And I spawn "tests/scripts/ipsec_node.sh ipsec_s2s_z2" in namespace "z2"
    Then show command "show interface" in namespace "z1" should eventually contain "i1"
    And show command "show interface" in namespace "z2" should eventually contain "i1"
    When I apply config "z2.conf" to namespace "z2"
    Then insomnia log in namespace "z2" should eventually contain "swanctl configuration loaded"
    When I apply config "z1.conf" to namespace "z1"
    Then insomnia log in namespace "z1" should eventually contain "swanctl configuration loaded"
    And show command "show vpn ipsec sa" in namespace "z1" should eventually contain "192-0-2-9-tunnel-1"
    And show command "show vpn ipsec sa" in namespace "z1" should eventually contain "AES_GCM_16_256"
    And show command "show vpn ipsec sa" in namespace "z2" should eventually contain "192-0-2-1-tunnel-1"

  Scenario: Traffic flows through the ESP tunnel and counters move
    Given the test topology exists
    Then command "ping -c 2 -I 10.0.1.1 10.0.2.1" in namespace "z1" should eventually contain "2 received"
    And show command "show vpn ipsec sa" in namespace "z1" should eventually not contain "0B/0B"
    And show command "show vpn ipsec state" in namespace "z1" should contain "proto esp"
    And show command "show vpn ipsec policy" in namespace "z1" should contain "10.0.2.0/24"
    And show command "show vpn ipsec connections" in namespace "z1" should contain "IKEv2"
    And show command "show vpn ipsec connections" in namespace "z1" should contain "10.0.1.0/24"

  Scenario: Deleting the config unloads the tunnel declaratively
    Given the test topology exists
    When I apply command "delete vpn ipsec" in namespace "z1"
    Then show command "show vpn ipsec sa" in namespace "z1" should eventually not contain "tunnel-1"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I execute "tests/scripts/ipsec_node_stop.sh ipsec_s2s_z1" in namespace "z1"
    And I execute "tests/scripts/ipsec_node_stop.sh ipsec_s2s_z2" in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
