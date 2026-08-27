# Site-to-site IPsec with strongSwan (vpn ipsec, ISO feature)

## Overview

zebra-rs owns the VyOS-style `vpn ipsec` config subtree (enabled
with `--feature iso`); insomnia subscribes to it over the
zebra.config.v1 gRPC API, renders strongSwan swanctl configuration
and loads it into charon over the vici socket, and answers
`show vpn ipsec` on the zebra-rs CLI as the zebra.show.v1 provider —
live SA state read back over the same socket (sa/connections) and
from the kernel (state/policy).

Topology: two nodes, IKEv2 with a pre-shared key, one policy-based
tunnel between dummy-anchored subnets.

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

## Config Files

- z1.conf, z2.conf: psk table with both endpoint ids, esp/ike
  groups (AES-256-GCM, DH group 19), one site-to-site peer with
  tunnel 1 between the dummy subnets.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup two IPsec nodes and establish the tunnel | |
| Traffic flows through the ESP tunnel and counters move | |
| Deleting the config unloads the tunnel declaratively | |
| Teardown topology | |
