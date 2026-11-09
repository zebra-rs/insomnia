# VRRP in a VRF beside the global table (vrrp vrf, insomnia feature)

## Overview

`vrrp vrf <name> …` is the `vrrp` tree for a VRF (zebra-rs's
`<feature> vrf <name>` convention; VyOS has no per-VRF VRRP). insomnia
renders one keepalived instance per VRF, `keepalived@<vrf>`, bound to
its VRF (`BPFProgram=` under systemd, `ip vrf exec` here), and follows
the per-VRF rules of design/process.md §4.9: every interface a group
names must be a member of the instance's VRF.

Topology: two routers run two VRRP groups side by side. LAN is in VRF
red, on the bridge the client h1 shares (the routers' bridge veths are
enslaved to red); WAN is in the global table, on a direct link.

Each router runs zebra-rs, insomnia (signal mode) and the global
table's keepalived in a private mount namespace
(tests/scripts/vrrp_node.sh); once zebra-rs has created VRF red,
`vrrp_node.sh … keepalived-vrf red` starts red's keepalived under
`ip vrf exec red`. Requires keepalived on the host.

## Config Files

- r1-vrfs.conf, r2-vrfs.conf: VRF red, the bridge veth enslaved to it,
  and both interfaces' addresses.
- r1.conf, r2.conf: group WAN on d1/d2 (global table) and group LAN on
  the bridge veth under `vrrp vrf red`, priority 200 / 100.
- bad.conf: a group in red on d1, which is in the global table.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup two routers with a VRRP group in VRF red and one in the global table | |
| The VRF's virtual address lives in the VRF | |
| Show is per instance | |
| Failover inside the VRF leaves the global table's group alone | |
| A group on an interface outside the VRF is skipped | |
| Deleting the VRF's tree stops its instance only | |
| Teardown topology | |
