# VRRP master/backup pair with keepalived (vrrp, ISO feature)

## Overview

zebra-rs owns the VyOS-derived `vrrp` config subtree (enabled with
`--feature iso`); insomnia subscribes to it over the zebra.config.v1
gRPC API, renders keepalived.conf, reloads keepalived, and answers
`show vrrp` on the zebra-rs CLI as the zebra.show.v1 provider — live
state read back from keepalived's JSON dump.

Topology: two routers and one host on a bridge. r1 (priority 200) and
r2 (priority 100) share VRID 10 and the virtual address 192.0.2.254;
h1 is the client that follows the virtual address.

Each router runs keepalived + zebra-rs + insomnia inside a private
mount namespace (tests/scripts/vrrp_node.sh) so both use the stock
/run/insomnia/vrrp/default instance directory without colliding on the
shared filesystem, and without touching any keepalived service the host
itself runs. keepalived is started on an empty config and insomnia runs
in signal mode, SIGHUPing it on every render. Requires keepalived
installed on the host, and a zebra-rs toolchain staged next to insomnia
(`make -C bdd stage`).

## Config Files

- r1.conf, r2.conf: one group LAN on the bridge veth, vrid 10, virtual
  address 192.0.2.254/24, priority 200 / 100, advertise-interval 1.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup two VRRP routers and elect the master | |
| The virtual address answers from the master | |
| Failover when the master loses its link, preemption when it returns | |
| Deleting the config withdraws the virtual address declaratively | |
| Teardown topology | |
