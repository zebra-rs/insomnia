# BDD Integration Tests

insomnia's integration tests live in `bdd/` and drive **real daemons** —
zebra-rs as the configuration owner, insomnia as the enforcement daemon,
and the daemon a feature is about (strongSwan's `charon`, keepalived,
Kea, the DHCP relay agent) — inside Linux network namespaces on the
host you run them on. They are written as
Cucumber features (`bdd/tests/features/*.feature`) and executed by a
Rust harness (`bdd/tests/cucumber.rs`) that creates the namespaces, wires
veth pairs, starts the daemons, applies configuration through `vtyctl`
and asserts on `show` output, daemon logs and the kernel.

The harness is the same one zebra-rs uses for its own suite, exported
here so both repositories share one step vocabulary; a feature written
for zebra-rs reads the same in insomnia.

## Prerequisites

- Linux with network-namespace support and non-interactive `sudo` — every
  in-namespace command runs as `sudo ip netns exec …`.
- A zebra-rs toolchain: `zebra-rs`, `vtyctl`, `vtyhelper` and the YANG
  schemas, laid out like `/usr` (the installed `zebra-rs` package, or a
  zebra-rs worktree's own `bdd/.stage`). zebra-rs must be recent enough
  to carry the gRPC config subscription and show-provider registration
  insomnia depends on.
- For the IPsec features: `charon-systemd` and `strongswan-swanctl`
  (`apt install charon-systemd strongswan-swanctl`).
- For the VRRP features: `keepalived` (`apt install keepalived`).
- For the DHCP features: Kea and `dhcpcd`, which plays the clients
  (`apt install kea-dhcp4-server kea-dhcp6-server dhcpcd-base`). On a
  host without Kea installed, an unpacked copy of the packages works
  too; see `KEA_PREFIX` below.
- Optional: the `allure` CLI to browse the HTML report.

## Staging the toolchain

A run never resolves binaries through `/usr` directly. `make -C bdd stage`
builds this worktree's `insomnia` (release profile) and copies it,
together with the zebra-rs toolchain taken from `ZEBRA_PREFIX`, into
`bdd/.stage/` mirroring the `/usr` layout:

```text
bdd/.stage/
  bin/{insomnia,insomnia-dhcp-relay,insomnia-kea-notify}
  bin/{zebra-rs,vtyctl,vtyhelper}
  share/zebra-rs/yang/*.yang
```

`ZEBRA_PREFIX` defaults to `/usr` (the installed package). To test
against an unreleased zebra-rs, point it at that worktree's stage:

```sh
make -C bdd stage ZEBRA_PREFIX=../../zebra-rs/bdd/.stage
```

Kea is taken from the host. To run the DHCP features without
installing it, unpack the Ubuntu packages (`dpkg-deb -x` of
`kea-common`, `kea-dhcp4-server`, `kea-dhcp6-server` and `liblog4cplus`
into one directory) and name that directory when staging:

```sh
make -C bdd stage KEA_PREFIX=/path/to/unpacked-kea
```

Every test target stages first, so a run can never exercise a stale
binary; `make -C bdd unstage` removes the stage again. Staged files are
copies, so rebuilding while a run is in flight does not swap the binary
out from under it.

## Running

```sh
make -C bdd ipsec_s2s        # one feature set (a cucumber --tags filter)
make -C bdd dhcp_server      # one DHCP feature
make -C bdd dhcp             # every DHCP feature
make -C bdd run              # every feature, one at a time
make -C bdd all              # every feature, 16 in parallel
make -C bdd open             # regenerate and open the Allure report
```

Any tag can be run directly from `bdd/` once staged:

```sh
cargo test --test cucumber -- --concurrency=1 --tags "@ipsec_s2s"
```

Set `BDD_KEEP=1` to leave the namespaces and daemons up after a run for
inspection (`BDD_KEEP=1 make -C bdd ipsec_s2s`); the next run's
`Given a clean test environment` sweeps them.

## What lands where

- `bdd/logs/<feature>_<node>.log` — the zebra-rs daemon log of each node.
- `bdd/logs/<feature>_<node>.insomnia.log` — insomnia's log for that node.
- `bdd/logs/<feature>_<node>.charon.log` — strongSwan's log (IPsec features).
- `bdd/logs/<feature>_<node>.keepalived.log` — keepalived's log (VRRP features).
- `bdd/logs/<feature>_<node>.relay.log` — the DHCP relay agent's log, at
  debug level (DHCP features).
- `bdd/logs/<feature>_<node>.kea4.log`, `.kea6.log` — Kea's logs: a
  standalone server's, or a router's default-VRF instance. A router's
  per-VRF instances log to `.kea4-<vrf>.log` and `.kea6-<vrf>.log`.
- `bdd/logs/<feature>.cucumber.log` — the per-feature step report when
  features run concurrently (serial runs print to the terminal).
- `bdd/allure-results/` — one JSON result per feature for the Allure report.

Daemon logs append across runs; the log-assertion steps only look at the
lines written since the daemon was started by the current run.

## Writing a feature

Every feature declares a scoping tag as its first tag (`@ipsec_s2s`); the
harness names that feature's namespaces, pid files and veths from it, so
features can run concurrently without colliding. A feature must end with
a `Scenario: Teardown topology` that stops each daemon, deletes each
namespace, and asserts `the test environment should be clean`.

Nodes that need more than zebra-rs run through a script spawned into the
namespace: `tests/scripts/ipsec_node.sh` starts `charon-systemd`, zebra-rs
(`--feature insomnia`) and insomnia inside a private mount namespace so both
IPsec nodes can use the stock `/etc/swanctl` and `/run/charon.vici` paths
on one host. Configuration files live under
`tests/configs/<feature>/` and are applied with `vtyctl apply`.

The DHCP features use three more scripts:

- `tests/scripts/dhcp_node.sh` runs a router: the relay agent, zebra-rs
  (`--feature insomnia`) and insomnia with `--kea-control socket
  --dhcp-relay-control signal`. `dhcp_node.sh NS kea` starts the
  default VRF's Kea pair on a bootstrap configuration that insomnia's
  first reload replaces, and `kea-vrf VRF` starts a VRF's pair under
  `ip vrf exec`.
- `tests/scripts/kea_server.sh` runs a standalone Kea, for the features
  that test the relay against a server insomnia does not drive.
- `tests/scripts/dhcp_client.sh` runs one `dhcpcd` per client and
  records the lease, which the `DHCPv4 client … should obtain an
  address in …` steps assert on. dhcpcd asks only for the options it is
  told to, so a scenario names an option before asserting it.

Gate a feature's first `show` step on the insomnia log line
`show provider registered`: the show steps fail on a connection error
instead of retrying while the daemons start.

`make -C bdd docs` regenerates one Markdown page per feature under
`bdd/docs/` from the feature text.

## Features

| Feature | Tag | What it proves |
|:--------|:----|:---------------|
| Site-to-site IPsec | `@ipsec_s2s` | Two nodes, IKEv2 + PSK, one policy-based tunnel: insomnia renders and loads the swanctl configuration, the IKE and CHILD SAs come up with the configured proposals, ESP traffic flows and the counters move, `show vpn ipsec sa/state/policy/connections` read live state, and deleting the config unloads the tunnel. |
| VRRP master/backup pair | `@vrrp_pair` | Two routers and a client on a bridge, one group with VRID 10: insomnia renders and loads the keepalived configuration, the higher priority becomes MASTER and holds the virtual address, the client reaches it, a link failure fails over to the backup and the master preempts when the link returns, `show vrrp` / `detail` / `statistics` read live state, and deleting the config withdraws the address. |
| DHCPv4 server | `@dhcp_server` | A router serving two LANs with Kea: a static mapping receives every option of its subnet and shared network, a new client gets the first address past an excluded one, a client class selects its own range, Kea does not listen on an interface without a subnet, the `show dhcp server` views read live state, a configuration change is a reload that keeps the leases, Kea keeps serving while insomnia is stopped, a range that fails a check is skipped while the rest is served, and `disable` and delete stop serving. |
| DHCPv6 server | `@dhcpv6_server` | Addresses from a static mapping by DUID and from a range, with the global and shared-network options; a delegated prefix gets a `proto dhcp` route to the requesting router that goes when the lease expires; `disable-route-autoinstall` delegates without routing; the `show dhcpv6 server` views; delete stops serving. |
| DHCPv4 relay | `@dhcp_relay` | A relay between two client LANs and a standalone server: a lease through the relay with option 82 and a unicast reply, a broadcast reply for a client that asks for one, per-interface counters, a reply forged by a client dropped and counted, a request at the hop limit dropped, removing one listen interface leaves the others relaying, and `disable` and delete stop relaying. |
| DHCPv6 relay | `@dhcpv6_relay` | An address through the relay with the subnet chosen by link address, the Interface-ID option, an explicit link address, a forged Relay-reply dropped and counted, per-interface counters, and a multicast server address. |
| Relay in front of the server | `@dhcp_server_relay` | insomnia's relay on one router and insomnia's Kea on another: the DHCPv4 subnet is chosen by `giaddr` and the client class by circuit ID, the DHCPv6 subnet by link address, and the counters on both routers line up. |
| DHCP servers per VRF | `@dhcp_server_vrf` | Two tenants with the same subnet in two VRFs beside the default table: each client gets its lease from its own Kea instance, the show views are per VRF, `show process` lists every instance, a delegated prefix is routed in its VRF's table only, and removing one tenant's server leaves the other alone. |
| DHCP relay per VRF | `@dhcp_relay_vrf` | DHCPv4 and DHCPv6 relay in two VRFs with overlapping addresses: each tenant reaches its own server, the counters are kept per VRF, an interface outside the instance's VRF is not relayed, a forged reply inside a tenant is dropped, removing one tenant's relay leaves the other alone, and a VRF that is deleted and re-created comes back. |
| Relay per VRF to server per VRF | `@dhcp_vrf_e2e` | Two routers, two overlapping tenants end to end: each tenant gets its lease from its own Kea instance through its own relay instance, and the relay counters and server leases line up per VRF. |
