# BDD Integration Tests

insomnia's integration tests live in `bdd/` and drive **real daemons** —
zebra-rs as the configuration owner, insomnia as the enforcement daemon,
and strongSwan's `charon` where a feature needs IPsec — inside Linux
network namespaces on the host you run them on. They are written as
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
- Optional: the `allure` CLI to browse the HTML report.

## Staging the toolchain

A run never resolves binaries through `/usr` directly. `make -C bdd stage`
builds this worktree's `insomnia` (release profile) and copies it,
together with the zebra-rs toolchain taken from `ZEBRA_PREFIX`, into
`bdd/.stage/` mirroring the `/usr` layout:

```text
bdd/.stage/
  bin/{insomnia,zebra-rs,vtyctl,vtyhelper}
  share/zebra-rs/yang/*.yang
```

`ZEBRA_PREFIX` defaults to `/usr` (the installed package). To test
against an unreleased zebra-rs, point it at that worktree's stage:

```sh
make -C bdd stage ZEBRA_PREFIX=../../zebra-rs/bdd/.stage
```

Every test target stages first, so a run can never exercise a stale
binary; `make -C bdd unstage` removes the stage again. Staged files are
copies, so rebuilding while a run is in flight does not swap the binary
out from under it.

## Running

```sh
make -C bdd ipsec_s2s        # one feature set (a cucumber --tags filter)
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
(`--feature iso`) and insomnia inside a private mount namespace so both
IPsec nodes can use the stock `/etc/swanctl` and `/run/charon.vici` paths
on one host. Configuration files live under
`tests/configs/<feature>/` and are applied with `vtyctl apply`.

`make -C bdd docs` regenerates one Markdown page per feature under
`bdd/docs/` from the feature text.

## Features

| Feature | Tag | What it proves |
|:--------|:----|:---------------|
| Site-to-site IPsec | `@ipsec_s2s` | Two nodes, IKEv2 + PSK, one policy-based tunnel: insomnia renders and loads the swanctl configuration, the IKE and CHILD SAs come up with the configured proposals, ESP traffic flows and the counters move, `show vpn ipsec sa/state/policy/connections` read live state, and deleting the config unloads the tunnel. |
| VRRP master/backup pair | `@vrrp_pair` | Two routers and a client on a bridge, one group with VRID 10: insomnia renders and loads the keepalived configuration, the higher priority becomes MASTER and holds the virtual address, the client reaches it, a link failure fails over to the backup and the master preempts when the link returns, `show vrrp` / `detail` / `statistics` read live state, and deleting the config withdraws the address. |
