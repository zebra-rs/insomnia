# AGENTS.md

This file provides guidance to coding agents including Claude Code (claude.ai/code) when working with code in this repository.

## What insomnia is

insomnia is the out-of-process firewall / IPsec / VRRP / DHCP server and relay
enforcement daemon for zebra-rs. zebra-rs owns the configuration (YANG schema,
candidate/running stores, commit); insomnia enforces it. It subscribes to the
`firewall`, `vpn ipsec`, `vrrp`, `service dhcp-server`, `service dhcpv6-server`,
`service dhcp-relay` and `service dhcpv6-relay` running-config subtrees over gRPC,
renders them into nftables, strongSwan (swanctl), keepalived, Kea and
insomnia-dhcp-relay state, and registers as the show provider so `show firewall …`,
`show vpn ipsec …`, `show vrrp …`, `show dhcp[v6] server [vrf <name>] …` and
`show dhcp[v6] relay [vrf <name>] statistics` typed at the zebra-rs CLI are answered by this
process. The DHCP relay agent itself, `insomnia-dhcp-relay`, is a second binary in this
workspace (`dhcp-relay/`, with the packet codec in `dhcp-packet/`, a vendored copy of
zebra-rs's `crates/dhcp-packet`); `kea-notify`
(`src/bin/insomnia-kea-notify.rs`) is the tiny program Kea's run_script hook calls for
DHCPv6 lease events. The backends were moved out of the zebra-rs
tree, not rewritten — `src/api.rs` deliberately mirrors the in-process channel types they
used to consume.

## Commands

`protoc` must be on PATH: `build.rs` compiles `proto/*.proto` with tonic-prost-build.

```sh
cargo build                                   # debug binary
cargo build --release                         # what packaging and the BDD stage use
cargo test --workspace --exclude bdd          # unit tests (this is exactly what CI runs)
cargo test firewall::tests::golden_render     # one test by path
cargo fmt --all -- --check                    # CI gate
cargo clippy --workspace --all-targets -- -D warnings   # CI gate
```

Run locally: `RUST_LOG=debug cargo run -- --host unix:zebra-rs/vty` (env-filter logging,
default `info`). `--host` accepts `unix:NAME` (Linux abstract socket, the default),
`unix:/PATH` (filesystem socket), `tcp:HOST:PORT` / `tcp://HOST:PORT`, or a bare host
(port 2666); `--swanctl-dir` and `--vici-socket`
default to the stock strongSwan paths. `--keepalived-dir` (default `/run/insomnia/vrrp`)
holds one keepalived instance directory per VRF; `--keepalived-control systemd|signal`
picks between the `insomnia-keepalived@<vrf>.service` template unit and SIGHUP to the
instance's pid file (what the BDD harness uses). The DHCP relay backend writes
`--dhcp-relay-dir/relay.json` (default `/run/insomnia/dhcp-relay`);
`--dhcp-relay-control systemd|signal` picks between `insomnia-dhcp-relay.service` and
SIGHUP to `relay.pid` in that directory, and `--dhcp-relay-socket` (default
`/run/insomnia-dhcp-relay/control`) is the agent's control socket that
`show dhcp relay statistics` queries. The DHCP server backend drives one Kea per family
per VRF: `--kea-dir` (default `/run/insomnia/kea`) holds `<vrf>/kea-dhcp{4,6}.conf`, the
control sockets and the `kea-notify` link; `--kea-state-dir` (default
`/var/lib/insomnia/kea`) the leases; `--kea-control systemd|socket` picks between the
`insomnia-kea-dhcp{4,6}@<vrf>.service` template units and talking only to instances
somebody else started (the BDD harness); `--kea-hooks-dir` defaults to
`/usr/lib/<multiarch>/kea/hooks`. Per-VRF template units are bound to their VRF by a
cgroup-BPF program insomnia pins at `--vrf-bpf-dir/<vrf>` (default
`/sys/fs/bpf/insomnia/vrf`) before it starts them (`src/vrf.rs`); `stop process`
holds live in `--holds-dir` (default `/run/insomnia/holds`).

### BDD integration tests (`bdd/`)

Cucumber features drive real zebra-rs + insomnia (+ charon) inside Linux network
namespaces. They need root-capable non-interactive `sudo`, an installed zebra-rs
toolchain (`zebra-rs`, `vtyctl`, `vtyhelper`, YANG schemas), for IPsec features
`charon-systemd` + `strongswan-swanctl`, for VRRP features `keepalived`, and for DHCP
features Kea (`kea-dhcp4-server`, `kea-dhcp6-server`) and `dhcpcd`. They are never run
by CI. `design/dhcp-bdd.md` is the plan for the DHCP suite.

```sh
make -C bdd stage            # build this worktree's insomnia + copy the zebra-rs toolchain into bdd/.stage/
make -C bdd stage ZEBRA_PREFIX=../../zebra-rs/bdd/.stage   # test against an unreleased zebra-rs
make -C bdd ipsec_s2s        # one feature (tag filter); every make target stages first
make -C bdd vrrp_pair        # the VRRP master/backup feature (needs keepalived on the host)
make -C bdd vrrp_vrf         # VRRP in a VRF beside the global table
make -C bdd dhcp             # every DHCP feature (dhcp_server, dhcpv6_server, dhcp_server_relay,
                             #   dhcp_server_vrf, dhcp_vrf_e2e, dhcp_relay, dhcpv6_relay, dhcp_relay_vrf)
make -C bdd stage KEA_PREFIX=/path/to/unpacked-kea   # Kea from `dpkg-deb -x` of the Ubuntu packages
make -C bdd run              # all features, serially
make -C bdd all              # all features, 16 in parallel
BDD_KEEP=1 make -C bdd ipsec_s2s   # leave namespaces/daemons up for inspection
make -C bdd open             # regenerate + open the Allure report
make -C bdd docs             # regenerate bdd/docs/<feature>.md from feature files (fails on orphans)
```

Direct invocation from `bdd/` once staged:
`cargo test --test cucumber -- --concurrency=1 --tags "@ipsec_s2s"`.
Logs land in `bdd/logs/<tag>_<node>.log` (zebra-rs), `.insomnia.log`, `.charon.log`,
`.keepalived.log`, `.relay.log` (the DHCP relay agent, debug level) and `.kea4.log` /
`.kea6.log` (a standalone server's Kea, or the router's default-VRF Kea; per-VRF router
instances log to `.kea4-<vrf>.log`).

### Packaging and releases

```sh
make -C packaging amd64      # cargo build --release + cargo deb; .deb lands in packaging/
make -C packaging release-notes
```

- `CHANGELOG.yaml` is the single source for both the Debian changelog and GitHub release
  bodies. Newest entry first, full ISO-8601 dates, Markdown bodies.
- The top-level `version` file is the source of truth; `packaging/version-update.sh`
  propagates it into `Cargo.toml`. Release flow: add a CHANGELOG entry, bump `version`,
  run the script, commit, then `git tag "v$(cat version)"` and push the tag. The release
  workflow fails if tag, `version`, and the top CHANGELOG entry disagree.
- `cargo-deb` is pinned in `.github/workflows/build-debs.yaml`; keep it in step with zebra-rs.

The `book/` directory is an mdBook (`mdbook build` inside `book/`; output is gitignored).

## Architecture

### Process layout (`src/main.rs`)

Six long-lived tokio tasks share one `--host`, plus the kernel link watcher:

- `firewall::run`, `ipsec::run`, `vrrp::run`, `dhcp_relay::run` and `dhcp_server::run` —
  one backend task per config subtree (the DHCP relay task subscribes to both relay
  subtrees and renders nothing until both snapshots have arrived; the DHCP server task
  subscribes to both server subtrees and also re-renders on link and address changes).
- `links::spawn` — a NETLINK_ROUTE watcher (links, addresses, VRF masters, the tentative
  flag) publishing a fresh `links::Snapshot` on a `watch` channel after each burst of
  kernel events; Kea's listen set is derived from it, and `vrf::run` re-pins or unpins
  VRF socket programs when a VRF is re-created or deleted (systemd mode only).
- `process::serve` — `show process` and `start|stop|restart process` against the
  `process::Registry`, where every backend registers its daemon instances
  (`keepalived@<vrf>`, `kea-dhcp4@<vrf>`, `dhcp-relay`) as it applies them.
- `provider::run` — registers the `firewall`, `ipsec`, `vrrp` and `dhcp` show trees with
  zebra-rs and routes each `ShowOrder` by path prefix (`/show/firewall` → firewall,
  `/show/vpn/ipsec` → ipsec, `/show/vrrp` → vrrp, `/show/dhcp[v6]/server` →
  dhcp_server, the rest of `/show/dhcp` and `/show/dhcpv6` → dhcp_relay,
  `/show|start|stop|restart/process` → the process registry) over an mpsc channel
  carrying `api::ShowRequest`. zebra-rs routes `start|stop|restart process` lines to
  the `process` provider the way it routes `show` lines. Each request holds a
  oneshot; every order must be answered exactly once, and a dropped oneshot is turned into
  an error chunk so the CLI never hangs.

Every connection retries forever with `endpoint::RECONNECT_DELAY`: zebra-rs restarting is
a normal condition. Do not turn connection failures into exits.

### Backend shape (`src/firewall.rs`, `src/ipsec.rs`, `src/vrrp.rs`, `src/dhcp_relay.rs`, `src/dhcp_server.rs`)

All five backends have the same structure, and new backends should keep it:

1. `subscribe::subscribe_json` opens a JSON-format `zebra.config.v1` subscription. The
   first event is always a snapshot of the whole subtree, then one whole-subtree document
   per commit that touches it (`"{}"` when the subtree is gone). Reconnecting therefore
   resyncs by simply re-applying the snapshot; applies must be idempotent.
2. A `run` loop `select!`s between stream events and show requests.
3. The JSON deserializes into a serde model (`FirewallConfig` / `IpsecConfig` /
   `VrrpConfig` / `Relay4Tree` + `Relay6Tree` / `Server4Tree` + `Server6Tree`).
4. `render(&cfg) -> (text, warnings)` produces a complete artifact: a full nft script
   (starting with add+delete of the `zebra_firewall` tables, so replace and teardown are
   one atomic `nft -f -` transaction), a full `swanctl.conf` loaded with `swanctl -q`, or
   a full `keepalived.conf` handed to `keepalived::apply`, or a full `relay.json` handed to
   `Relayd::apply`. Both go through `process::reload`: compare-before-reload, then
   `systemctl reload-or-restart`/`stop` on the unit or SIGHUP to the pid file.
   `relay.json` is built from the agent's own types (`dhcp_relay::config`, the
   `dhcp-relay` crate's library), so the two cannot drift apart. The DHCP server renders
   one complete Kea configuration per family per VRF (`dhcp4::render`, `dhcp6::render`,
   with the instance's VRF, interfaces and paths in a `dhcp_server::Context`) and hands it
   to `kea::Kea::apply`: compare with the file in place, `config-test` over the control
   socket, write, `config-reload` — a commit never restarts Kea, and a configuration Kea
   refuses leaves it running the previous one (shown as stale). DHCPv6 delegated
   prefixes get `proto dhcp` routes from `pd_routes.rs`, triggered by kea-notify and
   confirmed with `lease6-get`.
5. Anything the renderer cannot express safely is skipped with a warning naming the
   rule/peer. Rendered output must always be syntactically valid; one bad rule must never
   wedge the whole commit.

The renderers follow the VyOS templates line for line (vyos-1x `nftables.j2`,
`swanctl.conf.j2`, `keepalived.conf.j2`, `dhcrelay{,6}.conf.j2`, `kea-dhcp{4,6}.conf.j2`
with `python/vyos/kea.py`); each module doc lists
the deliberate deviations (table/chain naming `zebra_firewall` / `ZEBRA_*` so it coexists with VyOS, unapplied
sysctl/charon-level options, VRRP transition scripts as native `notify_*` lines, the
three FRR-derived VRRP extension leaves, etc.). `design/vrrp.md` is the VRRP design and
records why the VyOS `high-availability` wrapper was dropped. When adding a feature, check the VyOS template first and record any new
deviation in that doc comment.

### JSON config shapes (`src/json.rs`)

zebra-rs's JSON marshaler emits numeric-looking scalars as JSON numbers (`port 80` →
`80`, `port https` → `"https"`), so every user-string field in a model must be `Flex`,
not `String`. `type empty` leaves arrive as `"name": null` → use `de_presence`. Leaf-lists
use `de_flex_vec` (tolerates a bare scalar). YANG lists are arrays of objects with the key
leaf inline. `serde_json` is built with `preserve_order` so show JSON keeps zebra-rs's key
order.

### Daemon instances (`src/process.rs`, `src/vrf.rs`)

Every per-VRF instance follows `design/process.md` §4.9: an interface it names must be a
member of its VRF (`links::Snapshot::member`; anything else is skipped with a warning),
a missing VRF gets `links::missing_vrf`, a `vrf default` entry is ignored
(`links::reserved_vrf`; zebra-rs refuses the name at commit), and show grammar is
`show <feature> [vrf <name>] <view>`. A new per-VRF backend (`vrrp vrf`) must do the same.

Every daemon instance goes through the registry: `process::reload` (keepalived, the
relay agent) and `kea::Kea::apply` register it, honour an operator hold (`stop
process`: the file is still written, the unit stays stopped, also across an insomnia
restart), and call `Registry::bind(vrf)` before a per-VRF unit starts, which pins the
VRF's socket program (`vrf::Pins`). The template units carry
`AssertPathExists=/sys/fs/bpf/insomnia/vrf/%i` in `[Unit]` (a unit test checks the
section: systemd ignores it in `[Service]` and would run the daemon unbound) and
`BPFProgram=sock_create:` on the same path. In signal/socket mode the harness owns the
processes: `show process` reads pid files and the actions are refused.

### Show commands

Firewall show answers from the last committed model plus live counters fetched from
`nft --json list table`. IPsec show reads live state from charon via `src/vici.rs` (a minimal VICI client
implementing only the `list-sas` / `list-conns` command-event streaming pattern) and
from `ip xfrm` for state/policy. VRRP show sends keepalived its JSON signal and reads
the dump from the instance directory (`src/keepalived.rs`; `show vrrp vrf <name>` reads
that VRF's instance); the summary appends
`DISABLED` rows from the last committed model. DHCP relay show asks the relay agent's
control socket for its counters (`src/relayd.rs`). DHCP server show asks the instance's
Kea (`lease{4,6}-get-all`, `stat-lease{4,6}-get`) and maps subnet ids to shared networks
with the last configuration Kea accepted; static mappings come from that configuration. `ShowRequest.json` selects JSON
output (`vtyctl show -j`).

### Vendored from zebra-rs (`proto/`, `dhcp-packet/`)

`config.proto` (zebra.config.v1) and `show.proto` (zebra.show.v1) are copies of
zebra-rs's machine-facing APIs, exposed through `src/pb.rs`. `src/endpoint.rs` is copied
from zebra-rs's `vtyctl` so both accept the same `--host` spellings. Keep these in sync
with zebra-rs rather than diverging locally.

`dhcp-packet/` is an identical copy of zebra-rs's `crates/dhcp-packet`, the DHCPv4/DHCPv6
codec its DHCP client and this relay share. zebra-rs owns it: change it there, then
`rsync -a --delete ../zebra-rs/crates/dhcp-packet/ dhcp-packet/` and check with
`diff -r ../zebra-rs/crates/dhcp-packet dhcp-packet`. Its `Cargo.toml` spells out every
field instead of inheriting from a workspace so the file is the same in both repos.

### Tests

Unit tests are inline `#[cfg(test)]` modules. The core ones are golden-render tests: a
JSON config string goes through the `cfg(test)`-only `render_str` helper and the exact
nft / swanctl / keepalived / Kea text (and warning list) is asserted. None of `nft`,
`swanctl`, `keepalived` or Kea is needed; the VRRP show tests use a keepalived JSON dump
captured in a scratch namespace, and the DHCP server show tests Kea 2.4.1 replies. The Kea
goldens were also checked with `kea-dhcp{4,6} -t` in a namespace whose interfaces exist
(Kea refuses unknown interfaces, so that cannot run in CI).
When changing a renderer, update the golden text deliberately and explain why in the
commit.

### BDD harness conventions (`bdd/`)

- The harness (`bdd/src`, `bdd/tests/cucumber.rs`) is shared with zebra-rs's own suite,
  so it carries many zebra-rs step definitions (BGP, etc.) that insomnia does not use.
  Keep the step vocabulary compatible.
- A feature's first non-special tag (`@ipsec_s2s`) scopes every namespace, pid file,
  bridge and veth name; a feature must end with `Scenario: Teardown topology` asserting a
  clean environment. Configs live in `bdd/tests/configs/<tag>/` and are applied with
  `vtyctl apply`.
- The toolchain resolves from `$ZEBRA_BDD_PREFIX`, then `bdd/.stage/`, then `/usr`.
  Staged files are copies, so rebuilding mid-run cannot swap the binary.
- IPsec nodes run via `bdd/tests/scripts/ipsec_node.sh` inside a private mount namespace
  so two charons can share the stock `/etc/swanctl` and `/run/charon.vici` paths. Bring
  the responder up before the initiator; see the feature header for why.
- VRRP routers run via `bdd/tests/scripts/vrrp_node.sh` the same way: private `/run`, a
  keepalived started on an empty config, insomnia in signal mode. This keeps the routers
  clear of a keepalived service the development host itself may be running.
  `vrrp_node.sh NS keepalived-vrf VRF` starts a VRF's keepalived under `ip vrf exec`
  once zebra-rs has created the VRF (`vrrp_vrf` feature).
- The systemd side (VRF pins, template units, holds) is not BDD: `sudo
  bdd/tests/scripts/vrf_units.sh bdd/.stage <unpacked-kea>` runs zebra-rs and insomnia
  in a scratch namespace in systemd mode against the host's systemd, with the shipped
  Kea template in `/run/systemd/system`, and removes everything afterwards. Start
  insomnia there with `nsenter --net`, not `ip netns exec`, which remounts `/sys` and
  hides the bpffs.
- DHCP routers run via `bdd/tests/scripts/dhcp_node.sh` the same way: the relay agent
  started on no config (`--pid-file`), zebra-rs, insomnia in signal mode
  (`--kea-control socket`). `dhcp_node.sh NS kea` also starts the default VRF's
  kea-dhcp4/kea-dhcp6 on a bootstrap configuration at the paths insomnia renders to,
  which insomnia's `config-reload` replaces; `kea-vrf VRF` starts a VRF's pair under
  `ip vrf exec`; `stop-insomnia` / `start-insomnia` re-enter the node's mount namespace
  through the agent's pid. Kea's paths come from `kea_env.sh` (the host's packages or the
  staged `KEA_PREFIX` tree). Standalone servers run via `kea_server.sh`; clients are one
  `dhcpcd` run each through
  `dhcp_client.sh` (private `/run`, its own config, lease variables from a dhcpcd hook),
  asserted with the `DHCPv4/DHCPv6 client … should obtain an address|a prefix in …` steps.
  dhcpcd requests only the options it is told to: name them (`DHCPv4 client with
  "option ntp_servers" …`) before asserting a lease variable.
  Gate the first `show` on `insomnia log … "show provider registered"`: the `show`
  steps fail on the first connection error instead of retrying while zebra-rs starts.

## Conventions

- Rust edition 2024; `rustfmt.toml` sets the edition, and clippy runs with `-D warnings`.
  The `[workspace.lints.clippy]` allow-list is intentionally identical to zebra-rs so the
  shared harness lints the same in both repos — do not add allows without that in mind.
- The bdd crate inherits lints via `[lints] workspace = true` and is excluded from
  `cargo test` in CI; do not add it to CI.
- License is AGPL-3.0-or-later.
