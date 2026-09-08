# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What insomnia is

insomnia is the out-of-process firewall / IPsec enforcement daemon for zebra-rs.
zebra-rs owns the configuration (YANG schema, candidate/running stores, commit);
insomnia enforces it. It subscribes to the `firewall` and `vpn ipsec` running-config
subtrees over gRPC, renders them into nftables and strongSwan (swanctl) state, and
registers as the show provider so `show firewall …` and `show vpn ipsec …` typed at the
zebra-rs CLI are answered by this process. The backends were moved out of the zebra-rs
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
`tcp://HOST:PORT`, or a bare host (port 2666); `--swanctl-dir` and `--vici-socket`
default to the stock strongSwan paths.

### BDD integration tests (`bdd/`)

Cucumber features drive real zebra-rs + insomnia (+ charon) inside Linux network
namespaces. They need root-capable non-interactive `sudo`, an installed zebra-rs
toolchain (`zebra-rs`, `vtyctl`, `vtyhelper`, YANG schemas), and for IPsec features
`charon-systemd` + `strongswan-swanctl`. They are never run by CI.

```sh
make -C bdd stage            # build this worktree's insomnia + copy the zebra-rs toolchain into bdd/.stage/
make -C bdd stage ZEBRA_PREFIX=../../zebra-rs/bdd/.stage   # test against an unreleased zebra-rs
make -C bdd ipsec_s2s        # one feature (tag filter); every make target stages first
make -C bdd run              # all features, serially
make -C bdd all              # all features, 16 in parallel
BDD_KEEP=1 make -C bdd ipsec_s2s   # leave namespaces/daemons up for inspection
make -C bdd open             # regenerate + open the Allure report
make -C bdd docs             # regenerate bdd/docs/<feature>.md from feature files (fails on orphans)
```

Direct invocation from `bdd/` once staged:
`cargo test --test cucumber -- --concurrency=1 --tags "@ipsec_s2s"`.
Logs land in `bdd/logs/<tag>_<node>.log` (zebra-rs), `.insomnia.log`, `.charon.log`.

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

Three long-lived tokio tasks share one `--host`:

- `firewall::run` and `ipsec::run` — one backend task per config subtree.
- `provider::run` — registers the `firewall` and `ipsec` show trees with zebra-rs and
  routes each `ShowOrder` by path prefix (`/show/firewall` → firewall, `/show/vpn/ipsec`
  → ipsec) over an mpsc channel carrying `api::ShowRequest`. Each request holds a
  oneshot; every order must be answered exactly once, and a dropped oneshot is turned into
  an error chunk so the CLI never hangs.

Every connection retries forever with `endpoint::RECONNECT_DELAY`: zebra-rs restarting is
a normal condition. Do not turn connection failures into exits.

### Backend shape (`src/firewall.rs`, `src/ipsec.rs`)

Both backends have the same structure, and new backends should keep it:

1. `subscribe::subscribe_json` opens a JSON-format `zebra.config.v1` subscription. The
   first event is always a snapshot of the whole subtree, then one whole-subtree document
   per commit that touches it (`"{}"` when the subtree is gone). Reconnecting therefore
   resyncs by simply re-applying the snapshot; applies must be idempotent.
2. A `run` loop `select!`s between stream events and show requests.
3. The JSON deserializes into a serde model (`FirewallConfig` / `IpsecConfig`).
4. `render(&cfg) -> (text, warnings)` produces a complete artifact: a full nft script
   (starting with add+delete of the `zebra_firewall` tables, so replace and teardown are
   one atomic `nft -f -` transaction) or a full `swanctl.conf` loaded with `swanctl -q`.
5. Anything the renderer cannot express safely is skipped with a warning naming the
   rule/peer. Rendered output must always be syntactically valid; one bad rule must never
   wedge the whole commit.

The renderers follow the VyOS templates line for line (vyos-1x `nftables.j2`,
`swanctl.conf.j2`); each module doc lists the deliberate deviations (table/chain naming
`zebra_firewall` / `ZEBRA_*` so it coexists with VyOS, unapplied sysctl/charon-level
options, etc.). When adding a feature, check the VyOS template first and record any new
deviation in that doc comment.

### JSON config shapes (`src/json.rs`)

zebra-rs's JSON marshaler emits numeric-looking scalars as JSON numbers (`port 80` →
`80`, `port https` → `"https"`), so every user-string field in a model must be `Flex`,
not `String`. `type empty` leaves arrive as `"name": null` → use `de_presence`. Leaf-lists
use `de_flex_vec` (tolerates a bare scalar). YANG lists are arrays of objects with the key
leaf inline. `serde_json` is built with `preserve_order` so show JSON keeps zebra-rs's key
order.

### Show commands

Firewall show answers from the last committed model plus live counters fetched from
`nft --json list table`. IPsec show reads live state from charon via `src/vici.rs` (a minimal VICI client
implementing only the `list-sas` / `list-conns` command-event streaming pattern) and
from `ip xfrm` for state/policy. `ShowRequest.json` selects JSON output (`vtyctl show -j`).

### Vendored protos (`proto/`)

`config.proto` (zebra.config.v1) and `show.proto` (zebra.show.v1) are copies of
zebra-rs's machine-facing APIs, exposed through `src/pb.rs`. `src/endpoint.rs` is copied
from zebra-rs's `vtyctl` so both accept the same `--host` spellings. Keep these in sync
with zebra-rs rather than diverging locally.

### Tests

Unit tests are inline `#[cfg(test)]` modules. The core ones are golden-render tests: a
JSON config string goes through the `cfg(test)`-only `render_str` helper and the exact
nft / swanctl text (and warning list) is asserted. Neither `nft` nor `swanctl` is needed.
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

## Conventions

- Rust edition 2024; `rustfmt.toml` sets the edition, and clippy runs with `-D warnings`.
  The `[workspace.lints.clippy]` allow-list is intentionally identical to zebra-rs so the
  shared harness lints the same in both repos — do not add allows without that in mind.
- The bdd crate inherits lints via `[lints] workspace = true` and is excluded from
  `cargo test` in CI; do not add it to CI.
- License is AGPL-3.0-or-later.
