# Multi-path subscribe — implementation plan

Status: plan, 2026-10-21. Covers: §4.3 and decision D3 ([vyos-gap](../vyos-gap.md) §4.3, §11).
Priority: P1 · Effort: M · Owner: both (zebra-rs RPC and dispatch; insomnia `subscribe.rs` API)
Depends on: none; the request field numbers are coordinated with [secret-redaction](secret-redaction.md) (D-11) · Unblocks: [nat](nat.md), [pbr](pbr.md), [wan-load-balancing](wan-load-balancing.md), [conntrack](conntrack.md) (`ignore` group references only), [pki-x509](pki-x509.md), [ipsec-vti](ipsec-vti.md), [ipsec-remote-access](ipsec-remote-access.md) (through pki-x509's stream), [ipsec-syntax-parity](ipsec-syntax-parity.md) (optional `interface` part), [ipsec-dmvpn-l2tp](ipsec-dmvpn-l2tp.md) (L2TP only, if accepted), [vrrp-virtual-server](vrrp-virtual-server.md), [commit-validation](commit-validation.md) (reuses the `ConfigPath` / `Subtree` messages)

Assumes D3: multi-path subscribe in zebra-rs, not a root subscription and not several skewed streams.

## 1. Goal

- One gRPC stream can watch several running-config subtrees. It delivers one snapshot, then exactly one event per commit that touches any of them.
- Every event carries the post-commit JSON of every subscribed subtree, all read from the same committed tree. A commit that touches two subtrees can never be seen half-applied.
- Single-path `Subscribe` is unchanged on the wire. The insomnia firewall, IPsec and VRRP backends and `vtyctl watch` keep working without a rebuild.
- insomnia has one API, `subscribe::subscribe_json_multi`, that every multi-tree consumer uses. No renderer opens two streams.
- A new insomnia talking to an old zebra-rs degrades in a defined way and never mistakes a whole-config subscription for a scoped one.

## 2. Current state

**insomnia @ `ee4dfaa`:**
- `src/subscribe.rs:11-27`: `subscribe_json(host, path)` sends one `SubscribeRequest` with one path and retries forever.
- Each backend has one `CONFIG_PATH` const and wraps `event.json` into `JsonConfigUpdate { path, json }`: `firewall.rs:38,56-82`, `ipsec.rs:50,57-88`, `vrrp.rs:50,67-93`. The type is at `api.rs:16-19`.
- `ConfigServiceClient` is built with tonic's defaults (`subscribe.rs:14`). Nothing in either repo sets `max_decoding_message_size`, so the tonic 0.14 default of 4 MiB caps every event. Whether a real config reaches that is *unverified*.

**zebra-rs @ `141da2fc`:**
- `proto/config.proto:31-37`: `SubscribeRequest` has one `repeated string path`; `ConfigService` has one RPC, `Subscribe`.
- `src/config/subscribe.rs:37-51`: `ConfigSubscribeRequest` / `ConfigSubscriber` carry one path. `:56-58` is the segment-wise `path_has_prefix`. `:65-111` mints a bounded bus (`EVENT_BUFFER = 32`, `:32`) and hands it to the manager as `Message::ConfigSubscribe`.
- `src/config/manager.rs`:
  - `:652-664` `subtree_json(prefix)` reads `store.running`. A missing node gives `"{}"`. A list node gives a JSON array (`configs.rs:425-437`).
  - `:670-685` `config_snapshot`, `:689-707` `running_changes` (PATH snapshot).
  - `:712-740` `dispatch_config_subscribers`: one event per touched subscriber, `try_send`, pruned when full or closed.
  - `:1138-1166` builds the commit's `subscriber_changes` from the diff; `:1226` `store.commit()`; `:1231` dispatch. Delivery is post-commit.
  - `:1874-1887` registration: snapshot first, then push.
- `vtyctl/src/watch.rs:33-58` is the other client of `Subscribe`.

**VyOS @ `7f2c893`:**
- Every conf-mode script reads whatever paths it needs from one config: `src/conf_mode/nat.py:61-76` reads `firewall group`; `vpn_ipsec.py:148` loads PKI (`with_pki=True`) and `:204` reads `interfaces vti`.
- Dependants re-run on change: `data/config-mode-dependencies/vyos-1x.json` maps `firewall.group_resync` to `system_conntrack`, `nat`, `nat66`, `policy_route`, `load-balancing_wan`; `python/vyos/configdep.py:149` (`set_dependents`) queues them.
- So a VyOS `firewall group` commit re-renders NAT from one consistent tree. This plan gives zebra-rs the same property.

## 3. Design

**D-1. A new RPC, `SubscribeMulti`, not a new field on `SubscribeRequest`.**
- proto3 ignores unknown fields. An old zebra-rs would read a request with only the new field as an empty `path` and subscribe the client to the whole configuration. Nothing would fail, and the client would get the wrong shape.
- A new RPC fails with `UNIMPLEMENTED` on an old server, which insomnia detects (D-7).

**D-2. Every event carries every subscribed subtree, in request order, with a `changed` flag each.**
- Renderers render from complete models, exactly as today, so they need every subtree, not only the changed ones.
- `changed` lets a consumer skip work, e.g. not rebuilding the group index when only `nat` changed.
- Commits are rare. Repeating unchanged subtrees costs little.

**D-3. Delivery rule.** An event is sent iff some change path has some subscribed path as a prefix, using the existing `path_has_prefix` (`subscribe.rs:56-58`). A commit that touches none gets no event. `subtree[i].changed` uses the same test per path.

**D-4. Atomicity is structural.** The manager is one task. All subtrees of an event are serialized from `store.running` inside one `dispatch_config_subscribers` call, after `store.commit()`, so no other commit can interleave. The snapshot is built the same way in the registration arm.

**D-5. Request validation** (`InvalidArgument` otherwise):
- 1 to 16 paths;
- no duplicates;
- no path is a prefix of another. This also rejects the empty path (whole config), which stays a single-path `Subscribe` feature.

Paths are not checked against the schema, as today. An absent subtree, or one whose `if-feature` is off, is `"{}"`.

**D-6. Event payload.**
- JSON format: `subtrees` filled, `json` empty, `changes` empty.
- PATH format: `changes` holds the commit's changes under any subscribed path, in diff order, in one event; `subtrees` is empty.
- Snapshot: `snapshot = true`, every `changed = true`.
- A missing subtree is `"{}"` even when the path names a list, whose present form is an array. insomnia's `parse_subtree` (below) maps `"{}"` to the empty value.

**D-7. insomnia fallback when the server lacks `SubscribeMulti`.** The consumer chooses:
- `Fallback::Refuse`: log an error and retry every `RECONNECT_DELAY`. Use it for backends whose primary tree only exists in a zebra-rs that also has the RPC (NAT, PBR, conntrack). insomnia never exits on a connection condition (AGENTS.md).
- `Fallback::PrimaryOnly`: open a single-path `Subscribe` on `paths[0]` and deliver the other parts as `"{}"`, `changed = false`. Log one warning per connection naming the paths treated as empty. Use it for backends that extend an existing subscription (IPsec + `pki` + `vti`, VRRP + `virtual-server`). A user who upgrades insomnia ahead of zebra-rs keeps the old behaviour.
- In `PrimaryOnly` mode every `MultiUpdate` has `fallback = true`: its secondary parts are synthesized `"{}"`, not zebra-rs's documents. A consumer must not read such a part as "the subtree is empty"; it suppresses findings that depend on it (e.g. [ipsec-vti](ipsec-vti.md)'s bind-exists check). `fallback` is `false` on every event of a real `SubscribeMulti` stream, where `"{}"` does mean absent.

**D-8. Shape check.** insomnia rejects an event whose `subtrees` count or paths differ from the request, logs it, and resubscribes. The fresh snapshot resyncs.

**D-9. Message size.** insomnia sets `max_decoding_message_size(64 MiB)` on every `ConfigServiceClient`, both RPCs. An `interface` subtree on a large box, or a big firewall, must not be cut off at 4 MiB. The zebra-rs server encoder is not limited by default (*unverified* for tonic 0.14; check in M1).

**D-10. One stream per backend.** When two plans extend one backend (IPsec gets both `pki` from pki-x509 and VTI interfaces from ipsec-vti), the backend owns a single path list. Each plan appends a path; neither opens its own stream.

**D-11. Field numbers, agreed with [secret-redaction](secret-redaction.md).**
- `SubscribeRequest` is not edited by this plan: `format = 1`, `path = 2`. secret-redaction adds `optional bool secrets = 3`.
- `SubscribeMultiRequest` uses `format = 1`, `paths = 2`, and keeps `3` for the same `optional bool secrets`, with the same S5 rule. Whichever plan lands second adds it; nothing else may take 3.
- `ConfigEvent` gains `subtrees = 4`.
- secret-redaction's per-subscriber `redact` flag applies to Multi subscribers too: `subtrees_in` serializes with the subscriber's `Secrets`. Its insomnia `secrets: bool` argument is added to `subscribe_json_multi` as well, and the PrimaryOnly fallback passes it on to `Subscribe`.

**Rejected:**
- *Several single-path streams merged in insomnia.* There is no ordering across streams. A commit that adds a group and a NAT rule using it arrives as two events, and in between the renderer either skips the rule or applies a mixed state. A debounce would make correctness depend on timing.
- *A root subscription filtered client-side.* Every BGP or interface commit would wake every backend with the whole config, and the per-subtree "touched" signal would be lost.
- *Wildcard / projection paths* (`interface * vrf`). These would cut spurious events for `interface` consumers, but need a projecting marshaler in zebra-rs. Deferred: consumers compare before they apply instead (§8).

**Consumers.** Paths named for other plans are placeholders; the owning plan fixes them.

| Consumer plan | Paths, primary first | Fallback |
|:--|:--|:--|
| [nat](nat.md) | `nat`, `nat66`, `firewall group` | Refuse |
| [pbr](pbr.md) | `policy-route`, `policy-route6`, `firewall group` (spelling per D5) | Refuse |
| [wan-load-balancing](wan-load-balancing.md) | `load-balancing wan`, `firewall group` | Refuse |
| [conntrack](conntrack.md) | `system conntrack`, `firewall group` (only for `ignore` group references, its M7) | Refuse |
| [pki-x509](pki-x509.md) | `vpn ipsec`, `pki` | PrimaryOnly |
| [ipsec-vti](ipsec-vti.md) | appends `vti` to the IPsec list | PrimaryOnly |
| [ipsec-syntax-parity](ipsec-syntax-parity.md) | appends `interface` to the IPsec list (optional, later D-dhcp check) | PrimaryOnly |
| [ipsec-dmvpn-l2tp](ipsec-dmvpn-l2tp.md) | appends `vpn l2tp` to the IPsec list (only if L2TP is accepted) | PrimaryOnly |
| [vrrp-virtual-server](vrrp-virtual-server.md) | `vrrp`, `virtual-server` | PrimaryOnly |
| [commit-validation](commit-validation.md) | reuses `ConfigPath` / `Subtree` in `ValidateOrder` | — |

[ipsec-remote-access](ipsec-remote-access.md) adds no path: it rides the IPsec list above.

**Not consumers** (rows dropped at their plans' request):
- [fw-zones](fw-zones.md): VRF members come from the kernel through `crate::links` ([fw-global-options](fw-global-options.md) §3.2a), not from `interface … vrf` config, which misses devices enslaved outside it (its D-Z5);
- [vrrp-vrf](vrrp-vrf.md): the `vrf` list is under `vrrp`, so `["vrrp"]` alone covers its config, and membership is the kernel's, through `crate::links`;
- [conntrack](conntrack.md) VRF ct zones: the zone is the kernel table ID from `crate::links` (its §3.7), so it needs no `interface` part;
- [conntrack-sync](conntrack-sync.md): it reads `system conntrack` and `vrrp` state from the sibling tasks in the same process (its §3.4).

## 4. Changes

### zebra-rs

**`proto/config.proto`** (proposed; additive):

```proto
// One config-tree path, one segment per element (list keys count).
message ConfigPath {
  repeated string segment = 1;
}

message SubscribeMultiRequest {
  Format format = 1;
  // 1..16 paths; none may be a prefix of another (incl. the empty path).
  repeated ConfigPath paths = 2;
  // 3: kept for secret-redaction's `optional bool secrets` (D-11), the
  // same number and S5 rule as SubscribeRequest.secrets.
}

// One subscribed subtree in a SubscribeMulti JSON event.
message Subtree {
  repeated string path = 1;   // as requested
  string json = 2;            // post-commit subtree; "{}" when absent
  bool changed = 3;           // this commit touched it (true on snapshot)
}

message ConfigEvent {
  bool snapshot = 1;
  repeated Change changes = 2;
  string json = 3;
  // SubscribeMulti + Format.JSON: one entry per requested path, in
  // request order, always all of them. Empty on Subscribe events.
  repeated Subtree subtrees = 4;
}

service ConfigService {
  rpc Subscribe(SubscribeRequest) returns (stream ConfigEvent) {}
  // Snapshot, then one event per commit touching ANY of the paths;
  // every event is read from one committed tree.
  rpc SubscribeMulti(SubscribeMultiRequest) returns (stream ConfigEvent) {}
}
```

`ConfigPath` is not called `Path` because `crate::pb::config::Path` would read badly next to `std::path::Path`, which `ipsec.rs` and `vici.rs` import.

**`src/config/subscribe.rs`:**
- `ConfigSubscribeRequest` and `ConfigSubscriber` change from `path: Vec<String>` to `paths: Vec<Vec<String>>` plus `shape: Shape { Single, Multi }` (proposed).
- `pub const MAX_PATHS: usize = 16;` and `pub fn check_paths(&[Vec<String>]) -> Result<(), String>` implement D-5.
- The handler body moves into a private `open(register)`. `subscribe` calls it with `Shape::Single` and one path; `subscribe_multi` runs `check_paths` first and calls it with `Shape::Multi`.

**`src/config/manager.rs`:**
- Refactor `subtree_json(prefix)` into `subtree_json_in(root: &Rc<Config>, prefix)`; the old name stays as a wrapper over `store.running`. [commit-validation](commit-validation.md) calls it with `store.candidate`.
- New `fn subtrees_in(&self, root, paths, changed: &[bool]) -> Vec<config_pb::Subtree>`.
- `config_snapshot`:
  - `Multi` + JSON → `subtrees` with all `changed = true`;
  - `Multi` + PATH → `running_changes` filtered by any path.
- `dispatch_config_subscribers`:
  - compute `changed[i] = changes.iter().any(|c| path_has_prefix(&c.path, &paths[i]))`;
  - skip the subscriber when none is set;
  - otherwise build the `Multi` event per D-6.
- The `Single` arms keep today's code path unchanged.

**`vtyctl watch`** (optional, M3): accept a repeated `--path "<segments>"`. Two or more select `SubscribeMulti`, and each event prints `# <path> (changed)` followed by its JSON.

### insomnia

- **`proto/config.proto`:** copy zebra-rs's file byte for byte (AGENTS.md: vendored protos stay in sync).
- **`src/api.rs`:** `JsonConfigUpdate` gains `pub changed: bool`. The three existing run loops set `true`.
- **`src/json.rs`:** `pub fn parse_subtree<T: DeserializeOwned + Default>(json: &str) -> serde_json::Result<T>` (proposed). It returns `T::default()` for `""` and `"{}"`, so a missing list subtree parses as an empty `Vec`.
- **`src/subscribe.rs`** owns the API (proposed):

```rust
/// One delivery of a multi-path subscription.
#[derive(Debug)]
pub struct MultiUpdate {
    /// First delivery after (re)subscribing: apply everything.
    pub snapshot: bool,
    /// One part per requested path, in request order, always all.
    pub parts: Vec<JsonConfigUpdate>,
    /// PrimaryOnly against a zebra-rs without SubscribeMulti: parts[1..]
    /// are synthesized "{}", not zebra-rs's documents (D-7).
    pub fallback: bool,
}

/// What to do when zebra-rs answers `SubscribeMulti` with UNIMPLEMENTED.
#[derive(Debug, Clone, Copy)]
pub enum Fallback {
    /// Log an error and retry every RECONNECT_DELAY.
    Refuse,
    /// Single-path Subscribe on paths[0]; other parts are "{}", changed=false.
    PrimaryOnly,
}

pub struct MultiStream { /* Multi(Streaming<ConfigEvent>) | Primary(Streaming<ConfigEvent>) + paths */ }

impl MultiStream {
    /// Same contract as `tonic::Streaming::message`: `Ok(None)` at end of
    /// stream, cancel-safe, so it drops into the existing `select!` loops.
    pub async fn message(&mut self) -> Result<Option<MultiUpdate>, tonic::Status>;
}

/// Retries until subscribed (like `subscribe_json`).
pub async fn subscribe_json_multi(host: &str, paths: &[&[&str]], fallback: Fallback) -> MultiStream;
```

- The conversion is a pure function, `fn to_update(event: ConfigEvent, paths: &[Vec<String>]) -> Result<MultiUpdate, ShapeError>`, so the tests need no server. A `ShapeError` (D-8) ends the stream with `Status::internal`, and the caller's reconnect loop resubscribes.
- `subscribe_json` stays as it is, plus the 64 MiB decode limit (D-9). No backend changes in this plan.

**Consumer pattern** (for the NAT plan to follow):

```rust
const PATHS: &[&[&str]] = &[&["nat"], &["firewall", "group"]];
loop {
    let mut stream = subscribe::subscribe_json_multi(&host, PATHS, Fallback::Refuse).await;
    loop {
        tokio::select! {
            msg = stream.message() => match msg {
                Ok(Some(update)) => process(update, &mut state).await, // parse_subtree each part
                Ok(None) => break,
                Err(err) => { tracing::warn!("nat: subscription error: {err}"); break; }
            },
            Some(req) = show_rx.recv() => process_show(&state, req).await,
        }
    }
    tokio::time::sleep(crate::endpoint::RECONNECT_DELAY).await;
}
```

**Worked example.** `SubscribeMulti { format: JSON, paths: [["nat"], ["firewall","group"]] }` against this running config (the NAT spelling is the nat plan's):

```
set firewall group network-group LAN network 192.168.1.0/24
set nat source rule 10 source group network-group LAN
```

| Event | `subtrees[0]` (`nat`) | `subtrees[1]` (`firewall group`) |
|:--|:--|:--|
| snapshot | `{"source":{…}}`, changed | `{"network-group":[{"name":"LAN",…}]}`, changed |
| commit `set firewall group network-group LAN network 192.168.2.0/24` | unchanged JSON, `changed: false` | new JSON, `changed: true` |
| commit `set router bgp 65000` | no event | no event |
| commit `set nat source rule 20 …` together with `set firewall group network-group DMZ …` | `changed: true` | `changed: true`, both in **one** event |
| commit `delete nat` | `{}`, `changed: true` | unchanged, `changed: false` |

## 5. Tests

**zebra-rs unit tests.** `subscribe.rs` tests module; manager tests push a `ConfigSubscriber` with an `mpsc` bus and call `commit_config()`, as the existing manager tests do.
- `check_paths_rejects_empty_duplicate_overlapping_and_too_many`
- `multi_snapshot_carries_every_path_in_request_order`
- `multi_commit_touching_one_path_sends_one_event_with_flags`
- `multi_commit_touching_two_paths_sends_exactly_one_event`
- `multi_untouched_commit_sends_nothing`
- `multi_absent_subtree_is_empty_object`
- `multi_path_format_filters_changes_by_any_path`
- `single_path_subscribe_events_unchanged` (regression: byte-equal events before and after)

**insomnia unit tests:**
- `subscribe::tests::to_update_keeps_request_order_and_flags`
- `subscribe::tests::to_update_rejects_count_or_path_mismatch`
- `subscribe::tests::primary_only_synthesizes_empty_secondaries` (and sets `fallback`; a real Multi event never does)
- `json::tests::parse_subtree_maps_absent_list_to_default`

**BDD:** no feature of its own. Nothing user-visible changes until a consumer adopts the API. The first consumer's feature (NAT, PBR or the IPsec `pki` conversion) must include a scenario where one commit changes only the secondary subtree (`firewall group`) and the consumer's dataplane follows, so the cross-tree path is exercised end to end.

## 6. Docs

- The proto comments are the contract; keep both copies identical.
- `src/subscribe.rs` module doc: the delivery rule, atomicity, and both fallback modes.
- insomnia `AGENTS.md`, Backend shape step 1: add `subscribe_json_multi` and the one-stream-per-backend rule (D-10). Land this with M2.
- Book `ch-00-03-command-line-options.md:46` ("three configuration subscriptions (one per backend)"): reword when the first consumer lands to "one subscription per backend; some cover several subtrees".
- No module-doc VyOS deviation: this is plumbing. VyOS's equivalent mechanism is cited in the `subscribe.rs` doc.

## 7. Milestones

| # | Scope | Repo | Effort | Done when |
|:--|:--|:--|:--|:--|
| M1 | proto, `subscribe.rs` (`check_paths`, `subscribe_multi`), manager snapshot/dispatch, `subtree_json_in`, unit tests | zebra-rs | S–M | All §5 zebra-rs tests pass; existing `Subscribe` tests and `vtyctl watch` unchanged |
| M2 | Vendor proto, `subscribe_json_multi` + `Fallback`, `JsonConfigUpdate.changed`, `parse_subtree`, 64 MiB decode limit, unit tests, AGENTS.md note | insomnia | S | `cargo test --workspace --exclude bdd`, fmt and clippy clean; no backend behaviour change |
| M3 | `vtyctl watch --path … --path …` | zebra-rs | S (optional) | Manual: two watched paths print one block per commit |
| M4 | First adoption | consumer plan (nat, or pki-x509 / ipsec-vti) | — | Tracked in that plan; its BDD covers the cross-tree commit |

M1 must ship in a zebra-rs release before any `Refuse` consumer ships. `PrimaryOnly` consumers may ship first.

## 8. Risks and open questions

- **Spurious events.** An `interface` subscriber (now only ipsec-syntax-parity's optional D-dhcp check) is woken by every interface change (an MTU, an address) even if it reads one leaf. A `vti` or `firewall group` part wakes its backend in the same way. Requirement on every consumer: compare before apply, the `keepalived::apply` pattern and the fix for X12 in [fw-load-safety](fw-load-safety.md). Without it, every interface commit resets nft counters.
- **Event size.** Large `interface` or `firewall` subtrees are re-sent in full per event. D-9 lifts the decode limit. The 32-event bus (`subscribe.rs:32`) still drops a consumer that stops reading, and the consumer resyncs from the snapshot, as today.
- **PrimaryOnly hides data.** On an old zebra-rs, an IPsec peer bound to a VTI looks unbound and a `pki` reference looks missing. Requirement on PrimaryOnly consumers: test `MultiUpdate.fallback`, suppress findings that would be false, and warn per feature that needs a secondary subtree, naming the zebra-rs version gap, not just once per connection.
- **Typos are silent.** A misspelled path is `"{}"` forever, as with `Subscribe` today. Open: have zebra-rs log a warning when a requested path matches no schema node. Feasibility against the libyang `Entry` tree is *unverified*.
- **Open: a commit generation number** on `ConfigEvent`, for log correlation with [commit-validation](commit-validation.md) orders. Not needed for correctness; deferred.
- **Open: 16 paths.** Arbitrary. The largest planned consumer is the IPsec backend, with 4 (`vpn ipsec`, `pki`, `vti`, optional `interface`; 5 if L2TP is ever accepted).

## 9. Acceptance criteria

- [ ] `SubscribeMulti` is in zebra-rs and insomnia `proto/config.proto`, byte-identical.
- [ ] Overlapping, duplicate, empty or more than 16 paths are refused with `InvalidArgument`.
- [ ] Snapshot and every event carry all subtrees in request order, from one committed tree.
- [ ] A commit touching several subscribed paths produces exactly one event; an untouched commit produces none.
- [ ] Single-path `Subscribe` events are byte-identical to before (regression test).
- [ ] `subscribe_json_multi` with `Refuse` retries forever against an old zebra-rs; with `PrimaryOnly` it delivers the primary and empty secondaries, with a warning.
- [ ] insomnia clients decode events up to 64 MiB.
- [ ] Unit tests listed in §5 pass in both repos; fmt and clippy clean.
