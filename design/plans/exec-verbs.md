# Operational verbs (reset / restart / generate / clear) — implementation plan

Status: plan, 2026-10-21. Covers: §4.2 and decision D2, plus the §7.1 VICI and retained-model limits ([vyos-gap](../vyos-gap.md) §4.2, §7.1, §11).
Priority: P2 · Effort: M · Owner: both
Depends on: none · Unblocks: [ipsec-opmode](ipsec-opmode.md), [ipsec-remote-access](ipsec-remote-access.md), [conntrack](conntrack.md), [conntrack-sync](conntrack-sync.md), [vrrp-hardening](vrrp-hardening.md) (`restart vrrp`), [pki-x509](pki-x509.md) (`generate pki`), [ipsec-vti](ipsec-vti.md) (VICI `register`, D7 phase b), [charon-lifecycle](charon-lifecycle.md) (VICI `stats` / `reload-settings`), [fw-opmode](fw-opmode.md) (`generate` root, `EXEC_LOCAL`, shared `show log` container), [fw-dynamic-sources](fw-dynamic-sources.md) (the `update` verb, `update geoip`), [wan-load-balancing](wan-load-balancing.md) (`restart wan-load-balance`), [ipsec-dmvpn-l2tp](ipsec-dmvpn-l2tp.md) (`reset vpn ipsec profile`, via ipsec-opmode's row), [ipsec-syntax-parity](ipsec-syntax-parity.md) (bounded `vici::request`, retained model); soft: [nat](nat.md), [pbr](pbr.md) and [nat-cgnat-nat64](nat-cgnat-nat64.md) (`ROUTES`, `Backends`, `Answer`)

Assumes D2: extend `zebra.show.v1` with an exec order kind rather than add a sibling service.

## 1. Goal

- `reset …`, `restart …`, `generate …` and `update …` typed at the zebra-rs CLI, or sent with `vtyctl`, reach the insomnia backend that owns the tree. Each order is answered exactly once, with text and a success/failure flag.
- `clear …` paths can be served by a provider as well. Every `clear` is dispatched exactly once; today `vtyctl clear` dispatches twice.
- These verbs are admin-only and can never be triggered through the read-only show path: neither the `Show` RPC nor the vtyctl MCP show tool.
- insomnia registers verb trees next to its show trees. One routing table covers both.
- `src/vici.rs` can send any request with a body, and offers `terminate`, `initiate`, `stats` and a long-lived event subscription (`register`), all time-bounded.
- Every backend retains its last committed model as an `Arc`, so verb handlers can consult the configuration. Example: re-initiate only `connection-type initiate` peers.

## 2. Current state

**zebra-rs @ `141da2fc`:**
- **Grammar.** `yang/exec.yang` has `show` (`:131`) and `cli`, but no `reset`, `restart` or `generate`. `clear` exists only in configure mode (`yang/configure.yang:117`), for in-process daemons. `parse.rs:848-859` sets the `set`/`delete`/`show`/`clear` flags.
- **`clear` today.**
  - `manager.rs:1533-1536`: `execute()` calls `self.clear(paths)` during the parse phase. That is a broadcast to `cm_clients` (`:1500-1505`) with no reply path.
  - The `Clear` RPC (`serve.rs:504-530`, admin-gated by `enforce_admin`) sends `Message::ClearTx`, whose arm (`manager.rs:1848-1856`) broadcasts again.
  - `vtyctl clear` (`vtyctl/src/clear.rs:31-51`) calls `DoExec` in configure mode, which already runs the clear, and then calls `Clear`. Reading the code, every `vtyctl clear` therefore broadcasts twice.
- **`show` today.**
  - `DoExec` returns `REDIRECT_SHOW` (`manager.rs:1546-1551`). The client then calls `Show` (`serve.rs:436-473`, not admin-gated), which sends `DisplayTx`.
  - Routing uses `SHOW_PROTOS` (`manager.rs:2078-2092`), whose tests match any segment (`is_vpn` = any `vpn`). The result goes to the registry, then the provider bridge (`show_provider.rs:239-307`).
  - The MCP show tool (`vtyctl/src/mcp/client.rs:62-120`) pushes any line through `DoExec(exec)` and then `Show`.
- **`show.proto`:** `Register { name }`, `ShowOrder { id, path, args, json }`, `ShowChunk { id, text, eof }`.
- **Sessions.** `Session.username` is resolved at session creation and "retained for future audit logging" (`session.rs:82-85`).
- **Completion.** Dynamic completion (`ext:dynamic`) goes only to in-process `cm_clients` (`manager.rs:1554-1588`). Providers cannot complete.

**insomnia @ `ee4dfaa`:**
- **`provider.rs`:** `:17-27` registers `["firewall","ipsec","vrrp"]`; `:91-99` routes by an if-chain on `/show/...` prefixes; `:126-133` the relay guarantees one eof chunk per order.
- **`api.rs:27-36`:** `ShowRequest.resp` is `oneshot::Sender<String>`.
- **`vici.rs`:**
  - only `streamed_request` (`:217-257`), and it sends requests with no body (`named_packet`, `:188-192`);
  - the encoder exists only as `#[cfg(test)] test_encode` (`:260-293`);
  - socket I/O has no timeout, so a wedged charon hangs `show vpn ipsec sa`.
- **Retained models:**
  - firewall: `ShowState.model` (`firewall.rs:47-49`);
  - VRRP: `vrrp.rs:58-60`, set at `:108`;
  - IPsec: none. `process()` drops the model (`ipsec.rs:90-116`), and `process_show` receives only the socket path (`:1046`).

**VyOS @ `7f2c893`:**
- Op-mode verbs are scripts that the op-mode shell runs locally as root. Nothing is routed through a daemon:
  - `op-mode-definitions/vpn-ipsec.xml.in` (`reset` at `:3`, `restart ipsec` at `:109-116`) runs `src/op_mode/ipsec.py`, which uses `python/vyos/ipsec.py`:
    - `terminate_vici_ikeid_list` (`:118-139`) sends `{'ike-id': id, 'timeout': '-1'}`;
    - `terminate_vici_by_name` is at `:142-173`;
    - `vici_initiate` (`:209-240`) sends `timeout '-1'`.
  - `restart ipsec` and `restart vrrp` (`vrrp.xml.in:46`) run `src/op_mode/restart.py`.
  - `reset-conntrack.xml.in`.
  - `conntrack-sync.xml.in` has `reset conntrack-sync external-cache|internal-cache` and `restart conntrack-sync`.
  - `pki.xml.in` has `generate pki …`.

## 3. Design

**D-1. One provider stream for show and exec (D2).**
- Exec orders ride `zebra.show.v1` `Provide` with `ShowOrder.kind = EXEC`. They reuse:
  - registration replace/withdraw and the `same_channel` guard;
  - the bridge task;
  - the answer-exactly-once contract;
  - insomnia's reconnect loop.
- A sibling `zebra.exec.v1` would duplicate all of that, and a provider would hold two streams that can fail independently.
- The cost is a package named "show" that also carries exec. Accepted, and stated in the proto comment.

**D-2. Opt-in per tree.**
- `Register.exec` lists the trees whose verbs the provider serves.
- zebra-rs sends EXEC orders only to providers that listed the tree. An old insomnia therefore never receives one.
- An old zebra-rs ignores the field, and its grammar has no verbs to route.

**D-3. The answer contract.**
- Same `ShowChunk` stream. The eof chunk of an EXEC order carries `error = true` when the action failed.
- zebra-rs collects the chunks of an EXEC order into one unary reply.
- Missing answers:
  - provider disconnect → `"% <Name> provider disconnected"`, error;
  - insomnia backend gone (dropped oneshot) → `"% <backend> handler not running"`, error.

**D-4. The client path: a new `REDIRECT_EXEC` exec code, with `Clear` as the verb RPC.**
- `DoExec` parses `clear`, `reset`, `restart`, `generate`, `update` ([fw-dynamic-sources](fw-dynamic-sources.md)) and `import` ([pki-x509](pki-x509.md)) lines and **never executes them**. It returns `ExecCode::REDIRECT_EXEC` with the paths.
- The client then calls the admin-gated `Clear` RPC, which becomes the RPC for all operational verbs:
  - for `clear` it still broadcasts to the in-process daemons, now once;
  - for provider trees it routes to the provider.
- This fixes the double dispatch.
- Existing callers keep working. `vtyctl clear` already does `DoExec` followed by `Clear`, and the BDD step `I run {string} in namespace {string}` (`bdd/tests/cucumber.rs:946-956`) uses `vtyctl clear`, so features can drive `reset vpn ipsec …` with no new step.
- Rejected: returning `REDIRECT_SHOW` for verbs, so they reuse the `Show` RPC. `Show` is not admin-gated, and the MCP read-only show tool would then execute resets.
- Rejected: a separate `Operate` RPC. It would have the same semantics as `Clear` under a new name; it can be added later as an alias.

**D-5. Routing by leading segments (zebra-rs).**
- `EXEC_ROUTES` (proposed) matches exact leading segments, longest first. It does not use the any-segment tests of `SHOW_PROTOS`, which already misroute (`is_policy`, `manager.rs:2047-2061`; X15, fixed by [fw-opmode](fw-opmode.md) M1).
- A matched route with no registered provider → result 1, `"% IPsec is not configured or running"`. This mirrors the show fallback (`manager.rs:1827-1846`).
- An unmatched `clear` → in-process broadcast, as today.
- An unmatched `reset`/`restart`/`generate`/`update`/`import` → `EXEC_LOCAL` (proposed): a table of `(leading segments, fn(&ConfigManager, &[CommandPath]) -> ExecResult)` for verbs zebra-rs answers itself. The first users are [fw-opmode](fw-opmode.md)'s `generate firewall rule-resequence`, which never leaves zebra-rs, and [pki-x509](pki-x509.md)'s `import pki`, which edits the candidate (D-11). Anything else gets result 1, `% Unknown command`.
- The manager never blocks on an exec order: the `ClearTx` arm spawns a task that awaits the reply, like the show fallback task.

**D-6. Grammar placement.**
- New top-level `reset`, `restart`, `generate` and `update` containers in `exec.yang`. `import` is [pki-x509](pki-x509.md)'s grammar. Each is `if-feature feat:insomnia` while all its children are insomnia-served, so a build without the feature shows no empty verb.
- They are grafted into configure mode with `top_from_exec` (`manager.rs:615-621`), as `show` and `cli` are. `run …` keeps working too.
- Provider-served `clear` subtrees, if a consumer needs one (e.g. a PBR counters clear), go under `configure.yang` `container clear`, where `clear` already lives.
- Each consumer plan owns the grammar below its verb.
- **Shared `show log` container.** This plan also owns the empty `container log { if-feature feat:insomnia; ext:help "Show logs"; }` under `show` in `exec.yang`. [fw-opmode](fw-opmode.md), [ipsec-opmode](ipsec-opmode.md) and [vrrp-hardening](vrrp-hardening.md) add `firewall`, `ipsec` and `vrrp` children, so all three extend the same node.
  - These are SHOW orders, not EXEC orders. Each child's routing predicate matches the exact leading segments (`show log ipsec`) and sits in `SHOW_PROTOS` ahead of the any-segment tests.
  - The container lands in E4, or with the first of those consumers if that comes earlier, using the text above.

**D-7. No provider completion in this plan.** Peer names and the like are free strings. Open question §8.

**D-8. insomnia routing.**
- One `ROUTES` table (proposed) of `(prefix, Backend)` covers both kinds. Backends receive verbs on their existing request channel.
- `route()` matches a prefix only on a segment boundary: `path == p || path.starts_with(&format!("{p}/"))`. So `/show/nat` never captures `/show/nat64` or `/show/nat66`, `/show/conntrack` never captures `/show/conntrack-sync`, and row order does not matter.
- `ShowRequest` gains `kind` and `user`, and its answer type gains an error flag and the D-11 install lines.
- Handlers that may block for more than ~100 ms run in a spawned task holding an `Arc` of the model, so a slow VICI `terminate` or `systemctl restart` never delays a config apply. Every external call is time-bounded. Recommended bounds: `VICI_TIMEOUT` (10 s) for VICI, 30 s for `systemctl restart`, 5 s for a journal read. A timeout answers `error = true`.

**D-9. Audit.** zebra-rs fills `ShowOrder.user` from `Session.username`. insomnia logs every EXEC order at `info` (`exec: <user>: <path> <args>`) and its outcome.

**D-10. Retained models.**
- Each backend keeps `model: Option<Arc<Cfg>>` holding the last committed config that parsed: set right after parsing, before apply, and `None` for `"{}"` or an empty config.
- It is the committed intent, not necessarily what the dataplane loaded. Handlers must not treat it as live state; live state comes from VICI, nft or keepalived.

**D-11. Install lines** (for [pki-x509](pki-x509.md)'s `generate pki … install`).
- The eof chunk of an EXEC order may carry `install`: `set` lines the verb wants added to the candidate. `ExecResult` and insomnia's `Answer` carry them through.
- `ClearRequest` gains `mode` (proposed): the mode the line was typed in. vtyhelper copies it from the `DoExec` call that returned `REDIRECT_EXEC`.
- In configure mode, zebra-rs applies the lines to the candidate, uncommitted, the same way `import pki` does. All or nothing: if one line fails to parse, none is applied and the reply says which. The reply ends with `% <N> lines added to the candidate; review and commit`.
- In exec mode, or from an old vtyhelper that sends no `mode`, the lines are printed only, with "paste these lines in configure mode". That is VyOS's behaviour outside a config session.
- The lines may hold a private key, as the printed text already does. They cross the provider stream as show output does today; pki-x509 refuses `generate` when `--host` is TCP.

**VyOS deviation to record** in the `provider.rs` module doc: verbs are executed by the enforcement daemon via zebra-rs, not by a local op-mode script. Each consumer records its verb-specific deviations.

## 4. Changes

### zebra-rs

**`proto/show.proto`** (proposed; additive, vendored to insomnia):

```proto
message Register {
  repeated string name = 1;   // show trees (unchanged)
  // Exec-verb trees this provider serves, same keys as `name`:
  // "ipsec" receives `reset vpn ipsec …` and `restart ipsec`.
  repeated string exec = 2;
}

enum OrderKind {
  SHOW = 0;  // read-only; may be answered from cache
  EXEC = 1;  // changes state; admin-gated upstream; answer once
}

message ShowOrder {
  uint64 id = 1;
  string path = 2;            // "/reset/vpn/ipsec/site-to-site/peer"
  repeated string args = 3;   // ["OFFICE"]
  bool json = 4;
  OrderKind kind = 5;
  string user = 6;            // issuing operator for EXEC orders; may be empty
}

message ShowChunk {
  uint64 id = 1;
  string text = 2;
  bool eof = 3;
  bool error = 4;             // on the eof chunk of an EXEC order: action failed
  // On the eof chunk of an EXEC order: `set` lines for the
  // candidate (D-11). Applied only in configure mode.
  repeated string install = 5;
}
```

**`proto/vty.proto`:** `ExecCode` gains `REDIRECT_EXEC = 7`. `ClearRequest` gains `mode` (D-11). The `Clear` service comment is reworded: "operational verbs: clear, reset, restart, generate, update, import".

**`yang/exec.yang`** (skeleton; the leaves come from the consumer plans):

```yang
container reset {
  if-feature feat:insomnia;
  ext:help "Reset operational state";
  // container vpn { container ipsec { … } }      ipsec-opmode
  // container conntrack { … }                    conntrack
  // container conntrack-sync { … }               conntrack-sync
}
container restart {
  if-feature feat:insomnia;
  ext:help "Restart a service";
  // leaf vrrp { type empty; }                    vrrp-hardening
  // leaf ipsec { type empty; }                   ipsec-opmode
  // leaf wan-load-balance { type empty; }        wan-load-balancing
}
container generate {
  if-feature feat:insomnia;
  ext:help "Generate an object";
  // container pki { … }                          pki-x509
}
container update {
  if-feature feat:insomnia;
  ext:help "Update a dynamic data source";
  // container geoip { presence …; }              fw-dynamic-sources
}
// container import { … }                         pki-x509 (EXEC_LOCAL)
```

Whether zebra-rs hides a container with no enabled children is *unverified*. Gating the container itself avoids depending on that.

**`src/config/manager.rs`:**
- `fn op_verb(paths) -> bool` (first segment, after trimming `run`, is `clear|reset|restart|generate|update|import`). In `execute()` it replaces the `state.clear` branch (`:1533-1536`): return `(ExecCode::RedirectExec, String::new(), paths)`.
- `const EXEC_ROUTES: &[(&[&str], &str, &str)]` holds (leading segments, registry key, display name). Rows land with their consumer's grammar:

| Leading segments | Key | Consumer |
|:--|:--|:--|
| `reset vpn ipsec` | `ipsec` | ipsec-opmode, ipsec-remote-access, ipsec-dmvpn-l2tp (`profile`) |
| `restart ipsec` | `ipsec` | ipsec-opmode |
| `generate ipsec` | `ipsec` | ipsec-opmode (P3: `debug-archive`); ipsec-remote-access (`profile`, deferred, its D8) |
| `restart vrrp` | `vrrp` | vrrp-hardening |
| `reset conntrack` | `conntrack` | conntrack |
| `reset conntrack-sync`, `restart conntrack-sync` | `conntrack-sync` | conntrack-sync |
| `generate pki` | `pki` | pki-x509 |
| `restart wan-load-balance` | `wlb` | wan-load-balancing |
| `update geoip` | `firewall` | fw-dynamic-sources |

`import pki` ([pki-x509](pki-x509.md)) and `generate firewall rule-resequence` ([fw-opmode](fw-opmode.md)) are `EXEC_LOCAL` rows, not routes.

- `exec_clients: RefCell<HashMap<String, UnboundedSender<ExecRequest>>>` with `Message::SubscribeExec { name, tx }` and `Message::UnsubscribeExec { name, tx }` (same `same_channel` guard as `:1866-1873`).
- New arm for `Message::ClearTx`:
  - if `exec_route(&paths)` matches → look up the provider; if one exists, send an `ExecRequest` and spawn a task that awaits it and answers `ClearTxResponse`;
  - if it matches but nothing is registered → result 1 with the not-running text;
  - if an `EXEC_LOCAL` row matches → run it in the manager and answer;
  - if the verb is `clear` → today's broadcast;
  - otherwise → result 1, `% Unknown command`.

**`src/config/api.rs`** (proposed):
- `ExecRequest { paths, json, user: Option<String>, resp: oneshot::Sender<ExecResult> }`
- `ExecResult { error: bool, output: String, install: Vec<String> }`
- `ClearTxRequest` gains `user` and `mode`.

**`src/config/show_provider.rs`:**
- `Register.exec` names are registered with `SubscribeExec`.
- `bridge()` gets a third `select!` arm on `exec_rx`. It allocates an id from the same counter and sends `ShowOrder { kind: EXEC, user, … }`.
- `pending` becomes an enum: `Show(mpsc::Sender<String>)` or `Exec { buf: String, resp: oneshot::Sender<ExecResult> }`. Exec chunks accumulate until eof, which sends `ExecResult { error: chunk.error, output: buf }`.
- At exit the exec names are withdrawn. Dropping the pending entries yields the D-3 disconnect error, because the spawned waiter maps `RecvError` to it.

**`src/config/serve.rs`:**
- `ClearService` takes `user` from the session that `enforce_admin` already resolved.
- `ShowService::show` refuses paths whose first segment is not `show` with `InvalidArgument`. This is defence in depth for D-4.

**Clients:**
- `vtyhelper`: `REDIRECT_EXEC` → `Clear` RPC; print `str`; exit non-zero when `result != 0`.
- `vtyctl clear`: refuse a `DoExec` parse failure instead of sending garbage paths.
- `vtyctl show` and `mcp/client.rs` `exec_parse_error` (`:253-273`): `REDIRECT_EXEC` is an error, "not a show command".

### insomnia

**`proto/show.proto`:** vendor byte for byte.

**`src/api.rs`** (proposed):

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OrderKind { #[default] Show, Exec }

#[derive(Debug, Default)]
pub struct Answer { pub text: String, pub error: bool, pub install: Vec<String> }
impl From<String> for Answer { fn from(text: String) -> Self { Self { text, ..Self::default() } } }

pub struct ShowRequest {
    pub path: String,
    pub args: Vec<String>,
    pub json: bool,
    pub kind: OrderKind,
    pub user: String,
    /// Answered exactly once; a dropped sender becomes an error answer.
    pub resp: oneshot::Sender<Answer>,
}
```

Existing show handlers change `resp.send(text)` to `resp.send(text.into())`. That edit is mechanical.

**`src/provider.rs`:**
- `register_message()` sends `name: [firewall, ipsec, vrrp]` and `exec: EXEC_TREES`. `const EXEC_TREES: &[&str]` starts empty; each consumer plan adds its key when its first verb handler lands.
- The if-chain (`:91-99`) becomes `fn route(kind, path) -> Option<Backend>` over:

```rust
const ROUTES: &[(OrderKind, &str, Backend)] = &[
    (Show, "/show/firewall", Backend::Firewall),
    (Show, "/show/vpn/ipsec", Backend::Ipsec),
    (Show, "/show/vrrp", Backend::Vrrp),
    // consumer rows, e.g. (Exec, "/reset/vpn/ipsec", Backend::Ipsec),
    //                     (Exec, "/restart/vrrp", Backend::Vrrp)
];
```

- `chunk_message` sets `error` and `install` from `Answer`.
- The unknown-route answer is an error for EXEC orders.

**`src/main.rs`:** pass a `Backends` struct (proposed) of per-backend senders to `provider::run`, replacing the three positional arguments, so a new backend is one field.

**`src/ipsec.rs`:** add `struct ShowState { model: Option<Arc<IpsecConfig>> }`, set in `process()`. `process_show` receives `&ShowState`. Make `conn_name` (`:431-433`) `pub(crate)`, since handlers map a peer name to its swanctl connection.

**`src/firewall.rs`, `src/vrrp.rs`:** `model: Option<Arc<_>>`, so spawned handlers can hold it.

**`src/vici.rs`** owns this API (proposed):

```rust
/// Message encoder (replaces `test_encode`; tests use it too).
pub struct Builder { buf: Vec<u8> }
impl Builder {
    pub fn new() -> Self;
    pub fn kv(&mut self, key: &str, value: &str) -> anyhow::Result<&mut Self>;      // key ≤255 B, value ≤65535 B
    pub fn list(&mut self, key: &str, items: &[&str]) -> anyhow::Result<&mut Self>;
    pub fn section(&mut self, key: &str, f: impl FnOnce(&mut Builder) -> anyhow::Result<()>) -> anyhow::Result<&mut Self>;
    pub fn finish(self) -> Vec<u8>;
}

/// Upper bound on every request/response exchange.
pub const VICI_TIMEOUT: Duration = Duration::from_secs(10);

/// Core exchange: register `events`, send `command` with `msg`, collect
/// (event name, message) until CMD_RESPONSE, unregister. Bounded by VICI_TIMEOUT.
pub async fn exchange(socket: &Path, command: &str, msg: &[u8], events: &[&str])
    -> anyhow::Result<(Vec<(String, Value)>, Value)>;

/// Plain command; `success = no` becomes Err(errmsg).
pub async fn request(socket: &Path, command: &str, msg: &[u8]) -> anyhow::Result<Value>;

/// Kept: now `exchange(.., &[event])` with an optional filter message.
pub async fn streamed_request(socket: &Path, command: &str, event: &str) -> anyhow::Result<Vec<Value>>;

pub struct Terminate<'a> { pub ike: Option<&'a str>, pub child: Option<&'a str>,
    pub ike_id: Option<u64>, pub child_id: Option<u64>, pub force: bool, pub timeout_ms: i64 }
pub struct Terminated { pub matches: u64, pub terminated: u64 }
pub async fn terminate(socket: &Path, t: &Terminate<'_>) -> anyhow::Result<Terminated>;

pub struct Initiate<'a> { pub ike: Option<&'a str>, pub child: Option<&'a str>, pub timeout_ms: i64 }
pub async fn initiate(socket: &Path, i: &Initiate<'_>) -> anyhow::Result<()>;

pub async fn stats(socket: &Path) -> anyhow::Result<Value>;

/// Long-lived `register` subscription (no timeout). Ends with Err/None when
/// charon goes away; the caller reconnects.
pub struct EventStream { /* UnixStream */ }
impl EventStream { pub async fn next(&mut self) -> anyhow::Result<Option<(String, Value)>>; }
pub async fn subscribe(socket: &Path, events: &[&str]) -> anyhow::Result<EventStream>;
```

- `request` also serves `reload-settings` for [charon-lifecycle](charon-lifecycle.md).
- `subscribe` serves `child-updown` / `ike-updown` for [ipsec-vti](ipsec-vti.md) D7 phase (b), which uses `vici::subscribe` / `EventStream` directly. There is one implementation.
- Field names and semantics follow the strongSwan VICI README: `terminate` returns `success`, `matches`, `terminated`, `errmsg`; `timeout` is 0 to wait and -1 to return at once, which is what VyOS passes. Verify both against the strongSwan version the BDD host installs (*unverified* here).

**Worked example.** The handler logic and output text for `reset vpn ipsec site-to-site peer OFFICE` belong to [ipsec-opmode](ipsec-opmode.md).
1. The vty shell runs `DoExec(exec, "reset vpn ipsec site-to-site peer OFFICE")`. The reply is `REDIRECT_EXEC` with the paths `reset vpn ipsec site-to-site peer(Key) OFFICE(KeyMatched)`.
2. vtyhelper sends `Clear{paths}`. It passes `enforce_admin`, and the session user is `alice`.
3. The manager matches `EXEC_ROUTES` → `ipsec`, finds the provider in `exec_clients`, and the bridge sends `ShowOrder { id: 12, path: "/reset/vpn/ipsec/site-to-site/peer", args: ["OFFICE"], kind: EXEC, user: "alice" }`.
4. insomnia `route(Exec, path)` → `Backend::Ipsec`. The handler looks up `OFFICE` in the retained model, spawns `vici::terminate(&Terminate { ike: Some("OFFICE"), timeout_ms: -1, .. })`, then `initiate` when the peer is `initiate`, and answers `Answer { text, error: false }`.
5. The provider sends `ShowChunk { id: 12, text, eof: true, error: false }`. The bridge sends `ExecResult`, and `ClearReply { result: 0, str: text }` reaches the shell.

The VICI bytes for `terminate { ike = OFFICE, timeout = -1 }` are the golden value for `vici::tests::terminate_encodes`:

```
00 00 00 25                               length 37
00 09 74 65 72 6d 69 6e 61 74 65          CMD_REQUEST, "terminate"
03 03 69 6b 65 00 06 4f 46 46 49 43 45    KEY_VALUE ike = "OFFICE"
03 07 74 69 6d 65 6f 75 74 00 02 2d 31    KEY_VALUE timeout = "-1"
```

## 5. Tests

**zebra-rs unit tests:**
- `exec_route_matches_leading_segments_only` (`reset vpn ipsec …` → ipsec; `show vpn ipsec sa` → none; `clear bgp …` → none)
- `op_verbs_redirect_and_never_execute` (`execute()` on `clear`, `reset`, `restart`, `generate`, `update`, `import` returns `REDIRECT_EXEC` and broadcasts nothing; this is the regression test for the double dispatch)
- `clear_tx_without_provider_reports_not_running`
- `exec_local_runs_in_process_and_unknown_verb_errors`
- `bridge_aggregates_exec_chunks_into_one_reply`
- `bridge_exec_error_flag_sets_result`
- `exec_install_lines_reach_candidate_only_in_configure_mode` (exec mode prints them; one bad line applies none)
- `bridge_exit_turns_pending_exec_into_disconnect_error`
- `register_exec_replace_and_withdraw_guarded` (`same_channel`)
- `show_rpc_refuses_non_show_paths`
- vtyctl: `exec_parse_error_refuses_redirect_exec` (MCP) and the equivalent in `show.rs`.

**insomnia unit tests:**
- `provider::tests::route_table` (every show prefix; an unknown exec path is an error answer)
- `provider::tests::route_matches_on_segment_boundary` (`/show/nat64` is not `/show/nat`; `/show/conntrack-sync` is not `/show/conntrack`)
- `vici::tests::builder_round_trips_through_parse_message` (replaces `test_encode` use)
- `vici::tests::builder_rejects_oversize_key_and_value`
- `vici::tests::terminate_encodes` (the golden bytes above)
- `vici::tests::request_maps_success_no_to_errmsg`, using a fake charon on `tokio::net::UnixStream::pair()`
- `vici::tests::exchange_times_out` (a fake that never answers, with the timeout shortened under `cfg(test)`)
- `vici::tests::event_stream_yields_named_events`
- `ipsec::tests::model_retained_and_cleared` (`"{}"` → `None`)

**BDD:**
- None in this plan. The platform has no user-visible verb until a consumer adds grammar.
- Requirement on the first consumer (ipsec-opmode or vrrp-hardening): its feature must run its verb through the existing `I run {string} in namespace {string}` step and assert the effect. For IPsec, a new SA appears in `show vpn ipsec sa`. It must also assert that the same line sent through `show command …` is refused.

## 6. Docs

- **Book.** New chapter `ch-03-03-operational-commands.md` (proposed). It explains how verbs reach insomnia, that they need the admin role, and their exit status; each consumer appends its commands. Add a note to `ch-00-03` that insomnia registers verb trees on the same provider stream.
- **insomnia `AGENTS.md`.** In "Process layout" and "Show commands", document the `ROUTES` table, `OrderKind::Exec`, the answer-once rule for EXEC orders and the spawn guidance (D-8).
- **Module docs.** `provider.rs` gets the D-1 to D-3 contract and the VyOS deviation. The `vici.rs` header loses "exactly the subset the show commands need" and gains the request, event and timeout model.
- **zebra-rs.** The `vtyctl clear` help text says it accepts every operational verb.

## 7. Milestones

| # | Scope | Repo | Effort | Done when |
|:--|:--|:--|:--|:--|
| E1 | `vici.rs` `Builder`, `exchange`/`request`, `terminate`/`initiate`/`stats`/`subscribe`, `VICI_TIMEOUT` on existing calls; unit tests | insomnia | S | Tests pass; `show vpn ipsec sa` against a wedged socket returns an error after the timeout |
| E2 | Retained `Arc` models in all three backends; IPsec `ShowState` | insomnia | S | `model_retained_and_cleared` passes; show output unchanged |
| E3 | `REDIRECT_EXEC`, `op_verb` in `execute()`, `ClearTx` routing skeleton, client updates (vtyhelper, vtyctl clear/show/mcp), `Show` RPC path guard | zebra-rs | S–M | Double-dispatch regression test passes; `clear bgp …` still works interactively and via vtyctl |
| E4 | `show.proto` (`exec`, `kind`, `user`, `error`); `exec_clients`, bridge exec arm, `EXEC_ROUTES` table; exec.yang verb containers and the shared `show log` container | zebra-rs | M | Bridge and route unit tests pass with a mock provider stream |
| E5 | Vendor proto; `api.rs` `OrderKind`/`Answer`; `provider.rs` `ROUTES` + `EXEC_TREES`; `Backends` struct | insomnia | S | `route_table` passes; show behaviour byte-identical |
| E6 | First consumer verb (owned by ipsec-opmode or vrrp-hardening) with its BDD | consumer | — | Tracked there |

E1 and E2 have no protocol dependency and can land first. E3 is independent of E4. E5 needs E4's proto.

## 8. Risks and open questions

- **Behaviour change for `clear`.** Interactive `clear` now goes through two RPCs instead of executing in `DoExec`. Any client other than vtyhelper and vtyctl that relied on `DoExec` executing a clear breaks. In the zebra-rs repo only those two (and the MCP client, which never sends clear) call `DoExec`; external scripts are *unverified*. Mitigation: release note.
- **Long verbs.** `restart …` (systemd) and `generate pki` (key generation) can take seconds. `reset vpn ipsec … all` waits for each peer and needs up to about 30 s ([ipsec-opmode](ipsec-opmode.md)). The `Clear` RPC has no deadline and the bridge has no per-order timeout.
  - Requirement on consumers: bound every external call and answer with an error on timeout.
  - Promise to consumers: an EXEC order may take at least 30 s. zebra-rs sets no per-order deadline below 60 s, and vtyhelper and `vtyctl clear` set no gRPC deadline on `Clear` below 60 s. If a zebra-rs ceiling is added later, it is 60 s or more, so it never fires before the consumer's own bound (ipsec-opmode's `reset … all` takes about 16 s, `systemctl restart` up to 30 s).
- **No completion for provider trees** (D-7). `reset vpn ipsec site-to-site peer <TAB>` cannot list peers. Open: a `COMPLETE` order kind on the same stream (a later plan); until then, document the free-form argument.
- **Signal mode.** `restart vrrp` in the BDD harness has no systemd unit to restart. [vrrp-hardening](vrrp-hardening.md) decides between refusing and stopping and respawning keepalived.
- **Authorization granularity.** Every verb needs the admin role; VyOS has no finer split either. A per-verb role is out of scope.
- **Rogue provider.** Any client that passes `MachinePeerInterceptor` (`serve.rs:680-711`) can register `exec: ["ipsec"]` and receive the operator names in `user`. The exposure is the same as for show registration today. Document that `unix:` with a uid allow-list is the supported deployment ([vyos-gap](../vyos-gap.md) §4.6 and [secret-redaction](secret-redaction.md) S5 make the same point).
- **Settled:** `generate` output is text, not a file; [pki-x509](pki-x509.md) answered it. Its configure-mode `install` is D-11.

## 9. Acceptance criteria

- [ ] `show.proto` carries `Register.exec`, `OrderKind`, `ShowOrder.kind/user`, `ShowChunk.error/install` in both repos, byte-identical.
- [ ] `DoExec` never executes `clear`/`reset`/`restart`/`generate`/`update`/`import`; `vtyctl clear 'clear …'` dispatches once.
- [ ] insomnia `route()` matches on segment boundaries.
- [ ] A `reset`/`restart`/`generate` line through `Show` or the MCP show tool is refused.
- [ ] An EXEC order is answered exactly once, including on provider disconnect and on a dropped backend oneshot, with `result != 0` on failure.
- [ ] insomnia `ROUTES` covers all show prefixes; show output is unchanged.
- [ ] `vici.rs` exposes `Builder`, `request`, `exchange`, `terminate`, `initiate`, `stats`, `subscribe`; all exchanges are bounded by `VICI_TIMEOUT`.
- [ ] Firewall, IPsec and VRRP retain `Arc` models; IPsec `process_show` can read its model.
- [ ] Unit tests in §5 pass; fmt and clippy clean in both repos.
