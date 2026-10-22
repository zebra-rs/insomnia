# Commit-time validation — implementation plan

Status: plan, 2026-10-21. Covers: §4.1, decision D1, FW3, and the IPsec/VRRP verify rows of the §4.1 table ([vyos-gap](../vyos-gap.md) §4.1, §5, §8.1, §11).
Priority: P1 · Effort: L · Owner: both (zebra-rs: layer 1, the RPC and the commit path; insomnia: findings, the validator, layer 3)
Depends on: [multi-path-subscribe](multi-path-subscribe.md) (the `ConfigPath` / `Subtree` messages and `subtree_json_in`; layer 2 only) · coordinates with [fw-load-safety](fw-load-safety.md) (the X2 pre-pass produces Errors) and [ipsec-render-fixes](ipsec-render-fixes.md) (X4 is an Error)
Unblocks: every plan that adds VyOS verify rules: [nat](nat.md), [pki-x509](pki-x509.md), [fw-zones](fw-zones.md), [ipsec-vti](ipsec-vti.md), [vrrp-hardening](vrrp-hardening.md), [fw-matchers](fw-matchers.md), [fw-flowtable](fw-flowtable.md), [fw-packet-modification](fw-packet-modification.md), [fw-dynamic-sources](fw-dynamic-sources.md), [ipsec-remote-access](ipsec-remote-access.md), [ipsec-syntax-parity](ipsec-syntax-parity.md), [vrrp-virtual-server](vrrp-virtual-server.md), [vrrp-vrf](vrrp-vrf.md), [pbr](pbr.md), [wan-load-balancing](wan-load-balancing.md), [nat-cgnat-nat64](nat-cgnat-nat64.md), [conntrack](conntrack.md), [conntrack-sync](conntrack-sync.md), [fw-bridge](fw-bridge.md), [ipsec-dmvpn-l2tp](ipsec-dmvpn-l2tp.md), [charon-lifecycle](charon-lifecycle.md) (soft: `Findings`)

Assumes D1: YANG constraints, plus a dry-run validation RPC answered by insomnia. When insomnia is not connected, the commit goes through with a warning.

## 1. Goal

- With insomnia connected, a commit to an insomnia tree that VyOS would reject is refused before anything is dispatched. The refusal names the node.
- With insomnia not connected, or not answering in time, the commit goes through and prints one warning per unvalidated tree. Availability wins over strictness.
- Structural rules (a required leaf, a length, a range) are enforced by zebra-rs alone (layer 1), with no round trip. They never make an existing startup config fail to load.
- Every renderer finding has a severity: **Error** blocks the commit, **Warning** is printed and the commit proceeds. The renderer is the only implementation of cross-reference rules.
- An upgrade never changes what an already-committed config enforces. Rules that become stricter block *new* commits. At apply time they skip only what is already skipped today, plus load-safety and security cases (§3.2).
- `commit` at the CLI and `vtyctl apply` print warnings on success.

## 2. Current state

**zebra-rs commit path** (`src/config/manager.rs` @ `141da2fc`, `commit()` at `:849-1232`):
1. `:851-855`: `mandatory` and `ext:non-empty` over the whole candidate (`configs.rs:552-600`). There is no startup tolerance: a failing startup commit loads nothing (`:1369-1381`).
2. `:871-879`: `value_errors` on the lines this commit adds (`+`) only. It uses `check::value_check` (`check.rs:63-79`) and `check::startup_tolerant_check` (`check.rs:87-92`); the latter is refused at commit and only logged at startup. Errors print as `'<line>': <reason>` (`manager.rs:762`).
3. `:885-893`: the E-Tree whole-candidate check.
4. `:905-937`: the label check, under the label-space `MutexGuard`.
5. Dispatch to `cm_clients`, then `store.commit()` (`:1226`), then the gRPC subscribers (`:1231`).

How `commit` is reached:
- `commit()` is synchronous. `/commit` is an `fn(&ConfigManager)` pointer in `FuncMap` (`commands.rs:10,49,247-253`), called from `execute()` (`manager.rs:1539-1543`).
- `Deploy`, i.e. `vtyctl apply`, calls `commit_config()` at `:1698` and maps an error to `ApplyCode::MissingMandatory`. The MCP client already names that code "rejected by commit validation" (`vtyctl/src/mcp/client.rs:243-245`).
- `vtyctl apply` prints only `applied` on success; the description is dropped (`vtyctl/src/apply.rs:84-88`).
- Precedent for awaiting inside the manager loop: `comps_dynamic` awaits a daemon's oneshot (`manager.rs:1554-1588`).

YANG support in zebra-rs:

| Construct | Enforced? | Where |
|:--|:--|:--|
| `mandatory` leaf | Yes, but only on a node that exists. A container is checked only when it has children (`configs.rs:565`), so a mandatory leaf inside an absent non-presence container is not caught | `parse.rs:756-761`, `configs.rs:552-571` |
| integer `range` | Yes, at parse (`set`) time | `parse.rs:154-186` |
| decimal64 `range` | No | `parse.rs:189-194`, `check.rs:8-9` |
| string `length` | No. libyang parses it (`TypeNode.length`); `match_string` reads only `pattern` | `parse.rs:146-152` |
| `pattern` | Yes, but it consumes the rest of the line, so these trees avoid it | `firewall.yang:38-41`, `vrrp.yang:46-50` |
| `must`, `when`, `min-elements` | No | `extension.yang:60-61` (for `must`); no reader for the others |
| enumerations | Yes | `parse.rs:338-343` |

Also: `check.rs` has no rule for `firewall`, `vpn ipsec` or `vrrp`. None of `firewall.yang`, `ipsec.yang` or `vrrp.yang` uses `mandatory`. References are plain strings so that a referent can be staged after its referrer (`firewall.yang:42-44`).

**insomnia @ `ee4dfaa`:**
- `render(cfg) -> (String, Vec<String>)`: `firewall.rs:1173`, `ipsec.rs:516`, `vrrp.rs:936`.
- Every finding is a warning. `process()` logs it at `warn` and applies anyway.
- The book says so: `ch-05-04-keepalived-and-insomnia.md` ("A render never fails a commit").
- The firewall golden test jumps to the undefined chain `WEB-IN` (`firewall.rs:2104`) and asserts no warnings (`:2131`). That is X2, and [fw-load-safety](fw-load-safety.md) changes it.

**VyOS @ `7f2c893`:**
- A conf-mode `verify()` that raises `ConfigError` aborts the commit, and nothing is applied. `Warning()` prints and the commit continues. Schema validators (regex, numeric) reject at `set`.
- The rules:
  - `src/conf_mode/firewall.py`: `verify_rule` at `:255-505`; groups and includes at `:510-520`; flowtables and offload at `:525-575`; zones at `:625-710`;
  - `vpn_ipsec.py`: `verify` at `:262-770`;
  - `high-availability.py`: `:70-200`.

## 3. Design

### 3.1 Three layers

| Layer | What | Runs in | Needs insomnia | Lands |
|:--|:--|:--|:--|:--|
| 1 | Structural rules: required leaves, length, range, value shape of one leaf | zebra-rs (`check.rs`, YANG) | no | C3, C4 |
| 2 | Cross-reference and multi-leaf rules: the same `render()` run on the candidate, returning Errors | zebra-rs → insomnia `Validate` RPC | yes; skipped with a warning if absent | C5, C6 |
| 3 | The same rules at render time: an Error finding is logged and the effect applied (skip or keep) | insomnia `render()` | — | C1, C2 |

Layer 3 is not throwaway. Each rule is written once, in the renderer. It is logged today, and with layer 2 it also blocks the commit.

### 3.2 Severity and effect

**Error** iff either:
- (a) VyOS rejects it (`ConfigError` or a schema validator); or
- (b) the renderer cannot express the config as written: an unsafe token, an undefined reference, contradictory leaves.

**Warning** iff any of:
- VyOS accepts it, including its `Warning()` cases;
- the cause is an insomnia limitation ("not supported yet", "not applied yet"; every one has a gap ID);
- the cause is host state: a script is missing, an interface is absent. Host state changes after a commit, and validation of a candidate must be deterministic.

**Effect** is recorded separately, because it governs apply time:
- `Skipped`: rule, peer, group or child not rendered;
- `Dropped`: one element or member removed;
- `Adjusted`: value replaced, e.g. `drop` used, rounded;
- `Kept`: rendered as today;
- `NotApplied`: an insomnia limitation; the leaf has no effect yet.

**Upgrade-safety rule.** A rule that is newly classified as Error keeps today's apply effect, so something rendered today stays `Kept`. There are only two exceptions, which become `Skipped`:
- load-safety: nft or swanctl would reject the *whole* artifact. This is the X1/X2 class, and it includes a malformed `limit rate`, which reaches nft unchecked (`firewall.rs:1804-1807`);
- security defects: X4 (wildcard PSK), and the over-broad bypass child of X3, which [ipsec-render-fixes](ipsec-render-fixes.md) stops rendering. Also agreed here: a swanctl section-name collision ([ipsec-syntax-parity](ipsec-syntax-parity.md) D-names, e.g. `192.0.2.9` and `192-0-2-9`), which would merge two peers' identities and auth settings into one section. The later name is `Skipped`.

**Messages:**
- Name the node in config spelling, e.g. `ipv4 forward-filter rule 5: …`.
- Never include a secret value (PSK `secret`, VRRP `password`, or any other `ext:secret` leaf of [secret-redaction](secret-redaction.md)). That holds for `Finding.message` and for `Finding.path`, which names leaves and list keys but never a secret leaf's value.
- The effect is not part of the message: apply-time logs append it (`…; rule skipped`), and a refused commit does not.

### 3.3 Layer 1 mechanisms

- **New schema nodes** (NAT, PKI, …) use plain YANG `mandatory` / `range` / `enum` from day one.
- **Existing leaves** are never tightened at parse time. A startup line that stops parsing is dropped. For example, a 9-character VRRP password line would vanish, the group would then be skipped for `authentication requires both type and password` (`vrrp.rs:542`), and the result is an outage after the upgrade. Instead:
  - one-leaf value rules go in `check::startup_tolerant_check` (exists). It is refused at an interactive commit, only logged at startup, and fires only on lines the commit adds;
  - required leaves get `mandatory true` plus a new extension, **`ext:startup-tolerant`** (proposed). A violation is logged in the startup config. At an interactive commit it is refused only if the commit's diff touches the list entry that lacks the leaf; otherwise it is a warning. Without this extension, `mandatory true` on an existing leaf would reject the whole startup config (`manager.rs:1369-1381`) and then every later commit, even a BGP-only one.
  - If zebra-rs declines the extension, the "mandatory" rows in §4.4 move to layer 2 only.
- **Not in this plan:** enforcing `length` in `parse.rs` in general. It would also bite `dhcp.yang:165` and the IETF modules, so it is a separate zebra-rs decision.

### 3.4 Layer 2: the Validate RPC

**Direction.**
- insomnia is a gRPC *client* of zebra-rs. `--host` may even be `tcp:` to a remote zebra-rs.
- So the validator opens a bidirectional stream, as the show provider does: `ConfigService.Validate`.
- It inherits `MachinePeerInterceptor` because it lives on `ConfigServiceServer` (`serve.rs:852-855`).
- Every order carries the candidate's secrets in clear. So the handler applies [secret-redaction](secret-redaction.md)'s privileged-peer rule (S5): a UDS peer with uid 0 or in the config group; never a TCP peer unless `--vty-tcp-secrets`. Any other peer gets `PERMISSION_DENIED` on `register`, and its trees count as "not validated". Orders are not redacted instead: a placeholder secret counts as absent in insomnia (secret-redaction S10), so a redacted order would fail validation for the wrong reason.

**Units.**
- The validator registers *units*: a name plus the paths of the subscription that backend uses (`firewall` → `[firewall]`; later `nat` → `[nat]`, `[nat66]`, `[firewall group]`).
- A unit is validated iff the commit's changes touch one of its paths, by the same `path_has_prefix` as dispatch.
- Planned units. Each owning plan adds its `UNITS` row, its `<backend>::validate` and its `EXTERNAL_TREES` rows when its backend lands:

| Unit | Paths | `EXTERNAL_TREES` rows | Owner |
|:--|:--|:--|:--|
| `firewall` | `[firewall]` | `[firewall]` | this plan |
| `ipsec` | `[vpn ipsec]`, `[pki]`, `[vti]` | `[vpn ipsec]`, `[pki]` | this plan; `pki` from [pki-x509](pki-x509.md), `vti` from [ipsec-vti](ipsec-vti.md) |
| `vrrp` | `[vrrp]` | `[vrrp]` | this plan |
| `nat` | `[nat]`, `[nat66]`, `[firewall group]` | `[nat]`, `[nat66]` | [nat](nat.md) M9 |
| `nat64` | `[nat64]` | `[nat64]` | [nat-cgnat-nat64](nat-cgnat-nat64.md) |
| `pbr` | `[policy-route]`, `[policy-route6]`, `[firewall group]` | `[policy-route]`, `[policy-route6]` | [pbr](pbr.md) |
| `wlb` | `[load-balancing wan]`, `[firewall group]` | `[load-balancing wan]` | [wan-load-balancing](wan-load-balancing.md) |
| `conntrack` | `[system conntrack]`, `[firewall group]` | `[system conntrack]` | [conntrack](conntrack.md) |
| `conntrack-sync` | `[service conntrack-sync]` | `[service conntrack-sync]` | [conntrack-sync](conntrack-sync.md) |

- The `ipsec` unit validates `vpn ipsec`, `pki` and `vti` together, as one render. A `pki` or `vti` deletion that strands a reference is refused.
- `vti` is zebra-rs's tree (the XFRM link), so it is a unit path but not an `EXTERNAL_TREES` row. A `vti`-only commit with insomnia disconnected prints no warning; the bind finding comes back at the next IPsec apply (layer 3).

**Per commit:**
1. The local checks (steps 1–3 of §2) run as today.
2. Compute the change paths, the same list `subscriber_changes` builds today (`:1138-1166`), now built once and early.
3. For each validator connection with touched units, send one `ValidateOrder` holding the candidate subtrees (`subtree_json_in(&store.candidate, path)` from [multi-path-subscribe](multi-path-subscribe.md)).
4. Await all of them under one timeout: default 2 s, `--commit-validate-timeout <ms>` (proposed).
5. Any `ERROR` → refuse the commit. Nothing is dispatched, and the candidate is kept (CLI) or discarded (`Deploy`), as today.
6. `WARNING`s are printed after a successful commit.
7. A touched insomnia tree with no validator, or with a timeout or disconnect → warning `<tree>: not validated (insomnia not connected)`.

**Insomnia trees.**
- `EXTERNAL_TREES` (proposed, in `manager.rs`): `[firewall]`, `[vpn ipsec]`, `[vrrp]`, and `[pki]` with [pki-x509](pki-x509.md). Each new insomnia tree adds its row (the table above).
- It is needed because a disconnected insomnia has registered nothing.

**Placement in `commit()`.**
- After `value_errors` and E-Tree; before the label check. A `MutexGuard` held across an await would stall label allocation in the RIB.
- Before any dispatch.
- The startup commit skips layer 2: insomnia cannot be connected yet, and a startup config is never refused for external reasons.
- While awaiting, the manager loop processes nothing else, which is bounded by the timeout. That is the `comps_dynamic` precedent, and it also freezes the candidate, which is shared by all sessions.

**insomnia side.**
- The validator task calls pure `validate()` functions directly, not through the backend channels. A backend that is busy in `swanctl -q` must not delay a commit, and there is no possible cycle back into zebra-rs.

**Mode** (proposed): `--commit-validate enforce|warn|off`, default `enforce`.
- `warn` turns Errors into warnings. It is for a staged roll-out: run one release in `warn`, read the logs, then enforce.

**What `nft -c` cannot see.** The firewall's `validate()` never relies on `nft -c` alone. `nft -c` returns 0 for jump loops and over-deep chains, for `meta ipsec` inbound matches in an output-hook chain or a chain jumped from one, and for `flow add` in a chain jumped from `input` ([fw-load-safety](fw-load-safety.md) §2, [fw-matchers](fw-matchers.md), [fw-flowtable](fw-flowtable.md); measured with nftables 1.0.9). The real apply then fails.
- So `validate()` runs `render()`, and with it fw-load-safety's `plan_table` reference pass and chain graph (`reaching_hooks`), first. The pass turns each of those classes into an Error, the same one that skips the rule at apply time.
- fw-matchers and fw-flowtable register their hook limits with that graph; they add no dry-run check of their own.

**Optional artifact check (C8).**
- After `render()`, the rendered candidate script also goes to `nft -c -f -`. That is one check transaction in insomnia's netns, with no side effects. It turns any remaining userspace-phase rejection (the X1 class, an unknown token) into an Error. It is a backstop behind the pre-pass, never the only check.
- Rejected: applying the script in a scratch netns to get the kernel's commit-time checks. The interfaces and flowtable devices it names do not exist there, so it fails differently. The pre-pass covers the hook classes, and the flowtable plan gates on device existence itself.
- `keepalived --config-test` is the same idea for VRRP; that the packaged keepalived has it is *unverified*.
- swanctl has no dry run (*unverified*).

**Rejected:**
- Re-implementing the rules in `check.rs`: two implementations that drift, and zebra-rs would need every renderer's model.
- A unary RPC served by insomnia: wrong direction, and insomnia has no listener.
- Validating from the `Subscribe` stream: it is post-commit by contract.

### 3.5 Output

| Path | Refused | Committed with warnings |
|:--|:--|:--|
| CLI `commit` | one line per Error: `firewall: <message>` (layer 1 keeps `'<line>': <reason>`) | `warning: <unit>: <message>` lines; today's output is empty |
| `vtyctl apply` | `ApplyCode::MissingMandatory`; `description` = the error lines, printed as `error reply: …` as today | `ApplyCode::Applied` + `description` = warnings; vtyctl prints `applied` and then the description |

The BDD apply steps fail on the substring `error` anywhere in stdout (`bdd/tests/cucumber.rs:861-866`, `:893-898`), so a commit with warnings would fail them. C7 narrows both checks to lines starting with `error` (same step text, so the vocabulary stays compatible with zebra-rs's harness). Until then, warning text must not contain the word.

## 4. Changes

### 4.1 zebra-rs

**(a) `proto/config.proto`** (proposed; vendored to insomnia):

```proto
// Validator → server. First message: register; then one result per order.
message ValidatorMessage {
  oneof msg {
    ValidatorRegister register = 1;
    ValidateResult result = 2;
  }
}
message ValidatorRegister {
  repeated ValidationUnit unit = 1;   // replaces any earlier holder of a unit name
}
message ValidationUnit {
  string name = 1;                     // "firewall", "ipsec", "vrrp", "nat", …
  repeated ConfigPath paths = 2;       // same rules as SubscribeMulti
}
// Server → validator: the candidate for every unit this commit touches.
message ValidateOrder {
  uint64 id = 1;
  repeated UnitCandidate unit = 2;
}
message UnitCandidate {
  string name = 1;
  repeated Subtree subtrees = 2;       // candidate JSON; same shape as SubscribeMulti
}
enum Severity {
  SEVERITY_UNSPECIFIED = 0;            // treated as ERROR
  ERROR = 1;
  WARNING = 2;
}
message Finding {
  Severity severity = 1;
  repeated string path = 2;            // offending node when known; may be empty
  string message = 3;                  // names the node; never a secret value
}
message ValidateResult {
  uint64 id = 1;
  repeated UnitResult unit = 2;        // one per ordered unit
}
message UnitResult {
  string name = 1;
  repeated Finding finding = 2;
}

service ConfigService {
  rpc Subscribe(SubscribeRequest) returns (stream ConfigEvent) {}
  rpc SubscribeMulti(SubscribeMultiRequest) returns (stream ConfigEvent) {}
  // Dry-run validation of commits touching the registered units.
  rpc Validate(stream ValidatorMessage) returns (stream ValidateOrder) {}
}
```

**(b) `src/config/validate.rs`** (proposed): the service handler and bridge, shaped like `show_provider.rs:187-307`.
- Registration becomes `Message::RegisterValidator { units, tx }` / `WithdrawValidator` (`same_channel` guard).
- The manager holds `validators: RefCell<Vec<Validator>>`.
- A result whose id is unknown, a unit missing from a result, or a second `register` closes the stream. Its pending order becomes "not validated".

**(c) `manager.rs` commit split** (proposed names):
- `fn precheck(&self, startup) -> Result<Prepared, Err>`: steps 1–3, plus the diff and the change paths.
- `async fn external_validate(&self, &Prepared) -> Verdict { errors, warnings }`.
- `fn finish(&self, Prepared, startup)`: the label check, dispatch, commit and subscribers. This is today's code from `:905` on.
- `async fn commit_checked(&self, startup) -> anyhow::Result<Vec<String>>` returns the warnings.
- `execute()` returns an internal marker for `/commit` instead of calling the `fn` pointer. The `Execute` and `Deploy` arms of `process_message` await `commit_checked(false)`. `load_config` keeps the synchronous path, with no layer 2.
- Clone JSON out of the `RefCell`s before awaiting (`clippy::await_holding_refcell_ref`, as in `comps_dynamic`).

**(d) `EXTERNAL_TREES`**, the `--commit-validate*` flags, and output formatting per §3.5.

**(e) Layer 1:**
- `check.rs` rows (§4.4) under `startup_tolerant_check`;
- `ext:startup-tolerant` in `extension.yang`. `parse.rs:756-761` carries a tolerant flag next to each mandatory name. `configs.rs` `validate()` returns tolerant violations with their entry path, and `precheck` decides by the diff.

**(f) YANG edits** per §4.4.

**(g)** `vtyctl apply` prints `description` after `applied` when it is non-empty.

### 4.2 insomnia

**(a) `src/findings.rs`** (proposed), shared by all renderers:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity { Error, Warning }

/// Apply-time consequence; `log` renders it as the message suffix:
/// "rule skipped", "member dropped", "<how>", "rendered as configured", "not applied yet".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect { Skipped(&'static str), Dropped(&'static str), Adjusted(String), Kept, NotApplied }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding { pub severity: Severity, pub msg: String, pub effect: Effect }

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Findings(pub Vec<Finding>);

impl Findings {
    pub fn error(&mut self, msg: String, effect: Effect);
    pub fn warn(&mut self, msg: String, effect: Effect);
    pub fn errors(&self) -> Vec<&str>;     // messages, for tests and the RPC
    pub fn warnings(&self) -> Vec<&str>;
    /// Apply-time log: every finding at `warn`, as `"<msg>; <effect>"`.
    pub fn log(&self, backend: &str);
}
```

At apply time both severities stay at `warn` level, so log greps and the book's examples keep working; only the text format is normalised.

**(b) Renderers.**
- Each `Render` struct swaps `warnings: Vec<String>` for `findings: Findings`.
- `render()` returns `(String, Findings)` (`firewall.rs:1173`, `ipsec.rs:516`, `vrrp.rs:936`).
- `render_str` (test-only) returns `(String, Findings)`.
- Rendered text does not change in C1.

**(c) Per backend,** `pub fn validate(parts: &[JsonConfigUpdate]) -> Findings` parses (a parse failure is an Error) and returns `render(&cfg).1`.
- Requirement on [vrrp-hardening](vrrp-hardening.md) and later plans: keep `render()` pure. Host checks (script stat, interface existence) live in a separate `host_findings(&cfg)` that returns Warnings and is called by both `process()` and `validate()`.

**(d) `src/validate.rs`** (proposed): the validator task. It has the reconnect loop of `provider.rs:39-78`, sends `ValidatorRegister` with `UNITS` (`firewall`, `ipsec`, `vrrp`; consumer rows per the §3.4 table), maps each `UnitCandidate` to `<backend>::validate`, and answers every order exactly once; an unknown unit gets a single Error. It sets the 64 MiB decode limit from [multi-path-subscribe](multi-path-subscribe.md) D-9.

**(e)** `main.rs` spawns `validate::run(host)`.

**(f)** C8: after the pre-pass, `firewall::validate` runs `nft -c -f -` on the script, with a 1 s timeout. Its stderr becomes one Error.

### 4.3 Classification of today's findings (C1)

Firewall (`src/firewall.rs`):

| Site | Finding | Sev | Effect |
|:--|:--|:--|:--|
| `:1246` | chain name not a plain token | E | chain skipped |
| `:1418` | group name not a plain token | E | group skipped |
| `:1458` | group member unsafe | E | member dropped |
| `:1479` | group include not found (VyOS `:515`) | E | Kept (set without it) |
| `:1507` | rule `Err` from `render_rule`: unsafe token, group or interface-group reference (`:1678`, `:1737`), jump without target (`:1884`), unsafe jump-target (`:1888`), unsupported action (`:1906`), bad `time` (`:1974-2006`) | E | rule skipped |
| `:1540` | default-action jump without a valid target (VyOS `:605`) | E | Adjusted (`drop`) |
| module doc `:21-24` | `global-options` toggles and timeouts dropped silently | W (new finding) | not applied, until [fw-global-options](fw-global-options.md) |

IPsec (`src/ipsec.rs`):

| Site | Finding | Sev | Effect |
|:--|:--|:--|:--|
| `:553` | log / options / interface / disable-uniqreqids not applied | W | not applied ([charon-lifecycle](charon-lifecycle.md); X6 moves `disable-uniqreqids` out) |
| `:569` | psk without secret (VyOS `:275`) | E | psk skipped |
| `:575` | psk `dhcp-interface` ids unsupported | W | static ids only |
| `:599` | peer authentication mode missing (VyOS `:636`) | E | peer skipped |
| `:605`, `:611` | ike-group missing or undefined (VyOS `:620-622`) | E | peer skipped |
| `:617` | peer `dhcp-interface` unsupported | W | peer skipped |
| `:623` | no local-address (VyOS `:666`) | E | peer skipped |
| `:644` | no tunnel and no vti (VyOS `:704`). Split: every tunnel `disable`d → W | E | peer skipped |
| `:651` | ike-group without a complete proposal | E | peer skipped |
| `:857`, `:914` | child esp-group missing or undefined (VyOS `:709-714`) | E | child skipped |
| `:862`, `:1005` | vti bind is not `vti<N>` (VyOS `:699`) | E | child skipped / updown omitted |
| `:869`, `:922` | esp-group without a complete proposal | E | child skipped |

VRRP (`src/vrrp.rs`):

| Site | Finding | Sev | Effect |
|:--|:--|:--|:--|
| `:410`, `:978` | group / sync-group without a name (defensive) | E | skipped |
| `:418-550` | every `skip()` reason: unsafe name or interface, vrid or interface or address missing (VyOS `:76-82`), bad address, mixed families (`:106`), duplicate VRID (`:111`, `:126`), hello-source or peer family or shape (`:116-136`), auth needs type and password (`:86`), unknown auth type, unquotable password | E | group skipped |
| `:461`, `:487`, `:592` | unsafe address dev / bad excluded-address / unsafe track interface | E | Dropped |
| `:553` | password longer than 8 (VyOS regex `.{1,8}`) | E | Kept (keepalived truncates) |
| `:574` | VRRPv2 cannot carry IPv6 | W | Adjusted (v3) |
| `:634`, `:643` | health-check script unquotable / ping not an IP | E | health check omitted |
| `:649` | not exactly one of script/ping (VyOS `Warning`, `:184`) | W | omitted |
| `:662` | timeout < interval (VyOS `Warning`, `:195`) | W | Kept |
| `:694` | advertise-interval not positive (VyOS `--range 1-255`) | E | Adjusted (1) |
| `:703`, `:711` | rounded for v2 / clamped to the v3 maximum | W | Adjusted |
| `:799` | transition-script unquotable | E | Dropped |
| `:886` | VMAC name too long | E | Kept (rfc3768 ignored) |
| `:982`, `:1014` | sync-group unsafe name / no valid member | E | sync-group skipped |
| `:991` | member missing (VyOS `:146`) → E; member disabled → W (split) | E/W | member dropped |
| `:997` | member already in another sync-group | E | member dropped |
| `:1006` | member has its own health check (VyOS `ConfigError`, `:151`) | W (decided, §8) | Kept |

### 4.4 Layer 1 inventory (C3, C4)

| Tree | Rule (VyOS source) | Mechanism | Row |
|:--|:--|:--|:--|
| firewall | rule needs `action` (`firewall.py:258`) | `mandatory` + `ext:startup-tolerant` on `action` in `rule-common` and `rule-raw-common` (`firewall.yang:395-495`) | C4 |
| firewall | rule `recent` needs both `count` and `time` (V15; asked by [fw-matchers](fw-matchers.md)) | `mandatory` + tolerant on `recent count` and `recent time` (the container exists whenever either is set) | C4 |
| firewall | `description` ≤ 255 (VyOS generic description) | `startup_tolerant_check` on `…/rule/description` and group descriptions | C3 |
| ipsec | peer needs `ike-group` (`vpn_ipsec.py:622`) | `mandatory` + tolerant on `site-to-site peer ike-group` | C4 |
| ipsec | `authentication mode` (`:636`) | `mandatory` + tolerant on `peer authentication mode`. Catches only a present `authentication` container (§2 table); an absent one stays layer 2 | C4 |
| ipsec | psk needs `secret` (`:275`) | `mandatory` + tolerant on `psk secret`. `id` is a leaf-list (`min-elements` unsupported) → layer 2 | C4 |
| ipsec | peer `description` ≤ 255 | `startup_tolerant_check` | C3 |
| vrrp | group needs `vrid`, `interface` (`high-availability.py:76-79`) | `mandatory` + tolerant | C4 |
| vrrp | auth needs `type` and `password` (`:86`) | `mandatory` + tolerant on both, inside `authentication` (the container exists whenever either is set) | C4 |
| vrrp | `password` ≤ 8 (schema regex) | `startup_tolerant_check` on `/vrrp/group/authentication/password` | C3 |
| vrrp | `description` ≤ 255 | `startup_tolerant_check` | C3 |
| vrrp | health-check `timeout` ≥ 1 (`--positive`) | `startup_tolerant_check` on group and sync-group `health-check/timeout` (a YANG range would drop startup lines) | C3 |
| vrrp | `advertise-interval` > 0 (decimal64, unchecked by zebra-rs) | `startup_tolerant_check` | C3 |
| vrrp | at least one `address`; VIP not a network address (`ip-host`) | layer 2: no `min-elements`; the VIP is a list key, so a value check would see it only on key-only lines | — |

- The VRRP C3 rows match the [vrrp-vrf](vrrp-vrf.md) spelling as well: `/vrrp/group/…` and `/vrrp/vrf/group/…` (and the sync-group forms). One predicate strips an optional `vrf <name>` after `vrrp`, so the rows work before and after vrrp-vrf lands; vrrp-vrf only adds the tests. The C4 `mandatory` rows sit in the group definition that vrrp-vrf reuses.
- New nodes add their own constraints with their YANG (§3.3), e.g. `ext:non-empty` on [fw-matchers](fw-matchers.md)' new `fib` and `gre` containers. Only existing leaves are listed here.

### 4.5 FW3: the 29 VyOS rule families (raw IDs V1–V29)

| V | Rule | Layer / severity / effect today → after | Owner |
|:--|:--|:--|:--|
| 1 | action required | L1 + L2 E; Kept (verdict-less rule) | this plan |
| 2 | jump ⇒ jump-target; jump-target without action jump | L2 E; jump without target stays Skipped (as today); target without jump Kept (target ignored) | this plan |
| 3 | target exists, no loop | L2 E; Skipped (load-safety); 8-deep nesting → W | [fw-load-safety](fw-load-safety.md) pre-pass |
| 4 | default-action jump ⇔ target; exists; not self | L2 E | this plan + X2 pre-pass |
| 6 | `icmp` on ipv6 / `ipv6-icmp` on ipv4 | L2 E; Kept | this plan |
| 9 | queue / queue-options need action queue | L2 E; Kept | this plan (fanout range: [fw-matchers](fw-matchers.md)) |
| 10 | match-frag and match-non-frag | L2 E; Kept | this plan |
| 13 | limit rate integer ≥ 1 | L2 E; Skipped (malformed rate reaches nft; load-safety; nft behaviour on `0/second` *unverified*) | this plan |
| 15 | recent needs count and time (silently dropped today) | L1 (§4.4) + L2 E; Kept | this plan |
| 17 | tcp flags need protocol tcp; flag set and `not` | L2 E; Kept | this plan |
| 19 | one group type per side; group vs address; group exists; empty group → W | L2 E/W; exists → Skipped (X2) | this plan + X2 |
| 20 | port / port-group need tcp, udp or tcp_udp (insomnia falls back to `th`); not both | L2 E; Kept | this plan |
| 22 | log-options need log; snapshot-length and queue-threshold need group | L2 E; Kept | this plan |
| 23 | interface name and group exclusive (name wins); group exists; empty → W | L2 E/W; exists → Skipped (X2) | this plan + X2 |
| 24 | include exists; not circular (cycle cut) | L2 E; Kept | this plan |
| 12 | empty nodes | n/a: a non-presence container cannot be stored empty (*unverified*); re-check per new presence node | — |
| 5, 26, 28 | offload, flowtable | with FW9 | [fw-flowtable](fw-flowtable.md) |
| 7, 8, 11, 14, 16, 18 | synproxy, disable-conntrack, fib, ipsec, gre, mac mask | with the matchers | [fw-matchers](fw-matchers.md) (FW2, FW16, FW18) |
| 21 | add-address-to-group | with FW8 | [fw-packet-modification](fw-packet-modification.md) |
| 25, 27 | remote-group, geoip; also address/fqdn/geoip exclusivity (at most one per side), which fw-matchers does not cover | with FW10/11/14 | [fw-dynamic-sources](fw-dynamic-sources.md) (§3.4) |
| 29 | zones | with FW1 | [fw-zones](fw-zones.md) |

IPsec rules added in C2 (from the gap's IPsec table):
- Errors: `default-esp-group` undefined (Kept); AEAD proposal without `prf` (`vpn_ipsec.py:349`, Kept); transport mode with prefixes or without a fixed address (`:720-723`, Kept); psk without `id` (X4, Skipped, from [ipsec-render-fixes](ipsec-render-fixes.md)).
- Warnings: IKEv1 deprecation (`:332-339`); missing `remote-address` (advisory); `interface` names absent on the host.
- PKI, VTI, remote-access and ppk rules belong to their plans.

### 4.6 Worked example

```
zebra# set firewall ipv4 forward filter rule 5 action jump
zebra# set firewall ipv4 forward filter rule 5 jump-target WAN-IN
zebra# commit
firewall: ipv4 forward-filter rule 5: jump-target WAN-IN is not defined
```

The exchange behind it:

```
ValidateOrder  { id: 41, unit: [{ name: "firewall", subtrees: [{ path: ["firewall"], changed: true,
  json: "{\"ipv4\":{\"forward\":{\"filter\":{\"rule\":[{\"number\":5,\"action\":\"jump\",\"jump-target\":\"WAN-IN\"}]}}}}" }] }] }
ValidateResult { id: 41, unit: [{ name: "firewall", finding: [{ severity: ERROR,
  message: "ipv4 forward-filter rule 5: jump-target WAN-IN is not defined" }] }] }
```

With insomnia stopped, the same `commit` succeeds and prints:

```
warning: firewall: not validated (insomnia not connected)
```

When insomnia comes back, the snapshot apply logs `firewall: ipv4 forward-filter rule 5: jump-target WAN-IN is not defined; rule skipped`, and the rest of the ruleset loads (X2).

Layer 1, with or without insomnia, uses the existing `value_errors` format:

```
zebra# set vrrp group LAN authentication password longer-than-8
zebra# commit
'vrrp group LAN authentication password <redacted:5e0c19a2>': password must be 1-8 characters
```

The tag is [secret-redaction](secret-redaction.md) S8, which renders these lines with `Secrets::Redact`. Before S8 lands, the line echoes the secret the operator just typed (§8).

## 5. Tests

**insomnia unit tests:**
- C1: every existing test that asserts `warnings` asserts `findings.errors()` or `findings.warnings()` per §4.3. The text format becomes `<msg>` plus the effect. The rendered output is unchanged; update the goldens deliberately and say so in the commit.
- New tests:
  - `findings::tests::log_format_appends_effect`;
  - `firewall::tests::verify_rules_are_errors` (one case per row of §4.5 owned here, each asserting severity, message and effect);
  - `ipsec::tests::verify_rules_are_errors`;
  - `vrrp::tests::sync_group_member_missing_vs_disabled`;
  - `firewall::tests::validate_matches_render_findings`;
  - `firewall::tests::validate_catches_what_nft_check_misses` (a jump loop and an output-hook `meta ipsec` jump are Errors with no `nft` call);
  - `validate::tests::every_order_answered_once` (unknown unit, parse failure);
  - C8: `firewall::tests::nft_check_rejection_is_error` (needs `nft` and is gated like the existing nft-dependent tests; if there are none, put it in BDD).

**zebra-rs unit tests:**
- `startup_tolerant_mandatory_loads_startup_config`
- `startup_tolerant_mandatory_refuses_only_touched_entry`
- one `check.rs` test per C3 row
- `commit_without_validator_warns_for_external_trees`
- `commit_refused_on_error_finding_dispatches_nothing`
- `commit_warnings_returned_on_success`
- `validator_timeout_commits_with_warning`
- `untouched_units_get_no_order`
- `validate_order_carries_candidate_not_running`
- `validate_refuses_unprivileged_peer` (TCP and a non-config-group uid get `PERMISSION_DENIED`)
- `startup_commit_skips_layer2`
- `deploy_reports_validation_errors_as_missing_mandatory`

**BDD:** feature `@commit_validation` (C7).
- Topology: one namespace `r1` running zebra-rs `--feature insomnia` and insomnia via `tests/scripts/insomnia_node.sh` (created by [fw-load-safety](fw-load-safety.md)) (private `/run` and `/etc/swanctl`, like `ipsec_node.sh`; no charon or keepalived, since validation is pure). Its `--without-insomnia` mode starts zebra-rs alone.
- Port zebra-rs's step `applying command {string} in namespace {string} should be rejected with {string}` (`zebra-rs/bdd/tests/cucumber.rs:973`), keeping the same wording.
- Scenarios:
  1. Setup.
  2. A jump to an undefined chain is rejected with `jump-target WAN-IN is not defined`, and `show running-config` does not contain `WAN-IN`.
  3. A psk without `id` is rejected.
  4. A VRRP password of 9 characters is rejected (layer 1).
  5. A valid ruleset is applied, and `show firewall` contains the rule.
  6. In `--without-insomnia` mode, the jump commit succeeds and its output contains `not validated`.
  7. Teardown.

## 6. Docs

- **Book.** New `ch-00-04-commit-validation.md` (proposed): the three layers, severity versus effect, the `--commit-validate` modes, what "not validated" means, and the upgrade-safety rule. Fix `ch-05-04` ("A render never fails a commit"). In `ch-00-03` `--host`, add that insomnia also registers a validator. In the per-feature chapters, mark the rules that now refuse a commit.
- **insomnia `AGENTS.md`.** In Backend shape step 5, add "findings carry severity and effect; an Error blocks the commit through `validate()`; keep `render()` pure".
- **Module docs** of `firewall.rs`, `ipsec.rs` and `vrrp.rs`. Record the deviations: host-state findings are Warnings (VyOS rejects a missing script); a sync-group member with its own health check stays a Warning; the upgrade-safety `Kept` effects.
- **zebra-rs.** `extension.yang` documents `ext:startup-tolerant`, and the flag help documents `--commit-validate*`.

## 7. Milestones

| # | Scope | Repo | Effort | Done when |
|:--|:--|:--|:--|:--|
| C1 | `findings.rs`; renderers return `(String, Findings)`; §4.3 classification; test migration | insomnia | S | Rendered output byte-identical; tests assert severity and effect |
| C2 | Layer 3 rules of §4.5 and the IPsec list | insomnia | M | One test per rule; apply effects as tabled |
| C3 | `check.rs` rows of §4.4 | zebra-rs | S | Unit tests; a startup config with a long password still loads (logged) |
| C4 | `ext:startup-tolerant` + `mandatory` rows | zebra-rs | M | Startup-tolerance tests pass; an untouched legacy rule without action does not block a BGP commit |
| C5 | `Validate` RPC, bridge, commit split, `EXTERNAL_TREES`, flags, output, `vtyctl apply` | zebra-rs | M–L | zebra-rs §5 tests pass with a mock validator |
| C6 | Vendor proto; `validate.rs`; per-backend `validate()` | insomnia | S–M | Orders answered; `validate_matches_render_findings` |
| C7 | `@commit_validation` BDD + `insomnia_node.sh` + ported step; apply steps match `error` only at line start | insomnia | S | Feature green; teardown clean; `ipsec_s2s` and `vrrp_pair` still green |
| C8 | `nft -c` artifact check (optional; keepalived `--config-test` if verified) | insomnia | S | An X1-class overlap refused at commit |
| C9 | Book and AGENTS.md updates | insomnia | S | Chapters merged |

Order: C1 → C2 (any time); C3 and C4 in parallel; C5 needs [multi-path-subscribe](multi-path-subscribe.md) M1; C6 needs C1 and C5; C7 needs C5 and C6.

## 8. Risks and open questions

- **Manager stall.** Every commit to an insomnia tree waits up to the timeout when insomnia hangs, and every CLI session stalls with it. It is bounded at 2 s by default; the `--commit-validate off` escape exists.
- **Upgrades surface latent errors.** After C5, a config with a dangling reference committed earlier blocks the next commit to that tree until it is fixed. That is VyOS behaviour, but new to zebra-rs users. Mitigations: `warn` mode for one release, and a release note.
- **Version skew.** An insomnia without C6 makes every firewall/IPsec/VRRP commit print "not validated". That is intended, since it shows the gap.
- **Divergence.** Layer 2 equals apply only if `render()` is pure. Host checks must stay in `host_findings` (requirement on [vrrp-hardening](vrrp-hardening.md)). The C8 `nft -c` runs against the live kernel's nft feature set, which is the same kernel as apply.
- **Secrets.**
  - Orders carry candidate secrets in clear, so `Validate` admits only privileged peers (§3.4, [secret-redaction](secret-redaction.md) S5). Over `tcp:` without `--vty-tcp-secrets`, insomnia's trees are therefore "not validated".
  - `value_errors` echoes whole lines, including a refused VRRP password (`manager.rs:762`). secret-redaction S8 masks secret leaves there; that plan owns the change.
- **Size.** Large candidates exceed tonic's 4 MiB default. insomnia raises its decode limit (multi-path D-9).
- **Decided: sync-group member health check.** VyOS rejects it (`high-availability.py:151`, smoketest-asserted). `design/vrrp.md` §6 chose warn-and-ignore, and the VRRP owner keeps that ([vrrp-hardening](vrrp-hardening.md) §8): a Warning. [docs-corrections](docs-corrections.md) records it as a stronger deviation.
- **Open: `commit check`**, a dry run of layers 1–2 without applying. It is nearly free after C5. A zebra-rs follow-up.
- **Open: per-unit timeout or partial results.** One slow unit currently delays all of them; acceptable while one process serves all units.

## 9. Acceptance criteria

- [ ] Renderers return `(String, Findings)`; every finding in §4.3 has the tabled severity and effect; rendered text is unchanged by C1.
- [ ] The rules of §4.5 marked "this plan", and the IPsec list, are implemented, each with a test.
- [ ] Layer 1 rows of §4.4 refuse interactive commits, and the startup config still loads with a log line.
- [ ] A commit with an Error finding is refused before any dispatch, with `<unit>: <message>`.
- [ ] Without a validator, or on timeout, a commit touching an insomnia tree succeeds and prints `not validated`.
- [ ] Warnings are printed by `commit` and by `vtyctl apply`, and contain no secret values.
- [ ] `Validate` refuses peers that are not privileged under secret-redaction S5.
- [ ] `proto/config.proto` is identical in both repos.
- [ ] `@commit_validation` BDD passes and ends with a clean teardown.
- [ ] fmt and clippy clean in both repos; `cargo test --workspace --exclude bdd` green.
