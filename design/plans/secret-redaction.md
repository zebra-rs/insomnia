# Secret redaction — implementation plan

Status: plan, 2026-10-21. Covers: §4.6 secrets, the §8.1 "password masking"
row ([vyos-gap](../vyos-gap.md) §4.6, §7.3 PKI, §8.1).
Priority: P2, rising to P1 together with PKI · Effort: M · Owner: both (zebra-rs most of it)
Depends on: none to start. Coordinates with
[multi-path-subscribe](multi-path-subscribe.md) (the `secrets` field number,
its D-11) and [ipsec-render-fixes](ipsec-render-fixes.md) (X13 owns the
create-with-final-mode helper) · Unblocks:
[pki-x509](pki-x509.md), [ipsec-remote-access](ipsec-remote-access.md),
[ipsec-syntax-parity](ipsec-syntax-parity.md) (ppk secret),
[ipsec-dmvpn-l2tp](ipsec-dmvpn-l2tp.md) (profile `pre-shared-secret`),
[ipsec-opmode](ipsec-opmode.md) (op-mode policy, S11),
[fw-dynamic-sources](fw-dynamic-sources.md) (`maxmind-license-key`). Also
covers the password-masking item [vrrp-hardening](vrrp-hardening.md) leaves
here (no dependency in either direction)

Baselines: zebra-rs `141da2fc`, insomnia `ee4dfaa`, vyos-1x `7f2c893`,
libyang crate 2.2.0 (`~/.cargo/registry/.../libyang-2.2.0`).

## 1. Goal

- `show running-config` and `show candidate-config`, in every format (CLI,
  `formal`, `json`, `yaml`), never print the value of a leaf tagged
  `ext:secret`. The same holds for the configure-mode `show` diff, `vtyctl show`
  and MCP `get-config`. The value is replaced by a `<redacted:XXXXXXXX>` tag
  that changes when the value changes.
- An Admin session can still see cleartext, but only by asking for it
  explicitly (`show running-config secrets [formal|json|yaml]`). A View
  session, a TCP peer, or any caller without a session is refused.
- `zebra.config.v1 Subscribe` sends cleartext only to a privileged UDS peer
  that asks for it. In practice that is insomnia, which runs as root over
  `unix:`. Every other subscriber gets the tags. Secrets never cross `tcp:`
  unless the operator opts in.
- These keep cleartext: `save`, the startup load, the commit diff,
  in-process subscriptions, and insomnia's subscription.
- Pasting redacted output back in (`vtyctl apply`, `load`, configure mode)
  fails with an error that names the leaf. The placeholder never overwrites
  the real secret.
- insomnia never renders a placeholder into `swanctl.conf` or
  `keepalived.conf`. It never creates those files world-readable, not even
  for a moment, and never echoes a secret in show output or in warnings.

## 2. Current state

**zebra-rs: how running config is rendered.**
- `Config` nodes do not point at schema entries (`zebra-rs/src/config/configs.rs:175-191`).
  Per-node schema facts are stamped at `set` time from the
  `CommandPath` (`proto/vty.proto:212-229`). `ext:non-empty` is the
  precedent:
  - it is read from `mx.matched_entry.extension` (`parse.rs:768-777`);
  - it is copied into both `CommandPath` constructors (`parse.rs:815-837`);
  - it is stamped on new nodes (`configs.rs:658-667`);
  - `carbon_copy` copies it (`configs.rs:612-634`).
- The renderers are `write`/`format` (`configs.rs:249-317`),
  `json_marshal`/`json` (`379-448`), `yaml` (built from the JSON, `450-469`),
  `list` (`485-516`) and `formal` (`524-532`).
- The same functions serve two kinds of caller, with no option to tell them
  apart:
  - **Read surfaces:**
    - the exec- and configure-mode show handlers
      (`commands.rs:73-94`, `185-231`);
    - the configure-mode `show` diff (`commands.rs:162-182`);
    - the Show RPC arms (`manager.rs:1735-1795`), which always render the JSON
      too (`render_json()`, `1762-1764`);
    - the gRPC JSON subscription: `subtree_json` (`manager.rs:652-663`), the
      snapshot (`670-684`) and the deltas (`712-744`);
    - the PATH subscription: `running_changes` (`689-705`).
  - **Persistence and the engine:**
    - `serialize_running` and `save_config_as` (`manager.rs:1483-1498`,
      `1443-1470`);
    - the commit diff (`manager.rs:858-859`).
- Nothing in `src/config/` masks anything: a grep for `redact`/`strip` finds
  nothing.

**zebra-rs: schema and extensions.**
- `yang/extension.yang` declares `help`, `sort`, `no-sort`, `presence`,
  `dynamic`, `default-child`, `positional` and `non-empty`. There is no
  `secret`.
- libyang copies every unknown statement into `Entry.extension`, keyed by its
  literal `prefix:name` (`libyang-2.2.0/src/store/entry.rs:1101`, `1149`,
  `1193`, `1217`). So `ext:secret` reaches zebra-rs with no libyang change,
  including leaves inside `grouping`s: `ext:help` already works that way in
  `ipsec.yang`.
- Secret leaves in the trees insomnia owns:
  - `vpn ipsec authentication psk <n> secret` (`ipsec.yang:173-176`);
  - `vrrp group <g> authentication password` (`vrrp.yang:255-258`).
- Secret leaves owned by zebra-rs, out of scope here:
  - BGP passwords (`zebra-bgp-password.yang:57`, `zebra-bgp-auth.yang:238`,
    `zebra-bgp-vrf.yang:518`);
  - OSPF `md5` (`zebra-ospf-auth-md5.yang:80`) and `authentication-key`
    (`zebra-ospf-auth-simple.yang:91`);
  - IS-IS passwords (`config.yang:3828`, `3884`, `4241`).

**zebra-rs: who can read today.**
- **DoExec in exec mode** needs no admin. Only `mode != exec` and
  `configure` are gated (`serve.rs:156-182`), so a View session runs
  `show running-config`.
- **Show RPC (`vtyctl show`, MCP).** `ShowService` holds no session table
  (`serve.rs:430-466`).
- **TCP peers** get no `SessionContext` at all: the interceptor only reads
  `UdsConnectInfo`.
- **`config.v1 Subscribe`** runs behind `MachinePeerInterceptor`
  (`serve.rs:680-710`). That interceptor only applies the optional
  `ZEBRA_VTY_ALLOW_UIDS` list and lets TCP peers through untouched. The
  handler itself does no authorization (`subscribe.rs:67-118`).
- **The default socket.**
  - The default is the abstract socket `unix:zebra-rs/vty` (`main.rs:107-111`),
    which has no filesystem permissions.
  - A filesystem socket is chmod `0666` (`serve.rs:950`).
- **Result:** today every local uid in the netns, and every host that can
  reach a `tcp:` listener, can read every PSK and VRRP password.
- **Tab completion leaks the stored value.**
  - `config_match_value` pushes the stored leaf value as a completion
    candidate (`configs.rs:859-873`).
  - `set`/`delete` parsing merges those config candidates (`parse.rs:620-640`,
    `703-720`).
  - Completion requests are not admin-gated in any mode (`serve.rs:158-160`,
    `194-212`).
  - So `delete vpn ipsec authentication psk GW secret <TAB>`, sent as a
    `Complete` request with `mode=configure`, would return the secret to a
    View session. This comes from reading the code; it has not been tried, so
    it is *unverified* by experiment.
- **Commit errors echo the line.** Value-check errors print the whole line,
  value included (`'{line}': {e}`, `manager.rs:762`, `768`).
- **Saved file.**
  - The package ships `/etc/zebra-rs/zebra-rs.conf` with mode `644`
    (`zebra-rs/Cargo.toml:74`).
  - `save` keeps whatever mode the file already has (`manager.rs:1451-1458`).
  - So after `save` the secrets sit in a world-readable file.

**zebra-rs: session and client facts.**
- Roles are `View` and `Admin` (`session.rs:60-63`). Root and members of the
  config group are promoted without a password (`serve.rs` `enable`, D20/D27).
- `vtyhelper -u` decides "uncommitted?" by comparing
  `show running-config formal` with `show candidate-config formal` through
  un-gated exec calls (`vtyhelper/src/main.rs:329-380`; book ch-06-01 D29).
- MCP `get-config` returns `show running-config <fmt>` verbatim
  (`vtyctl/src/mcp/tools/config.rs:30-61`).
- The crypto pieces this plan needs are already dependencies: `sha2` 0.11,
  `hmac` 0.13 and `rand` 0.10 (`zebra-rs/Cargo.toml:184`, `197-198`).

**insomnia.**
- `swanctl.conf` and `keepalived.conf` end up mode `0600` (`ipsec.rs:118-129`,
  `keepalived.rs:283-284`). Both writers, though, create the temp file with
  the default mode and chmod it afterwards (`ipsec.rs:126-128`,
  `keepalived.rs:232-236`). Under umask 022 the PSKs sit in a `0644` file
  during that window. The insomnia unit sets no `UMask=`
  (`packaging/systemd/insomnia.service`).
- No placeholder check: the secret goes through verbatim (`ipsec.rs:568-584`;
  `vrrp.rs:541-557`, `896-899`).
- `show vrrp -j` passes keepalived's dump through verbatim
  (`vrrp.rs:1106-1124`). The keepalived 2.2.8 binary contains the string
  `auth_data`, so the dump probably carries the password whenever
  authentication is configured. This is *unverified*: the fixtures at
  `vrrp.rs:1898-1899` have `auth_type 0`.
- Warnings name the group or psk and never the value (`vrrp.rs:542-555`,
  `ipsec.rs:568-571`). Nothing enforces that.
- `--host tcp:` is documented (book ch-00-03:58-65), and `Cargo.toml:70-72`
  says insomnia "can run on a different host than zebra-rs". Neither repo
  enables tonic TLS.
- Book ch-02-03:56-58 tells readers that running-config shows secrets in the
  clear.

**VyOS.**
- **`python/vyos/utils/strip_config.py`** keeps a hand-maintained
  `__secret_paths` list:
  - three placeholders: `<PASSWORD REDACTED>`, `<KEY DATA REDACTED>` and
    `<DATA REDACTED>`;
  - fix-ups for VRF and remote-access local users.
- **Callers:** `show configuration --strip-private` (top level only,
  `src/utils/vyos-show-config:32-55`) and tech-support
  (`src/op_mode/tech_support.py:92-99`).
- **The pipe filter** `src/helpers/strip-private.py` (`| strip-private`) is a
  separate, regex-based one (`secret \S+`, `password \S+`, `key \S+`, …).
- **Redaction is opt-in:** admins see cleartext.
- **The path list has already drifted:** it lacks rolling's
  `vpn ipsec authentication ppk <n> secret` (`vpn_ipsec.xml.in:58-60`). Only
  the regex filter catches that leaf, and only by its keyword.

## 3. Design

**S1. Tag the schema; do not keep a path list.**
- A leaf or leaf-list carries `ext:secret "<what it is>"`.
- Rejected:
  - VyOS's path list, which drifts (the ppk case above).
  - A regex over the rendered text, which cannot handle JSON and fires on
    `description` text.

**S2. Stamp the tag at set time.**
- `CommandPath` gains `secret`, `config_set_dir` stamps `Config.secret`, and
  `carbon_copy` copies it. This is the `ext:non-empty` precedent.
- Rejected: walking the schema in parallel at render time. That would thread
  `Rc<Entry>` through eight renderer functions that never needed one.

**S3. Redaction is a render option.**
- Today's `format/json/yaml/list/formal` stay cleartext, because persistence
  and the commit engine depend on them.
- New `*_with(&Secrets)` variants serve every read surface.
- The guard against a future show path calling the cleartext form is a test,
  `read_surfaces_redact`. It drives every show handler and both Show RPC arms
  with a sentinel secret.

**S4. The placeholder is `<redacted:XXXXXXXX>`.**
- `XXXXXXXX` is the first 32 bits, in hex, of HMAC-SHA256 under a 32-byte key.
  The key is random, generated once per zebra-rs process, and never exported.
- The input is the leaf's path tokens (`Config::list_command()` without the
  value, `configs.rs:471-483`), NUL-joined, then NUL and the value.
- What the tag preserves:
  - The configure-mode `show` diff still shows that a secret changed.
  - `vtyhelper -u` (D29) still sees a secret-only edit as DIRTY.
  - Hashing the path means two leaves sharing a PSK do not show equal tags.
  - The secret key rules out an offline dictionary attack on an 8-character
    VRRP password.
- Tags change when zebra-rs restarts; that is documented.
- Rejected:
  - A constant `<redacted>`. A secret-only edit would compare CLEAN, so the
    exit prompt would be skipped.
  - An unkeyed hash, which can be brute-forced.

**S5. Who sees what.**

| Caller | Default | `secrets` keyword / flag |
|:--|:--|:--|
| View session (DoExec or Show RPC), TCP peer, no session | redacted | refused: `% secrets require admin; run 'enable'` |
| Admin session | redacted | cleartext |
| `config.v1 Subscribe`, `secrets` unset | cleartext if privileged peer, else redacted | — |
| `config.v1 Subscribe`, `secrets = false` | redacted | — |
| `config.v1 Subscribe`, `secrets = true` | — | cleartext if privileged peer, else `PERMISSION_DENIED` |
| `save`, startup load, commit diff, in-process subscriptions, Apply/Deploy input | cleartext, never redacted | — |

- A **privileged peer** is a UDS peer whose `SO_PEERCRED` uid is 0 or belongs
  to the config group (`SessionTable::is_config_group_member`,
  `session.rs:203`). In other words, a uid that could reach Admin without a
  password.
- A **TCP peer** is never privileged unless zebra-rs runs with
  `--vty-tcp-secrets` (proposed). That flag logs a startup warning. It covers
  the cross-host case in insomnia's `Cargo.toml`.
- The remote path we recommend instead is zebra-rs on `unix:/PATH` plus an
  SSH-forwarded Unix socket.
- The `unset` row keeps an old insomnia, which sends no field, working
  unchanged. That is why the field is proto3 `optional`.
- Redacting by default for Admin too is a **deliberate deviation from VyOS**.
  CLI output ends up in tickets, scrollback and, through MCP, in LLM
  contexts. Asking for cleartext costs one keyword.

**S6. The `secrets` grammar.**
- It is `show {running,candidate}-config secrets [formal|json|yaml]`: a
  presence container `secrets` holding the same three `type empty` leaves.
- A trailing `… formal secrets` would be nicer. But once an empty leaf has
  matched, the exec parser does not move on to a sibling: `LeafMatched` has
  no transitions (`parse.rs:724-747`). This is read from the code, not run,
  so it is *unverified*.

**S7. Placeholder guard.**
- Setting an `ext:secret` leaf to a value matching
  `^<redacted(:[0-9a-f]{8})?>$` is refused with
  `'<path>': value is a redacted placeholder; supply the secret`. This covers
  `set`, Apply, `load` and the MCP `apply-config`.
- In the startup config the line is dropped with a warning, the same way as
  `startup_tolerant_check` (`manager.rs:764-770`), so boot never fails.
- The cost: a real secret that looks exactly like a placeholder cannot be
  set. That is documented.

**S8. No secret in error text or completion.**
- Commit errors render the offending line with `Secrets::Redact`
  (`manager.rs:762`, `768`). That covers the layer-1 rows
  [commit-validation](commit-validation.md) adds, which print through the
  same `'<line>': <reason>` path (its §4.6 example). Its layer-2 messages
  come from insomnia and name leaves, never values (its §3.2).
- For a secret node, `config_match_value` offers the completion `<secret>`.
- It also matches any typed token exactly, so that
  `delete … secret <anything>` still resolves the node. That removes both the
  value leak and the prefix-match oracle (§2).

**S9. Secrets at rest.**
- When the running config holds an `ext:secret` leaf, `save` clears the
  target file's other-permission bits (`mode & !0o007`) and says so in the
  save reply.
- The package ships `zebra-rs.conf` as `640 root:zebra-rs`. How dpkg treats a
  changed conffile mode is *unverified*, so the `save` rule is the backstop.

**S10. insomnia defends itself and does not rely on zebra-rs.**
- A placeholder secret counts as absent: skip it with a warning. This catches
  a misconfigured, unprivileged insomnia before it renders a broken
  `secret = "<redacted:…>"`.
- Temp files are created with their final mode at `open`.
- Show output never contains a secret, because a `ShowOrder` carries no
  caller identity (`proto/show.proto:40-49`).
- Startup warns when `--host` is TCP.

**S11. Op-mode output never prints a configured secret or key material.**
- Provider show and EXEC answers are read surfaces too, and a `ShowOrder`
  carries no caller identity (S10). So insomnia treats every caller as
  unprivileged there.
- `show vpn ike secrets` ([ipsec-opmode](ipsec-opmode.md) decision 10)
  prints `********` in the Secret cell, and `-j` omits `secret`. Admins get
  the cleartext with `show running-config secrets`. A deviation from VyOS,
  which prints them, for the S5 reasons.
- ESP/AH keys from `ip xfrm state` (`show vpn ipsec state`, `debug`, the
  `generate ipsec debug-archive` tarball) are never shown. Use
  `ip xfrm state list nokeys` where iproute2 supports it (*unverified* on
  6.1). In any case the parser replaces the key of every `auth`,
  `auth-trunc`, `enc` and `aead` line with `<redacted>` before
  output, so an older iproute2 cannot leak them.
- One exception: `generate pki` prints the private key it has just made.
  The admin-gated EXEC path asked for it, and VyOS does the same.
- Deferred: carrying the caller's `privileged` bit on `ShowOrder` (the §4
  item 3 plumbing, extended to the provider bridge), so an Admin could see
  cleartext op-mode secrets.

**Module-doc notes to record:**
- `src/ipsec.rs` and `src/vrrp.rs` get "a `<redacted:…>` secret is treated as
  absent (skipped with a warning)".
- No renderer output changes for a privileged subscription, so no VyOS
  template deviation is added.
- `src/ipsec.rs` records the S11 op-mode deviation: masked
  `show vpn ike secrets`, no xfrm keys.

## 4. Changes

### zebra-rs

YANG:

```yang
// yang/extension.yang
extension secret {
  description
    "Marks a leaf or leaf-list whose value is secret. show running-config,
     show candidate-config and unprivileged zebra.config.v1 subscriptions
     print a <redacted:...> tag instead of the value; save, commit and
     privileged subscriptions keep the cleartext. Ignored on containers,
     lists and list keys. The argument names the secret in messages.";
  argument "secret";
}

// yang/ipsec.yang:173
leaf secret {
  ext:help "IKE pre-shared secret key";
  ext:secret "IKE pre-shared secret";
  type string;
}

// yang/vrrp.yang:255
leaf password {
  ext:help "VRRP password (1-8 characters)";
  ext:secret "VRRP authentication password";
  type string;
}

// yang/exec.yang: inside container running-config (and candidate-config)
container secrets {
  ext:help "Show secret values in cleartext (admin only)";
  presence "Show running config with secrets";
  leaf formal { ext:help "Set-style flat statement listing"; type empty; }
  leaf json   { ext:help "Pretty-printed JSON"; type empty; }
  leaf yaml   { ext:help "YAML"; type empty; }
}
```

Leaves that must carry `ext:secret` when their plan adds them:

| Plan | Leaves |
|:--|:--|
| [pki-x509](pki-x509.md) | `pki {ca,certificate,key-pair} <n> private key`, `vpn ipsec site-to-site peer <p> authentication x509 passphrase`, `vpn ipsec site-to-site peer <p> authentication rsa passphrase`. There is no `pki … private passphrase`: VyOS's `pki` has only `password-protected`, and passphrases live under `vpn ipsec` |
| [ipsec-remote-access](ipsec-remote-access.md) | `vpn ipsec remote-access connection <c> authentication local-users username <u> password`, `vpn ipsec remote-access connection <c> authentication pre-shared-secret`, `vpn ipsec remote-access radius server <addr> key`; the RA `x509 passphrase` comes tagged with pki-x509's shared `x509-ref` grouping |
| [ipsec-syntax-parity](ipsec-syntax-parity.md) | `vpn ipsec authentication ppk <n> secret` |
| [ipsec-dmvpn-l2tp](ipsec-dmvpn-l2tp.md) | `vpn ipsec profile <p> authentication pre-shared-secret` |
| [fw-dynamic-sources](fw-dynamic-sources.md) | `firewall global-options geoip maxmind-license-key` |
| zebra-rs (own decision) | the BGP, OSPF and IS-IS leaves listed in §2 |

Certificates, CRLs and public keys are not secret. VyOS also elides them,
because they are long; we do not.

Rust, in order:
1. **Proto and stamping.**
   - `proto/vty.proto` `CommandPath`: `bool secret = 8;` (proposed).
   - `parse.rs:768-777`: set `secret` from
     `mx.matched_entry.extension.contains_key("ext:secret")` on leaf and
     leaf-list entries only. Pass it through both constructors
     (`815-837`).
   - `configs.rs`: add `pub secret: bool` to `Config`; stamp it in
     `config_set_dir`; copy it in `carbon_copy`.
2. **Render options (`configs.rs`, proposed API).**

   ```rust
   pub struct Redactor { key: [u8; 32] }            // rand at startup
   pub enum Secrets<'a> { Clear, Redact(&'a Redactor) }
   impl Redactor { pub fn tag(&self, path: &[String], value: &str) -> String }
   impl Config {
       pub fn format_with(&self, out: &mut String, s: &Secrets);
       pub fn json_with(&self, out: &mut String, s: &Secrets);
       pub fn yaml_with(&self, out: &mut String, s: &Secrets);
       pub fn list_with(&self, out: &mut String, s: &Secrets);
       pub fn formal_with(&self, out: &mut String, s: &Secrets);
   }
   ```

   - The existing methods delegate with `Secrets::Clear`.
   - Every place that emits `self.value` or a `self.list` entry checks
     `self.secret` there: `write` (`261-279`), `marshal_key_value` (`331-349`)
     and `list` (`485-516`).
3. **Caller identity, carried to the manager.**
   - `api.rs` `ExecuteRequest` and `DisplayTxRequest` gain
     `privileged: bool` (proposed).
   - `serve.rs` sets it from `sessions.require_admin(&key).is_ok()`. TCP gives
     `false`. `ShowService` gains `sessions`.
   - `ConfigManager` holds the `Redactor` plus a per-request
     `caller: Cell<bool>`, set around `self.execute(...)` (`manager.rs:1624-1637`).
4. **Read surfaces.**
   - `commands.rs:162-231`: all show handlers and the diff `show` use
     `Secrets::Redact`.
   - The new handlers `/show/{running,candidate}-config/secrets[/formal|json|yaml]`
     check `caller`.
   - `manager.rs:1735-1795`: the same, for both `text` and `json`.
5. **Subscribe.**
   - `proto/config.proto` `SubscribeRequest`: `optional bool secrets = 3;`,
     and the same field 3 in `SubscribeMultiRequest`, with the same S5 rule
     (agreed in [multi-path-subscribe](multi-path-subscribe.md) D-11).
   - `ConfigSubscribeService` gains `sessions` for the group check.
   - The handler reads `UdsConnectInfo.peer_cred` (the same source as
     `serve.rs:692-708`) and applies the S5 table.
   - `ConfigSubscriber` gains `redact: bool`.
   - `subtree_json(path, &Secrets)`.
   - The PATH format redacts the value token that follows a stamped leaf.
     The redacted change vector is built once per commit and shared by all
     redacted subscribers.
6. **Guard and errors.**
   - The S7 check runs in the commit loop (`manager.rs:755-770`), keyed on
     the stamped `CommandPath.secret`, not on the path.
   - The S8 changes go to `manager.rs:762`, `768` and `configs.rs:859-873`.
7. **Saving, flags and clients.**
   - S9: `manager.rs:1451-1458`, `Cargo.toml:74`, plus a `postinst` chgrp.
   - `main.rs`: `--vty-tcp-secrets` (proposed).
   - `vtyctl watch` sends `secrets = false`.
   - MCP `get-config` stays unchanged and is now redacted. Do not add a
     cleartext option to MCP.

**Worked example.** Configuration:

```
set vpn ipsec authentication psk GW id 192.0.2.1
set vpn ipsec authentication psk GW id 192.0.2.9
set vpn ipsec authentication psk GW secret Zebra-Lab-PSK-1
set vrrp group LAN authentication type plaintext-password
set vrrp group LAN authentication password s3cret
```

`show running-config formal`, for any caller (the tags are illustrative):

```
set vpn ipsec authentication psk GW id 192.0.2.1
set vpn ipsec authentication psk GW id 192.0.2.9
set vpn ipsec authentication psk GW secret <redacted:9c1e04af>
set vrrp group LAN authentication password <redacted:3b7d52e0>
set vrrp group LAN authentication type plaintext-password
```

`show running-config json` gives
`"psk":[{"name":"GW","id":["192.0.2.1","192.0.2.9"],"secret":"<redacted:9c1e04af>"}]`.
`format_json_value` quotes the tag, so a numeric password such as `12345678`
(`vrrp.rs:1497`) also becomes a string.

`show running-config secrets formal` prints the cleartext to Admin. A View
session gets `% secrets require admin; run 'enable'`.

insomnia's `["vpn","ipsec"]` subscription (`secrets = true`, uid 0,
`unix:zebra-rs/vty`) is byte-for-byte today's document. Feeding the redacted
dump to `vtyctl apply` gives
`'vpn ipsec authentication psk GW secret': value is a redacted placeholder; supply the secret`,
and nothing is committed.

### insomnia

1. **Placeholder check.**
   - `src/json.rs` gets `pub fn redacted(v: &str) -> bool` (the S7 pattern).
   - `ipsec.rs` psk rendering (`563-586`): a placeholder secret skips that psk,
     with the warning
     `authentication psk GW: secret is redacted (zebra-rs sent a placeholder; run insomnia as root over unix:); skipped`.
   - `vrrp.rs` auth (`541-557`) skips the group in the same way.
2. **Temp files.**
   - The mechanism is [ipsec-render-fixes](ipsec-render-fixes.md) X13:
     `fsutil::write_private_atomic` removes any stale temp file, creates it
     `create_new` with mode `0600`, writes and renames. `swanctl.conf` and
     `keepalived.conf` switch to it there. If X13 has not landed, milestone 1
     lands it as that plan specifies; there is one helper, not two.
   - Every later secret-bearing file goes through the same helper:
     [charon-lifecycle](charon-lifecycle.md)'s drop-in (RADIUS keys) and
     [pki-x509](pki-x509.md)'s key files.
   - This plan adds only `UMask=0077` to `packaging/systemd/insomnia.service`.
3. **Show output.** `vrrp.rs:1106-1124`: remove `data.auth_data` from every
   dump record before the JSON output. `detail_text` already prints only
   `auth_type` (`vrrp.rs:1440`).
   - `show vpn ipsec state` (`ipsec.rs:1094-1115`) prints the xfrm keys
     today: apply the S11 key filter there. [ipsec-opmode](ipsec-opmode.md)'s
     new views (`ike secrets`, `debug`, the archive) use the same filter.
4. **Subscription.**
   - `subscribe.rs`: `subscribe_json(host, path, secrets: bool)`, and the
     same argument on `subscribe_json_multi`. `ipsec` and `vrrp` pass `true`;
     `firewall` passes `false` (and `true` once a secret leaf lands under
     it, e.g. `maxmind-license-key`).
   - On `PERMISSION_DENIED`, log one `error!` that names the fix, then keep
     retrying at `RECONNECT_DELAY`. Never exit (AGENTS.md).
   - `proto/config.proto` is re-copied from zebra-rs.
5. **Startup warning.** `main.rs`: when `--host` is `tcp:`, `tcp://`,
   `http://` or a bare host, warn
   `--host … is plain TCP: IPsec PSKs and VRRP passwords cross it in clear; use unix:`.

## 5. Tests

**zebra-rs unit tests:**

| Test | What it checks |
|:--|:--|
| `ext_secret_stamped_on_leaf` | the psk `secret` is stamped and `id` is not; the vrrp `password` is stamped |
| `carbon_copy_keeps_secret` | the flag survives `carbon_copy` |
| `read_surfaces_redact` | sentinel absent across CLI, formal, JSON and YAML; running and candidate; DoExec handlers, both DisplayTx arms and the diff `show` |
| `redaction_tag_tracks_value` | equal value gives an equal tag; a changed value gives a new tag; the same value at two paths gives different tags |
| `secrets_keyword_requires_admin` | View is refused; Admin gets cleartext |
| `save_and_commit_stay_clear` | `serialize_running` and `list()` are unchanged |
| `subscribe_secrets_policy` | the S5 table: uid 0, a config-group uid, another uid, TCP; JSON and PATH |
| `placeholder_rejected_on_set` | a placeholder value is refused at commit |
| `placeholder_dropped_at_startup` | at startup it is dropped with a warning |
| `commit_error_redacts_value` | commit errors carry the tag, not the value |
| `completion_hides_secret` | a configure-mode `Complete` returns `<secret>` |

The existing JSON contract tests (`manager.rs:7398-7450`, `7930`, `8137`)
must pass unchanged.

**insomnia golden-render and unit tests:**

| Test | Input | Expected |
|:--|:--|:--|
| `psk_placeholder_skipped` | `"secret":"<redacted:0123abcd>"` | `secrets {\n}\n` plus the warning |
| `vrrp_password_placeholder_skipped` | `"password":"<redacted:0123abcd>"` | the group is skipped, with a warning |
| `warnings_never_echo_secrets` | every skip path of both renderers, with sentinel secrets | no warning contains the sentinel |
| `show_vrrp_json_strips_auth_data` | a fixture containing `"auth_type":1,"auth_data":"s3cret"` | the output has no `auth_data` |
| `ipsec_xfrm_keys_redacted` | `ip xfrm state` text with `enc`/`auth-trunc` keys | no key hex in the output |
| `ike_secrets_masked` | a psk with a sentinel secret | `********`; `-j` has no `secret` |

For `show_vrrp_json_strips_auth_data`, replace the hand-written fixture with
a dump captured in a scratch namespace once `auth_data` is confirmed. The
create-at-`0600` tests belong to ipsec-render-fixes X13.
`ike_secrets_masked` lands with [ipsec-opmode](ipsec-opmode.md)'s view.

**BDD, `@ipsec_s2s`.** No topology change. Add one scenario after
"tunnel up":
- `show command "running-config formal" in namespace "z1" should not contain "Zebra-Lab-PSK-1"`
  and `… should contain "<redacted:"`.
- `show command "running-config secrets formal" in namespace "z1" should contain "Zebra-Lab-PSK-1"`.
  The harness runs `vtyctl` as root, and root is Admin.
- Through the generic step (`bdd/tests/cucumber.rs:1845-1923`),
  `command "setpriv --reuid=65534 --regid=65534 --clear-groups vtyctl show running-config secrets formal" in namespace "z1" should contain "require admin"`.
  Whether the harness permits this is *unverified*.
- The existing tunnel-up scenarios already prove that the privileged
  subscription still carries cleartext.
- Run against a zebra-rs staged with `ZEBRA_PREFIX`.

## 6. Docs

- **zebra-rs book:**
  - `ch-06-02-show-config-commands.md`: redaction, tags (unstable across
    restarts), the `secrets` keyword, the placeholder guard.
  - `ch-06-01-session-design.md`: a new decision row for secret visibility
    (S5) and for completion (S8).
  - `ch-06-00-vty-access.md`: no secrets over TCP; `--vty-tcp-secrets`.
- **insomnia book:**
  - `ch-02-03-authentication.md:56-58`: running-config now shows tags; admins
    use `secrets`.
  - `ch-05-02-unicast-and-authentication.md`: the same, for the VRRP
    password.
  - `ch-00-03-command-line-options.md` (`--host`, :58-65): `unix:` is
    required for IPsec PSKs, VRRP passwords and, later, PKI keys; recommend
    SSH-forwarded `unix:/PATH` for cross-host.
- **Module docs** for `ipsec.rs` and `vrrp.rs`: the placeholder rule (§3).
- A CHANGELOG entry in both repos. In zebra-rs it calls out the Admin-default
  change.

## 7. Milestones

| # | Repo | Scope | Effort | Done when |
|:--|:--|:--|:--|:--|
| 1 | insomnia | §4 insomnia items 1–3 and 5: placeholder skip, `UMask=0077` (with X13's helper, or X13 itself if it has not landed), `auth_data` strip, TCP warning, tests | S | the unit tests above are green. It ships first, so an insomnia that receives placeholders is never silent |
| 2 | zebra-rs | `ext:secret`, stamping, `Redactor`, redaction on every read surface, the two leaves tagged, guard, error and completion redaction | M | `read_surfaces_redact`, `placeholder_*`, `completion_hides_secret` green; the JSON contract tests unchanged |
| 3 | zebra-rs | `secrets` keyword, caller plumbing (`serve.rs`, `api.rs`), the vtyhelper D29 check re-verified | S | `secrets_keyword_requires_admin` green; the exit prompt fires on a secret-only edit |
| 4 | zebra-rs | `SubscribeRequest.secrets`, the peer check, redaction for unprivileged subscribers, `--vty-tcp-secrets`, `vtyctl watch` | S | `subscribe_secrets_policy` green; an old insomnia as root still gets cleartext |
| 5 | insomnia | proto sync, per-backend `secrets`, `PERMISSION_DENIED` logging, BDD scenarios, book | S | `make -C bdd ipsec_s2s` green against the staged zebra-rs |
| 6 | zebra-rs | S9 file mode and packaging; tag the zebra-rs-owned leaves (optional) | S | a `save` with a secret leaves no `o+r` bit |

## 8. Risks and open questions

- **Admin default.** Redacting for Admin by default is a workflow change.
  The alternative is VyOS parity: Admin sees cleartext and opts into
  redaction. Decide in the milestone 2 review. Everything else in the plan
  stands either way.
- **Grammar.** The parser behaviour behind S6 is *unverified* until it is
  implemented. The fallback is a top-level `show secrets running-config …`.
- **Tags.** Tags reveal whether a secret changed, and collide with
  probability 2^-32. Both are acceptable.
- **Completion.** S8 closes the value leak for secret leaves only. Whether to
  admin-gate completion in non-exec modes (`serve.rs:158-160`) altogether is
  a broader zebra-rs decision. It costs little, because a View session cannot
  run configure-mode commands anyway.
- **keepalived `auth_data`.** Whether it is in the JSON dump is
  *unverified*; check with a scratch-namespace capture in milestone 1.
- **Other show commands.** Other zebra-rs show output, such as
  `show bgp neighbor`, may print passwords. That is *unverified* and out of
  scope; it is zebra-rs's follow-up when it tags its own leaves.
- **Release order.** Milestone 4 must not ship before milestone 1 is released,
  or an older insomnia over TCP would render placeholders. As root over
  `unix:` (the default unit) nothing changes, thanks to the `unset` row.
- **Field numbers.** Agreed with [multi-path-subscribe](multi-path-subscribe.md)
  (its D-11): `secrets = 3` in both `SubscribeRequest` and
  `SubscribeMultiRequest`; `ConfigEvent.subtrees = 4` is that plan's. Land
  the two in one PR if they share a release window.
- **Interaction with other plans.**
  - [commit-validation](commit-validation.md)'s dry-run RPC sends candidate
    subtrees to insomnia. That RPC must be privileged, as Subscribe is, and
    its error text must name leaves, never values. Both are now in that plan
    (§3.4, §3.2).
  - [pki-x509](pki-x509.md) must tag every private-key and passphrase leaf.
    Under S5 those leaves then never cross TCP, which closes the gap's
    "require `unix:` for PKI" item without a PKI-specific rule.

- **Rejected: masking only the userinfo of `firewall group remote-group
  <n> url`** ([fw-dynamic-sources](fw-dynamic-sources.md)). S1 tags whole
  values; a partial mask is the regex approach S1 rejects. That plan
  redacts userinfo and query in its own logs and show, and may tag the
  whole `url` leaf if credentials in URLs turn out to be common.

## 9. Acceptance criteria

- [ ] `ext:secret` declared in `extension.yang`; psk `secret` and vrrp
      `password` tagged.
- [ ] No read surface (§2) prints a tagged value: `show {running,candidate}-config`
      in all four formats, the diff `show`, `vtyctl show`, MCP `get-config`.
- [ ] Admin `show … secrets …` prints cleartext; View and TCP callers are
      refused.
- [ ] `save` output, the commit diff and insomnia's subscription are
      byte-identical to today.
- [ ] An unprivileged or TCP subscriber gets tags; `secrets = true` from
      such a peer gets `PERMISSION_DENIED`.
- [ ] Applying a redacted dump fails, names the leaf, and commits nothing.
- [ ] Neither commit errors nor configure-mode completion reveal a tagged
      value.
- [ ] A secret-only candidate edit still makes the shell's exit prompt fire
      (D29).
- [ ] insomnia skips placeholder secrets with a warning; secret files are
      never created world-readable; `show vrrp -j` carries no `auth_data`.
- [ ] No op-mode answer prints a configured secret or an xfrm key (S11).
- [ ] `ipsec_s2s` BDD is green with the redaction scenarios; the book
      chapters listed in §6 are updated.
