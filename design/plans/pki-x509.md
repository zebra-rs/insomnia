# PKI and X.509 authentication — implementation plan

Status: plan, 2026-10-21. Covers: §7.3 "PKI"; §7.2 rows `authentication mode x509` (+ `x509 certificate|passphrase|ca-certificate`), `authentication mode rsa` (+ `pki key-pair`), `use-x509-id`; §7.4 `show pki`, `generate pki`, `import pki` ([vyos-gap](../vyos-gap.md) §4.1, §4.3, §4.6, §7.2–§7.4).
Priority: P1 (PKI + x509), P2 (rsa, show/generate/import), P3 (use-x509-id) · Effort: L · Owner: both
Depends on:
- [multi-path-subscribe](multi-path-subscribe.md) (assumes D3; `subscribe_json_multi` + `parse_subtree`, PrimaryOnly);
- [secret-redaction](secret-redaction.md) (P1 together with this plan; `ext:secret`, S5 and S10);
- [commit-validation](commit-validation.md) (assumes D1; C1 `Findings`; C5/C6 `Validate` for refusing in-use deletes);
- [exec-verbs](exec-verbs.md) (assumes D2; E1 `vici::stats` for the load compare; EXEC orders for `generate pki`);
- [ipsec-render-fixes](ipsec-render-fixes.md) (the X13 helper `fsutil::write_private_atomic` for key files).

Unblocks:
- [ipsec-remote-access](ipsec-remote-access.md) (x509 server mode, eap-tls, the `x509-ref` grouping, RA credentials in the `CredSet`; and its deferred `generate ipsec profile` (D8), which needs this plan's X.509 parsing);
- [ipsec-dmvpn-l2tp](ipsec-dmvpn-l2tp.md) (L2TP x509, only if its D-F ever accepts L2TP; DMVPN profiles stay PSK-only).

## 1. Goal

- `set pki ca|certificate|key-pair …` exists under `--feature insomnia`, in VyOS spelling and value shape: base64 DER bodies without armour lines. Private keys and passphrases carry `ext:secret` and are masked in `show running-config` and JSON ([secret-redaction](secret-redaction.md)).
- A commit is refused for:
  - malformed base64 or an unsafe object name (zebra-rs, layer 1);
  - a `vpn ipsec` reference to a missing or incomplete PKI object, or deleting a PKI object that `vpn ipsec` still references (insomnia `Validate`, layer 2, [commit-validation](commit-validation.md)).
  - With insomnia disconnected, D1 commits these with a "not validated" warning; at apply, the peer is skipped.
- A peer with `authentication mode x509` renders VyOS-equivalent swanctl state:
  - credential files under `--swanctl-dir` with exact modes, written idempotently and cleaned up without touching files insomnia did not write;
  - a BDD tunnel comes up with a lab CA;
  - a certificate from a CA not listed for that peer is rejected.
- `mode rsa` (raw keys from `pki key-pair`) and `use-x509-id` work.
- `show pki [ca|certificate|crl|key-pair] [NAME [pem|text|fingerprint sha256|sha384|sha512]]` shows subject, issuer and validity.
- `import pki … file PATH` (zebra-rs) and `generate pki …` (insomnia, non-interactive) print `set pki …` lines, or insert them into the candidate when run from configure mode. Nothing is committed for the user.

## 2. Current state

**zebra-rs.**
- There is no `pki` node in `config.yang` or `exec.yang`.
- `ipsec.yang`:
  - the `authentication mode` enum has only `pre-shared-secret` (`:462-467`);
  - the deferral is recorded at `:455-460` and in the module description (`:26-32`).
- Hooks:
  - the per-line value-check hook is `check.rs:64-85`;
  - commit validation runs in `commit()` (`manager.rs:849-878`);
  - show routing is `SHOW_PROTOS` (`manager.rs:2078-2092`).
- **No config write path for a daemon:**
  - `zebra.config.v1` has only `Subscribe` (`proto/config.proto:79-81`, identical in both repos).
  - The vty `Apply` service (`proto/vty.proto:244-263`) requires an admin session (`serve.rs:47-66`, `:550`). The session key comes from SO_PEERCRED uid/pid, so there is none over `tcp:`; root is a "permanent admin" (`session.rs:399-401`).
  - Its `Message::Deploy` applies set lines to the **shared** candidate and commits it (`manager.rs:1652-1712`). That would also commit an operator's half-finished edits.

**insomnia.**
- `render_peer` skips every mode but PSK (`src/ipsec.rs:593-603`).
- `PeerAuth` has `local_id`, `mode` and `remote_id` (`:276-282`).
- There is one subscription path (`:51`; `subscribe.rs:11-27`).
- `swanctl_apply` writes only `swanctl.conf` (`:122-149`).
- `process()` drops the model after rendering (`:90-116`).
- The provider registers `firewall`/`ipsec`/`vrrp` (`provider.rs:17-27`) and routes by prefix (`:91-99`).

**VyOS model and checks.**
- Objects (`pki.xml.in`):

  | Object | Leaves |
  |:--|:--|
  | `pki ca` | `certificate`, `description`, `private key` + `password-protected`, `crl` (multi), `system-install`, `revoke` |
  | `pki certificate` | `certificate`, `acme …`, `description`, `private`, `revoke` |
  | `pki key-pair` | `public key`, `private key` + `password-protected` |

  It also has `dh`, `openssh`, `openvpn` and `x509 default`. Values are validated as base64 (`include/pki/cli-*-base64.xml.i`). Names are alphanumeric plus `-_.`.
- `pki.py verify()` (`:592-738`):
  - parses every object, and a CA must be a CA certificate (`:555-560`);
  - refuses to delete an object something still references, via `sync_search` (`:61-121`; the `vpn ipsec` keys `certificate`, `ca_certificate`, `local_key` and `remote_key` at `:92-94`; the check at `:705-736`).
- `vpn_ipsec.py`:
  - `verify_pki_x509` / `verify_pki_rsa` (`:230-260`) and the peer checks (`:636-663`);
  - the `use-x509-id` exclusivity check (`:638-639`) tests the key `id`, which never exists (the leaf is `local_id`), so it is dead;
  - `peer.j2` never reads `use_x509_id`; only `remote_access.j2:36` does.

**VyOS files.**
- `cleanup_pki_files()` wipes all five credential directories on every commit (`:772-779`, called at `:825`).
- It writes credentials for every peer not skipped for DHCP, **including disabled peers** (`:879-886`):
  - `x509ca/<ca>.pem`, `x509crl/<ca>_<i>.pem`, `x509/<cert>.pem`, `private/x509_<cert>.pem` (`:781-804`);
  - rsa: `private/rsa_<k>.pem`; `pubkey/<local>.pem`, derived from the private key; `pubkey/<remote>.pem` (`:806-822`).
- Directories are 0755, `private/` 0700 (`:851-857`).
- The key armour is chosen by whether the *consumer* has a passphrase (`:799-804`, `wrap_private_key` `python/vyos/pki.py:256-267`), not by the object's `password-protected`.

**VyOS render.**
- `send_cert = always` (`peer.j2:29-31`).
- `local { auth = pubkey; certs = <cert>.pem | pubkeys = <k>.pem }` (`:60-70`).
- `remote { id; auth = pubkey }` with **no `cacerts`** (`:71-77`). Every loaded CA is therefore trusted for every peer.
- Secrets `private_<peer> { file = <cert>.pem; secret }` and `rsa_<peer>_local { file = <k>.pem; secret }` (`swanctl.conf.j2:62-81`).

**VyOS op mode.**
- `show pki ca|certificate|crl [NAME [pem [full-chain]|text|fingerprint …|private pem]]` (`op-mode-definitions/pki.xml.in:489-630`).
- Certificate table columns: Name, Type (Server / Client / Unknown by EKU), Subject CN, Issuer CN, Issued, Expiry, Revoked, Private Key, CA Present (`src/op_mode/pki.py:1350-1460`). Fingerprints are sha256/384/512 (`:63`).
- `generate pki ca|certificate [sign <ca>|self-signed] [file|install <name>]|crl|key-pair|…` (`pki.xml.in:3-350`) is **interactive** (`generate_certificate_request`, `pki.py:497-563`).
- `import pki … file|key-file` (`:352-488`).
- `install` runs `my_set` into the session candidate without committing; outside configure mode it prints `set` lines (`python/vyos/utils/misc.py:33-73`).

**strongSwan 5.9.13, `swanctl/commands/load_creds.c` (source read).**
- An encrypted file in `private/` is decrypted only with a `secrets` section whose name starts with `private` and whose `file` equals the file name (case-insensitive). The fallback is a prompt, which `--noprompt` and `-q` scripts never answer.
- So VyOS's `private_<peer> { file = <cert>.pem }` never matches the `private/x509_<cert>.pem` it writes.
- `rsa_<peer>_local`, with its `rsa` prefix, never matches any file in `private/`.
- Passphrase-protected keys therefore look unusable on VyOS. This is from source reading, not a test. insomnia must not copy it.

## 3. Design

**P1. Schema: `pki.yang`, a grouping library in the `firewall.yang` style.**
- Instantiated as `container pki { if-feature feat:insomnia; uses "pki:pki"; }` in `config.yang`, next to `vpn` (`:5694-5701`).
- Scope:

  | Object | Leaves |
  |:--|:--|
  | `ca <name>` | `certificate`, `description`, `private { key, password-protected }`, `crl` (leaf-list), `revoke` |
  | `certificate <name>` | `certificate`, `description`, `private { key, password-protected }`, `revoke` |
  | `key-pair <name>` | `public { key }`, `private { key, password-protected }` |

- **`grouping x509-ref`** in `ipsec.yang` holds the peer `container x509 { certificate; passphrase; ca-certificate* }`. Site-to-site peer `authentication` uses it, and so does `remote-access connection <c> authentication` ([ipsec-remote-access](ipsec-remote-access.md) D1), so both trees carry the same leaves, help text and secret tag.
- Out of scope: `acme`, `system-install`, `dh`, `openssh`, `openvpn` and `x509 default` (§7.3 out-of-scope list; `x509 default` returns with `generate` defaults if wanted).
- Values are plain `type string`, with no pattern (`ipsec.yang:36-41` convention).
- **Secret tags** ([secret-redaction](secret-redaction.md)):
  - `pki {ca,certificate,key-pair} <n> private key` carries `ext:secret "PKI private key"`;
  - `x509-ref`'s `x509 passphrase` carries `ext:secret "X.509 private key passphrase"`. That tags both `vpn ipsec site-to-site peer <p> authentication x509 passphrase` and `… remote-access connection <c> authentication x509 passphrase`;
  - `… authentication rsa passphrase` carries `ext:secret "RSA private key passphrase"`.
  - These match secret-redaction's table of leaves to tag. There is no `pki … private passphrase`: VyOS's `pki` has only `password-protected`, and passphrases live under `vpn ipsec`.
- **Redacted placeholders.** insomnia's subscription is privileged and receives cleartext (secret-redaction S5 table). A `<redacted:…>` placeholder counts as absent (secret-redaction S10): the peer is skipped with a Warning that names the cause (an unprivileged or `tcp:` subscription).
- **No YANG `mandatory`.**
  - commit-validation §3.3 has new nodes use plain `mandatory`. Here, though, `x509 certificate` and `rsa local-key` sit in non-presence containers under every peer. A mandatory leaf there would bind every peer, PSK ones included (RFC 7950 §7.6.5: the closest ancestor that is not a non-presence container is the `peer` entry).
  - The pki lists have no leaf VyOS requires unconditionally.
  - So these requirements are layer-2 rules.
- `generate pki` and `import pki` stay outside the config tree.

**P2. Validation, per [commit-validation](commit-validation.md) (three layers, findings with severity and effect).**

| Layer | Where | Rules |
|:--|:--|:--|
| 1 | zebra-rs `check.rs` `value_check`: one-leaf value shape; new leaves, so no startup tolerance is needed | Object names match `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`. Names become file names: no `/`, no leading dot. Every certificate/key/CRL value is RFC 4648 base64 with no whitespace and decodes non-empty. |
| 2 | insomnia `Validate`: the same `render()` on the candidate. The `ipsec` unit registers the backend's full path list, including `[pki]`, so a pki-only commit is validated too | The rows of the findings table below. |
| 3 | insomnia `render()` at apply | The same findings, logged with their effect. This is the only enforcement until layer 2 ships. |

Findings. All are new features, so upgrade safety does not apply and every Error is `Skipped`:

| Finding | VyOS | Sev | Effect |
|:--|:--|:--|:--|
| x509 peer without `x509 certificate` or without any `ca-certificate` | `vpn_ipsec.py:643-647` | E | peer skipped |
| referenced certificate missing, or lacking `certificate` / `private key`; referenced CA missing or lacking `certificate` | `:230-246` | E | peer skipped. **This is also the in-use rule:** deleting a referenced object makes the candidate render fail, and layer 2 refuses the commit (VyOS `pki.py:705-736`) |
| rsa peer: `local-key` lacks `private key` or `public key` (deviation: VyOS derives the public key); `remote-key` lacks `public key` | `:248-260` | E | peer skipped |
| `use-x509-id` together with `local-id` | `:638-639` (dead in VyOS) | E | Adjusted("local-id ignored") |
| `use-x509-id` with mode psk | — | W | Kept (no effect) |
| certificate or CRL does not parse; CA without `basicConstraints CA:TRUE`; certificate key ≠ private key (unencrypted keys only); key DER not PKCS#8 / EncryptedPrivateKeyInfo | `pki.py:592-700` | E | peer skipped |
| `password-protected` key and no passphrase | — | E | peer skipped (`--noprompt` cannot load it) |
| passphrase for an unprotected key | — | W | Dropped("passphrase ignored") |
| certificate expired or not yet valid | — (VyOS does not check) | W | Kept |
| x509 with `remote-id` unset or `%any` | — | W | Kept |
| redacted placeholder received | — | W | peer skipped |

- Messages never contain key material or passphrases (commit-validation §3.2).
- Rejected: X.509 parsing or cross-tree checks inside zebra-rs. commit-validation rejects re-implementing renderer rules in `check.rs`, and a parser would come with it.

**P3. Subscription.**
- The IPsec backend's single stream (multi-path D-10):
  ```rust
  subscribe_json_multi(host, &[&["vpn","ipsec"], &["pki"], &["vti"]], Fallback::PrimaryOnly)
  ```
  This is the [multi-path-subscribe](multi-path-subscribe.md) table row "pki-x509: `vpn ipsec`, `pki`, PrimaryOnly". `&["vti"]` is appended by [ipsec-vti](ipsec-vti.md).
  - Each part is parsed with `json::parse_subtree`. A missing `pki` is `PkiConfig::default()`.
  - Whichever of this plan and ipsec-vti lands first converts the backend from `subscribe_json`.
- **PrimaryOnly fallback** (an old zebra-rs) delivers `pki` as `"{}"`. That zebra-rs also has no `x509`/`rsa` modes in its schema, so no peer can reference PKI, and nothing is lost or misreported.
- The model becomes `IpsecInput { ipsec: IpsecConfig, pki: PkiConfig }`. It is retained as `Arc<IpsecInput>`, per [exec-verbs](exec-verbs.md) D-10, for `show pki` and `generate … sign`.
- **Compare before apply. This plan owns the IPsec load compare** (multi-path-subscribe §8 requirement).
  - `swanctl -q` is skipped when all of these equal the last successful load:
    - the rendered `swanctl.conf`;
    - the `CredSet`;
    - charon's start time, from `vici::stats` (`uptime.since`, exec-verbs E1).
  - So a `pki` or `vti` commit that changes nothing rendered does no reload, and a charon restarted behind insomnia's back is still reloaded.
  - `Applied::Restarted` from [charon-lifecycle](charon-lifecycle.md) always forces the load.
  - Credential files are `write_if_changed` either way.
- Rejected interim: two independent streams. A commit that adds both a certificate and the peer using it would transiently skip the peer, and D3 rejects skewed streams. If multi-path slips, this plan waits.

**P4. Credential writer (`src/pki.rs`, proposed).**
- `CredSet = BTreeMap<RelPath, (Vec<u8>, Mode)>`, built by the pure renderer, so it can be golden-tested.
- Directories under `--swanctl-dir`:
  - `x509/`, `x509ca/`, `x509crl/` and `pubkey/` at 0755;
  - `private/` at 0700. An existing `private/` with any other mode is chmod'ed, with a warning.
- Files:
  - certificates, CRLs and public keys at 0644;
  - private keys at 0600, written with `fsutil::write_private_atomic` (X13), so they are never readable under the umask.
- Names follow VyOS: `x509ca/<ca>.pem`, `x509crl/<ca>_<i>.pem` (1-based, in `crl` order), `x509/<cert>.pem`, `private/x509_<cert>.pem`, `private/rsa_<k>.pem`, `pubkey/<k>.pem`.
- **Armour:** `-----BEGIN <L>-----`, the body re-wrapped at 64 columns (RFC 7468), then `-----END <L>-----`.
  - Labels: `CERTIFICATE`, `X509 CRL`, `PUBLIC KEY`, `PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`.
  - The private-key label follows the object's own `password-protected`. Deviation: VyOS uses the consumer's passphrase.
  - The re-wrap is a harmless deviation; VyOS writes one line.
- **Only credentials of rendered peers and remote-access connections are written** (enabled, not skipped). Deviation: VyOS also writes disabled peers' CAs, which then become trusted globally.
  - A rendered RA connection ([ipsec-remote-access](ipsec-remote-access.md)) contributes its server-mode certificate and key, and the CAs named by its `ca-certificate` list, through the same `x509-ref` lookup as a peer.
- **Manifest-based cleanup** (deviation from VyOS's wipe-all) in `<swanctl-dir>/.insomnia-creds`, mode 0600, a JSON list of relative paths:
  1. Write `manifest ∪ desired`, so a crash never orphans an unlisted file.
  2. Create the directories.
  3. `write_if_changed` each desired file.
  4. Remove `manifest \ desired`, ignoring `NotFound`.
  5. Write `manifest = desired`.
  6. Write `swanctl.conf`, then run one `swanctl -q`.
  - A resync with identical config makes zero writes and zero removals.
  - Files the operator placed by hand are never deleted. `swanctl -q` still loads them; that is documented.
- Whether `swanctl -q` (`--load-all`) drops credentials whose files were deleted is *unverified*. The BDD checks it via `swanctl --list-certs`. If it does not, run `swanctl --load-creds --clear` before `-q`; that flag is also *unverified* for 5.9.13.

**P5. x509 render, following `peer.j2`, with three fixes.**
- `send_cert = always` after `remote_addrs`.
- `local { [id]; auth = pubkey; certs = <cert>.pem }`.
- `remote { id; auth = pubkey; cacerts = <ca>.pem[,<ca2>.pem] }`.
- `secrets { private_<conn> { file = x509_<cert>.pem; secret = "<passphrase>" } }`, only when a passphrase is set.
- Fixes, recorded in the module doc:
  1. **`cacerts` restricts each peer to its own `ca-certificate` list.** VyOS trusts every loaded CA for every peer: with the default `remote-id %any`, a certificate from peer B's CA authenticates as peer A. strongSwan's `cacerts` constraint is believed to match any CA in the verified chain, root or intermediate (*unverified*; the BDD covers the root case).
  2. **The secret's `file` names the key file actually written** (`x509_<cert>.pem`).
  3. **A `password-protected` key without a passphrase skips the peer** with a warning, because `--noprompt` cannot load it. A passphrase given for an unprotected key is ignored, with a warning.
- **Remote access gets the same three rules per `ra-<n>` connection** ([ipsec-remote-access](ipsec-remote-access.md) D1 and §8): `cacerts` from its own `ca-certificate` list, a protected key without a passphrase skipped, and its own secret `private_ra-<n> { file = x509_<cert>.pem; secret = "…" }` when its `x509 passphrase` is set. VyOS renders no `private_*` secret for RA at all (`swanctl.conf.j2:124-145`), so an encrypted RA key cannot load there.
- **New warning, not in VyOS:** `peer P: authentication x509 with remote-id %any accepts any certificate issued by LAB-CA; set remote-id to the peer's certificate identity`. It fires when `remote-id` is unset or `%any`.
  - With `cacerts` rendered, no x509 peer is ever without a CA constraint. A peer with no `ca-certificate` is skipped (P2 findings, layers 2 and 3).
  - So the warning covers the remaining case: an identity that is not pinned.

**P6. rsa render.**
- `local { [id]; auth = pubkey; pubkeys = <local>.pem }` and `remote { id; auth = pubkey; pubkeys = <remote>.pem }`.
- Files `private/rsa_<local>.pem`, `pubkey/<local>.pem` (from the key-pair's `public key`) and `pubkey/<remote>.pem`.
- The secret is `private_rsa_<conn> { file = rsa_<local>.pem; … }`, with the `private` prefix. Fix: VyOS's `rsa_…` never matches.
- Requiring the local public key avoids a crypto dependency for derivation. `generate pki key-pair install` emits both halves.

**P7. `use-x509-id`.**
- Implements VyOS's evident intent: no `local.id` line, so charon uses the certificate's subject DN. That is the strongSwan default when `certs` is set (*per swanctl.conf docs, not re-read*).
- `use-x509-id` together with `local-id` → an Error finding: layer 2 refuses the commit, and layer 3 drops `local-id` (Adjusted).
- With mode psk it is meaningless → warning.
- Deviation: VyOS site-to-site ignores the leaf entirely.
- `remote-access connection <c> authentication use-x509-id` is the same leaf with the same rules; `remote_access.j2:36` is the one place VyOS reads it.

**P8. `show pki` in insomnia.**
- The model and the parsing dependencies are already there. zebra-rs adds grammar and routing only.
- The VyOS tables and columns, as above, plus `pem` (re-armoured), `text` (insomnia's own field dump: subject, issuer, serial, validity, SANs, key usage, EKU, basic constraints, fingerprint; deviation: not `openssl x509 -text`), `fingerprint sha256|sha384|sha512`, and JSON via `-j`.
- **No `private pem` view.** Deviation: private keys never leave insomnia through show, regardless of redaction.
- `key-pair` view: Name, Public Key (type/bits), Private Key (Yes/No).

**P9. Import and generate. Neither needs a config write RPC.**
- **`import pki` belongs to zebra-rs** (in-process, S):
  - `import pki ca|certificate NAME file PATH [key-file PATH]`, `import pki crl CA file PATH`, `import pki key-pair NAME public-file|private-file PATH`;
  - zebra-rs reads the file **on its own host**, which is where `vtyctl` runs; insomnia may be remote;
  - it strips the armour, checks the label and the base64, and sets `password-protected` for `ENCRYPTED PRIVATE KEY`;
  - in configure mode it applies the lines to the candidate through the same `execute` path as typed commands, without committing (VyOS `install_into_config` semantics); otherwise it prints them;
  - admin only.
- **`generate pki` belongs to insomnia**, as an EXEC order ([exec-verbs](exec-verbs.md)), using `rcgen`:
  - Plumbing, all from exec-verbs:
    - the `EXEC_ROUTES` row `generate pki` → key `pki`, already listed there;
    - insomnia adds `"pki"` to `EXEC_TREES` (`Register.exec`) and a `(Exec, "/generate/pki", Backend::Ipsec)` row to `ROUTES`;
    - the handler answers `Answer { text, error }` exactly once;
    - the `generate` root is grafted into configure mode by exec-verbs D-6.
  - Key generation runs in `spawn_blocking` under a timeout (exec-verbs §8 "long verbs"), holding an `Arc` of the retained model.
  - Non-interactive: VyOS's prompts become optional keywords.
  - `sign CA` uses the CA private key from the retained model; a `password-protected` CA key → error.
  - The answer text carries the human-readable PEM plus the `set pki …` lines. The exec-verbs open question (§8, "generate output as a file") is answered: text only. VyOS's `file` option is not offered.
  - **Configure-mode `install`** is exec-verbs D-11: the eof chunk carries `ShowChunk.install` (repeated string) through `ExecResult`, and in configure mode zebra-rs applies those lines to the session's candidate, uncommitted and all-or-nothing, exactly like `import`. In exec mode, or from an old vtyhelper, the lines are printed only (VyOS's behaviour outside a config session).
  - insomnia refuses `generate` when `--host` is `tcp:`, because the private key would cross the wire in clear (§4.6).
- Rejected:
  - insomnia calling vty `Apply`: it needs an admin session that a daemon over `tcp:` cannot have, and it commits the shared candidate (§2);
  - a new `zebra.config.v1` write RPC: an enforcement daemon writing config inverts ownership and needs its own RBAC, for two op commands;
  - generate in zebra-rs: it pulls `rcgen` and `ring` into the routing daemon.

**P10. Transport security.**
- The startup warning for a `tcp:` `--host` belongs to [secret-redaction](secret-redaction.md) S10.
- So does the rule that a TCP peer is unprivileged, and so receives placeholders, unless zebra-rs runs with `--vty-tcp-secrets` (S5).
- This plan adds only:
  - the `generate` refusal over `tcp:`;
  - the "redacted placeholder received" finding in P2;
  - the book statement that `unix:` is required with PKI (§4.6).

**Crates (insomnia):** `x509-parser` (certificates and CRLs), `base64`, `sha2` (fingerprints), `rcgen` (generate only). All are MIT/Apache-2.0/ISC, compatible with AGPL-3.0-or-later. `rcgen`'s `ring` / `aws-lc-rs` backend choice must build on amd64 and arm64 (`packaging/`).

## 4. Changes

### zebra-rs

`yang/pki.yang` (new; `config.yang` imports it as `pki`):

```yang
grouping private-key {
  container private { ext:help "Private key";
    leaf key { ext:help "Private key in PEM format (base64 body)"; ext:secret "PKI private key"; type string; }
    leaf password-protected { ext:help "Private key portion is password protected"; type empty; } } }
grouping pki {
  list ca { key "name"; ext:help "Certificate Authority";
    leaf name { type string; }
    leaf certificate { ext:help "Certificate in PEM format (base64 body)"; type string; }
    leaf description { type string { pattern '.*'; } }
    uses private-key;
    leaf-list crl { ext:help "Certificate revocation list in PEM format (base64 body)"; type string; }
    leaf revoke { ext:help "Include certificate in parent CRL"; type empty; } }
  list certificate { key "name"; /* certificate, description, private-key, revoke as above */ }
  list key-pair { key "name";
    container public { leaf key { ext:help "Public key in PEM format (base64 body)"; type string; } }
    uses private-key; } }
```

`yang/ipsec.yang`, peer `authentication` (`:451-472`); VyOS `include/ipsec/authentication-{x509,rsa}.xml.i`:

```yang
grouping x509-ref {   // also used by remote-access connection authentication
  container x509 { ext:help "X.509 certificate";
    leaf certificate { ext:help "Certificate in PKI configuration"; type string; }
    leaf passphrase  { ext:help "Private key passphrase"; ext:secret "X.509 private key passphrase"; type string; }
    leaf-list ca-certificate { ext:help "Certificate Authority chain in PKI configuration"; type string; } } }

// peer authentication:
leaf mode { type enumeration { enum pre-shared-secret; enum rsa; enum x509; } }
uses x509-ref;
container rsa { ext:help "RSA keys";
  leaf local-key  { type string; }
  leaf passphrase { ext:secret "RSA private key passphrase"; type string; }
  leaf remote-key { type string; } }
leaf use-x509-id { ext:help "Use certificate common name as ID"; type empty; }
```

Checks:
- `check.rs` `value_check` entries for `/pki/{ca,certificate}/certificate`, `/pki/*/private/key`, `/pki/ca/crl` and `/pki/key-pair/public/key` (base64), plus the name rule. These are new leaves, so plain `value_check`, not `startup_tolerant_check`.
  - Whether list keys reach `value_check` is *unverified*. If they do not, the name rule becomes a layer-2 Error in insomnia: the renderer refuses an unsafe name, and the effect is Skipped.
- No cross-tree rule is written in zebra-rs (P2).
- [commit-validation](commit-validation.md)'s `EXTERNAL_TREES` gains `[pki]`, so a pki commit with insomnia disconnected prints "not validated".
- The `ipsec` validation unit's paths become `[vpn ipsec]`, `[pki]` and `[vti]`.

`exec.yang`, after `container vpn` (`:409-431`):

```yang
container pki { if-feature feat:insomnia; ext:help "Show PKI information"; presence "All PKI objects";
  list ca { key "name"; ext:presence "All CA certificates"; leaf name { type string; }
    container pem { presence "PEM"; } container text { presence "Text"; } }
  list certificate { key "name"; ext:presence "All certificates"; leaf name { type string; }
    container pem { presence "PEM"; } container text { presence "Text"; }
    leaf fingerprint { type enumeration { enum sha256; enum sha384; enum sha512; } } }
  list crl { key "name"; ext:presence "All CRLs"; leaf name { type string; } container pem { presence "PEM"; } }
  list key-pair { key "name"; ext:presence "All key pairs"; leaf name { type string; } container pem { presence "PEM"; } } }
```

- `manager.rs`: `fn is_pki` (the first path element after `show` is `pki`) and `(is_pki, "pki", "PKI")` in `SHOW_PROTOS`. Note `is_vpn` matches any element named `vpn` (`:2026-2028`); `is_pki` must be anchored.
- The `import pki` grammar and handler are new (P9). They are an `EXEC_LOCAL` row in exec-verbs D-5 terms: answered by zebra-rs, never sent to a provider. [exec-verbs](exec-verbs.md)'s `op_verb` admits `import` (its D-4, D-5).
- The `generate pki` grammar goes under exec-verbs' `container generate`. Its routing row already exists there.

### insomnia

- `src/pki.rs` (proposed):
  - `PkiConfig` (`Ca`, `Certificate`, `KeyPair`, `PrivateKey { key: Option<Flex>, password_protected: bool }`);
  - `armour(label, b64) -> String`;
  - `CredSet`;
  - `write_creds(dir, &CredSet) -> anyhow::Result<()>` (the manifest algorithm);
  - X.509 helpers on `x509-parser`;
  - `show_pki(&PkiConfig, &ShowRequest) -> Answer` (exec-verbs `api::Answer`).
- `src/ipsec.rs`:
  - `PeerAuth` gains `x509 { certificate, passphrase, ca_certificate }`, `rsa { local_key, passphrase, remote_key }` and `use_x509_id`;
  - `render(&IpsecInput) -> (String, CredSet, Findings)`, with [commit-validation](commit-validation.md) C1's `Findings`;
  - `validate(parts)` covers the new findings for free;
  - the auth-mode switch at `:593-603` becomes a match;
  - local/remote blocks for psk, pubkey+certs and pubkey+pubkeys;
  - the secrets section gains the `private_*` entries;
  - `run()` uses `subscribe_json_multi` (P3), keeps `Arc<IpsecInput>`, and does the load compare.
- `src/provider.rs`:
  - `Register.name` gains `pki`;
  - exec-verbs' `ROUTES` gains `(Show, "/show/pki", Backend::Ipsec)` and `(Exec, "/generate/pki", Backend::Ipsec)`;
  - `EXEC_TREES` gains `pki`.
- `#[cfg(test)] render_with_pki_str(ipsec_json, pki_json)`.

**Worked example.** Config (bodies abbreviated):

```
set pki ca LAB-CA certificate MIIBszCCAVmgAwIBAgIU…
set pki certificate Z1 certificate MIIB0TCCAXegAwIBAgIU…
set pki certificate Z1 private key MIGHAgEAMBMGByqGSM49…
set vpn ipsec site-to-site peer 192.0.2.9 authentication mode x509
set vpn ipsec site-to-site peer 192.0.2.9 authentication local-id z1.lab.example
set vpn ipsec site-to-site peer 192.0.2.9 authentication remote-id z2.lab.example
set vpn ipsec site-to-site peer 192.0.2.9 authentication x509 certificate Z1
set vpn ipsec site-to-site peer 192.0.2.9 authentication x509 ca-certificate LAB-CA
```

Connection text, golden `x509_peer_golden`, with the IKE/ESP groups of `ipsec_s2s` and `connection-type initiate`:

```
    192-0-2-9 {
        proposals = aes256gcm128-sha256-ecp256
        version = 2
        local_addrs = 192.0.2.1 # dhcp:no
        remote_addrs = 192.0.2.9
        send_cert = always
        dpd_timeout = 120
        dpd_delay = 30
        rekey_time = 28800s
        mobike = yes
        keyingtries = 0
        local {
            id = "z1.lab.example"
            auth = pubkey
            certs = Z1.pem
        }
        remote {
            id = "z2.lab.example"
            auth = pubkey
            cacerts = LAB-CA.pem
        }
        children { …unchanged… }
    }
```

`CredSet`, asserted exactly:

| Path | Mode | First line |
|:--|:--|:--|
| `x509ca/LAB-CA.pem` | 0644 | `-----BEGIN CERTIFICATE-----` |
| `x509/Z1.pem` | 0644 | `-----BEGIN CERTIFICATE-----` |
| `private/x509_Z1.pem` | 0600 | `-----BEGIN PRIVATE KEY-----` |

There are no `secrets` entries (no passphrase) and no warnings. Adding `set pki certificate Z1 private password-protected` and `… x509 passphrase S3cret` changes the key label to `ENCRYPTED PRIVATE KEY` and adds:

```
    private_192-0-2-9 {
        file = x509_Z1.pem
        secret = "S3cret"
    }
```

`show pki certificate`, in the VyOS layout (dates as UTC `YYYY-MM-DD HH:MM:SS`):

```
Certificates:
Name  Type    Subject CN         Issuer CN  Issued               Expiry               Revoked  Private Key  CA Present
----  ------  -----------------  ---------  -------------------  -------------------  -------  -----------  ------------
Z1    Server  CN=z1.lab.example  CN=LAB-CA  2026-10-21 00:00:00  2126-09-27 00:00:00  No       Yes          Yes (LAB-CA)
```

## 5. Tests

**zebra-rs unit:**
- `pki_schema_gated`;
- `pki_name_rule` (`a/b`, `.x` and 65 characters rejected);
- `pki_base64_rule`;
- `show_pki_routes_to_provider`, as the `"ipsec"` routing test does (`manager.rs:7677-7699`);
- `pki_is_external_tree`: a pki-only commit with no validator prints "not validated";
- `import_pki_lines`: PEM fixtures → exact `set` lines, encrypted-key detection.

**insomnia golden/unit** (fixture certificates in `src/testdata/pki/`, generated once by the BDD script below):
- `x509_peer_golden` and `x509_passphrase_golden`: §4;
- `rsa_peer_golden`;
- `use_x509_id_golden`: no `id` line in `local`;
- `x509_remote_any_warns`;
- `disabled_peer_writes_no_creds`;
- `ra_connection_creds` (lands with [ipsec-remote-access](ipsec-remote-access.md) M6): a server-mode x509 RA connection puts its certificate, key and CAs in the `CredSet`, and renders `private_ra-<n>` only when it has a passphrase;
- `protected_key_without_passphrase_skips`;
- `armour_wraps_64`;
- `ca_without_ca_flag_skipped` (layer 3);
- `pki_findings_table`: one case per P2 finding row, asserting severity, effect and message, and that no message contains key bytes or a passphrase. Cases include:
  - `x509_refs_must_exist`;
  - `rsa_parts_required`;
  - `use_x509_id_excludes_local_id`;
  - `redacted_placeholder_skips`;
- `validate_refuses_in_use_delete`: `ipsec::validate` on a candidate whose `pki` lacks a referenced CA returns the Error. That is the in-use rule;
- `load_compare_skips_reload`: an unchanged conf, `CredSet` and charon start time skip `swanctl -q`; a changed `uptime.since` or `Applied::Restarted` forces it;
- `creds_manifest_idempotent` (scratch dir):
  - first apply writes the files;
  - the second makes zero writes (mtimes unchanged);
  - removing the peer deletes only manifest files;
  - a foreign file survives;
  - modes are asserted, `private/` 0700;
- `show_pki_tables`: certificate/CA/CRL/key-pair tables and JSON from fixtures; expired certificate rendering.
- `generate_*` (with I5): a self-signed CA and a signed certificate round-trip through `x509-parser`; SAN, EKU and validity as requested; `tcp:` refusal.

**BDD: new feature `ipsec_x509.feature` (`@serial @ipsec_x509`)**, on the `ipsec_s2s` topology.
- Fixtures: `bdd/tests/scripts/ipsec_x509_certs.sh` (openssl, run by a developer; outputs committed under `bdd/tests/configs/ipsec_x509/`). It makes:
  - LAB-CA and ROGUE-CA (CA:TRUE);
  - Z1 and Z2 (SAN DNS `z{1,2}.lab.example`, EKU server+client, signed by LAB-CA);
  - ROGUE (SAN `z1.lab.example`, signed by ROGUE-CA);
  - all valid until 2126.
- Configs are full restatements (`cucumber.rs:876-881`):

  | File | Contents |
  |:--|:--|
  | `z1.conf` | Z1 identity |
  | `z2.conf` | Z2. Also loads ROGUE-CA through a dummy peer `192.0.2.77 … x509 ca-certificate ROGUE-CA` |
  | `z1-rogue.conf` | ROGUE presented as `z1.lab.example` |

- New harness steps:
  - `applying command {string} in namespace {string} should fail with {string}`: asserts that `vtyctl apply -c` printed `error` and the needle;
  - `command {string} in the IPsec mount namespace of {string} should eventually contain {string}`: runs through `nsenter -m -t $(cat /tmp/<scoped>.insomnia.pid)`, because `/etc/swanctl` is private to the node (`ipsec_node.sh:33-35`).

Scenarios:
1. **x509 tunnel.**
   - Responder first; the SA is up.
   - `show vpn ipsec connections` in z1 contains `z2.lab.example`.
   - `show pki certificate` contains `Z1` and `2126`.
   - mount-ns `stat -c '%a %n' /etc/swanctl/private /etc/swanctl/private/x509_Z1.pem` contains `700 /etc/swanctl/private` and `600 /etc/swanctl/private/x509_Z1.pem`.
   - Ping and counters as `ipsec_s2s`.
2. **A certificate from another loaded CA is rejected (the `cacerts` fix).**
   - `delete vpn ipsec` in z1, then apply `z1-rogue.conf`.
   - charon log in z2 eventually contains `constraint check failed` (wording *unverified*; the step comes from [ipsec-render-fixes](ipsec-render-fixes.md)).
   - After 5 s, no SA in either node.
   - VyOS would accept this: ROGUE-CA is loaded and the identity matches.
3. **In-use deletion is refused** (needs [commit-validation](commit-validation.md) layer 2, C5/C6). `applying command "delete pki ca LAB-CA" in namespace "z2" should fail with "LAB-CA"`. The message comes from the P2 finding.
   - Before layer 2 ships, this scenario instead asserts that the deletion commits and z2's insomnia log contains the Error finding with "peer skipped".
4. **Removal cleans up.**
   - `delete vpn ipsec` on z1.
   - mount-ns `ls /etc/swanctl/x509 /etc/swanctl/private` eventually does not contain `Z1.pem`.
   - `swanctl --list-certs` does not contain `z1.lab.example`. This checks P4's unverified clear-on-reload.
5. **Teardown topology.**

## 6. Docs

- **ch-02-03, rewritten** ("Authentication: Pre-Shared Keys and X.509"):
  - the PSK section, with the [ipsec-render-fixes](ipsec-render-fixes.md) id rules;
  - PKI objects and their base64 bodies;
  - `import pki` and `generate pki`, with examples;
  - an x509 peer;
  - pinning `remote-id`;
  - the `cacerts` deviation, and why;
  - passphrases and `password-protected`;
  - CRLs (charon's default revocation policy is relaxed; *unverified* that VyOS sets nothing stricter, as its template shows);
  - rsa raw keys;
  - `use-x509-id`;
  - the file layout under `/etc/swanctl`, and the manifest;
  - **`unix:` is required**.
- **ch-03-01:** a `show pki` section.
- **ch-00-03:** a note that `--swanctl-dir` now also holds credentials.
- **Appendix A:** RFC 5280 (PKIX profile), RFC 7468 (textual encodings), RFC 7427 (IKEv2 signature authentication, which strongSwan uses for `auth = pubkey`; *unverified* default).
- **zebra-rs book:** the `pki` tree and `import pki`.
- **Module docs (`ipsec.rs`, `pki.rs`):** the deviations in P4–P8.

## 7. Milestones

1. **Z1: `pki.yang` + `config.yang` container + name/base64 checks + redaction markers.** zebra-rs, M. Done when: the schema/check tests pass and a 4096-bit RSA key body round-trips through `set` and `show running-config` (line-length limits are *unverified*). Ships after or with [secret-redaction](secret-redaction.md) M1; otherwise the book carries a warning that keys are visible.
2. **Z2: `ipsec.yang` x509/rsa/use-x509-id with `ext:secret` tags; `EXTERNAL_TREES` gains `[pki]`.** zebra-rs, S. Done when: schema tests pass and the passphrases are redacted.
3. **I1: `subscribe_json_multi` conversion of the IPsec backend, the IPsec load compare, `PkiConfig`, retained `Arc<IpsecInput>`, `CredSet` + manifest writer, armour.** insomnia, M. Needs [multi-path-subscribe](multi-path-subscribe.md) M2. If [ipsec-vti](ipsec-vti.md) I1 lands first, it does the conversion and the compare, and this milestone appends `["pki"]`. Done when: `creds_manifest_idempotent`, `load_compare_skips_reload` and the armour tests pass.
4. **I2: x509 render + the P2 findings (layers 2 and 3 share them via `render()`).** insomnia, M. Done when:
   - the x509 goldens, `pki_findings_table` and `validate_refuses_in_use_delete` pass;
   - with [commit-validation](commit-validation.md) C6 live, deleting a referenced CA is refused.
5. **B1: BDD `ipsec_x509`, the fixture script, two new steps.** insomnia `bdd/`, M. Done when: `make -C bdd ipsec_x509` passes; scenario 2 fails if `cacerts` is removed from the render.
6. **I3: rsa + `use-x509-id`.** insomnia, S. Done when: `rsa_peer_golden` and `use_x509_id_golden` pass. An rsa BDD scenario may be added to B1.
7. **Z3 + I4: `show pki` grammar/routing (zebra-rs, S); tables, `pem`/`text`/`fingerprint`, JSON (insomnia, M).** Done when: `show_pki_tables` and the routing test pass; BDD scenario 1 asserts the expiry.
8. **Z4: `import pki`.** zebra-rs, S. Done when: `import_pki_lines` passes; configure-mode import leaves the candidate uncommitted.
9. **I5: `generate pki` (ca, certificate sign/self-signed, key-pair, crl) on `rcgen`, as an EXEC order.** insomnia + [exec-verbs](exec-verbs.md), M. The configure-mode `install` uses exec-verbs D-11's `ShowChunk.install`. Done when: the `generate_*` tests pass and a generated certificate establishes the BDD tunnel.
10. **Docs**, in parallel with milestones 4–9. insomnia + zebra-rs, S.

## 8. Risks and open questions

- **`cacerts` is a deviation users may trip over** when they listed only their own CA and relied on another peer's CA being loaded. The failure is explicit (an auth failure plus a charon log). Open: keep it default-on (recommended), or add a parity switch?
- **The X.509 crates add weight**, mostly `rcgen` + `ring`. Gate `generate` behind a cargo feature if the binary size matters for the .deb.
- **Long base64 tokens:** CLI, `vtyctl` and set-format line limits are *unverified*. Z1 tests a 4 KB token.
- **The VyOS passphrase bug was found by source reading.** The fixed naming is tested in BDD only if a protected-key scenario is added. Recommendation: add it to B1 (a protected Z1 key with a passphrase).
- **Clear-on-reload of deleted credentials** (P4) is unverified. The BDD scenario 4 decides whether `--load-creds --clear` is needed.
- **A configure-mode `install` path** needs zebra-rs exec in configure mode, which [exec-verbs](exec-verbs.md) D-11 provides. Fallback, as there: print the lines only (VyOS's behaviour outside a session).
- **Out of scope:** ACME/certbot, `system-install`, `dh`/`openssh`/`openvpn` objects, OCSP. Revocation checking beyond loaded CRLs is not configured.

## 9. Acceptance criteria

- [ ] `pki ca|certificate|key-pair` exist behind `--feature insomnia`; private keys and passphrases are masked in show output ([secret-redaction](secret-redaction.md)).
- [ ] zebra-rs refuses bad names and bad base64 (layer 1).
- [ ] With insomnia validating (layer 2), commits with missing or incomplete references, `use-x509-id` with `local-id`, or deletion of in-use objects are refused.
- [ ] At apply, every P2 finding carries its severity and effect, and no message leaks key material.
- [ ] The IPsec backend uses one `subscribe_json_multi` stream (`vpn ipsec`, `pki`, `vti`; PrimaryOnly). It skips `swanctl -q` when nothing rendered changed and charon has not restarted.
- [ ] An x509 peer renders `send_cert`, `certs`, `cacerts` and the correctly named `private_*` secret; an RA connection gets the same rules through `x509-ref`. A credential file set with exact modes, covering rendered peers and RA connections, is written idempotently, and only insomnia's files are removed.
- [ ] rsa and `use-x509-id` render per P6/P7; disabled peers write no credentials.
- [ ] `make -C bdd ipsec_x509` passes, including the cross-CA rejection and the in-use refusal.
- [ ] `show pki …` matches the VyOS columns; there is no private-key view.
- [ ] `import pki` (zebra-rs) and `generate pki` (insomnia) emit or insert `set pki` lines without committing; `generate` refuses over `tcp:`.
- [ ] ch-02-03 is rewritten; a `show pki` section and appendix A entries are added.
