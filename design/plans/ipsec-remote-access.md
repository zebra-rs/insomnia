# IPsec remote access (IKEv2 road warrior) — implementation plan

Status: plan, 2026-10-21. Covers: §7.2 row `remote-access`, §7.4 row 5 (remote-access views
and resets, `generate ipsec profile`), §4.6 consumers ([vyos-gap](../vyos-gap.md) §7.2,
§7.3, §7.4).
Priority: P2 · Effort: L (M without the PKI-dependent modes) · Owner: both
Depends on:
- [pki-x509](pki-x509.md): server-mode `x509`, the VyOS default, and client-mode
  `x509`/`eap-tls`.
- [charon-lifecycle](charon-lifecycle.md): the `eap-radius` and `dhcp` plugin settings.
- [secret-redaction](secret-redaction.md): local-user passwords, the RA PSK and RADIUS keys.
- [ipsec-vti](ipsec-vti.md): `bind` (the XFRM link, and its bind-exists finding, which covers RA binds).
- [ipsec-render-fixes](ipsec-render-fixes.md): X4 and X6 land first. RA reuses the X4b `quoted_ok` guard, and X6 scopes `unique = never` to site-to-site and profile connections (D3).
- [ipsec-syntax-parity](ipsec-syntax-parity.md): the `childless`/`unique`/`ppk`
  groupings, the `dhcp-interface` resolver and the name checks.
- [exec-verbs](exec-verbs.md): the resets.
- [ipsec-opmode](ipsec-opmode.md): the shared op helpers.
- [commit-validation](commit-validation.md): `findings.rs` and `validate(parts)` (its C1);
  the validation RPC (later) refuses the D6 Errors at commit.
- [multi-path-subscribe](multi-path-subscribe.md): through the IPsec backend's one stream
  (`vpn ipsec` + `pki` from pki-x509, `vti` from ipsec-vti).

Unblocks: `generate ipsec profile` (deferred, §3 D8).

Assumes D1 (verify rules are commit-validation findings: an Error refuses the commit once
layer 2 exists, and until then is logged with its apply-time effect), D2 (exec order
kind) and D3 (multi-path subscribe, consumed through pki-x509).

## 1. Goal

- `vpn ipsec remote-access` exists in the zebra-rs schema with VyOS rolling's leaf set:
  - `connection <n>`: authentication with server-mode `x509`/`pre-shared-secret` and
    client-mode `x509`/`eap-tls`/`eap-mschapv2`/`eap-radius`, `local-users`, `eap-id`,
    `always-send-cert` and `ppk`; plus `local-address`/`dhcp-interface`, `local`
    selector, `pool`, `timeout`, `unique`, `childless`, `bind` and `replay-window`;
  - `pool`, `dhcp` and `radius`.
- insomnia renders VyOS `remote_access.j2` line for line:
  - the `ra-<n>` connections;
  - the pools (replacing today's always-empty `pools {}`);
  - the `ike_<n>` and `eap-<n>-<user>` secrets;
  - the charon `eap-radius`/`dhcp` plugin settings, through charon-lifecycle.
- Clients can connect:
  - strongSwan clients (desktop and Android): PSK server auth plus EAP-MSCHAPv2 users,
    with no PKI;
  - the native Windows and macOS/iOS clients: once x509 server auth lands with pki-x509.
    They do not accept PSK server auth with EAP; per-client details are *unverified*;
  - with users held in RADIUS instead of `local-users`.
- `show vpn ipsec remote-access summary|detail|username <u>|connection-id <id>` and
  `reset vpn ipsec remote-access all|user <u>` work.
- One bad connection or pool is an Error finding and is skipped; the rest load. Once
  commit-validation's RPC is live, the commit is refused instead.

## 2. Current state

**zebra-rs @ 141da2fc**
- `ipsec.yang:26-34` defers `remote-access` ("needs PKI, RADIUS and local-user trees").
- The parse test asserts the tree is absent: `manager.rs:7846`,
  `"set vpn ipsec remote-access connection RA pool CLIENTS"` in `bad_with_insomnia`.
- `vpn ipsec` is instantiated at `config.yang:5694-5701`.
- `zebra-rs/docs/design/vpn-ipsec-followups.md` lists remote-access as "its own arc".

**insomnia @ ee4dfaa**
- `render()` always emits an empty `pools {\n}` (`ipsec.rs:536-538`). Secrets hold only the
  psk table (`ipsec.rs:540-546`).
- `IpsecConfig` has no `remote_access` field (`ipsec.rs:160-173`); serde ignores unknown
  keys.
- The building blocks exist:
  - `cipher_strings` (`ipsec.rs:384-427`);
  - `render_child_lifetimes` (`787-805`);
  - `find_ike`/`find_esp` (`435-445`);
  - `vti_if_id` (`840-842`);
  - the default IKE/ESP lifetimes (`319-320`).
- There are no plugin settings, because charon is not owned (`ipsec.rs:20-27`).

**VyOS @ 7f2c893**
- **Schema** (`interface-definitions/vpn_ipsec.xml.in`, the `remote-access` node). Connection
  names match `[a-zA-Z][0-9a-zA-Z_-]+`. Defaults:
  - `eap-id any`;
  - `client-mode eap-mschapv2`;
  - `server-mode x509`;
  - `timeout 28800`;
  - `radius timeout 2`;
  - radius server `port 1812`.

  Includes: `auth-local-users.xml.i`, `ipsec/authentication-x509.xml.i`, `ipsec/ppk.xml.i`,
  `ipsec/childless.xml.i`, `vpn-ipsec-unique.xml.i`, `radius-auth-server-ipv4.xml.i`,
  `accel-ppp/radius-additions-disable-accounting.xml.i`.
- **Templates:**
  - `data/templates/ipsec/swanctl/remote_access.j2` (whole file);
  - `swanctl.conf.j2:30-48` (pools) and `124-145` (RA secrets);
  - `charon/eap-radius.conf.j2` and `charon/dhcp.conf.j2`. VyOS renders both on every
    commit with `load = yes` (`vpn_ipsec.py:932-933`).
- **verify:** `vpn_ipsec.py:403-600`, the RA connection, pool and RADIUS rules.
- **generate:**
  - `vpn_ipsec.py:859-873`: the dhcp-interface address and the x509 files;
  - `apply` marks RA `bind` VTIs persistent (`vpn_ipsec.py:479-482`, `947-951`).
- **Op-mode:**
  - `op-mode-definitions/vpn-ipsec.xml.in:45-63` (reset) and `207-237` (show);
  - `src/op_mode/ipsec.py`: `reset_ra` (713-720, VICI `terminate {ike-id, timeout -1}`);
  - `_get_ra_sessions` (826-845): selects SAs that carry `remote-eap-id`;
  - `_get_formatted_output_ra_summary` (933-983); `show_ra_detail` (986-1000).
- **Profiles:** `generate-ipsec-profile.xml.in` with `src/op_mode/ikev2_profile_generator.py`.
  The generator is interactive (`ask_input`), reads `pki`, and uses
  `ios_profile.j2`/`windows_profile.j2`.

**Host packaging** (Ubuntu 24.04, strongSwan 5.9.13, checked on this host):
- `libcharon-extauth-plugins` ships `eap-mschapv2` and `xauth-generic`.
- `eap-identity`, `eap-radius` and `eap-tls` are in `libcharon-extra-plugins` (package
  description).
- The location of the `dhcp` plugin is *unverified*.
- swanctl 5.9.13 documents `pools.<name>.addrs/dns/split_exclude`, `secrets.eap<suffix>`,
  `children.<child>.inactivity`, `send_certreq`, `eap_id`, `unique` and `childless`
  (`man swanctl.conf`).

## 3. Design

**D1: the shared machinery is consumed, not redefined.**

| Need | Owner | Used for |
|:--|:--|:--|
| The grouping `x509-ref` (`container x509 { certificate; passphrase (ext:secret); ca-certificate* }`), which pki-x509 P1 factors out of the peer so RA reuses it verbatim; the `use-x509-id` rule (P7). Also the `src/pki.rs` `CredSet` + manifest credential writer, which includes rendered RA connections' credentials (P4), and the P5 rules applied per `ra-<n>`: `cacerts` per connection, the `private_ra-<n>` secret naming the written `x509_<cert>.pem`, and a protected key without a passphrase skipped | [pki-x509](pki-x509.md) | server-mode x509, client `cacerts` |
| `vpn ipsec` + `pki` (+ `vti`) in one subscription. The IPsec backend's single path list (multi-path D-10) is opened with `subscribe_json_multi(host, &[vpn ipsec, pki, vti], Fallback::PrimaryOnly)`; each part is read with `json::parse_subtree`. RA adds no path and opens no stream | [pki-x509](pki-x509.md) and [ipsec-vti](ipsec-vti.md) over [multi-path-subscribe](multi-path-subscribe.md) | as above; `bind` checks |
| Keys in the one drop-in `/etc/strongswan.d/insomnia.conf` (mode `0600`) via `CharonSettings`, with the reload/restart class table. **Requirement:** `CharonSettings` is `Vec<(&'static str, String)>` today, but the RADIUS server keys are per server (`charon.plugins.eap-radius.servers.<name>.*`), so it must take owned `String` keys or a section-valued entry | [charon-lifecycle](charon-lifecycle.md) | `charon.plugins.eap-radius`, `charon.plugins.dhcp` |
| `ext:secret "<what>"` on the leaves secret-redaction's table assigns to this plan; `json::redacted()` placeholder handling | [secret-redaction](secret-redaction.md) | local-user `password`, `pre-shared-secret`, RADIUS server `key` (`passphrase` is pki-x509's) |
| `vti_if_id` (with `checked_add`); the bind-exists **Error finding** over the `vti` part (its I1), which covers `remote-access connection <c> bind` too | [ipsec-vti](ipsec-vti.md) | `bind` |
| The `quoted_ok` guard (X4b); X6's `unique = never`, rendered for site-to-site and profile connections only | [ipsec-render-fixes](ipsec-render-fixes.md) | quoted values, D3 |
| `src/findings.rs` (`Findings`, `Severity`, `Effect`); `render()` → `(String, Findings)`; per-backend `validate(parts)`; `mandatory` / `ext:startup-tolerant` rules | [commit-validation](commit-validation.md) | D6 |
| `childless`, `unique` and `ppk` groupings and render helpers; the `dhcp-interface` address resolver (`RenderEnv`); the name-charset check | [ipsec-syntax-parity](ipsec-syntax-parity.md) | the same leaves on RA |
| Exec orders (`OrderKind::Exec`, `Answer { text, error }`, `EXEC_ROUTES` row `reset vpn ipsec`); the bounded `vici` API (`terminate`, `stats`); the `Arc` retained model | [exec-verbs](exec-verbs.md) | resets, plugin probe |
| `ViciOps`, `swanctl --list-sas` runner, IKE/ESP proposal text | [ipsec-opmode](ipsec-opmode.md) | RA views |

**D2: schema location and shape.**
- A new `grouping remote-access-config` in `ipsec.yang`, used from `grouping vpn-ipsec`
  between `options-config` and `site-to-site-config`, in VyOS node order.
- Leaves are VyOS-verbatim, with no `pattern`, following the module convention
  (`ipsec.yang:36-42`).
- VyOS `defaultValue`s are applied in the renderer (the `ipsec.rs:316-318` convention).
- The connection-name regex becomes a renderer finding (D6), because a patterned key would
  consume the rest of the line.

**D3: the renderer follows `remote_access.j2` exactly.** Points worth stating:
- Connection `ra-<n>`, child `<n>-client`. Field order:
  - `ppk_id`, `ppk_required`, `childless`;
  - `remote_addrs = %any`, `local_addrs = … # dhcp:…`, `proposals`, `version`,
    `send_certreq = no`, `send_cert = always`;
  - dpd, `rekey_time`, `keyingtries = 0`, `unique`, `pools`;
  - `local {}`, `remote {}`, `children {}`.
- `local_ts` defaults to `0.0.0.0/0,::/0`. A port suffix is `[%any/<port>]`, not
  `[<proto>/…]`. There is no `remote_ts`: charon's `dynamic` resolves to the client's
  virtual IP.
- Child: `dpd_action = clear`, `inactivity = <timeout>`, `if_id_in/out` from `bind`. RA
  children carry no `start_action`, `close_action`, `mode` or `ipcomp`, as in VyOS.
- `eap_id = %any` when `eap-id any`. `local id` is omitted under `use-x509-id`; that leaf
  is owned by pki-x509.
- **Global `unique` is not applied.** `disable-uniqreqids` reaches RA nowhere in VyOS: its
  `global_unique` is passed to peers, profiles and l2tp only (`swanctl.conf.j2:7`, `22`).
  Kept, and [ipsec-render-fixes](ipsec-render-fixes.md) X6 is scoped to match.
- **Quoted values** (`local id`, `eap_id`, the `ike_<n>` id and secret, EAP user names and
  passwords, RADIUS `secret`) go through ipsec-render-fixes' `quoted_ok` guard (X4b).
- **Secrets order:** psk, then ppk, then RA (`swanctl.conf.j2:82-145`).
  - `ike_<n>` with `id = local-id`, else `local-address`, else the resolved dhcp address.
  - `eap-<n>-<user> { secret = …; id-<n>-<user> = "<user>" }` only for
    `client-mode eap-mschapv2` and enabled users.
- **Pools:** `addrs = <prefix>` or `<start>-<stop>`, `dns = a,b`, `split_exclude = …`, in
  name order.
- `pool dhcp` and `pool radius` are emitted literally in `pools = …`. charon resolves them
  to the `dhcp` and `eap-radius` plugin pools.

**D4: plugin settings go through charon-lifecycle.**
- Sections are emitted only when configured:
  - `charon.plugins.eap-radius`: `nas_identifier` (default `strongSwan`),
    `retransmit_timeout = <timeout as float>`, and `servers.<addr-dashed>` with
    `address`, `secret`, `auth_port`, `acct_port = port+1` unless `disable-accounting`,
    and `sockets = 20`;
  - `charon.plugins.dhcp`: `interface`, `server`.
- DEVIATION: VyOS writes both plugin files on every commit with `load = yes`, and so
  overwrites the distro's `/etc/strongswan.d/charon/{eap-radius,dhcp}.conf`. insomnia
  leaves plugin loading to the distro files and writes only settings, in its own drop-in.
- DEVIATION: secret values are quoted. VyOS writes `secret = {{ key }}` bare, which breaks
  on `#` or spaces.
- `radius source-address` is in the schema, but VyOS does not render it either. Kept and
  documented.
- Whether these keys need a charon restart or only `swanctl --reload-settings` is
  charon-lifecycle's call. Add them to its class table, restart-class until a BDD case
  proves a reload is enough (its own rule). That eap-radius servers can be reloaded is
  *unverified*.
- The keys override the distro's `charon/eap-radius.conf` only because `insomnia.conf` is
  included after the plugin includes. That ordering is *unverified*, and charon-lifecycle
  pins it in its BDD.

**D5: required plugins are probed after load.**
- After a successful load, VICI `stats` (exec-verbs E1) lists the loaded plugins. Each active RA
  connection is warned about once per missing plugin:
  - `eap-mschapv2`, plus `eap-identity` when `eap_id = %any`;
  - `eap-tls`;
  - `eap-radius` (client-mode `eap-radius` or `pool radius`);
  - `dhcp` (`pool dhcp`).
- The connection still loads. The renderer stays pure.
- That `eap_id = %any` needs `eap-identity` follows strongSwan's EAP-Identity design and
  is *unverified* until the BDD.

**D6: verify rules are findings.**
- Every rule is a `findings.rs` `Finding` raised inside `render()`, in commit-validation's
  vocabulary. So the same code:
  - refuses the commit through `ipsec::validate(parts)`, once the validation RPC exists;
  - logs `"<msg>; <effect>"` at apply time until then.
- Severity follows commit-validation §3.2:
  - **Error** when VyOS raises `ConfigError`, or when the renderer cannot express the
    config;
  - **Warning** when VyOS accepts it, or when the cause is host state.
- Upgrade safety does not apply here: nothing in this tree renders today, so every Error
  may be `Skipped`.
- Messages name the node in config spelling and never include a secret value.

| Rule (VyOS `vpn_ipsec.py`) | Sev | Effect |
|:--|:--|:--|
| name matches `[a-zA-Z][0-9a-zA-Z_-]+` (schema regex) | E | connection skipped |
| `local-address` or `dhcp-interface` (406-407) | E | connection skipped |
| dhcp-interface has no address yet (428-431): host state | W | connection skipped; re-rendered when the address appears (syntax-parity resolver) |
| esp-group set and exists (433-437); ike-group set, exists and `key-exchange ikev2` (439-448) | E | connection skipped |
| server-mode x509: `x509 certificate` + `ca-certificate` (453-460); PKI material present (462, cross-tree over the `pki` part) | E | connection skipped. Before pki-x509: W, `NotApplied` ("x509 server mode needs pki") |
| server-mode psk: `pre-shared-secret` (463-465) | E | connection skipped |
| client-mode eap-radius needs a radius server (470-472) | E | connection skipped |
| `bind` interface exists (474-477) | E | Kept: ipsec-vti's bind-exists finding over the `vti` part, not a zebra-rs check; suppressed under the PrimaryOnly fallback |
| *added:* a quoted value fails `quoted_ok` (X4b) | E | user / connection / server skipped |
| pool references: dhcp xor radius; neither combined with named pools; dhcp needs `dhcp server`; radius needs a server and eap-radius; a named pool exists (484-507) | E | connection skipped |
| ppk / childless need explicit IKEv2 (511-526) | E | connection skipped (ppk) / `Dropped("childless")`, per syntax-parity |
| ppk without childless (517-520) | W | kept |
| pool: prefix xor range; start ≤ stop and same family; no overlap; ≤ 2 name-servers; name-server and exclude same family (528-595) | E | pool skipped, plus every connection that references it |
| radius server needs `key` (597-600) | E | server skipped |
| a `<redacted:…>` placeholder in `password`, `pre-shared-secret` or `key` (secret-redaction) | as secret-redaction specifies for psk | user / connection / server skipped |
| *added:* a pool named `dhcp` or `radius` (VyOS accepts it) | W | pool skipped (it would shadow the plugin pool) |
| *added:* client-mode eap-mschapv2 with no enabled local user | W | kept |
| *added:* `local-users` set under another client-mode (VyOS silently ignores) | W | `NotApplied` |

**Layer 1 YANG.** `mandatory true` goes on `connection esp-group`, `connection ike-group`
and `radius server key`.
- These leaves are new, so no stored startup config can lack them, and plain `mandatory`
  is safe.
- Any `mandatory` added in a release after the tree first ships must carry
  `ext:startup-tolerant` (commit-validation).
- "local-address or dhcp-interface" and the pool rules stay layer 2.

**D7: RA sessions are identified by connection name.**
- An IKE_SA belongs to remote access when its name starts with `ra-`.
- DEVIATION: VyOS selects SAs carrying `remote-eap-id`, which hides `client-mode x509`
  sessions from every RA view and reset.
- `Username` is `remote-eap-id`, else `remote-id`.
- The VyOS summary indexes `remote-vips[0]` and throws when there is none; insomnia prints
  `-`.

**D8: `generate ipsec profile` is deferred.** Not in this plan's acceptance criteria.
- It needs X.509 parsing: the CN, the issuer and the CA chain via `find_chain`. That parsing
  arrives with `show pki` in pki-x509.
- The VyOS generator prompts interactively (`ask_input`) when several proposals fit. A
  oneshot reply cannot prompt.
- Follow-up sketch, milestone 7:
  - grammar: `generate ipsec profile ios-remote-access <conn> remote <host> [name <n>] [profile <p>]`
    and `windows-remote-access <conn> remote <host> [name <n>]`;
  - choose the first proposal the target OS supports, using VyOS's
    `vyos2apple_cipher`/`vyos2windows_cipher` tables; error when none fits;
  - return the mobileconfig XML or the PowerShell in the reply.

**Rejected alternatives.**
- Writing `/etc/strongswan.d/charon/eap-radius.conf` the way VyOS does: it fights the
  distro package's conffile, and it is charon-lifecycle's file layout to decide.
- RA sessions selected by `remote-eap-id`: see D7.
- A separate `remote-access` subscription: it is the same subtree (`vpn ipsec`), so no new
  stream is needed.

**Module-doc deviations to add** (`ipsec.rs` header): D4 (plugin files, quoting), D7, the
added verify rules in D6, and the unrendered `radius source-address`.

## 4. Changes

### zebra-rs

`ipsec.yang`, new grouping (sketch; the help strings are VyOS's):

```yang
grouping remote-access-config {
  container remote-access {
    ext:help "IKEv2 remote access VPN";
    list connection {
      ext:help "IKEv2 VPN connection name"; key "name";
      leaf name { type string; }
      container authentication {
        leaf local-id { type string; }
        uses x509-ref;                      // pki-x509 P1: container x509 { certificate; passphrase; ca-certificate* }
        leaf use-x509-id { type empty; }    // pki-x509 P7 rule
        leaf eap-id { type string; ext:help "Remote EAP ID for client authentication (VyOS default: any)"; }
        leaf client-mode { type enumeration { enum x509; enum eap-tls; enum eap-mschapv2; enum eap-radius; } }
        container local-users { list username { key "name"; leaf name { type string; }
          leaf disable { type empty; } leaf password { type string;
            ext:secret "IPsec remote-access local user password"; } } }
        leaf always-send-cert { type empty; }
        leaf server-mode { type enumeration { enum pre-shared-secret; enum x509; } }
        uses ppk-ref;                       // syntax-parity: container ppk { id; required }
        leaf pre-shared-secret { type string; ext:secret "IPsec remote-access pre-shared secret"; }
      }
      uses ipsec-childless;                 // syntax-parity
      leaf description { type string { pattern '.*'; } }
      leaf disable { type empty; }
      leaf esp-group { type string; }
      leaf ike-group { type string; }
      leaf local-address { type union { type inet:ipv4-address; type inet:ipv6-address; type string; } }
      leaf dhcp-interface { type string; }
      container local { uses traffic-selector; }
      leaf replay-window { type uint32 { range "0..2040"; } }
      leaf bind { type string; }
      leaf timeout { type uint32 { range "0..86400"; } }   // VyOS default 28800
      leaf-list pool { type string; }
      uses ipsec-unique;                    // syntax-parity
    }
    container dhcp { leaf interface { type string; } leaf server { type inet:ipv4-address; } }
    list pool {
      key "name"; leaf name { type string; }
      leaf-list exclude { type union { type inet:ipv4-prefix; type inet:ipv6-prefix; } }
      leaf prefix { type union { type inet:ipv4-prefix; type inet:ipv6-prefix; } }
      container range { leaf start { type inet:ip-address; } leaf stop { type inet:ip-address; } }
      leaf-list name-server { type inet:ip-address; }
    }
    container radius {
      leaf source-address { type inet:ipv4-address; }
      leaf nas-identifier { type string; }
      leaf timeout { type uint8 { range "1..240"; } }      // VyOS default 2
      list server { key "address"; leaf address { type inet:ipv4-address; }
        leaf disable { type empty; } leaf key { type string; ext:secret "RADIUS shared secret"; }
        leaf port { type uint16; }                         // VyOS default 1812
        leaf disable-accounting { type empty; } }
    }
  }
}
```

- `ext:dynamic "rib:interface"` on `dhcp-interface` and `dhcp interface`.
- **Tests:**
  - move the `manager.rs:7846` line from `bad_with_insomnia` to `ok`;
  - add about 25 RA `set` lines to `ok`;
  - add negative cases: `client-mode eap-md5`, `timeout 90000`, `radius timeout 0`.
- **exec.yang** (insomnia-gated):
  - `show vpn ipsec remote-access { summary; detail; list username; list connection-id }`
    as presence nodes;
  - under exec-verbs' `reset vpn ipsec`:
    `remote-access { container all { presence }; list user { key name; ext:presence } }`.
  - Routing: the show views are covered by `is_vpn`. The verbs are covered by exec-verbs'
    `EXEC_ROUTES` row `reset vpn ipsec` → `ipsec`, which ipsec-opmode adds.
- **Commit checks:**
  - The D6 findings reach commit time through commit-validation's validation RPC and
    `ipsec::validate(parts)`; no new `check.rs` code is needed.
  - `bind`: ipsec-vti's bind-exists finding covers `remote-access connection <c> bind`;
    no zebra-rs check (commit-validation rejects cross-tree rules in `check.rs`; ipsec-vti §3).
  - The layer-1 `mandatory` statements are listed in D6.

### insomnia

**`src/ipsec.rs`:**
- Model:

  ```rust
  RemoteAccess { connection: Vec<RaConn>, dhcp: Option<RaDhcp>, pool: Vec<RaPool>, radius: Option<RaRadius> }
  ```

  `RaConn` mirrors the YANG, with `Flex` user strings, `de_presence` and `de_flex_vec`,
  per `json.rs`. Then `IpsecConfig.remote_access: Option<RemoteAccess>`.
- New `fn render_ra(r, cfg, env)`, after the s2s peers inside `connections {}`.
- New `fn render_pools(r, cfg)`, replacing `ipsec.rs:536-538`.
- New `fn render_ra_secrets(r, cfg, env)`, after psk (and ppk, from syntax-parity).
- New `fn ra_plugin_keys(cfg) -> Vec<(String, String)>` (dotted key, value). It is
  appended to charon-lifecycle's `charon::render(cfg)` output, so one `CharonSettings`
  and one `apply` cover the whole drop-in.
- The pure validation helpers run inside the render pass: `pool_overlaps`, `same_family`,
  `range_ok`.

**`src/ipsec_op.rs`** (from [ipsec-opmode](ipsec-opmode.md)):
- `ra_sessions(sas, filter)`;
- `ra_summary_text`, using VyOS's `_get_formatted_ike_proposal` /
  `_get_formatted_ipsec_proposal` layouts;
- `ra_detail`, which runs `swanctl --list-sas --ike-id <id>` per session (VyOS) through
  the opmode runner;
- `reset_ra(v, user: Option<&str>)`: exec-verbs'
  `vici::terminate(&Terminate { ike_id: Some(id), timeout_ms: -1, .. })` per session.
  VyOS does the same, and terminating clients need no wait. The reply is
  `Terminated N remote-access session(s)`; VyOS prints nothing.
- The plugin probe (D5) uses `vici::stats`.

**Worked example.** Config (PKI-free):

```
set vpn ipsec ike-group IKE-RA key-exchange ikev2
set vpn ipsec ike-group IKE-RA proposal 10 encryption aes256gcm128
set vpn ipsec ike-group IKE-RA proposal 10 hash sha256
set vpn ipsec ike-group IKE-RA proposal 10 dh-group 19
set vpn ipsec esp-group ESP-RA proposal 10 encryption aes256gcm128
set vpn ipsec esp-group ESP-RA proposal 10 hash sha256
set vpn ipsec remote-access connection RW authentication server-mode pre-shared-secret
set vpn ipsec remote-access connection RW authentication pre-shared-secret Lab-RA-PSK
set vpn ipsec remote-access connection RW authentication local-id vpn.example.net
set vpn ipsec remote-access connection RW authentication local-users username alice password Alice-Pass-1
set vpn ipsec remote-access connection RW authentication local-users username bob disable
set vpn ipsec remote-access connection RW authentication local-users username bob password Bob-Pass-1
set vpn ipsec remote-access connection RW esp-group ESP-RA
set vpn ipsec remote-access connection RW ike-group IKE-RA
set vpn ipsec remote-access connection RW local-address 192.0.2.1
set vpn ipsec remote-access connection RW pool RA-POOL
set vpn ipsec remote-access pool RA-POOL prefix 10.99.0.0/24
set vpn ipsec remote-access pool RA-POOL name-server 10.0.1.53
```

Expected `swanctl.conf` fragments. The ESP line is shown before
[ipsec-syntax-parity](ipsec-syntax-parity.md)'s ESN change; after it, the line becomes
`aes256gcm128-sha256-ecp256-noesn,aes256gcm128-sha256-ecp256`.

```
connections {
    ra-RW {
        remote_addrs = %any
        local_addrs = 192.0.2.1 # dhcp:no
        proposals = aes256gcm128-sha256-ecp256
        version = 2
        send_certreq = no
        rekey_time = 28800s
        keyingtries = 0
        pools = RA-POOL
        local {
            id = "vpn.example.net"
            auth = psk
        }
        remote {
            auth = eap-mschapv2
            eap_id = %any
        }
        children {
            RW-client {
                esp_proposals = aes256gcm128-sha256-ecp256
                life_time = 3600s
                dpd_action = clear
                inactivity = 28800
                local_ts = 0.0.0.0/0,::/0
            }
        }
    }
}

pools {
    RA-POOL {
        addrs = 10.99.0.0/24
        dns = 10.0.1.53
    }
}

secrets {
    ike_RW {
        id = "vpn.example.net"
        secret = "Lab-RA-PSK"
    }
    eap-RW-alice {
        secret = "Alice-Pass-1"
        id-RW-alice = "alice"
    }
}
```

Adding `remote-access radius server 192.0.2.50 key Radius-Key` and
`client-mode eap-radius` changes the `remote` block to `auth = eap-radius`, drops the
`eap-RW-*` secrets, and hands charon-lifecycle this section:

```
charon {
    plugins {
        eap-radius {
            nas_identifier = strongSwan
            retransmit_timeout = 2.0
            servers {
                192-0-2-50 {
                    address = 192.0.2.50
                    secret = "Radius-Key"
                    auth_port = 1812
                    acct_port = 1813
                    sockets = 20
                }
            }
        }
    }
}
```

**Show example** (`show vpn ipsec remote-access summary`, `tabulate` layout via
`text::table`):

```
Connection ID  Username  Protocol  State  Uptime  Tunnel IP  Remote Host  Remote ID   IKE Proposal                              IPSec Proposal
-------------  --------  --------  -----  ------  ---------  -----------  ----------  ----------------------------------------  ------------------
3              alice     IKEv2     UP     2m5s    10.99.0.1  192.0.2.20   192.0.2.20  AES_GCM_16-256/PRF_HMAC_SHA2_256/ECP_256  ESP:AES_GCM_16-256
```

## 5. Tests

**Golden-render tests** (`ipsec.rs`):
- `ra_psk_mschapv2_golden`: the worked example, exact text, no warnings. The disabled user
  `bob` is absent.
- `ra_x509_server_golden`: `auth = pubkey`, `certs = <c>.pem`, `send_cert = always`.
  Lands with pki-x509.
- `ra_eap_tls_and_x509_client_cacerts`: `cacerts = CA1.pem,CA2.pem`.
- `ra_eap_radius_golden`: plus the drop-in keys from `ra_plugin_keys`, rendered through `charon::to_text`.
- `ra_pool_variants`: prefix, range, IPv6, exclude, two name-servers.
- `ra_pool_dhcp_and_radius_literal`; `ra_local_port_suffix` (`[%any/443]`).
- `ra_bind_if_id`; `ra_unique_childless_ppk_lines` (groupings from syntax-parity).
- `ra_dhcp_interface_resolved_and_missing`, using `RenderEnv` from syntax-parity.
- `ra_verify_findings`: one case per D6 row. Each asserts the severity, the message and
  the effect via `Findings::errors()` / `warnings()`, that the other connections still
  render, and that the file stays syntactically whole.
- `ra_validate_refuses_errors`: `ipsec::validate(parts)` over `vpn ipsec` plus `pki`
  parts returns the D6 Errors, and no secret value appears in any message.
- `empty_config_renders_empty_sections`: updated, since pools are now rendered.
- The `full_config_golden` test is unchanged; RA is absent there.

**Unit tests** (`ipsec_op.rs`):
- `ra_sessions_by_conn_prefix_includes_x509_clients`;
- `ra_summary_golden`; `ra_summary_no_vip_dash`;
- `reset_ra_all_and_user`; `ra_plugin_probe_warnings`.

**BDD: new feature `@ipsec_ra`.**
- Topology:
  - **z1**, the server: zebra-rs + insomnia + charon via `ipsec_node.sh`. `i1` is
    `192.0.2.1/24`; `d1` is `10.0.1.1/24`.
  - **c1**, the client: charon + swanctl only, via a new `bdd/tests/scripts/ipsec_client.sh`.
    That script runs the same `unshare -m` tmpfs recipe and loads a static
    `bdd/tests/configs/ipsec_ra/c1.swanctl.conf`:
    - EAP-MSCHAPv2 `alice`, PSK `vpn.example.net`, `vips = 0.0.0.0`,
      `remote_ts = 10.0.1.0/24`;
    - `start_action = start`, so no operation from outside is needed.
    - `i1` is `192.0.2.20/24`.
  - A helper `ipsec_client_ctl.sh <ns> <swanctl args>` runs swanctl inside the client's
    mount namespace with `nsenter -t <charon pid> -m`, for re-initiation.
- Host prerequisites:
  - `libcharon-extauth-plugins` (eap-mschapv2);
  - `libcharon-extra-plugins` (eap-identity);
  - the script fails fast when a plugin `.so` is missing.
- Scenarios:
  1. *Setup.* Bring up the namespaces. Apply `z1.conf` (the worked example), then wait for
     `swanctl configuration loaded`. Spawn the client.
  2. *Client connects and gets a pool address.* `show vpn ipsec remote-access summary` on z1
     eventually contains `alice` and `10.99.0.1`.
  3. *Traffic through the tunnel.* `ping -c 2 -I 10.99.0.1 10.0.1.1` in c1 eventually
     contains `2 received`.
  4. *Reset by user.* `I run "reset vpn ipsec remote-access user alice" in namespace "z1"`
     (the existing step, `bdd/tests/cucumber.rs:946-956`, which exec-verbs routes). Then
     the summary eventually does not contain `alice`.
  5. *Disabled user is refused.* Apply `set … username alice disable`; re-initiate with
     `ipsec_client_ctl.sh c1 --initiate --child home`. The summary does not contain
     `alice`, and the charon log on z1 contains `EAP` and `failed`. The exact log text is
     *unverified*.
  6. *Teardown.*
- RADIUS and DHCP pools are covered only by the golden tests. A RADIUS BDD needs
  freeradius in a third namespace and is listed as a follow-up (`@ipsec_ra_radius`).

## 6. Docs

- New `book/src/ch-02-09-remote-access.md`:
  - the modes matrix (server × client);
  - the PSK+EAP quickstart (the worked example);
  - pools and DNS; RADIUS; the plugin package requirements per mode (D5);
  - a Windows/macOS client note: these clients need x509 server auth, so PSK server mode
    works only with strongSwan or Android strongSwan clients (*unverified* per client);
  - the deviations.
- `SUMMARY.md`: add the chapter.
- `book/src/ch-03-01-show-ipsec.md`: RA views and resets.
- `ch-02-00-what-is-ipsec.md:46-47`: drop "IKEv2 remote-access … planned".
- `ch-00-01-install.md`: the optional plugin packages.
- `Cargo.toml` `[package.metadata.deb]`: add `libcharon-extauth-plugins` and
  `libcharon-extra-plugins` to `suggests`.
- zebra-rs `docs/design/vpn-ipsec-followups.md`: mark remote-access as in progress.

## 7. Milestones

| # | Scope | Repo | Effort | Done when |
|:--|:--|:--|:--|:--|
| 1 | YANG for the whole tree, plus parse tests | zebra-rs | S | `manager.rs` parse test updated and green |
| 2 | PSK server + EAP-MSCHAPv2 + named pools: render, secrets, D6 findings, goldens (after commit-validation C1 introduces `findings.rs`) | insomnia | M | Goldens and `ra_verify_findings` green; `pools {}` populated |
| 3 | RA show views + resets + exec grammar (needs exec-verbs and ipsec-opmode M1/M3) | both | S | Unit tests green |
| 4 | BDD `@ipsec_ra` scenarios 1–6 | insomnia | S | Feature green on a host with the plugins |
| 5 | RADIUS + DHCP pools: plugin sections through charon-lifecycle, plugin probe | insomnia | S | Goldens and probe tests green |
| 6 | x509 server mode, `eap-tls`/`x509` clients, `always-send-cert` (needs pki-x509) | insomnia | S | `ra_x509_server_golden` green; BDD variant with a pki-issued server cert |
| 7 | *(deferred, D8)* `generate ipsec profile ios-remote-access\|windows-remote-access` | both | M | Separate PR after pki-x509's `show pki` |
| 8 | Docs and packaging | insomnia | S | `mdbook build` clean |

## 8. Risks and open questions

- **Wildcard PSK.** `ike_<n>` always has an `id`, because local-address is mandatory. But
  if a later change allowed neither, the secret would match any identity, the X4 class of
  bug ([ipsec-render-fixes](ipsec-render-fixes.md)). `ra_verify_findings` pins that a missing
  id skips the connection.
- **PSK server mode is weak.** Anyone who has the group PSK can impersonate the server to
  EAP clients. Document it; recommend x509 server mode once pki-x509 exists.
- **Plugin packaging.** The `dhcp` plugin's package, and whether `eap-identity` is
  required, are *unverified*. The D5 probe turns either into a clear warning.
- **Reload vs restart.** Whether RADIUS/DHCP setting changes take effect on
  `--reload-settings` or need a restart: charon-lifecycle's call (*unverified*).
- **Return routing for client addresses.** Server-side routing to pool addresses relies on
  charon's table-220 routes (`install_routes` default). If `disable-route-autoinstall` is
  set ([charon-lifecycle](charon-lifecycle.md); VTI itself does not need it, since charon
  installs no routes for VTI children, ipsec-vti §2), RA without `bind` loses them. Warn
  when both are configured.
- **Encrypted keys.** VyOS writes RA x509 keys as `private/x509_<cert>.pem` but renders no
  `private_*` secret for an RA `passphrase`, so an encrypted RA key cannot load
  (`swanctl.conf.j2:124-145`).
  - Fix: [pki-x509](pki-x509.md) P5 applies its secret rule to RA too, as
    `private_ra-<n> { file = x509_<cert>.pem; secret = "…" }`.
  - Its `CredSet` includes the credentials of rendered RA connections, not only peers'
    (P4; test `ra_connection_creds`).
- **eBPF fast path.** RA traffic forwarded in XDP bypasses xfrm. That is
  [ebpf-netfilter](ebpf-netfilter.md)'s documented limit (§4.7).

## 9. Acceptance criteria

- [ ] `set vpn ipsec remote-access …` parses with `--feature insomnia` for every VyOS
      rolling leaf, and the zebra-rs parse test is updated.
- [ ] `ra_psk_mschapv2_golden` matches `remote_access.j2` and `swanctl.conf.j2` semantics
      line for line; pools render; the secrets order is psk → ppk → RA.
- [ ] Every D6 rule is a `Finding` with the listed severity and effect. Only the offending
      connection, pool or server is skipped. Errors refuse the commit through
      `ipsec::validate` once the commit-validation RPC is live.
- [ ] RADIUS and DHCP settings reach charon through charon-lifecycle's drop-in at mode
      `0600`; no distro plugin file is overwritten.
- [ ] Missing charon plugins produce one warning per connection after load.
- [ ] RA show views and resets work and include `client-mode x509` sessions.
- [ ] BDD `@ipsec_ra` is green: connect, pool address, traffic, reset, disabled user,
      teardown.
- [ ] The local-user `password`, the RA `pre-shared-secret` and the RADIUS `key` carry
      `ext:secret` (secret-redaction's table); a `<redacted:…>` placeholder is never rendered.
- [ ] Book chapter, deviations and packaging suggestions merged.
