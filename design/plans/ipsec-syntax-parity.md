# IPsec rolling-syntax parity — implementation plan

Status: plan, 2026-10-21. Covers: the §7.2 rows `connection-type trap`, `childless`,
`unique`, proposal `esn`, DH groups 33–35 (ML-KEM), `authentication ppk` + peer `ppk`,
psk `secret-type`, peer-name charset, and peer/psk `dhcp-interface`
([vyos-gap](../vyos-gap.md) §1 "Version skew", §7.2, §11 D10).
Priority:
- P2: `trap` (pasting current VyOS configs) and `dhcp-interface`.
- P3: the rest. ML-KEM stays P3 per D10.

Effort: S per item, M overall · Owner: both
Depends on:
- [ipsec-render-fixes](ipsec-render-fixes.md): X4 (psk without id), X5 and X6
  (`global_unique`). Land this after it so the goldens change once per cause.
- [exec-verbs](exec-verbs.md): the bounded `vici::request` for `version`, and the `Arc`
  retained model (`ShowState.model`). Used by the ML-KEM probe and the `dhcp-interface`
  re-render.
- [secret-redaction](secret-redaction.md): `ext:secret` on the PPK `secret` leaf, and
  placeholder handling.
- [commit-validation](commit-validation.md): `findings.rs`. Every rule below is a `Finding`
  with a severity and an effect, `render()` returns `(String, Findings)`, and
  `ipsec::validate(parts)` refuses the Errors at commit once the RPC exists.
- [multi-path-subscribe](multi-path-subscribe.md): optional, only for the later
  `interface`-tree check in D-dhcp.

Unblocks: [ipsec-remote-access](ipsec-remote-access.md), which reuses the `childless`,
`unique` and `ppk` groupings and the `dhcp-interface` resolver.

## 1. Goal

- A `vpn ipsec` config written for VyOS rolling (IPsec syntax v14) loads unchanged:
  - `connection-type trap`;
  - `childless`, `unique`;
  - proposal `esn`;
  - `dh-group 33..35` and `pfs dh-group33..35`;
  - `authentication ppk …` and peer `authentication ppk id|required`;
  - psk `secret-type`.

  The 1.5 spelling `respond` keeps working.
- The renders match `peer.j2`, `swanctl.conf.j2` and `template.py`
  `_get_esp_ike_cipher` for those leaves. That includes rolling's `X-noesn,X` ESP
  proposal pairs.
- `show vpn ipsec connections` gains rolling's PPK column.
- Peer and psk names that would break `swanctl.conf`, or that collide after dashing, are
  Error findings and are skipped. The accepted dotted-name deviation is documented.
- `dhcp-interface` (peer and psk) works from the interface's current kernel address, and
  re-renders when that address changes. No zebra-rs DHCP client is required.

## 2. Current state

**zebra-rs @ 141da2fc** (`ipsec.yang`, a VyOS 1.5 port, `ipsec.yang:15-19`):
- `connection-type` is `initiate | respond | none` (`ipsec.yang:473-480`).
- IKE `dh-group` range is `1..2 | 5 | 14..32` (`349-354`). ESP `pfs` enums stop at
  `dh-group32` (`226-254`).
- `psk` has `dhcp-interface*`, `id*` and `secret`, with no `secret-type` (`155-179`).
- There is no `ppk`, `childless`, `unique` or `esn`.
- Peer name is `type string` (`443-446`). Peer `dhcp-interface` is a single leaf
  (`494-497`).
- The parse test pins today's shape: `manager.rs:7816` (`respond`), and `dh-group 3`
  rejected at `manager.rs:7856`.
- `interface X ipv4 address dhcp` is an insomnia-gated enum arm that "stores config
  without acting on it" (`config.yang:5787-5813`). No DHCP client exists.
- There is no config-value migration machinery. `RENAMED_FEATURES` (`manager.rs:363-367`)
  renames feature flags only.

**insomnia @ ee4dfaa** (`src/ipsec.rs`):
- Connection type:
  - `respond` renders `keyingtries = 1` (`717-719`) and `start_action = trap` (`813`).
  - Any other value falls to `none` (`814`), so `trap` would silently become `none` once
    the schema allowed it.
- `dh_group_name` ends at 32 (`328-354`). `cipher_strings` has no ESN handling
  (`384-427`).
- `render_psk` emits `secret = "<s>"` only (`584`), and warns on `dhcp-interface`
  (`574-579`).
- `render_peer` skips any peer that has `dhcp-interface` (`616-621`). `local_addrs` always
  carries `# dhcp:no` (`676`).
- `conn_name` strips `@` and dashes `.` and `:` (`431-433`). Nothing checks other
  characters or collisions. psk names go into `ike-<name>` unmapped (`580`).
- The connections table has nine columns and no PPK column (`1312-1371`); its test is at
  `1923-1993`.

**VyOS @ 7f2c893:**
- Syntax version 14 (`include/version/ipsec-version.xml.i`).
- `src/migration-scripts/ipsec/13-to-14` renames `connection-type respond` to `trap`
  (T7594).
- `peer.j2`:
  - `ppk_id`, `ppk_required`, `childless` come before `proposals` (`13-21`);
  - `unique` (peer, else global) comes after `encap` (`52-59`);
  - `trap` → `keyingtries = 1` (`49-50`) and `start_action = trap` (`120-121`, `184-185`).
- `swanctl.conf.j2`: psk `secret-type` (`92-98`) and `ppk-<n>` secrets (`103-122`).
- `template.py:497-588`:
  - ML-KEM `mlkem512|768|1024` for groups 33–35;
  - ESN for ESP only: `required` → `-esn`; `optional` → `X-esn-noesn, X`; `disabled`
    (the default) → `X-noesn, X`;
  - IKE ignores ESN (T9254).
- `include/vpn-ipsec-esn.xml.i` (default `disabled`), `include/ipsec/ppk.xml.i`,
  `childless.xml.i`, `vpn-ipsec-unique.xml.i`.
- `vpn_ipsec.py`:
  - PPK id and secret required, ids unique (277-289);
  - ppk/childless need IKEv2 (738-753);
  - peer name must not contain `.` or `:` (605-608);
  - dhcp handling (665-694, 887-893, 922-929);
  - `get_dhcp_address` takes the first non-link-local address on the interface, which may
    come from any source (221-228).
- The re-render trigger is a dhclient exit hook,
  `src/etc/dhcp/dhclient-exit-hooks.d/99-ipsec-dhclient-hook`.
- `src/op_mode/ipsec.py:232-252`, `360-370`, `436`, `482-497`: the PPK column and legend.

**strongSwan on the reference host** (Ubuntu 24.04, 5.9.13, `man swanctl.conf`):
- documents `childless` (RFC 6023), `ppk_id`, `ppk_required` and `unique`;
- secrets accept `0x…` and `0s…` encodings;
- no ML-KEM, which needs strongSwan ≥ 6.0.

## 3. Design

**D-trap: `trap` is an alias of `respond` (both spellings stay).**
- YANG gains `enum trap`. `respond` stays, documented as the VyOS ≤ 1.5 spelling.
- insomnia treats the two identically (`ipsec.rs:717`, `813`).
- **Rejected:**
  - Renaming outright: it breaks stored configs, and zebra-rs has no value migration.
  - Rewriting `respond` to `trap` at load time: that needs new zebra-rs machinery for a
    cosmetic gain.
- DEVIATION: a superset of VyOS rolling, which no longer accepts `respond` after its
  migration. Record it in `ipsec.rs` and in the `ipsec.yang` description.
- [ipsec-opmode](ipsec-opmode.md)'s reset rule keys on `start_action`, so it needs no
  change.

**D-childless / D-unique.**
- New groupings `ipsec-childless` and `ipsec-unique` in `ipsec.yang`, used by peer here
  and by RA in [ipsec-remote-access](ipsec-remote-access.md).
- Render positions follow `peer.j2`: `childless` before `proposals`; `unique` after
  `encap`.
- `unique = <peer.unique or global_unique>`. `global_unique` comes from the X6 fix in
  [ipsec-render-fixes](ipsec-render-fixes.md) (`disable-uniqreqids` → `never`). A
  remote-access connection renders its own `unique` only, with no global fallback
  (VyOS; [ipsec-remote-access](ipsec-remote-access.md) D3).
- `childless` without explicit `key-exchange ikev2` (a VyOS `ConfigError`): finding
  **Error**, `Dropped("childless")`. The line is omitted and the connection still loads,
  since no security property depends on `childless`.

**D-esn: follow rolling exactly, including the default.**
- `esn` is added to esp-group proposals, and to ike-group proposals as well (VyOS has it
  in both schemas, `vpn_ipsec.xml.in:309`, `626`; IKE ignores it).
- ESP rendering when `esn` is absent: insomnia applies VyOS's `defaultValue disabled`,
  the `ipsec.rs:316-318` convention. So every ESP proposal becomes `X-noesn,X`.
- **This is a deliberate golden change** to every `esp_proposals` line:
  - Reason: a config pasted from VyOS then renders the same proposal set, and charon's
    matching against peers that do send an ESN transform is the same as on VyOS.
  - The two proposals are equivalent for strongSwan peers: strongSwan treats a missing ESN
    transform as no-ESN.
  - The commit message must say this.
- **Rejected:** emitting ESN only when it is configured. That keeps today's goldens but
  silently diverges from the rolling template on every ESP line.

**D-mlkem: accept and render; probe at apply time.**
- Range `1..2 | 5 | 14..35`; enums `dh-group33..35`; `dh_group_name` maps 33→`mlkem512`,
  34→`mlkem768`, 35→`mlkem1024`.
- The renderer stays pure. After `swanctl -q`, when a loaded config uses groups 33–35
  and `vici::request(socket, "version", …)` (exec-verbs) reports a major version below
  6, log one warning:
  `dh-group 34 (mlkem768) needs strongSwan >= 6.0 with ML-KEM support; charon is 5.9.13`.
- This is an apply-time log line, not a render `Finding`. The charon version is host
  state, and `validate` must stay deterministic (commit-validation §3.2).
- swanctl then fails that one connection. That the others still load is *unverified*.
- Which distro builds ship strongSwan ≥ 6.0 with a backend providing ML-KEM (the `ml`
  plugin, or OpenSSL ≥ 3.5) is *unverified*.
- VyOS renders ML-KEM as the only key exchange (`…-mlkem768`), not strongSwan 6's hybrid
  `ke1_` syntax. Kept for parity; see §8.

**D-ppk.**
- A new `authentication ppk <name> { id*, secret, secret-type }` list, plus peer
  `authentication ppk { id, required }` (grouping `ppk-ref`).
- Rendering:
  - peer: `ppk_id = "<id>"`, then `ppk_required = yes`;
  - secrets: `ppk-<name> { id-N = "…"; secret = … }` after the psk entries.
  - DEVIATION: `ppk_id` is quoted; VyOS renders it bare, which breaks ids with spaces.
- Findings (commit-validation §3.2). These leaves are new, so the upgrade-safety rule
  does not constrain the effects:
  - ppk entry missing `id` or `secret` (`vpn_ipsec.py:280-283`): **E**, entry skipped.
  - Duplicate ppk id across entries (`:284-289`): **E**, later entry skipped.
  - A `<redacted:…>` ppk secret (secret-redaction): entry skipped, as it specifies for psk.
  - Peer ppk without explicit IKEv2 (`:738-743`): **E**, **peer skipped**, because
    silently dropping `ppk_required` would weaken it.
  - Peer ppk id not present in any ppk entry: **W**, kept. With `required` the connection
    can never come up. VyOS's comment promises this check but its code does not make it.
  - ppk without `childless`: **W**, kept. The VyOS text is "It is recommended to use
    childless IKE SAs when using PPKs".
- Layer-1 YANG: `mandatory true` on `authentication ppk <n> secret`. The leaf is new, so
  plain `mandatory` is safe without `ext:startup-tolerant`. `id` is a leaf-list and stays
  a finding.
- **PPK column.** `show vpn ipsec connections` gains column `PPK` and VyOS's legend line.
  - The IKE row is `<none|opt|req>/<no|yes>`; child rows are `-`. JSON gains `"ppk"`.
  - Source: `list-conns` `ppk_id`/`ppk_required` and `list-sas` `ppk`, as VyOS reads
    them. Whether 5.9.13's VICI emits these keys is *unverified*. If it does not, the
    configured half comes from the retained model (exec-verbs' `ShowState.model`) and
    the negotiated half reads `no`.

**D-secret-type.**
- `secret-type base64|hex|plaintext` on psk and ppk.
- Rendering: `0s<v>` / `0x<v>` / `"<v>"`. Absent means `plaintext`, today's output.
- Validation: base64 must match `[A-Za-z0-9+/]+={0,2}` with length a multiple of 4; hex
  must match `[0-9A-Fa-f]+` with even length.
- Otherwise: **E** (a token the renderer cannot hand to charon), entry skipped. charon is
  never handed a mis-encoded key. The message names the entry, never the value.

**D-names: keep the dotted-name deviation; add safety checks.**
- Keep accepting `.` and `:` in peer names, and keep dashing them.
  - VyOS rejects them since T4118, but the BDD itself uses `peer 192.0.2.9`, and so do
    existing configs.
  - Document the deviation.
- No finding for dotted names. VyOS rejects them, which under commit-validation §3.2 (a)
  would make them an Error. The recorded deviation overrides that, so existing configs
  keep committing.
- After mapping, a peer section name must match `[A-Za-z0-9_|-]+` (VyOS's
  `[-_a-zA-Z0-9|@]+` minus `@`, which is stripped).
  - Otherwise: **E**, peer skipped,
    `peer <p>: name contains characters swanctl.conf cannot carry`.
  - That is the load-safety exception to upgrade safety: such a name breaks the whole
    `swanctl.conf`.
- **Collisions.** `192.0.2.9` and `192-0-2-9`, or `@x` and `x`, map to one section, which
  strongSwan would merge or reject (*unverified* which).
  - **E**: the later name in sort order is skipped, and the message names both.
  - `Skipped` rather than upgrade-safe `Kept` claims commit-validation's security
    exception: a merged section mixes two peers' identities and auth settings. That claim
    needs commit-validation's agreement; if it is refused, the effect is `Kept`.
- psk and ppk names now go through the same dash mapping, plus the charset and collision
  check, for the `ike-<n>`/`ppk-<n>` section name.
  - VyOS leaves psk names unconstrained and emits them raw. strongSwan settings paths are
    `.`-separated, so a dotted name breaks there as it does for peers (T4118).
  - DEVIATION: psk and ppk names are dashed for the section name only. No reference
    resolves through a psk name, so this changes no behaviour.
- Quoted values introduced here (the `ppk_id`, the ppk `id-N`, and the dhcp-derived
  `id-N`) go through ipsec-render-fixes' `quoted_ok` guard (X4b). Section names are
  unquoted, so they get the charset check instead.
- **Rejected:** a YANG `pattern` on the key. In this CLI a patterned string leaf
  consumes the rest of the line (`ipsec.yang:36-42`). The rule moves to commit time with
  [commit-validation](commit-validation.md).

**D-dhcp: read the address from the kernel, poll, and re-render on change.**
- The current kernel address is what VyOS reads too: `get_dhcp_address` takes the first
  non-link-local address on the interface, whatever assigned it. So the "interim" is the
  final design. A future zebra-rs DHCP client (or networkd, or a manual address) only
  changes who assigns it.
- **Resolution.** `RenderEnv { iface_addrs: BTreeMap<String, Vec<IpAddr>> }` is built
  from one `ip -j addr show` call.
  - Entries with `scope link`, `tentative` or `dadfailed` are dropped.
  - Pick: the family of the peer's first literal `remote-address`, else IPv4 first.
    DEVIATION: VyOS takes whatever comes first.
- **Rendering.**
  - `render_with(cfg, &env)` is pure. `render(cfg)` keeps its signature, with
    `RenderEnv::default()`, so the existing goldens are untouched.
  - The peer gets `local_addrs = <addr> # dhcp:<if>`, and the transport-mode `local_ts`
    uses the same address.
  - Each psk gets one extra `id-N` per resolved interface, after the static ids. A psk
    whose only ids are unresolved interfaces is skipped, consistent with X4.
- **Findings.** These replace commit-validation's IPsec rows `:575` and `:617`
  ("dhcp-interface unsupported").
  - No address yet: **W** (host state), peer skipped:
    `peer <p>: dhcp-interface <if> has no address yet`. VyOS prints the same, `-- skipped`.
    For a psk: **W**, static ids only.
  - `local-address` and `dhcp-interface` both set (VyOS accepts; `local-address` wins,
    generate 887-891): **W**, `Adjusted("local-address used")`.
  - With `vti`, both set (VyOS `ConfigError`, 693-694): **E**, peer skipped. That is
    today's effect for every dhcp peer, so upgrade-safe.
- **Validation is deterministic.** `ipsec::validate(parts)` renders with
  `RenderEnv::default()`. Address-dependent outcomes are therefore only ever Warnings, as
  commit-validation requires for host state.
- **Re-render.**
  - The IPsec task adds a 5 s `interval` arm to its `select!` (`ipsec.rs:67-83`). It is
    active only while the retained model (exec-verbs' `ShowState.model`) names a
    `dhcp-interface` (a peer, a psk, or a remote-access connection,
    [ipsec-remote-access](ipsec-remote-access.md) D6).
  - On a tick it rebuilds `RenderEnv`. If the watched interfaces' addresses changed, it
    renders and runs `swanctl_apply`. An unchanged env does nothing.
  - Commit events keep today's always-load behaviour.
- **Rejected:**
  - A dhclient hook, as VyOS does: it ties insomnia to one DHCP client.
  - `ip monitor` as a long-lived child: process lifecycle to manage.
  - An rtnetlink crate: a new dependency. Polling at 5 s is enough for a WAN lease
    change, and costs one `ip` exec.
- **No zebra-rs work required.** Optional later: warn when the interface is not
  configured `ipv4 address dhcp`. That needs the `interface` tree.
  - The path is appended to the IPsec backend's single path list (multi-path D-10;
    `subscribe_json_multi(…, Fallback::PrimaryOnly)`, read with `json::parse_subtree`).
    It is not a second stream.
  - The backend must then compare before apply, because every interface commit would
    wake it.

**Module-doc changes** (`ipsec.rs:19-33`):
- Replace the `dhcp-interface` bullet (`28-30`) with D-dhcp.
- Add D-trap, D-names (dotted names, psk dashing), the quoted `ppk_id`, and D-mlkem's
  probe.

## 4. Changes

### zebra-rs

`ipsec.yang` (sketch):

```yang
grouping ipsec-childless {
  leaf childless { ext:help "Enable support for childless IKE SA initiation (IKEv2 only)";
    type enumeration { enum allow; enum prefer; enum force; enum never; } } }
grouping ipsec-unique {
  leaf unique { ext:help "Connection uniqueness enforcement policy";
    type enumeration { enum never; enum keep; enum replace; } } }
grouping ppk-ref {
  container ppk { ext:help "Post-quantum preshared key";
    leaf id { ext:help "Post-quantum preshared key for this connection"; type string; }
    leaf required { ext:help "Require a valid PPK for connection to establish"; type empty; } } }
grouping secret-type {
  leaf secret-type { ext:help "Secret type (VyOS default: plaintext)";
    type enumeration { enum base64; enum hex; enum plaintext; } } }

// authentication (ipsec.yang:155-179): psk gains `uses secret-type;` and a sibling list
list ppk { key "name"; leaf name { type string; } leaf-list id { type string; }
           leaf secret { mandatory true; ext:secret "IPsec post-quantum preshared key"; type string; }
           uses secret-type; }

// proposal lists (esp 255-265, ike 340-368)
leaf esn { ext:help "Extended Sequence Number (ESN) (VyOS default: disabled)";
  type enumeration { enum optional; enum required; enum disabled; } }

// ike dh-group (349-354): range "1..2 | 5 | 14..35"; help mentions 33-35 = ML-KEM
// esp pfs (226-254): + enum dh-group33; enum dh-group34; enum dh-group35;

// peer (440-590)
leaf connection-type { type enumeration {
  enum initiate; enum trap;
  enum respond { description "VyOS <= 1.5 spelling of trap (vyos-1x migration ipsec/13-to-14)"; }
  enum none; } }
uses ipsec-childless;  uses ipsec-unique;
// peer authentication: uses ppk-ref;
```

- Help texts: [ipsec-remote-access](ipsec-remote-access.md) uses the same groupings.
- **Parse test** (`manager.rs:7764-7890`). Add to `ok`:
  - `… connection-type trap`;
  - `… childless prefer`;
  - `… unique replace`;
  - `… esp-group ESP-1 proposal 10 esn optional`;
  - `… ike-group IKE-1 proposal 10 dh-group 34`;
  - `… esp-group ESP-1 pfs dh-group35`;
  - `… authentication ppk PQ id pq1`, `… ppk PQ secret x`, `… ppk PQ secret-type hex`;
  - `… authentication psk GW secret-type base64`;
  - `… peer OFFICE-A authentication ppk id pq1`, `… ppk required`.

  Add to `bad_with_insomnia`: `dh-group 36`, `esn sometimes`, `childless always`.
  `respond` stays in `ok`.

### insomnia (`src/ipsec.rs`)

- **Model:**
  - `Peer` gains `childless`, `unique: Option<String>`.
  - `PeerAuth` gains `ppk: Option<PpkRef { id: Option<Flex>, required: bool }>`.
  - `Proposal` gains `esn: Option<String>`.
  - `Psk` gains `secret_type`.
  - `Authentication` gains `ppk: Vec<Ppk>`.
- **Proposal strings.** `cipher_strings(…, is_ike, …)`: in the ESP branch, push the
  `-noesn` / `-esn-noesn` twin before the base string, exactly in `template.py` order.
  `dh_group_name` gains 33–35.
- **`render_peer`:**
  - ppk / childless lines before `proposals`;
  - `unique` after `encap`;
  - `trap` alongside `respond` at `717`;
  - `start_action` at `813`;
  - the `local_addrs` comment and address come from `RenderEnv`.
- **`render_psk`:** `secret-type`, dhcp ids, the dashed section name. New `render_ppk`.
- **Name checks.** `fn section_name(raw) -> Result<String, String>` and a collision set
  per section kind (peers, psk, ppk), inside `render_with`.
- **`format_connections_table` / `connections_raw`:** the PPK column and legend.
- **Address resolver.** `fn iface_addrs() -> RenderEnv`: `ip -j addr show`, parsed with
  serde_json.
- **The interval arm in `run`.**

**Worked example 1: rolling-style peer.**

```
set vpn ipsec authentication ppk PQ id pq-branch
set vpn ipsec authentication ppk PQ secret 00112233445566778899aabbccddeeff
set vpn ipsec authentication ppk PQ secret-type hex
set vpn ipsec site-to-site peer 192.0.2.9 connection-type trap
set vpn ipsec site-to-site peer 192.0.2.9 childless prefer
set vpn ipsec site-to-site peer 192.0.2.9 unique replace
set vpn ipsec site-to-site peer 192.0.2.9 authentication ppk id pq-branch
set vpn ipsec site-to-site peer 192.0.2.9 authentication ppk required
set vpn ipsec esp-group ESP-A proposal 10 esn optional
```

On top of the `FULL` fixture (`ipsec.rs:1429-1516`), the connection changes to:

```
    192-0-2-9 {
        ppk_id = "pq-branch"
        ppk_required = yes
        childless = prefer
        proposals = aes256gcm128-sha256-prfsha384-ecp256,aes256-sha512-modp1024
        version = 2
        …
        keyingtries = 1
        unique = replace
        local {
        …
            192-0-2-9-tunnel-1 {
                esp_proposals = aes256gcm128-sha256-ecp256-esn-noesn,aes256gcm128-sha256-ecp256
                …
                start_action = trap
```

and `secrets {}` gains, after `ike-MAIN`:

```
    ppk-PQ {
        id-1 = "pq-branch"
        secret = 0x00112233445566778899aabbccddeeff
    }
```

**Worked example 2: the ESN default golden change.** The `full_config_golden` lines become:

```
                esp_proposals = aes256gcm128-sha256-ecp256-noesn,aes256gcm128-sha256-ecp256   (tunnel-1, tunnel-3, vti)
                esp_proposals = aes128-sha1-modp2048-noesn,aes128-sha1-modp2048               (tunnel-2)
```

IKE `proposals =` lines are unchanged (T9254).

**Worked example 3: dhcp-interface.**

```
set vpn ipsec site-to-site peer 192.0.2.9 dhcp-interface eth0     (no local-address)
set vpn ipsec authentication psk MAIN dhcp-interface eth0
```

With `RenderEnv { eth0: [198.51.100.7] }`:
- the peer renders `local_addrs = 198.51.100.7 # dhcp:eth0`;
- `ike-MAIN` gains `id-3 = "198.51.100.7"`.

With `eth0` unaddressed:
- warnings `peer 192.0.2.9: dhcp-interface eth0 has no address yet; skipped` and
  `authentication psk MAIN: dhcp-interface eth0 has no address yet`;
- `ike-MAIN` keeps its two static ids.

**Show example (PPK column):**

```
PPK Codes: none - Not Configured, opt - PPK is Optional, req - PPK is required, no - PPK not negotiated, yes - PPK negotiated
Connection          State  Type   Remote address  Local TS     Remote TS    Local id  Remote id  Proposal                                 PPK
------------------  -----  -----  --------------  -----------  -----------  --------  ---------  ---------------------------------------  -------
192-0-2-9           up     IKEv2  192.0.2.9       -            -            left      right      AES_CBC/256/HMAC_SHA2_256_128/MODP_2048  req/yes
192-0-2-9-tunnel-1  up     IPsec  192.0.2.9       10.0.1.0/24  10.0.2.0/24  left      right      AES_GCM/256/None/None                    -
```

## 5. Tests

**Golden and unit tests** (`ipsec.rs`):
- `connection_type_trap_alias`: `respond` and `trap` render byte-identical.
- `childless_unique_ppk_golden`: worked example 1. The secrets order is psk → ppk.
- `unique_peer_overrides_global`: with X6's `disable-uniqreqids`.
- `childless_without_ikev2_dropped`; `ppk_without_ikev2_skips_peer`; `ppk_id_unknown_warns`;
  `ppk_duplicate_id_skipped`; `ppk_missing_secret_skipped`; `ppk_placeholder_skipped`.
- `findings_severity_and_effect`: one row per finding in §3. It asserts `Severity`, the
  message (which never contains a secret) and the `Effect`, through `Findings::errors()` /
  `warnings()` (commit-validation).
- `validate_is_env_independent`: `ipsec::validate` on a dhcp-interface config yields only
  Warnings for the address-dependent cases.
- `esn_variants`: absent, `disabled`, `optional`, `required`; and IKE ignoring `esn`.
- `full_config_golden` and `cipher_string_pfs_variants`: updated deliberately (worked
  example 2).
- `mlkem_groups_render`: 33/34/35 for IKE and pfs.
- `secret_type_variants`, plus invalid base64/hex skipped.
- `peer_name_charset_rejects`: space, `"`, `{`, `#`, `=`, `/`.
- `peer_name_collision_skips_later`: `192.0.2.9` vs `192-0-2-9`, and `@x` vs `x`.
- `psk_name_dashed_and_collision`.
- `dhcp_interface_peer_and_psk`: worked example 3 via `render_with`.
- `dhcp_interface_unresolved_skips`; `dhcp_local_address_precedence`;
  `dhcp_vti_both_set_skips`; `dhcp_family_follows_remote`.
- `iface_addrs_parses_ip_json`: a captured `ip -j addr show` fixture, with link-local and
  tentative entries.
- `connections_table_from_vici`: updated for the PPK column and legend, plus
  `connections_ppk_states` (none/opt/req × no/yes).

**BDD: new feature `@ipsec_parity`.** Same two-node topology as `ipsec_s2s`, reusing
`ipsec_node.sh`. Configs in `bdd/tests/configs/ipsec_parity/`.
1. *Setup.* z2 uses `connection-type trap`; both nodes use `childless prefer`,
   `unique replace`, `esn optional`, PPK `required` with a hex secret, and a base64 PSK.
   The responder is applied first, as in `ipsec_s2s`. Then `show vpn ipsec sa` on z1
   eventually contains `192-0-2-9-tunnel-1`.
2. *PPK negotiated.* `show vpn ipsec connections` on z1 contains `req/yes`. Whether 5.9.13
   negotiates PPK in this combination is *unverified*; if it does not, record that in this
   doc and mark the scenario `@wip`.
3. *dhcp-interface follows the address.*
   - Delete `192.0.2.1/24` from `i1` on z1 (`I execute "ip addr del …"`), and apply a
     variant that replaces `local-address` with `dhcp-interface i1` and adds
     `dhcp-interface i1` to the psk.
   - The insomnia log eventually contains `dhcp-interface i1 has no address yet`.
   - Add the address back. The insomnia log eventually contains
     `swanctl configuration loaded`, and `show vpn ipsec sa` eventually contains the tunnel.
4. *Teardown.*

ML-KEM has no BDD (no strongSwan ≥ 6 on the reference host).

## 6. Docs

- `book/src/ch-02-02-site-to-site.md:46`, `:72-73`: document `trap`, with `respond` as the
  accepted legacy spelling. Change the example to `trap`.
- `ch-02-08-nat-traversal.md:28`: change the example to `trap`.
- `ch-02-01-ikev2.md`: ESN, childless, unique, ML-KEM (with the strongSwan ≥ 6.0 note) and
  PPK.
- `ch-02-03-authentication.md`: `secret-type`, PPK, and `dhcp-interface` for psk ids.
- `ch-02-02-site-to-site.md`: `dhcp-interface` (kernel-address semantics, the 5 s
  re-render) and the peer-name rules (dotted names accepted and dashed; the charset;
  collisions).
- `ch-03-01-show-ipsec.md`: the PPK column.
- `appendix-a-supported-rfcs.md`: rows for RFC 6023 (childless), RFC 8784 (PPK), RFC 4304
  (ESN), and the ML-KEM IKEv2 draft/RFC as *conditional on strongSwan ≥ 6.0*.
- `ipsec.rs` module doc per §3.

## 7. Milestones

| # | Scope | Repo | Effort | Done when |
|:--|:--|:--|:--|:--|
| 1 | `trap` alias | zebra-rs + insomnia | S | `connection_type_trap_alias` and the parse test green; book updated |
| 2 | `childless`, `unique` (after ipsec-render-fixes X6; findings need commit-validation C1's `findings.rs`) | both | S | Goldens and findings tests green |
| 3 | `esn` + the deliberate golden update | both | S | `esn_variants` green; commit message explains the change |
| 4 | PPK table, peer ppk, PPK column | both | S | PPK tests green |
| 5 | psk/ppk `secret-type` | both | S | `secret_type_variants` green |
| 6 | DH 33–35 + apply-time version warning (needs exec-verbs `version`) | both | S | `mlkem_groups_render` green; warning unit-tested with a fake version |
| 7 | Name charset, collisions, psk name dashing | insomnia | S | Name tests green |
| 8 | `dhcp-interface` resolver, `render_with`, interval re-render (needs exec-verbs' retained model) | insomnia | M | dhcp tests green |
| 9 | BDD `@ipsec_parity` | insomnia | S | Scenarios 1, 3, 4 green; scenario 2 green or recorded `@wip` |

Milestones 1–7 are independent once [ipsec-render-fixes](ipsec-render-fixes.md) has
landed. Milestone 8 is independent of 1–7.

## 8. Risks and open questions

- **ESN golden change.** It touches every ESP line. If a peer implementation rejects
  duplicate equivalent proposals, interop breaks the same way VyOS rolling's does. Watch
  for it; the fallback is D-esn's rejected alternative.
- **ML-KEM syntax.** strongSwan 6 recommends hybrid `ke1_mlkem*`. VyOS renders the pure
  form. A future VyOS change would need a new leaf; D10 keeps this P3.
- **VICI PPK keys** on 5.9.13 are *unverified*; a fallback is defined.
- **Address poll churn.** A flapping interface re-renders at most once per 5 s. Each
  re-render runs `swanctl -q`, which reloads only changed connections (*unverified*
  charon behaviour for unchanged ones).
- **Old configs with clashing names.** Two names that already collide will now lose one
  connection with a warning. Today both render into one merged section, which is already
  broken.
- **Who owns the shared groupings.** `childless`, `unique` and `ppk-ref` are defined here
  and consumed by [ipsec-remote-access](ipsec-remote-access.md). If remote access lands
  first, it must take this plan's milestones 2 and 4 with it rather than define its own.

## 9. Acceptance criteria

- [ ] Every §1 leaf parses with `--feature insomnia`; `respond` still parses.
- [ ] `trap` and `respond` render identically; `trap` never falls through to `none`.
- [ ] ESP proposals match `template.py` for absent, `disabled`, `optional` and `required`
      ESN; IKE proposals carry no ESN.
- [ ] `ppk_id`, `ppk_required`, `childless` and `unique` appear in `peer.j2` order; the
      `ppk-<n>` secrets follow the psk.
- [ ] `secret-type` encodes as `0s`/`0x`/quoted; a malformed value is an Error finding
      and its entry is skipped.
- [ ] Unsafe or colliding peer, psk and ppk names are Error findings and are skipped; the
      file always parses.
- [ ] `dhcp-interface` peers and psk ids track the kernel address within 5 s, and no
      reload happens while the address is unchanged.
- [ ] `show vpn ipsec connections` shows the PPK column and legend.
- [ ] Every rule here is a `findings.rs` `Finding` with the severity and effect stated in
      §3. `ipsec::validate` is deterministic, and the ppk `secret` carries `ext:secret`.
- [ ] Book, appendix A and the module doc are updated; the deviations are recorded.
