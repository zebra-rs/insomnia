# IPsec render fixes — implementation plan

Status: plan, 2026-10-21. Covers: X3, X4, X5, X6, X7, X8 (interim), X13 ([vyos-gap](../vyos-gap.md) §3, §7.2).
Priority: P1 (X3, X4, X13), P2 (X5–X7), P1-with-VTI (X8) · Effort: S · Owner: insomnia
Depends on: none · Unblocks: [ipsec-vti](ipsec-vti.md) (X8 final), [commit-validation](commit-validation.md) (these skips become validation errors), [docs-corrections](docs-corrections.md) (ch-02-01 / appendix A reauth wording), [charon-lifecycle](charon-lifecycle.md) and [pki-x509](pki-x509.md) (both reuse the X13 helper `fsutil::write_private_atomic`), [ipsec-syntax-parity](ipsec-syntax-parity.md) (lands after X4, X5 and X6 so the goldens change once per cause), [ipsec-remote-access](ipsec-remote-access.md) (lands after X4 and X6: the X4b guard and the X6 scope below), [secret-redaction](secret-redaction.md) (S10's create-with-final-mode rule is the X13 helper)

Baselines: insomnia `ee4dfaa`, zebra-rs `141da2fc`, vyos-1x `7f2c893`, strongSwan 5.9.13 (Ubuntu 24.04 host).

## 1. Goal

- A bypass ("passthrough") child is rendered only for a local prefix that is strictly inside a remote prefix of the same family, in tunnel mode. `local 0.0.0.0/0`, a local supernet, or local == remote never produces a pass policy over the tunnel's own traffic.
- An `authentication psk` entry with no static `id` is not loaded, and a warning names it. No wildcard PSK can be rendered.
- `ikev2-reauth` behaves as in VyOS rolling: `reauth_time = <ike lifetime>s` for IKEv2 initiators that opt in.
- `disable-uniqreqids` renders `unique = never` in every connection, with no charon restart.
- `tunnel N protocol all` loads.
- No connection references the non-existent `/etc/ipsec.d/vti-up-down` helper.
- A secret-bearing file (`swanctl.conf`, `keepalived.conf`) is never readable by group or other at any moment, under any umask (X13).
- A BDD feature shows X3 (traffic stays encrypted with `local 0.0.0.0/0`) and X4 (an unknown identity is rejected) against real charon.

## 2. Current state

| # | insomnia @ `ee4dfaa` | VyOS @ `7f2c893` |
|:--|:--|:--|
| X3 | `render_tunnel_child` builds the passthrough list with `nets_overlap` in either direction (`src/ipsec.rs:1013-1032`). `nets_overlap` returns true for any plen 0 in-family (`:476-479`). The block runs after the mode branch (`:961-992`), so transport-mode tunnels get pass children from prefixes they do not even use as selectors. Test `overlap_detection` pins the bug (`:1709` supernet ⊃ subnet, `:1716` `0.0.0.0/0` overlaps a /24). The FULL golden's passthrough (`:1586-1591`, 10.0.3.0/24 ⊂ 10.0.0.0/8) is a correct case. | `generate()` skips `dynamic`, the XML default (`vpn_ipsec.xml.in:1286,1326`; `vpn_ipsec.py:876,906,910`), and adds a local prefix only if `local_net.subnet_of(remote_net)` (`:915-918`). The template renders it (`peer.j2:205-212`). Transport mode forbids prefixes (`vpn_ipsec.py:723`, ConfigError). |
| X4 | `render_psk` writes `ike-<name> { secret = … }` with zero `id-N` lines when `id` is empty, including when only `dhcp-interface` is set: that case only warns (`:563-586`, `:574-579`). | `verify()` refuses a psk with no `id` or no `secret` (`vpn_ipsec.py:271-276`), even when `dhcp-interface` is set. |
| X5 | `IkeGroup.ikev2_reauth` (`:215`) and `Peer.ikev2_reauth` (`:265`) are parsed and never read. `reauth_time = 0` is written only for `@` peers (`:711-719`). | Effective value (`peer.j2:6-12`): peer `yes` → on; `inherit` → the ike-group's valueless leaf; unset or `no` → off. The peer leaf has no `defaultValue` (`vpn_ipsec.xml.in:1245-1267`), so an ike-group leaf alone does nothing. Rendered only for `connection-type` unset/`initiate`, non-`@` peers, and `key-exchange ikev2` (`peer.j2:44-48`). `verify()` refuses it with a non-IKEv2 group (`vpn_ipsec.py:757-768`). |
| X6 | Folded into the "charon-level, not applied" warning (`:548-558`; module doc `:25-27`). | `global_unique = 'never'` (`swanctl.conf.j2:7`), rendered per connection after `encap` (`peer.j2:55-59`). |
| X7 | The suffix closure renders `[all/<port>]` (`:929-941`). | `proto = '' if proto == 'all'` (`peer.j2:138-143`). |
| X8 | `updown = "/etc/ipsec.d/vti-up-down <bind>"` in the `-vti` child (`:879`) and in tunnel children with a bind (`:1001`). The package ships only the binary (`Cargo.toml:91-93`). | Ships `src/etc/ipsec.d/vti-up-down`, a Python script built on `vyos.configquery`, `vti_updown_db` and the commit lock. It cannot be ported as is. |
| X13 | Secret files are created with default permissions and only chmod'ed afterwards. `swanctl_apply` runs `tokio::fs::write(&tmp)` → `set_permissions(0o600)` → `rename` (`src/ipsec.rs:126-129`; `swanctl.conf` holds every PSK). `keepalived::write_atomic` has the same pattern (`src/keepalived.rs:229-243`); `keepalived.conf` can hold the VRRP auth password. Between write and chmod, the file has mode `0666 & ~umask`, which is `0644` under systemd's default `UMask=0022`: world-readable. `fs::write` also truncates a leftover temp file and keeps its old mode. | — (an insomnia defect; not compared with VyOS) |

Facts checked for this plan:
- **The wildcard is real.** strongSwan 5.9.13 `vici_cred.c` `load_shared` inserts `identification_create_from_string("%any")` when a shared key has no owners. A secret with no ids therefore matches every (local, remote) identity pair. Checked in the source; the BDD below confirms it end to end.
- **Python `subnet_of`** (the rule VyOS uses):
  - It is non-strict: `10.0.0.0/24 ⊆ 10.0.0.0/24` and `0.0.0.0/0 ⊆ 0.0.0.0/0` are both true.
  - It raises `TypeError` on mixed families. VyOS's commit therefore crashes when a v4 local is paired with a v6 remote.
  - `ip_network('any')` raises `ValueError`.
  - Checked with `python3 -I`.
- **`any` is not reachable.** VyOS rolling validates prefixes as ipv4/ipv6-prefix only, and so does zebra-rs (`ipsec.yang:142-148`). The `any` widening in `ts_prefixes` (`:951-960`) and in `peer.j2:164` is legacy.
- **Correction to the gap doc.** The gap doc's "the default prefix is skipped" means `dynamic`. zebra-rs models `dynamic` as an absent prefix, and insomnia already renders no selector, and no passthrough, for an absent prefix.

## 3. Design

**X3: strict containment, tunnel mode only.**
- New `fn strict_subnet(local, remote) -> bool`. It is true iff:
  - the prefixes parse;
  - they are the same family;
  - `local.plen > remote.plen`;
  - they agree under `remote.plen`.
- `nets_overlap` is deleted. It has no other caller.
- The pass policy L↔L shadows the tunnel's L→R traffic for every destination in L ∩ R. It is only harmless when L ⊊ R, where the tunnel still carries R \ L.
  - With L = R, or L ⊇ R, the tunnel would carry nothing.
  - So strict containment is the rule. It also excludes every /0 local without a special case, because nothing is a strict superset of /0. That covers the required "skip 0/0 and ::/0".
- The passthrough block moves inside the `mode == "tunnel"` branch.
- Transport mode with prefixes warns: `peer P tunnel N: local/remote prefix is ignored in transport mode`. VyOS refuses this with a ConfigError.
- Deviations recorded in the module doc:
  - local == remote gets no passthrough (VyOS renders one, disabling the tunnel);
  - mixed families are never paired (VyOS crashes).
- Rejected: copying `subnet_of`. That keeps the L = R hole, and the /0↔/0 case, which `local 0.0.0.0/0 remote 0.0.0.0/0` hits.

**X4: skip the entry, never the whole file.**
- `id` empty → warning `authentication psk NAME: no id configured; skipped (a secret without an id matches every IKE identity)`, and nothing is rendered.
- `id` empty with `dhcp-interface` set → `authentication psk NAME: only dhcp-interface ids, which are not supported yet; skipped`.
- The existing "static ids only" warning stays for entries with both.
- A peer whose secret is no longer loaded fails authentication. That is the safe failure.
- Once [commit-validation](commit-validation.md) layer 2 exists, the same rule refuses the commit (assumes D1). It is listed there in §4.5 as Error / Skipped.

**X4b: hardening found while planning, not in the gap doc.**
- Values rendered inside double quotes are interpolated unescaped (`:582-584`, `:729`, `:740`):
  - psk `id` and `secret`;
  - `local-id` and `remote-id`.
- A `"` would at least break the whole swanctl.conf, which violates the module rule that one bad peer cannot wedge the file.
- Unverified:
  - whether strongSwan's settings lexer honours `\"` escapes in quoted strings;
  - whether zebra-rs lets a `"` into a string leaf at all.
- Guard: a value containing `"`, `\` or a control character skips its psk or peer with a warning. This is not escaped. Escaping semantics we have not verified are worse than a skip.
- `quoted_ok` is the one guard for every quoted swanctl value. [ipsec-syntax-parity](ipsec-syntax-parity.md) (ppk ids, dhcp-derived ids) and [ipsec-remote-access](ipsec-remote-access.md) (RA ids, EAP user names and passwords, RADIUS secrets) reuse it.

**X5: VyOS semantics exactly, with mismatches warned.**
- Effective reauth:
  ```
  match peer.ikev2_reauth { Some("yes") => true, Some("inherit") => ike.ikev2_reauth, _ => false }
  ```
- When it is on and `ike.key_exchange == "ikev2"`, the initiate branch (`:715-716`) adds `reauth_time = <ike lifetime or 28800>s` after `keyingtries = 0`.
- On with `key-exchange` ikev1 or unset: no line, and a warning `peer P: ikev2-reauth requires key-exchange ikev2 in ike-group G; not applied`. VyOS rejects the commit; the peer still renders.
- A respond/none peer with reauth on renders nothing, silently. That matches VyOS, which renders it only for initiators.
- New hint warning when an ike-group sets `ikev2-reauth` and a peer using it has no `ikev2-reauth` leaf: `ike-group G: ikev2-reauth applies only to peers with "ikev2-reauth inherit"`. VyOS is silent here, but the book has told users the group leaf works.

**X6.**
- When `disable_uniqreqids` is set, every site-to-site connection gets `unique = never` after the `encap` line (`peer.j2` order). DMVPN profile connections get it too once they exist ([ipsec-dmvpn-l2tp](ipsec-dmvpn-l2tp.md)).
- Remote-access `ra-*` connections never do: VyOS passes `global_unique` to peers, profiles and l2tp only (`swanctl.conf.j2:7`, `:22`), as [ipsec-remote-access](ipsec-remote-access.md) D3 records.
- It is removed from the charon-level warning condition (`:548-550`).
- The per-peer `unique` leaf belongs to [ipsec-syntax-parity](ipsec-syntax-parity.md); this plan renders only the global one.

**X7.** `let proto = if proto == "all" { "" } else { proto };` before the suffix closure. It applies to both modes.

**X8 (interim) — decision: stop rendering `updown`; do not render it conditionally on the helper existing.**
- `render` stays pure. Golden tests must not depend on the host filesystem, and insomnia could stat a different host than charon's only if `--swanctl-dir` lies.
- There is nothing to ship. VyOS's helper needs VyOS's config DB.
- [ipsec-vti](ipsec-vti.md) owns link state, and under D7 the link is always up. An updown hook has no job to do, now or later. Phase (b) uses VICI events, not a script.
- `if_id_in` / `if_id_out` stay, so the swanctl side of `vti bind` keeps working with a hand-made xfrm link.
- Module-doc deviation: "no updown hook; the XFRM link's state belongs to zebra-rs (ipsec-vti)".

**X13: create with the final mode, and use one helper for every backend.**
- New `src/fsutil.rs` with `write_private_atomic(path, content, mode) -> io::Result<()>`:
  - The temp file is `<path>.insomnia-tmp`, in the same directory, so the rename is atomic.
  - A stale temp file from a crash is removed first.
  - It is opened with `std::fs::OpenOptions::new().write(true).create_new(true)` plus `std::os::unix::fs::OpenOptionsExt::mode(mode)`. `create_new` is O_EXCL: it never reuses an existing file's mode, and never follows a symlink.
  - Then `write_all`, `sync_all`, `rename`, and an fsync of the directory.
  - It runs under `tokio::task::spawn_blocking`.
- The umask can only clear bits, so a file created with `0o600` is never more permissive than that, for any umask.
- Used by:
  - `ipsec::swanctl_apply`: replaces `:126-129`, mode 0600;
  - `keepalived::write_atomic` / `write_if_changed`: `:229-252`, modes 0600 and 0644 unchanged;
  - later, the [charon-lifecycle](charon-lifecycle.md) drop-in and the [pki-x509](pki-x509.md) credential writer.
- [charon-lifecycle](charon-lifecycle.md) M1 extends this same `fsutil.rs` (with `systemctl`) instead of creating its own.
- Rejected: setting the process umask to `0077` at startup. It is global, it silently affects files that must be 0644 (keepalived `env`, future certificates), and nothing stops it from being dropped in a refactor.
- This is the mechanism [secret-redaction](secret-redaction.md) S10 asks for ("temp files are created with their final mode at `open`").

**Findings.**
- This plan is Phase 0 and may land before [commit-validation](commit-validation.md) C1 (`src/findings.rs`). Until then each new finding is a `warn()` string with the text below.
- When C1 lands, the findings migrate with this classification. It follows commit-validation §3.2, including the upgrade-safety exceptions for X3 and X4.

| Finding | Sev | Effect |
|:--|:--|:--|
| psk without `id` (X4) | E (VyOS `:271-276`) | Skipped (security exception) |
| psk with only `dhcp-interface` ids | E (VyOS requires `id`) | Skipped |
| quoted value with `"`, `\` or a control character (X4b) | E (unsafe token) | Skipped (psk or peer) |
| transport-mode tunnel with prefixes (X3b) | E (VyOS `:723`; already listed in commit-validation §4.5 as Kept) | Adjusted("prefixes ignored; no pass-through child"): the pass child is the X3 security exception |
| `ikev2-reauth` on with a non-IKEv2 group (X5) | E (VyOS `:757-768`) | Dropped("reauth_time not rendered") |
| ike-group `ikev2-reauth` with no `inherit` peer (X5 hint) | W | Kept |
| local overlaps remote without being contained in it (§8 open) | W | Kept |

- Messages never contain a secret value (commit-validation §3.2). X4b reads `authentication psk NAME: secret contains a character that cannot be quoted`, without the value.
- After X8, the commit-validation §4.3 row `:862, :1005` effect "child skipped / updown omitted" becomes "child skipped / if_id omitted".

## 4. Changes

### zebra-rs

None. The X3 and X4 rules are listed for [commit-validation](commit-validation.md).

### insomnia

`src/ipsec.rs`:
- `strict_subnet` replaces `nets_overlap` (`:467-488`). Passthrough is computed inside the tunnel-mode branch (`:961-984`), plus the transport-mode prefix warning.
- `render_psk`: the id-empty skips, and the X4b guard (shared helper `quoted_ok(&str) -> bool`, also used by `render_peer` for `local-id` / `remote-id`).
- `render_peer`: `reauth_time` and its warnings (`:711-719`); `unique = never` after `:720-722`.
- `render`: the charon-level warning drops `disable_uniqreqids` (`:548-558`). `render` also emits the ike-group reauth hint, because it sees every peer.
- `render_tunnel_child`: `all` mapped to empty (`:929-941`); both `updown` lines deleted (`:879`, `:1001`).
- Module doc (`:19-33`):
  - remove `disable-uniqreqids` from the charon-level list;
  - add the X3, X4, X5 and X8 deviations above.
- `swanctl_apply` (`:122-149`): the write becomes `fsutil::write_private_atomic(&dir.join("swanctl.conf"), conf, 0o600)`.

`src/fsutil.rs` (new, X13): `write_private_atomic`, and `create_private_tmp(path, mode) -> io::Result<(File, PathBuf)>`. The latter is split out so a test can observe the mode before any content is written. `src/main.rs` adds `mod fsutil;`.

`src/keepalived.rs`: `write_atomic` (`:229-243`) becomes a thin wrapper over `fsutil::write_private_atomic`. `write_if_changed` keeps its compare-first behaviour.

**Worked example: golden `render_fixes_golden`.** Input:

```json
{"disable-uniqreqids": null,
 "authentication": {"psk": [
   {"name": "GOOD", "id": ["@z1"], "secret": "good"},
   {"name": "ORPHAN", "secret": "orphan"},
   {"name": "DHCPONLY", "dhcp-interface": ["eth0"], "secret": "dhcp"}]},
 "esp-group": [{"name": "ESP", "proposal": [{"number": 1, "encryption": "aes256gcm128", "hash": "sha256"}]}],
 "ike-group": [{"name": "IKE", "key-exchange": "ikev2", "lifetime": 3600, "ikev2-reauth": null,
   "proposal": [{"number": 1, "encryption": "aes256gcm128", "hash": "sha256", "dh-group": 19}]}],
 "site-to-site": {"peer": [{"name": "192.0.2.9",
   "authentication": {"mode": "pre-shared-secret"}, "connection-type": "initiate",
   "ikev2-reauth": "inherit", "ike-group": "IKE", "default-esp-group": "ESP",
   "local-address": "192.0.2.1", "remote-address": ["192.0.2.9"],
   "tunnel": [
     {"number": 1, "local": {"prefix": ["0.0.0.0/0"]}, "remote": {"prefix": ["192.168.1.0/24"]}},
     {"number": 2, "local": {"prefix": ["10.0.3.0/24"]}, "remote": {"prefix": ["0.0.0.0/0"]}},
     {"number": 3, "protocol": "all", "local": {"prefix": ["10.0.5.0/24"], "port": 443},
      "remote": {"prefix": ["10.0.6.0/24"]}}]}]}}
```

Expected output, exact. The children of tunnels 2 and 3 have the same body as tunnel 1 apart from their selectors.

```
connections {
    192-0-2-9 {
        proposals = aes256gcm128-sha256-ecp256
        version = 2
        local_addrs = 192.0.2.1 # dhcp:no
        remote_addrs = 192.0.2.9
        rekey_time = 3600s
        mobike = yes
        keyingtries = 0
        reauth_time = 3600s
        unique = never
        local {
            auth = psk
        }
        remote {
            id = "%any"
            auth = psk
        }
        children {
            192-0-2-9-tunnel-1 {
                esp_proposals = aes256gcm128-sha256-ecp256
                life_time = 3600s
                local_ts = 0.0.0.0/0
                remote_ts = 192.168.1.0/24
                ipcomp = no
                mode = tunnel
                start_action = start
                close_action = none
            }
            192-0-2-9-tunnel-2 { … local_ts = 10.0.3.0/24 / remote_ts = 0.0.0.0/0 … }
            192-0-2-9-tunnel-2-passthrough {
                local_ts = 10.0.3.0/24
                remote_ts = 10.0.3.0/24
                start_action = trap
                mode = pass
            }
            192-0-2-9-tunnel-3 { … local_ts = 10.0.5.0/24[/443] / remote_ts = 10.0.6.0/24 … }
        }
    }
}
…
secrets {
    ike-GOOD {
        id-1 = "@z1"
        secret = "good"
    }
}
```

What the example pins:
- tunnel 1 has no passthrough: the X3 case, which today gets `local_ts = remote_ts = 0.0.0.0/0`;
- tunnel 2 keeps one: the strict subset of a /0 remote, the classic VyOS case.

Expected warnings, exactly two: `authentication psk ORPHAN: no id configured; skipped …` and `authentication psk DHCPONLY: only dhcp-interface ids …`.

Changes to existing tests:

| Test | Change |
|:--|:--|
| `full_config_golden` (`:1518`) | Delete `updown = "/etc/ipsec.d/vti-up-down vti0"` (`:1620`). Add tunnel 4 (`local 10.0.0.0/8 remote 10.0.4.0/24`), whose child renders with **no** `-passthrough` sibling. Keep tunnel 3's passthrough, which is still correct. The commit message explains both. |
| `overlap_detection` (`:1706`) | Becomes `strict_subnet_rule`. See §5. |
| `skips_warn_and_never_wedge` (`:1722`) | Unchanged. NOSECRET fails the secret check first. |

There is no show output change.

## 5. Tests

Unit tests (`src/ipsec.rs`):

- **`strict_subnet_rule`.** True:
  - `10.0.3.0/24` ⊂ `10.0.0.0/8`;
  - `10.0.3.0/24` ⊂ `0.0.0.0/0`;
  - `2001:db8::/48` ⊂ `2001:db8::/32`.

  False:
  - `10.0.0.0/8` vs `10.0.3.0/24`;
  - `0.0.0.0/0` vs `192.168.1.0/24`;
  - `0.0.0.0/0` vs `0.0.0.0/0`;
  - `::/0` vs `::/0`;
  - `10.0.0.0/24` vs `10.0.0.0/24`;
  - `10.0.1.0/24` vs `10.0.2.0/24`;
  - `10.0.0.0/8` vs `::/0`;
  - `any` vs `10.0.0.0/8`.
- **`render_fixes_golden`**: §4.
- **`transport_mode_never_gets_passthrough`**: an ESP group in transport mode with prefixes 10.0.3.0/24 → 10.0.0.0/8 gives no `-passthrough` and the transport warning.
- **`psk_without_id_is_skipped`**: id-less, dhcp-only, and both-kinds entries. Asserts the secrets text and the warnings.
- **`quoted_values_are_guarded`**: a psk secret containing `"` is skipped with a warning, and the rest of the file renders.
- **`reauth_matrix`**: one table-driven test over

  | peer leaf | ike leaf | key-exchange | type / name | expect |
  |:--|:--|:--|:--|:--|
  | unset | set | ikev2 | initiate | none + hint |
  | inherit | set | ikev2 | initiate | `reauth_time = <lifetime>s` |
  | inherit | unset | ikev2 | initiate | none |
  | yes | — | ikev2 | unset | line |
  | yes | — | ikev1 | initiate | none + warning |
  | yes | — | ikev2 | respond | none |
  | yes | — | ikev2 | `@x` | `reauth_time = 0` (unchanged) |
  | no | set | ikev2 | initiate | none |
- **`unique_never_per_connection`**: two peers, both get `unique = never`, and there is no charon-level warning.
- **`protocol_all_is_empty`**: `all` + local port 443 gives `[/443]`; `all` with no ports gives no suffix.
- **X13 tests (`src/fsutil.rs`), umask-independent.** The security property is "no group/other bits", and the umask can only clear bits, so the assertions hold for every umask. No test changes the process-global umask.
  - **`private_tmp_mode_at_creation`**: `create_private_tmp(scratch/x, 0o600)`. *Before writing anything*, assert `metadata(tmp).mode() & 0o077 == 0` and `& 0o700 == 0o600`.
  - **`private_write_replaces_permissive_leftovers`**: pre-create `x.insomnia-tmp` at 0666 and the target at 0644 with old content. After `write_private_atomic(x, "new", 0o600)`: the content is `new`, the mode is 0600, and no temp file remains.
  - **`private_write_refuses_symlinked_tmp`**: the temp path is a symlink to a scratch file. The helper removes the link and does not write through it.
  - **`swanctl_conf_is_0600`**: an `ipsec.rs` test on a scratch `--swanctl-dir`. A `swanctl` that is not found gives `Ok(false)` (`:138`), and the file is checked for mode 0600.
  - The existing `apply_writes_files_and_detects_unchanged` (`keepalived.rs:412`) keeps passing, and gains a mode assertion: conf 0600, env 0644.

**BDD: new feature `bdd/tests/features/ipsec_safety.feature` (`@serial @ipsec_safety`).**

Why a new feature rather than extending `ipsec_s2s`: `ipsec_s2s` is the baseline smoke, and its `bdd/docs` page documents one config pair. These scenarios need five configs and a rogue identity. Keeping them apart keeps failure attribution clear.

- **Topology:** that of `ipsec_s2s.feature:16-18`. The nodes are spawned with the same `ipsec_node.sh`.
- **Configs** (`bdd/tests/configs/ipsec_safety/`, set form). Each file is a full restatement on top of the `ipsec_s2s` groups and peers, because a file apply replaces the whole config (`bdd/tests/cucumber.rs:876-881`). The table lists only what differs:

  | File | Contents |
  |:--|:--|
  | `z1-x3.conf` | `tunnel 1 local prefix 0.0.0.0/0`, `remote prefix 10.0.2.0/24` |
  | `z2-x3.conf` | `local prefix 10.0.2.0/24`, `remote prefix 0.0.0.0/0`, `connection-type respond` |
  | `z2-x4.conf` | `psk GOOD id @z1 secret Good-Secret-1`, `psk ORPHAN secret Orphan-Secret-1` (no id); peer `192.0.2.1` with `local-id 192.0.2.9` and no `remote-id` (`%any`) |
  | `z1-x4-good.conf` | `psk GOOD id @z1 id 192.0.2.9 secret Good-Secret-1`, `local-id @z1` |
  | `z1-x4-rogue.conf` | `psk ROGUE id @rogue id 192.0.2.9 secret Orphan-Secret-1`, `local-id @rogue` |

- **New harness step:** `charon log in namespace {string} should eventually contain {string}`. It reads `logs/<scoped>.charon.log` and is modelled on the insomnia-log step (`bdd/tests/cucumber.rs:3114-3147`). The step is additive, so the zebra-rs vocabulary stays compatible.

Scenarios:
1. **Setup.** As `ipsec_s2s.feature:44-55`, without applying config.
2. **A 0.0.0.0/0 local selector stays encrypted.**
   - Apply z2 first, then z1, the `ipsec_s2s` ordering rule.
   - `show vpn ipsec sa` in z1 eventually contains `192-0-2-9-tunnel-1`.
   - `show vpn ipsec connections` in z1 should not contain `passthrough`.
   - In z2 it should contain `192-0-2-1-tunnel-1-passthrough`, so strict containment still works.
   - `command "ip xfrm policy list nosock dir out"` in z1 should not contain `src 0.0.0.0/0 dst 0.0.0.0/0`. `nosock` hides charon's per-socket IKE bypass policies, which print as 0/0↔0/0. The filter syntax is to be confirmed against iproute2 6.x.
   - `ping -c 2 -I 10.0.1.1 10.0.2.1` eventually shows `2 received`.
   - `show vpn ipsec sa` in z1 eventually not contains `0B/0B`.
   - Before the fix this scenario fails. z1's 0/0 pass policy sends the ICMP in clear, z2's IPsec in-policy drops it, and the counters stay at 0.
   - Ends with `delete vpn ipsec` on both nodes.
3. **The legitimate identity authenticates (control).**
   - Apply `z2-x4`, then `z1-x4-good`.
   - insomnia log in z2 contains `authentication psk ORPHAN: no id configured; skipped`.
   - The SA comes up.
4. **An identity no psk id names is rejected.**
   - `delete vpn ipsec` in z1. Wait until z2 has no `tunnel-1` SA.
   - Apply `z1-x4-rogue`.
   - charon log in z2 eventually contains `no shared key found`. The exact strongSwan wording is *unverified*; the fallback needle is `AUTHENTICATION_FAILED` in z1's charon log.
   - `I wait 5 seconds`.
   - `show vpn ipsec sa` in z1 and in z2 should not contain `tunnel-1`.
   - Before the fix, z2's id-less `ike-ORPHAN` secret has owner `%any` (`vici_cred.c`) and the rogue initiator gets an SA.
5. **Teardown topology.** As `ipsec_s2s.feature:78-86`.

Then run `make -C bdd docs` to generate `bdd/docs/ipsec_safety.md`.

## 6. Docs

- **ch-02-02 (`book/src/ch-02-02-site-to-site.md:97-99`):** "overlaps" becomes "is contained in"; local == remote and `0.0.0.0/0` get no pass-through; there is no pass-through in transport mode.
- **ch-02-01 (`:66-76`):** document the peer leaf `ikev2-reauth yes|no|inherit`. The ike-group leaf only takes effect through `inherit`. It needs IKEv2, and applies to initiators only.
- **Appendix A RFC 7296 row:** true again once X5 lands.
- **Coordination with [docs-corrections](docs-corrections.md) (its D3): the X5 PR owns the `ikev2-reauth` text.** It rewrites `ch-02-01:75-76` and `appendix-a:32` in the same commit as the behaviour (milestone 3), whichever plan lands first:
  - X5 first: docs-corrections drops its `ikev2-reauth` item.
  - docs-corrections PR 1 first: it lands its interim "accepted but not applied yet" wording (its §4.4), and the X5 PR replaces it.
- **ch-02-03:**
  - a psk entry must list at least one `id`;
  - listing the *local* identity makes the secret valid for any remote identity (strongSwan matches either owner), so pin `remote-id`;
  - `disable-uniqreqids` maps to `unique = never`.
- **ch-02-04:** drop "nor the up/down helper the rendered configuration references".
- **CHANGELOG.yaml (breaking-behaviour notes):**
  - id-less PSKs stop loading;
  - `ikev2-reauth yes|inherit` now reauthenticates every IKE lifetime;
  - local == remote tunnels lose their pass child and start carrying traffic.
- **Module doc deviations:** §3.

## 7. Milestones

1. **First PR, the P1 fixes: X13 + X3 + X3b (transport guard).** insomnia, S.
   - X13: `src/fsutil.rs`, with `swanctl_apply` and `keepalived::write_atomic` switched over.
   - X3 and X3b.
   - Done when:
     - the four X13 tests pass, plus the keepalived mode assertion;
     - `strict_subnet_rule` and the transport test pass;
     - `full_config_golden` is updated with tunnel 4;
     - the `overlap_detection` assertions are gone.
2. **X4 + X4b.** insomnia, S. Done when: `psk_without_id_is_skipped` and `quoted_values_are_guarded` pass, and the module doc is updated. This may ride in the first PR.
3. **X5, X6, X7, X8 interim + `render_fixes_golden`.** insomnia, S. The X5 commit carries the ch-02-01 and appendix A `ikev2-reauth` text (§6). Done when: the golden and `reauth_matrix` pass, no `vti-up-down` string remains in `src/`, and clippy and fmt are clean.
4. **BDD `ipsec_safety`, the charon-log step and the five configs.** insomnia `bdd/`, S. Done when: `make -C bdd ipsec_safety` passes on a charon-systemd host, and it fails at scenario 2 or 4 when run against `ee4dfaa`.
5. **Book and CHANGELOG** (the rest of §6). insomnia, S. Done when: `mdbook build` is clean and no interim docs-corrections reauth wording remains.

Milestones 1 and 2 are the P1 security fixes (X13, X3, X4) and ship ahead of the rest.

## 8. Risks and open questions

- **X4 breaks configs that relied on the wildcard.** The tunnels go down on upgrade. The warning names the entry and the CHANGELOG flags it; that is intended.
- **Reauthentication outages.** Peers with `ikev2-reauth yes|inherit` start reauthenticating. strongSwan 5.9.13 reads `charon.make_before_break` in `task_manager_v2_create`. Its default is believed to be `no` in 5.9 (*unverified*). If so, each reauth is a short break-before-make outage. Document it; do not change the default.
- **X4b may be over-strict** if strongSwan does unescape `\"`. Revisit after a test against charon.
- **The X3 BDD needle depends on iproute2 output.** The fallback is the `passthrough` connection-name assertion plus the counters.
- **Open: should X3 also warn** when a local prefix overlaps a remote prefix without being contained in it (`10.0.0.0/8` vs `10.0.0.0/24`)? Intra-site traffic to the overlap enters the tunnel. VyOS is silent. Recommendation: warn, with no rendering change.

## 9. Acceptance criteria

- [ ] No rendered config contains a `-passthrough` child whose local prefix is /0, equals the remote prefix, or contains it, or one in transport mode.
- [ ] `strict_subnet_rule`, `render_fixes_golden`, `reauth_matrix`, `psk_without_id_is_skipped`, `quoted_values_are_guarded`, `unique_never_per_connection` and `protocol_all_is_empty` pass.
- [ ] `full_config_golden` is updated deliberately (no updown; tunnel 4 without passthrough), and the commit message explains why.
- [ ] Every `authentication psk` entry rendered under `secrets` has at least one `id-N` line. (The id-less DMVPN profile secret is [ipsec-dmvpn-l2tp](ipsec-dmvpn-l2tp.md)'s accepted D-E2 exception.)
- [ ] `grep -r vti-up-down src/` is empty.
- [ ] `swanctl.conf` and `keepalived.conf` are only ever created through `fsutil::write_private_atomic`. No `fs::write` followed by `set_permissions` remains in `src/`. The X13 tests pass without touching the umask.
- [ ] `make -C bdd ipsec_safety` passes; scenarios 2 and 4 fail on `ee4dfaa`.
- [ ] Book chapters ch-02-01, ch-02-02, ch-02-03 and ch-02-04 and appendix A are updated, and the CHANGELOG entry is written.
- [ ] `cargo test --workspace --exclude bdd`, fmt and clippy `-D warnings` are clean.
