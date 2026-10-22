# DMVPN (`vpn ipsec profile` + NHRP) and L2TP/IPsec — implementation plan

Status: plan, 2026-10-21. Covers: the §7.2 rows `profile` (DMVPN) and
`vpn l2tp remote-access ipsec-settings`, the §7.3 "NHRP / DMVPN" dependency, and the
§7.4 `reset vpn ipsec profile …` / `show ip nhrp …` items
([vyos-gap](../vyos-gap.md) §7.2, §7.3, §7.4, §9).
Priority: P3 · Effort: L. Most of it is zebra-rs work owned by two separate designs (§3
D-A); the insomnia share is S–M · Owner: both (+ an external LNS for L2TP)
Depends on:
- [exec-verbs](exec-verbs.md): `reset vpn ipsec profile`.
- [ipsec-opmode](ipsec-opmode.md): the reset helpers and `ViciOps`.
- [nft-common](nft-common.md): the NHRP NFLOG table.
- [multi-path-subscribe](multi-path-subscribe.md): not for DMVPN (D-D). Only for L2TP, if
  it is ever accepted (D-F).
- [commit-validation](commit-validation.md): `findings.rs` for the profile rules (D-E).
- [secret-redaction](secret-redaction.md): `ext:secret` on the profile
  `pre-shared-secret`. That leaf is a new row for its table.
- [pki-x509](pki-x509.md): not for DMVPN (profiles are PSK-only, D-E2). Only for L2TP
  `ipsec-settings authentication mode x509`, if D-F is ever accepted.
- [ipsec-vti](ipsec-vti.md) (soft): its zebra-rs `list vti` + `rib/vti` builder is the
  pattern the tunnel-interface design copies (§4).
- Not charon-lifecycle: DMVPN needs no strongswan.d setting.
- The proposed zebra-rs designs "tunnel interfaces" and "native NHRP" (§3 D-A).

Unblocks: GRE-over-IPsec, a P2 item on its own, through the zebra-rs tunnel-interface
design.

## 1. Goal

- **Decision record.** Which parts of DMVPN and L2TP land where, and in what order. This
  plan is a scoping and sequencing document as much as an implementation plan.
- **DMVPN, when done:**
  - `vpn ipsec profile <p>` with `authentication`, `bind tunnel*`, `esp-group`,
    `ike-group` and `disable` renders VyOS `profile.j2` connections and secrets;
  - zebra-rs creates mGRE tunnels and runs native NHRP: hub/spoke registration,
    resolution, shortcuts;
  - spoke↔hub and spoke↔spoke GRE is protected by IPsec;
  - `reset vpn ipsec profile <p> tunnel <t> [remote-host <nbma>]` and `show ip nhrp …`
    work;
  - a BDD with one hub and two spokes passes.
- **Static mGRE first.** A useful intermediate state: mGRE with static NBMA mappings plus
  IPsec, with no NHRP at all. It is reachable early if the trap spike in D-C succeeds.
- **L2TP/IPsec: recorded as out of scope** unless an L2TP LNS (accel-ppp) is accepted as
  a dependency. If it is, it becomes a separate backend design.

## 2. Current state

**zebra-rs @ 141da2fc**
- `ipsec.yang:30-31` defers `profile` ("needs the tunnel-interface and NHRP trees"). The
  parse test asserts its absence (`manager.rs:7845`).
- No tunnel or GRE interface type exists:
  - the type-specific lists are `bridge` (`config.yang:382`), `vxlan` (`401`) and `vlan`
    (`479`), beside the generic `interface` list (`5711`);
  - `config.yang` mentions `tunnel` only for VXLAN.
- No NHRP exists anywhere (grep of `zebra-rs/src`, `yang/` and `docs/`; the only hits are
  the deferral notes).
- Precedents for a native NHRP:
  - raw `AF_PACKET` I/O in IS-IS (`zebra-rs/src/isis/network.rs:125`,
    `src/isis/link.rs:1033`);
  - kernel neighbour programming (the EVPN neighbour path,
    `src/fib/netlink/handle.rs:4902-4948`) and route programming in `src/fib/netlink`.
- `docs/design/vpn-ipsec-followups.md` lists `profile` (needs GRE + NHRP) and "l2tp glue"
  (out of scope until a `vpn l2tp` tree exists).

**insomnia @ ee4dfaa**
- `ipsec.rs` renders site-to-site only (`ipsec.rs:516-561`). `connections {}` has no
  profile section.
- The firewall exposes `log-options group N` (NFLOG) to operators (`firewall.rs:1864`),
  which matters for NHRP's NFLOG groups (D-D).
- `ipsec.rs:1-38` describes the backend shape a profile renderer joins.

**VyOS @ 7f2c893**
- **Profile:**
  - schema in `interface-definitions/vpn_ipsec.xml.in` (`tagNode profile`: `disable`,
    `authentication mode pre-shared-secret` + `pre-shared-secret`, `bind tunnel*`,
    `esp-group`, `ike-group`);
  - template `data/templates/ipsec/swanctl/profile.j2`: `dmvpn-<p>-<tun>`, child
    `dmvpn-<p>-<tun>-child`, `local_ts = remote_ts = dynamic[gre]`, `start_action = none`,
    `rand_time = 540s`;
  - secrets `ike-dmvpn-<tun> { secret = … }` with **no id** (`swanctl.conf.j2:51-61`);
  - verify `vpn_ipsec.py:386-401`.
- **NHRP:**
  - `interface-definitions/protocols_nhrp.xml.in`: `tunnel tunN` with `authentication`
    (≤ 8 characters), `holdtime`, `map tunnel-ip <ip> nbma`, `multicast`, `network-id`,
    `nhs tunnel-ip <ip|dynamic> nbma*`, `redirect`, `registration-no-unique`, `shortcut`,
    `mtu`;
  - `data/templates/frr/nhrpd.frr.j2` renders FRR `nhrpd` config, including
    `tunnel protection vici profile dmvpn-<p>-<tun>-child` (`:53-55`): nhrpd itself drives
    charon over VICI;
  - `python/vyos/frrender.py:243-253` links a profile to its tunnels;
  - `nhrpd_nftables.conf.j2` renders NFLOG tables `vyos_nhrp_multicast` and
    `vyos_nhrp_redirect`;
  - `src/conf_mode/protocols_nhrp.py` sets NFLOG groups `redirect = 1`, `multicast = 2` (`:32-33`)
    and verifies (`:46-94`): tunnel exists, `encapsulation gre`, no `remote`, `/32`
    address, `network-id` required, an NBMA maps to one tunnel-ip.
- **Op-mode:**
  - `reset vpn ipsec profile <p> tunnel <t> [remote-host <nbma>]`
    (`op-mode-definitions/vpn-ipsec.xml.in:15-44`; `src/op_mode/ipsec.py:723-781`,
    VICI terminate by IKE name or by ike-id filtered on `remote-host`);
  - `show|reset ip nhrp …` (`op-mode-definitions/nhrp.xml.in`, through `vtysh`);
  - VICI initiation toward a given peer (`python/vyos/ipsec.py:209-247`, `my-host`/
    `other-host`).
- **L2TP:**
  - `interface-definitions/vpn_l2tp.xml.in` (`ipsec-settings`: `authentication mode psk|x509`,
    `ike-lifetime`, `lifetime`, `esp-group`, `ike-group`; `lns`, `outside-address`);
  - `data/templates/ipsec/swanctl/l2tp.j2`: transport mode, `local_ts = dynamic[/1701]`.
    The defaults are `aes256-sha1-modp1024,3des-sha1-modp1024` (`vpn_ipsec.py:191-192`).
  - The LNS itself is accel-ppp (`data/templates/accel-ppp/l2tp.config.j2`).

**Ecosystem** (checked with `apt-cache policy` on the Ubuntu 24.04 reference host):
- `opennhrp` and `accel-ppp` have no candidate.
- `frr` (10.7.1, FRR's repository) and `xl2tpd` (1.3.18) are available.
- FRR `nhrpd` needs FRR's `zebra` (ZAPI) for interfaces and routes.

## 3. Design

**D-A: the split. Which design owns what.**

| Piece | Owner | Where it is designed |
|:--|:--|:--|
| GRE / mGRE (and ip6gre) tunnel interfaces: YANG, netlink create, `/32` + NOARP handling, multicast flag | zebra-rs | new zebra-rs design `docs/design/tunnel-interfaces.md` (*proposed*). Also serves GRE-over-IPsec (P2) |
| Native NHRP: RFC 2332 NHC/NHS, registration, resolution, purge; Cisco-style redirect/shortcut (draft-detienne-dmvpn); NHRP cache → kernel neighbours on the mGRE device + shortcut routes into the RIB; `show/reset ip nhrp …`; NHRP config tree | zebra-rs | new zebra-rs design `docs/design/nhrp.md` (*proposed*) |
| How NHRP gets IPsec SAs toward a learned NBMA peer (D-C) | both | this plan decides; the NHRP design implements its side |
| `vpn ipsec profile` YANG | zebra-rs (`ipsec.yang`), driven by insomnia | this plan |
| Profile render, secrets, verify-as-warnings, `reset vpn ipsec profile` | insomnia | this plan |
| NHRP NFLOG nft table (multicast replication and redirect triggers) | insomnia (D-D) | this plan |
| L2TP LNS (`vpn l2tp remote-access`) | external daemon + a new backend | separate `design/l2tp.md`, only if accepted (D-F) |

**D-B: the NHRP engine is native in zebra-rs.**
- **Rejected: FRR `nhrpd`.** It needs FRR `zebra` through ZAPI. Running FRR zebra beside
  zebra-rs means two RIB owners programming one kernel.
- **Rejected: a ZAPI shim in zebra-rs.** A large protocol surface, version-coupled to FRR.
- **Rejected: `opennhrp`.** Unmaintained (last upstream release age *unverified*), not
  packaged on the reference host, and built for the racoon era.
- **Accepted: native NHRP.** zebra-rs already does raw-socket protocol I/O (IS-IS
  `AF_PACKET`), and owns the kernel neighbour and route programming NHRP results need.
  NHRP packets are GRE protocol `0x2001` on the tunnel device.

**D-C: NHRP↔IPsec coupling. Spike a trap-based protection first.**
- VyOS renders `start_action = none` and lets nhrpd initiate each spoke SA over VICI.
  Three ways to replace that:
  1. **Trap (preferred if the spike passes).** insomnia renders the profile children with
     `start_action = trap` and keeps `remote_addrs = %any` and `dynamic[gre]` selectors.
     The first GRE packet toward a new NBMA address (an NHRP registration or resolution
     included) raises a kernel acquire, and charon initiates to the acquire's destination.
     - No NHRP→charon API at all; charon stays insomnia's alone.
     - DEVIATION to record: `trap` instead of `none`.
     - That charon initiates trap-triggered transport-mode SAs toward a `%any` remote, using
       the acquire's destination, is *unverified* and is the spike's question.
  2. **insomnia RPC.** zebra-rs NHRP asks insomnia, which owns VICI, to initiate or
     terminate `dmvpn-<p>-<tun>-child` for `my-host`/`other-host`. That is a new
     machine-to-machine RPC, which the NHRP design would define.
  3. **zebra-rs speaks VICI directly.** Rejected: two clients steering one charon breaks
     insomnia's ownership (reset semantics, restarts in
     [charon-lifecycle](charon-lifecycle.md)).
- **Order:** spike option 1 (milestone 3). If it fails, the NHRP design takes option 2.

**D-D: the NFLOG rules are rendered by insomnia.**
- VyOS's two tables become one table `ip zebra_nhrp`, with chains `ZEBRA_NHRP_*`. The
  rename follows the coexistence naming of `zebra_firewall`. The table is replaced
  atomically with the add+delete idiom, through [nft-common](nft-common.md).
- **Input** is the NHRP tree's `tunnel` / `multicast` / `redirect` leaves:
  - The table does not need to be atomic with `vpn ipsec`. `src/nhrp.rs` is its own
    backend, so a plain single-path `subscribe::subscribe_json` on the NHRP tree is
    enough.
  - Multi-path's one-stream-per-backend rule (D-10) is respected, and
    [multi-path-subscribe](multi-path-subscribe.md) is not required.
  - Implementation: a small new task of the standard backend shape. It compares before
    apply (the X12 / `keepalived::apply` pattern), so a zebra-rs resubscribe does not
    reset the counters.
- **NFLOG groups** are VyOS's constants (`redirect` 1, `multicast` 2) unless the NHRP
  schema makes them configurable, which is recommended to the NHRP design.
  - The firewall can log to any group (`firewall.rs:1864`). Document the reservation, and
    have the NHRP design warn on overlap.
- **Rejected: zebra-rs installs the rules itself.** zebra-rs does not run `nft` for policy
  today. Its only `nft` invocation is the Lua scripting side-effect channel, which does
  set-element add/delete (`src/script/sideeffect.rs:1-8`, `57`). Two `nft` owners would
  also need coordinating.
- The NHRP design may instead pick `AF_PACKET` capture on the tunnel for multicast. Then
  only the redirect chain remains here.

**D-E: profile rendering follows `profile.j2`.**
- Profile connections come first in `connections {}`, before site-to-site (VyOS order).
- `ike-dmvpn-<tun>` secrets come first in `secrets {}`.
- Verify rules are commit-validation findings. Each is **E** with the profile skipped
  (VyOS `vpn_ipsec.py:386-401`); the tree is new, so upgrade safety does not apply:
  - missing or unknown `esp-group`;
  - missing or unknown `ike-group`;
  - missing `authentication`.
- No `bind tunnel`: **W**, profile skipped. VyOS silently renders nothing
  (`swanctl.conf.j2:11`).
- Layer-1 YANG: `mandatory true` on `profile esp-group` and `ike-group`, which are new
  leaves.
- VyOS's `ipcomp = yes` on `compression is vyos_defined('enable')` can never fire, because
  `compression` is valueless. Reproduce: emit nothing. DEVIATION recorded as "VyOS dead
  branch".

**D-E2: the DMVPN PSK has no owner. Accepted with VyOS, flagged loudly.**
- `ike-dmvpn-<tun>` carries no `id` (`swanctl.conf.j2:55-57`), so it matches any identity,
  the X4 class ([ipsec-render-fixes](ipsec-render-fixes.md)).
- In DMVPN that is inherent: spokes have dynamic addresses.
- The cross-connection risk: a site-to-site peer with `remote-id %any` (the default) can be
  authenticated with the DMVPN PSK.
- Finding **W**, kept, when a profile coexists with such peers. The message recommends
  explicit `remote-id`s on those peers. A future x509 profile mode is
  [pki-x509](pki-x509.md)'s to add (VyOS has none).

**D-F: L2TP/IPsec is out of scope unless accel-ppp is accepted.**
- Facts:
  - The IPsec half is trivial (`l2tp.j2`, S). It is useless without an LNS.
  - VyOS's LNS is accel-ppp, which is not packaged on the reference host.
  - `xl2tpd` + `pppd` is packaged but single-threaded, with weaker RADIUS and IPv6.
  - L2TP/IPsec is legacy: VyOS's own defaults still include `3des`/`modp1024`
    (`vpn_ipsec.py:191-192`).
- **Recommendation:** do not implement.
- If accepted, write `design/l2tp.md` as a new backend in the `design/vrrp.md` shape:
  - the `vpn l2tp remote-access` YANG;
  - the accel-ppp config and lifecycle (the keepalived-style compare-before-reload);
  - PPP interfaces appearing dynamically, and how zebra-rs treats their `/32` routes;
  - RADIUS and pools; `show l2tp-server sessions`;
  - the IPsec half: append `vpn l2tp` to the IPsec backend's single path list, opened
    with `subscribe_json_multi(…, Fallback::PrimaryOnly)` and read with
    `json::parse_subtree` (multi-path D-7, D-10); `authentication mode x509` reuses
    [pki-x509](pki-x509.md)'s `x509-ref` grouping and `CredSet`.

**Module-doc deviations to add** (`ipsec.rs`, when the profile lands): D-C (`trap`, if
chosen), D-E (dead ipcomp branch), D-E2 (the warning).

## 4. Changes

### zebra-rs (in this plan's scope)

`ipsec.yang`, profile grouping (sketch, VyOS-verbatim):

```yang
grouping profile-config {
  list profile {
    ext:help "VPN IPsec profile"; key "name";
    leaf name { type string; }                    // VyOS regex [a-zA-Z][0-9a-zA-Z_-]+ → Error finding, profile skipped
    leaf disable { type empty; }
    container authentication {
      leaf mode { type enumeration { enum pre-shared-secret; } }
      leaf pre-shared-secret { type string; ext:secret "IPsec DMVPN profile pre-shared secret"; }
    }
    container bind { leaf-list tunnel { ext:help "Tunnel interface associated with this profile";
                                        ext:dynamic "rib:interface"; type string; } }
    leaf esp-group { type string; }
    leaf ike-group { type string; }
  }
}
// grouping vpn-ipsec: `uses profile-config;` between options-config and remote-access/site-to-site (VyOS order)
```

- Parse test: move `manager.rs:7845` from `bad_with_insomnia` to `ok`.
- `exec.yang`, under exec-verbs' `reset vpn ipsec`:
  `list profile { key name; list tunnel { key name; ext:presence; list remote-host { key address; ext:presence } } }`.

### zebra-rs (out of scope; requirements handed to the two proposed designs)

**Tunnel interfaces:**
- `list tunnel { name; encapsulation gre|ip6gre|gretap; source-address; remote (absent = multipoint); key; ttl; mtu }`
  alongside `vxlan` and `vti`, built like ipsec-vti's `rib/vti` (adopt, re-create on a
  mismatch, refuse a foreign kind). Addresses and VRF come through the generic `interface` list.
- Netlink `IFLA_INFO_KIND gre` with `IFLA_GRE_LOCAL`/`REMOTE`/`IKEY`/`OKEY`/`TTL`.
- An mGRE device is a GRE device with no remote and NOARP.

**NHRP:**
- A config tree covering the VyOS `protocols nhrp` leaves, in zebra-rs spelling (for
  example `router nhrp`, the zebra-rs naming convention, §1 "Syntax scope").
- Configurable NFLOG groups (D-D). The D-C side, if option 2.
- Commit checks from `protocols_nhrp.py:46-94`.
- `show ip nhrp cache|nhs|shortcut`; `reset ip nhrp cache|shortcut`.

### insomnia

- **`src/ipsec.rs`:**
  - model `Profile { name, disable, authentication: { mode, pre_shared_secret }, bind: { tunnel: Vec<Flex> }, esp_group, ike_group }`;
  - `fn render_profile(r, cfg)` before the site-to-site loop at `ipsec.rs:526-532`;
  - `fn render_profile_secrets(r, cfg)` before `render_psk` at `ipsec.rs:541-545`;
  - the D-E2 warning.
- **`src/ipsec_op.rs`:** `reset_profile(v, profile, tunnel, nbma: Option<&str>)`. VyOS
  strings:
  - `Profile <p> tunnel <t> reset result: success`;
  - `Profile <p> tunnel <t> remote-host <nbma> reset result: success`;
  - `SA(s) for profile <p> tunnel <t> not found, aborting`, with `Answer.error = true`.
  - It goes through exec-verbs' bounded `vici::terminate`, by IKE name or by `ike_id`
    (`timeout_ms = -1`, as VyOS does), in a spawned task.
  - exec-verbs' `EXEC_ROUTES` row `reset vpn ipsec` (added by ipsec-opmode) already
    covers the `profile` subtree, so no route row is added.
- **New `src/nhrp.rs`:** subscribes to the NHRP tree (the path is fixed by the NHRP
  design) and renders the D-D table with `nft -f -`. It follows the backend shape in
  `AGENTS.md`. `main.rs` spawns it; it has no show tree.

**Worked example: profile.**

```
set vpn ipsec ike-group IKE-DM key-exchange ikev2
set vpn ipsec ike-group IKE-DM proposal 10 encryption aes256gcm128
set vpn ipsec ike-group IKE-DM proposal 10 hash sha256
set vpn ipsec ike-group IKE-DM proposal 10 dh-group 19
set vpn ipsec esp-group ESP-DM mode transport
set vpn ipsec esp-group ESP-DM proposal 10 encryption aes256gcm128
set vpn ipsec esp-group ESP-DM proposal 10 hash sha256
set vpn ipsec profile DMVPN authentication mode pre-shared-secret
set vpn ipsec profile DMVPN authentication pre-shared-secret Lab-DMVPN-PSK
set vpn ipsec profile DMVPN bind tunnel tun0
set vpn ipsec profile DMVPN esp-group ESP-DM
set vpn ipsec profile DMVPN ike-group IKE-DM
```

Expected. The ESP line is shown before
[ipsec-syntax-parity](ipsec-syntax-parity.md)'s ESN pair. `start_action` is shown as VyOS
renders it; D-C option 1 would make it `trap`.

```
connections {
    dmvpn-DMVPN-tun0 {
        proposals = aes256gcm128-sha256-ecp256
        version = 2
        rekey_time = 28800s
        keyingtries = 0
        local {
            auth = psk
        }
        remote {
            auth = psk
        }
        children {
            dmvpn-DMVPN-tun0-child {
                esp_proposals = aes256gcm128-sha256-ecp256
                rekey_time = 3600s
                rand_time = 540s
                local_ts = dynamic[gre]
                remote_ts = dynamic[gre]
                mode = transport
                dpd_action = clear
                close_action = none
                start_action = none
            }
        }
    }
    …site-to-site peers…
}
…
secrets {
    ike-dmvpn-tun0 {
        secret = "Lab-DMVPN-PSK"
    }
    …psk entries…
}
```

- DEVIATION: the secret is quoted; VyOS writes it bare.
- `unique = never` appears after `keyingtries` when `disable-uniqreqids` is set, from the
  X6 `global_unique` in [ipsec-render-fixes](ipsec-render-fixes.md).

**Worked example: NFLOG table.** For `tun0` with `multicast` and `redirect`. Checked with
`nft -c` (nftables 1.0.9) in a throwaway network namespace on 2026-10-21:

```
table ip zebra_nhrp
delete table ip zebra_nhrp
table ip zebra_nhrp {
    chain ZEBRA_NHRP_MULTICAST_OUTPUT {
        type filter hook output priority filter + 10; policy accept;
        oifname "tun0" ip daddr 224.0.0.0/24 counter log group 2
        oifname "tun0" ip daddr 224.0.0.0/24 counter drop
    }
    chain ZEBRA_NHRP_MULTICAST_FORWARD {
        type filter hook forward priority filter + 10; policy accept;
        oifname "tun0" ip daddr 224.0.0.0/4 counter log group 2
        oifname "tun0" ip daddr 224.0.0.0/4 counter drop
    }
    chain ZEBRA_NHRP_REDIRECT_FORWARD {
        type filter hook forward priority filter + 10; policy accept;
        iifname "tun0" oifname "tun0" meter loglimit-0 size 65535 { ip daddr & 255.255.255.0 . ip saddr & 255.255.255.0 timeout 1m limit rate 4/minute burst 1 packets } counter log group 1
    }
}
```

With no NHRP config the output is the first two lines only, which removes the table.

## 5. Tests

**Golden and unit tests** (insomnia):
- `profile_golden`: the worked example. The secrets order is dmvpn → psk.
- `profile_multi_tunnel`: `bind tunnel tun0 tun1` gives two connections and two secrets.
- `profile_disabled_or_unbound_skipped`.
- `profile_verify_findings`: missing or unknown esp/ike group, and missing authentication
  (Error, profile skipped); no bind tunnel (Warning). Asserted via `Findings`.
- `profile_wildcard_psk_warning_with_any_remote_peer`.
- `profile_trap_start_action`: only if D-C option 1 is adopted.
- `nhrp_nft_golden`: the worked example. Also check it under `sudo -n unshare -n nft -c`
  in an `#[ignore]` test, the same practice as the firewall goldens.
- `nhrp_nft_empty_removes_table`.
- `reset_profile_all_and_remote_host`: a fake `ViciOps` from
  [ipsec-opmode](ipsec-opmode.md).

**BDD.**
- `@ipsec_mgre_static` (after milestones 2 and 3): a hub and two spokes on one bridge
  underlay.
  - mGRE `tun0` is created with `ip tunnel` through `I execute …` until zebra-rs tunnel
    interfaces land, with static `ip neigh` NBMA mappings and no NHRP.
  - The profile is applied on all three. A spoke-to-spoke ping over `tun0` eventually
    succeeds, and `show vpn ipsec sa` shows `dmvpn-DMVPN-tun0-child`.
  - This is the D-C spike made permanent.
- `@ipsec_dmvpn` (after the zebra-rs NHRP design lands):
  - spokes register (`show ip nhrp cache` on the hub);
  - a spoke-to-spoke shortcut forms after traffic (`show ip nhrp shortcut`);
  - direct spoke↔spoke SAs exist;
  - `I run "reset vpn ipsec profile DMVPN tunnel tun0 remote-host <spoke>" in namespace "hub"`
    drops the SA, and the next GRE packet re-forms it;
  - teardown.
  - An FRR `nhrpd` node in its own namespace, with its own FRR zebra and no zebra-rs, is a
    possible interop peer for a later scenario.
- L2TP: none (D-F).

## 6. Docs

- Book: a new `ch-02-10-dmvpn.md`, written when milestone 2 lands. It states plainly what
  works:
  - static mGRE + IPsec first;
  - NHRP when zebra-rs has it;
  - the D-E2 risk.
- `ch-02-05-transport-mode.md:34` mentions "the DMVPN `profile` tree". Keep it accurate.
- `ch-02-00-what-is-ipsec.md:46-47`: update the "planned" sentence.
- Mention L2TP once, as not supported, with the D-F reason.
- `ipsec.rs` module doc: the §3 deviations.
- zebra-rs: the two proposed design docs (owned there).
  `docs/design/vpn-ipsec-followups.md` gets links to them.

## 7. Milestones

| # | Scope | Repo | Effort | Done when |
|:--|:--|:--|:--|:--|
| 0 | Accept D-A, D-B and D-F (decision record in this doc and `vyos-gap.md` §11) | both | S | Decisions marked accepted |
| 1 | Tunnel interfaces (GRE/mGRE) under their own zebra-rs design | zebra-rs | M | That design's acceptance; GRE-over-IPsec usable |
| 2 | `profile` YANG (with `ext:secret`, `mandatory`) + render + secrets + D-E findings + goldens (after commit-validation C1) | zebra-rs + insomnia | S | Goldens and findings tests green; parse test updated |
| 3 | D-C spike: trap-initiated transport SAs toward `%any`, over manually created mGRE | insomnia | S | Spike result recorded here; `@ipsec_mgre_static` green if option 1 holds |
| 4 | Native NHRP under its own zebra-rs design, including the D-C side if option 2 | zebra-rs | L | That design's acceptance |
| 5 | `src/nhrp.rs` NFLOG table task (needs nft-common and the NHRP tree path) | insomnia | S | `nhrp_nft_golden` green |
| 6 | `reset vpn ipsec profile …` (needs exec-verbs, ipsec-opmode) + BDD `@ipsec_dmvpn` | both | S | Feature green |
| 7 | *(only if accel-ppp is accepted)* `design/l2tp.md`, then its own plan | both + external | L | Not scheduled |

Milestones 1 and 2 are independent. Milestone 3 needs 2. Milestones 5 and 6 need 4.

## 8. Risks and open questions

- **D-C trap to `%any`** is *unverified*. If charon cannot initiate to an acquire's
  destination with `remote_addrs = %any`, option 2 (an RPC) is required, and the NHRP
  design grows an IPsec client.
- **NHRP interop.** Cisco DMVPN phase 3 interop needs Traffic Indication and redirect
  handling compatible with draft-detienne-dmvpn. Testing needs a Cisco image, or FRR
  `nhrpd` in an isolated namespace as a reference.
- **NFLOG group collisions** with operator firewall logging (D-D).
- **Wildcard DMVPN PSK** (D-E2) weakens site-to-site peers that accept any remote id.
- **eBPF fast path.** XDP-forwarded tunnel traffic bypasses both netfilter (the NFLOG
  rules) and xfrm. That is [ebpf-netfilter](ebpf-netfilter.md)'s limit (§4.7). mGRE
  interfaces should not be eBPF data-plane ports.
- **L2TP demand.** If operators require L2TP/IPsec for legacy clients, revisit D-F with
  data. The cost is a whole new backend, not an IPsec feature.

## 9. Acceptance criteria

- [ ] D-A, D-B and D-F are recorded as accepted. The two zebra-rs designs exist (as
      stubs, at least) and are linked from `docs/design/vpn-ipsec-followups.md`.
- [ ] `vpn ipsec profile` parses with `--feature insomnia`. `profile_golden` matches
      `profile.j2` apart from the recorded deviations.
- [ ] The DMVPN PSK warning fires when a profile coexists with `remote-id %any` peers.
- [ ] The D-C spike result is recorded, and the start-action choice is fixed in the golden.
- [ ] The NFLOG table renders, passes `nft -c`, and is removed when NHRP config is gone.
- [ ] `reset vpn ipsec profile …` answers with VyOS's strings.
- [ ] BDD `@ipsec_mgre_static` is green (option 1) or replaced by `@ipsec_dmvpn` (option 2).
- [ ] L2TP is documented as unsupported, with the reason, until D-F is revisited.
