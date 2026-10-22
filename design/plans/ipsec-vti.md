# Route-based IPsec (VTI) — implementation plan

Status: plan, 2026-10-21. Covers: §7.3 "VTI / XFRM interfaces"; §7.2 rows `peer vti bind` (PARTIAL) and `peer vti traffic-selector` (MISSING-SCHEMA); X8 final; decision D7 ([vyos-gap](../vyos-gap.md) §3, §7.2, §7.3, §11).
Priority: P1 · Effort: M · Owner: both (zebra-rs: link, schema, name check; insomnia: render, verify findings, BDD, book)
Depends on:
- [ipsec-render-fixes](ipsec-render-fixes.md) (X8 interim: `updown` already removed);
- [charon-lifecycle](charon-lifecycle.md) (soft, never blocking: charon installs no routes for VTI children (§2), so `disable-route-autoinstall`, P2 in vyos-gap §7.2, matters only on hosts that mix policy-based and VTI peers);
- [multi-path-subscribe](multi-path-subscribe.md) (assumes D3; the `vti` part for the bind-exists finding; not blocking Z1/Z2);
- [commit-validation](commit-validation.md) (assumes D1; `Findings`, and layer 2 for refusing bad binds; not blocking M1);
- [fw-global-options](fw-global-options.md) (optional: `crate::links` for one host warning);
- [exec-verbs](exec-verbs.md) (phase (b): E1's `vici::subscribe` / `EventStream`; also E1 `vici::stats` if this plan implements the IPsec load compare before pki-x509's I1).

Unblocks:
- [ipsec-remote-access](ipsec-remote-access.md) (`connection … bind`: the link, and the bind-exists finding, which covers RA binds);
- [ipsec-dmvpn-l2tp](ipsec-dmvpn-l2tp.md) (soft: the `list vti` + `rib/vti` pattern that the zebra-rs tunnel-interface design copies).

Not blocked by this plan: ipsec-opmode's `reset … peer P vti` acts on the `-vti` child insomnia already renders, and fw-zones takes a `vti` link as a zone member like any other interface.

Assumes D7: link always up first, a VICI-driven state later.

## 1. Goal

- `set vti vti1` makes zebra-rs create the kernel XFRM interface `vti1` with `if_id 2`, admin up. Deleting the entry deletes the link. A leftover link is adopted, or re-created if its `if_id` differs.
- `interface vti1 ipv4|ipv6 address`, `mtu` and `vrf` apply through the existing `interface` tree, including when the `vti` entry is created in the same commit.
- `vpn ipsec site-to-site peer P vti bind vti1` plus ordinary zebra-rs routing (static or BGP) carries traffic encrypted. charon installs no routes for it.
- `vti traffic-selector local|remote prefix` narrows the `-vti` CHILD_SA (VyOS rolling).
- No updown hook is ever rendered (X8 final).
- The link state is "always up" (DEVIATION, D7 (a)), documented with its blackhole caveat. Phase (b), VICI-driven state, is designed here and scheduled after M6.
- BDD `ipsec_vti` passes with static routing and with eBGP over the VTI.

## 2. Current state

**insomnia** (swanctl side, done):
- `Vti { bind, esp_group }` (`src/ipsec.rs:305-310`).
- `render_vti_child` (`:844-892`):
  - selectors fixed at `0.0.0.0/0,::/0` (`:877-878`);
  - `updown` (`:879`, removed by ipsec-render-fixes);
  - `if_id_in/out` (`:880-881`).
- Tunnel children with a bind get the same `if_id` (`:999-1010`).
- `vti_if_id` = N+1 (`:838-842`). Its `n + 1` overflows for `vti4294967295`.
- Golden `:1615-1628`.
- insomnia never sees the interface tree.

**zebra-rs** has no XFRM code at all (`grep -ri xfrm zebra-rs/src` is empty). The pattern to copy is the `vlan` list:

| Piece | Location |
|:--|:--|
| Schema | `config.yang:479-…`, `ext:sort "25"`, free-form key |
| Config builder | `rib/vlan/{mod,config,builder}.rs` (`VlanBuilder::exec`/`commit`) |
| Dispatch and commit | `rib/inst.rs:5726-5727`, commit at CommitEnd `:5745` |
| Messages | `Message::VlanAdd/VlanDel` (`rib/inst.rs:164-170`, handled at `:3709-3730`) |
| Apply | `Rib::vlan_apply`: adopt, or re-create on a mismatch, or refuse a foreign link (`rib/link.rs:1290-1320`); parent replay on `link_add` (`:1262-1278`) |
| netlink | `FibHandle::vlan_add/vlan_del` (`fib/netlink/handle.rs:3710-3740`) |
| Link-info parse | Vxlan/Vrf/Vlan/Bridge only (`handle.rs:5632-5665`) |

- The pinned `rtnetlink` (`Cargo.toml:216`, rev `2d7b183`) already has `LinkMessageBuilder::<LinkXfrm>` with `.if_id()` and an optional `.dev()` (`src/link/xfrm.rs`).
- `netlink-packet-route` has `InfoXfrm::{Link, IfId}`.
- **Known limitation**, per zebra-rs's own note (`config.yang:481-487`): "`interface` addresses on a device created in the same commit are dropped today". VRF and bridge binds are staged (`pending_vrf_bind`, `pending_bridge_bind`, `rib/inst.rs:1304-1310`). MTU is replayed on `link_add` (`rib/link.rs:1881-1888`). Addresses are not.

**VyOS.**
- `interfaces vti vtiN`:
  - name regex `vti[0-9]+`;
  - `address`, `description`, `disable`, `mtu` (default 1500), `vrf`, mirror/redirect (`interfaces_vti.xml.in:5-33`).
- `VTIIf._create` runs `ip link add vtiN type xfrm if_id N+1` and leaves the link admin-down (`python/vyos/ifconfig/vti.py:34-61`). `set_admin_state` brings it up only if `vti_updown_db` says an SA wants it (`:63-75`).
- `src/etc/ipsec.d/vti-up-down` updates that DB on `up-client|up-host[-v6]` / `down-*` under the commit lock.
- `verify()`:
  - bind must exist (`vpn_ipsec.py:695-699`);
  - a single local-address or dhcp-interface (`:693-694`);
  - VTI or tunnel required (`:704`).
- `apply()` commits the DB (`:946-951`).
- Child template with traffic-selector: `peer.j2:79-132` (TS `:95-107`). With tunnels: `:196-203`.

**strongSwan 5.9.13**, read in `kernel_netlink_ipsec.c`:
- A route is installed only when `install_routes && !proto && !ports && (install_routes_xfrmi || !policy->if_id)`.
- `install_routes_xfrmi` defaults to no (the stock `kernel-netlink.conf` documents `# install_routes_xfrmi = no`).
- So charon installs **no** table-220 route for a VTI child, even with `install_routes = yes`.
- vyos-gap §4.5 and §7.3 now record this, and its §7.2 row puts `disable-route-autoinstall` at P2. `install_routes = no` is needed only when policy-based tunnels share the charon, and for VyOS parity.

## 3. Design

**Schema: a top-level `list vti` in zebra-rs, next to `bridge` / `vxlan` / `vlan`.**
- This is the spelling zebra-rs uses for created devices. The syntax-scope rule (`vyos-gap.md` §1) keeps interfaces in zebra-rs's own model, so VyOS `interfaces vti` is not copied.
- The list is gated with `if-feature feat:insomnia`: without insomnia nothing would key SAs to the link. Feature pruning is generic in zebra-rs (`manager.rs:351-353`). `if-feature` on a list, rather than a container, is untested: *unverified*, pinned by a schema test like `manager.rs:7241-7257`.
- Key `name`, constrained to `vti[0-9]+` with N+1 ≤ u32::MAX. The check goes in `check.rs`, because a patterned string consumes the rest of the line (`ipsec.yang:36-37`). Whether `value_check` sees list-key values is *unverified*. If it does not, `VtiBuilder` refuses the name.
- `if_id` is **derived** (N+1), never configured. This is the shared contract with insomnia's `vti_if_id`, and both repos test `vti0 → 1`.
- Rejected:
  - an `xfrm` list with an explicit `if-id`, which diverges from VyOS's `bind vtiN` and would force insomnia to subscribe to the interface tree to resolve ids;
  - creating devices from `interface vtiN`, because the `interface` list only attaches config to existing devices (`config.yang:5711`);
  - insomnia creating the link, which would make two netlink writers.

**zebra-rs link handling.**
- Mirrors `vlan`. `FibHandle::xfrm_add(name, if_id)` builds `LinkMessageBuilder::<LinkXfrm>::new(name).if_id(id).up().build()` with no `dev`, which is what VyOS does.
- Whether kernel 6.8 accepts a missing `IFLA_XFRM_LINK` is *unverified*; the BDD pins it. Fallback: `dev lo`.
- `Rib::vti_apply`:
  - a missing link → create it;
  - an existing XFRM link with the same `if_id` → adopt it;
  - a different `if_id` → delete and re-create;
  - a non-XFRM link of that name → warn and leave it alone.
- The link-info parser learns `InfoData::Xfrm`, as `Link::xfrm_if_id`, for adopt and for `show interface`.
- There is no parent dependency, so no replay hook is needed.

**Same-commit addresses (zebra-rs Z2).**
- Stage configured `interface X ipv4|ipv6 address` for a link that does not exist yet. Replay them from `link_add`, the way MTU already is.
- Scope check first. The comment at `config.yang:481-487` is zebra-rs's own description, not re-verified in code.
- This fixes `vlan`/`vxlan`/`bridge` too.
- Until it lands, a two-commit workaround is documented and used by the BDD.

**Link state, D7 (a): always up.**
- Effects:
  - BGP/OSPF/BFD over the VTI are unaffected; their timers detect a dead SA.
  - A static route over a VTI whose SA is down stays installed and blackholes. The packet is routed into the xfrmi, finds no SA, and is dropped.
  - With `connection-type respond` (start_action `trap`), traffic into the link triggers negotiation, which is a benefit of the link being up.
- Recorded as a DEVIATION in the zebra-rs `vti` description, in the `src/ipsec.rs` module doc and in ch-02-04. Mitigation: BFD or BGP over the tunnel.

**Phase (b): VICI-driven state (designed, not in M1–M6).**
- zebra-rs leaf `vti vtiN link-state always-up|follow-sa` (default `always-up`, so behaviour (a) stays).
- insomnia:
  - registers for `child-updown` / `ike-updown` with `vici::subscribe(socket, &["child-updown", "ike-updown"])`, and consumes the `EventStream`. That API is owned by [exec-verbs](exec-verbs.md) E1; this plan adds no VICI code of its own;
  - reconnects when `EventStream::next` ends, with `RECONNECT_DELAY`;
  - seeds counts from `vici::streamed_request("list-sas")` on every (re)connect, which is bounded by E1's `VICI_TIMEOUT`;
  - keeps a per-`if_id_out` count of INSTALLED children;
  - reports `(vti name, up)` over a proposed `zebra.link.v1 LinkStateService.Report(stream)`.
- zebra-rs remains the only netlink writer. It applies admin up/down only to `follow-sa` links, and reverts them to up when the stream closes: fail-open, because SAs outlive insomnia.
- Rejected:
  - (c) an updown helper script: a root fork per SA event, races with commits, and zebra-rs re-ups on re-create;
  - insomnia toggling the link via netlink: a second writer with no persistence.

**insomnia render (I1).**
- `vti traffic-selector` replaces the default `0.0.0.0/0,::/0` per side (`peer.j2:95-107`), joined with `,`.
- `vti_if_id` uses `checked_add`.
- Module doc: "no updown hook; the XFRM link and its state are zebra-rs's (`vti` list); always up (D7)". That is X8 final.
- The findings are listed below.

**insomnia reads the `vti` tree** for the bind-exists rule (the [multi-path-subscribe](multi-path-subscribe.md) table row "ipsec-vti: `vpn ipsec`, VTI interface tree, PrimaryOnly").
- The IPsec backend has one stream (multi-path D-10). This plan appends `&["vti"]` to its path list: `subscribe_json_multi(host, &[&["vpn","ipsec"], &["pki"], &["vti"]], Fallback::PrimaryOnly)`. Each part is parsed with `json::parse_subtree`.
- [pki-x509](pki-x509.md) appends `&["pki"]`. Whichever of the two plans lands first converts the backend from `subscribe_json` to `subscribe_json_multi`; the other appends a path.
- **Compare before apply.** A `vti` commit that changes no bind (a `description`, a new unbound VTI) re-delivers the IPsec event. The IPsec load compare skips `swanctl -q` when nothing rendered changed. [pki-x509](pki-x509.md) I1 owns the compare: conf, `CredSet` and charon start time via `vici::stats`. If this plan lands first it implements it, with the same contract.
- **PrimaryOnly fallback.** On a zebra-rs without `SubscribeMulti`, the `vti` part is `"{}"` and every bind would look missing.
  - [multi-path-subscribe](multi-path-subscribe.md) D-6/D-7 already let a consumer tell: a real snapshot marks every part `changed = true`, and a PrimaryOnly fallback part arrives as `"{}"` with `changed = false`. So a snapshot part with `changed = false` means "not delivered".
  - The bind-exists finding is suppressed in that state, with the per-feature warning that plan requires ("vti bind checks need zebra-rs ≥ …").
- Rendering itself needs only the bind name, so nothing else depends on the `vti` part.

**Verify rules, as [commit-validation](commit-validation.md) findings.**
- `render()` emits them as `Findings`.
- Layer 2 runs the same `render()` on the candidate. The `ipsec` validation unit registers the backend's full path list, including `[vti]`, so a `vti` deletion triggers it.
- No zebra-rs cross-tree check is written: commit-validation rejects re-implementing rules in `check.rs`.

| Rule | VyOS | Layer | Sev | Effect |
|:--|:--|:--|:--|:--|
| key matches `vti[0-9]+`, N+1 fits u32 | XML regex | 1: zebra-rs `check.rs` value check (a one-leaf value shape on a new node) | E | refused at parse/commit |
| `vti bind X`, or a remote-access `connection <c> bind X` ([ipsec-remote-access](ipsec-remote-access.md)), names an existing `vti X` | `vpn_ipsec.py:699`; RA `:474-477` | 2 + 3 | E | Kept: the child still renders; an SA with an unmatched `if_id` carries nothing, so rendering it is harmless |
| deleting a `vti` entry bound by an enabled peer or RA connection | — | the same rule, evaluated on the candidate | E | refused when insomnia validates; otherwise Kept |
| bind is not `vti<N>` (`ipsec.rs:861-866`, `:1004-1009`) | XML regex | 3 (today) | E | child skipped / if_id omitted (commit-validation §4.3) |
| VTI or tunnel present | `:704` | 3 (today, `:643-648`) | E | peer skipped (commit-validation §4.3) |
| two enabled peers bind one VTI without disjoint selectors | — | 2 + 3 | W | Kept |
| the bound VTI has no kernel link on this host | — | `host_findings`: `crate::links` snapshot from [fw-global-options](fw-global-options.md) | W (host state, commit-validation §3.2) | Kept. Useful for the hand-made-link workaround |

- With insomnia disconnected, D1 lets a commit binding an unknown VTI, or deleting a bound one, through with zebra-rs's "not validated" warning. VyOS refuses it.
- Phase (b) needs no link events (VICI drives it). `crate::links` is used only for the host warning above.

**VRF.**
- `interface vti1 vrf RED` puts the xfrmi in a VRF while IKE/ESP stays in the default table.
- Kernel behaviour for the outer lookup is *unverified*. Documented as untested; no BDD in M5.

## 4. Changes

### zebra-rs

`yang/config.yang`, after `list vlan`:

```yang
list vti {
  if-feature feat:insomnia;
  ext:help "Virtual tunnel interface (XFRM) for route-based IPsec";
  ext:sort "25";
  key "name";
  description
    "An XFRM interface created and owned by zebra-rs, equivalent to
     `ip link add <name> type xfrm if_id <N+1>` for name vtiN (the +1
     keeps vti0 off the reserved if_id 0; insomnia renders the same
     value as swanctl if_id_in/out). Always admin-up (D7): routes over
     it stay installed while its SA is down. Addresses, MTU and VRF
     come from `interface <name>`.";
  leaf name { ext:help "VTI interface name (vtiN)"; type string; }
  leaf description { ext:help "Description"; type string { pattern '.*'; } }
}
```

`yang/ipsec.yang`, inside `container vti` (`:579-590`); VyOS `vpn_ipsec.xml.in:1346-1400`:

```yang
container traffic-selector {
  ext:help "Traffic-selectors parameters";
  container local  { ext:help "Local parameters for interesting traffic";
    leaf-list prefix { ext:help "Local IPv4 or IPv6 prefix";
      type union { type inet:ipv4-prefix; type inet:ipv6-prefix; } } }
  container remote { ext:help "Remote parameters for interesting traffic";
    leaf-list prefix { ext:help "Remote IPv4 or IPv6 prefix";
      type union { type inet:ipv4-prefix; type inet:ipv6-prefix; } } }
}
```

New code:
- `rib/vti/{mod,config,builder}.rs`: `Vti { name, if_id }`, `VtiBuilder`.
- `Message::VtiAdd/VtiDel`.
- Dispatch `/vti` in `rib/inst.rs` beside `:5726`, commit at CommitEnd beside `:5745`.
- `Rib::vti_apply` / `vti_del`.
- `FibHandle::xfrm_add/xfrm_del`.
- `InfoData::Xfrm` parsing. `show interface` detail and JSON (`link_to_detailed_json`, `rib/link.rs`) gain `kind: xfrm, if-id: N`.

Z2: an address replay map keyed by interface name, filled when an address is configured on an absent link, drained in `link_add`.

exec.yang and manager routing: no change. `show interface vti1` is served by the RIB.

### insomnia

- `Vti` gains `traffic_selector: Option<VtiTs { local: Option<Selector>, remote: Option<Selector> }>`. This reuses `Selector`; `port` is ignored, because VyOS's VTI selectors have no port.
- `render_vti_child`: the TS lines.
- `render`: the duplicate-bind pre-pass and the bind-exists findings (peer `vti bind`, tunnel binds and, once it exists, RA `connection … bind`), against the `vti` part.
- `run`: `["vti"]` appended to the IPsec backend's `subscribe_json_multi` path list (shared with [pki-x509](pki-x509.md)).
- `host_findings`: the `crate::links` check.
- `vti_if_id`: `checked_add`.
- Module doc.

**Worked example.** Config:

```
set vti vti1
set interface vti1 ipv4 address 10.255.0.1/30
set vpn ipsec site-to-site peer 192.0.2.9 vti bind vti1
set vpn ipsec site-to-site peer 192.0.2.9 vti esp-group ESP
set vpn ipsec site-to-site peer 192.0.2.9 vti traffic-selector local prefix 10.0.1.0/24
set vpn ipsec site-to-site peer 192.0.2.9 vti traffic-selector remote prefix 10.0.2.0/24
set vpn ipsec site-to-site peer 192.0.2.9 vti traffic-selector remote prefix 2001:db8:2::/48
set router static ipv4 route 10.0.2.0/24 nexthop 10.255.0.2
```

(The static-route set form follows `router.static.ipv4.route[].nexthop[]` in zebra-rs YAML; to be confirmed against `config-static.yang`.)

Kernel: `ip -d link show vti1` shows an `xfrm` link with `if_id 0x2`, UP. The iproute2 layout is *unverified*. The route `10.0.2.0/24 via 10.255.0.2 dev vti1` comes from zebra-rs. Table 220 is empty.

Exact child, golden `vti_traffic_selector_golden`, ESP = aes256gcm128/sha256, IKE dh-group 19, peer with no `connection-type`:

```
            192-0-2-9-vti {
                esp_proposals = aes256gcm128-sha256-ecp256
                life_time = 3600s
                local_ts = 10.0.1.0/24
                remote_ts = 10.0.2.0/24,2001:db8:2::/48
                if_id_in = 2
                if_id_out = 2
                ipcomp = no
                mode = tunnel
                start_action = start
                close_action = none
            }
```

Show: `show vpn ipsec sa` lists `192-0-2-9-vti`; `show vpn ipsec policy` shows `if_id 0x2` on the 0/0 or narrowed policies. No new show grammar.

## 5. Tests

**zebra-rs unit:**
- `vti_schema_gated`: present with `--feature insomnia`, absent without.
- `vti_name_check`: `vti0` ok; `vti`, `eth0` and `vti4294967295` rejected.
- `vti_if_id_contract`: `vti0 → 1`, `vti41 → 42`.
- `vti_apply_adopt_recreate`, with the rib test harness, as for vlan: adopt same `if_id`; re-create a mismatch; refuse a foreign kind.
- `traffic_selector_schema`.
- Z2 `address_replayed_on_late_link`.

**insomnia golden/unit:**
- `vti_traffic_selector_golden`: §4.
- `vti_default_selectors`: no traffic-selector gives `0.0.0.0/0,::/0`. Pins `full_config_golden`.
- `duplicate_vti_bind_warns`.
- `vti_bind_findings`:
  - an unknown bind gives Error/Kept, and the child still renders;
  - a known bind gives no finding;
  - an unknown RA `connection … bind` gives the same Error (added when [ipsec-remote-access](ipsec-remote-access.md) renders `bind`);
  - a fallback `vti` part gives no bind finding, plus the version warning;
  - `validate()` on a candidate without the bound `vti` returns the Error.
- `vti_if_id_checked`: `vti4294967295` → skip + warning, no panic.

**BDD: new feature `ipsec_vti.feature` (`@serial @ipsec_vti`).**
- Topology: `ipsec_s2s`, plus `vti1` on each node (10.255.0.1/30 ↔ 10.255.0.2/30).
- Configs in `bdd/tests/configs/ipsec_vti/`. `I apply config` with a file is a whole-config replace (`bdd/tests/cucumber.rs:876-881`), so every file restates everything:
  - `z{1,2}-link.conf`: only `set vti vti1`. This is the first commit of the pre-Z2 two-commit workaround, and the file is dropped once Z2 lands.
  - `z{1,2}-static.conf`: `vti` + `interface vti1` address + `vpn ipsec` + static route.
  - `z{1,2}-bgp.conf`: the same with BGP in place of the static route. AS 65001/65002 neighbors over the /30, announcing the dummy /24s.

Scenarios:
1. **Setup.**
   - Nodes up; apply the `-link` configs.
   - `command "ip -d link show vti1"` in both eventually contains `if_id 0x2`.
   - `show interface` contains `vti1`.
   - After Z2: one scenario applies `-static` directly, and asserts `command "ip addr show vti1"` contains `10.255.0.1/30`. That pins the same-commit fix.
2. **Static route over the VTI.**
   - Responder first.
   - `show vpn ipsec sa` in z1 eventually contains `192-0-2-9-vti`.
   - `kernel route "10.0.2.0/24"` in z1 eventually contains `dev vti1`.
   - `command "ip route show table 220"` in z1 should not contain `10.0.2.0`. This pins the `install_routes_xfrmi` finding.
   - Ping `10.0.1.1 → 10.0.2.1`: `2 received`. Counters move.
3. **BGP over the VTI.**
   - Replace static with the BGP configs.
   - `BGP session in "z1" to "10.255.0.2" should eventually be "Established"`.
   - The route to 10.0.2.0/24 eventually goes `via 10.255.0.2 dev vti1`.
   - Ping ok.
4. **The always-up deviation is visible.**
   - `delete vpn ipsec` on z2.
   - z1's SA eventually disappears.
   - `command "ip link show vti1"` in z1 still contains `UP`.
   - The ping fails. This pins D7 (a).
5. **Deleting the entry deletes the link.** `delete vti vti1` on z1 → `ip link show vti1` eventually contains `does not exist`.
6. **Teardown topology.**

## 6. Docs

**ch-02-04, rewritten:**
- drop "preview";
- `set vti vtiN` and the `if_id` = N+1 contract;
- addresses, MTU and VRF via `interface vtiN`;
- static and BGP examples in zebra-rs syntax;
- `vti traffic-selector`;
- the always-up deviation and BFD/BGP as the mitigation;
- charon installs no routes for VTI SAs, and `disable-route-autoinstall` matters only when policy-based tunnels share the charon ([charon-lifecycle](charon-lifecycle.md));
- MTU and MSS guidance (`interface vti1 mtu 1400`; MSS clamping waits for FW7, see [fw-packet-modification](fw-packet-modification.md));
- troubleshooting: `ip -d link`, `ip xfrm policy` with `if_id`;
- the two-commit workaround until Z2.

Also:
- **ch-03-01:** the `-vti` child in `show vpn ipsec sa`.
- **zebra-rs book/docs:** the `vti` list.
- **Module doc deviations:** §3.

## 7. Milestones

1. **Z1: `list vti`, name check, `rib/vti`, netlink create/delete/adopt, link-info parse, `show interface` kind.** zebra-rs, M. Done when: the zebra-rs unit tests pass, and `set vti vti1` creates the link in a scratch netns.
2. **Z2: address replay for links that appear after their config.** zebra-rs, S–M. Done when: `address_replayed_on_late_link` passes, and the vlan/vxlan same-commit case is fixed and noted in `config.yang`.
3. **Z3: `vti traffic-selector` schema.** zebra-rs, S. Done when: the schema test passes and insomnia renders the selectors from a real commit.
4. **I1: insomnia TS render, checked `if_id`, the findings table (bind-exists, duplicate bind, `crate::links` host warning), `["vti"]` on the IPsec path list, module doc (X8 final).** insomnia, S. Done when:
   - the goldens and `vti_bind_findings` pass;
   - with [commit-validation](commit-validation.md) layer 2 live, a commit binding an unknown VTI, or deleting a bound one, is refused;
   - a `vti` description change does not run `swanctl -q`.
5. **B1: BDD `ipsec_vti`.** insomnia `bdd/`, M. Done when: `make -C bdd ipsec_vti` passes with a staged zebra-rs (`ZEBRA_PREFIX=…`).
6. **D1: book.** insomnia, S.
7. *(later, separate PRs)* **Phase (b): `link-state follow-sa`, `zebra.link.v1` (proposed), insomnia event consumer on `vici::subscribe`.** Both, M. Needs [exec-verbs](exec-verbs.md) E1.

## 8. Risks and open questions

- **The kernel may require `IFLA_XFRM_LINK`.** Fallback `dev lo`; the BDD decides.
- **`if-feature` on a list** may not prune in zebra-rs's loader. Fallback: ungated, harmless without insomnia.
- **Z2 could be larger than expected** if address handling assumes an ifindex at config time. Then the BDD keeps the two-commit sequence and ch-02-04 documents it.
- **Static routes blackhole while the SA is down (D7 (a)).** Users migrating from VyOS expect the route to withdraw. Open: prioritise phase (b) over the other Phase-3 IPsec work?
- **Phase (b) fail-open vs fail-closed** when insomnia disconnects. The recommendation is fail-open; it needs a decision before phase (b).
- **VRF-enslaved VTIs are untested.**
- **The insomnia BDD needs an unreleased zebra-rs** until Z1 ships. Run it with `make -C bdd stage ZEBRA_PREFIX=…`, per AGENTS.md.

## 9. Acceptance criteria

- [ ] `set vti vtiN` creates, adopts and deletes an XFRM link with `if_id` N+1, admin up; `show interface` shows kind and if_id.
- [ ] An address configured in the same commit as the `vti` entry is applied (Z2), or the limitation is documented with the workaround.
- [ ] `vti traffic-selector` exists and renders per `peer.j2:95-107`; default `0.0.0.0/0,::/0` otherwise.
- [ ] No `updown` line is rendered anywhere; the module doc records the D7 (a) deviation.
- [ ] The bind-exists rule is an Error finding (Kept at apply) for peer and RA binds. With layer 2 live, a commit binding an unknown `vti`, or deleting a bound one, is refused. It is suppressed in the PrimaryOnly fallback.
- [ ] A `vti` change that alters no bind does not reload swanctl (compare before apply).
- [ ] `make -C bdd ipsec_vti` passes: static, BGP, the always-up demonstration, deletion, clean teardown; table 220 stays empty.
- [ ] ch-02-04 is rewritten; `if_id` contract tests exist in both repos.
