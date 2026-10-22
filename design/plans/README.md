# Implementation plans — index

Status: 2026-10-21. These plans implement the gap analysis in
[vyos-gap](../vyos-gap.md). There is one plan per independently
shippable work package, and every gap ID in `vyos-gap.md` maps to
exactly one plan (§2).

Baselines are the same as `vyos-gap.md`:

| Repo | Commit |
|:--|:--|
| insomnia | `ee4dfaa` |
| zebra-rs | `141da2fc` |
| vyos-1x | `rolling` @ `7f2c893` |

Line references inside the plans point at these commits.

Every plan uses the same sections:

1. Goal
2. Current state
3. Design
4. Changes (zebra-rs, then insomnia)
5. Tests
6. Docs
7. Milestones
8. Risks and open questions
9. Acceptance criteria

The header gives what it covers, priority, effort, owner, and its
dependencies in both directions ("Depends on", "Unblocks"); a *soft*
dependency is one the plan can start without. Shared infrastructure has
exactly one owning plan (§3); other plans state what they need from it
and link it rather than redefine it.

**Not covered:** the new backends in `vyos-gap.md` §9 (DHCP, DNS
forwarding, WireGuard, QoS, PPPoE, NTP, syslog/SNMP/LLDP/SSH, OpenVPN,
…). Each needs its own design document, in the shape of
[vrrp](../vrrp.md), before it can have an implementation plan.

## 1. Plans by phase

Phases follow `vyos-gap.md` §10. "Hard deps" lists the plans that must
land first; soft dependencies are in each plan's header. The milestone
count is the number of PR-sized steps in the plan's §7.

### Phase 0: correctness and docs

| Plan | Covers | Priority | Effort | Milestones | Hard deps |
|:--|:--|:--|:--|:--|:--|
| [fw-load-safety](fw-load-safety.md) | X1, X2, X9, X12; §4.1 layer 3 | P1 (X1, X2), P2, P3 | M | 5 | — |
| [ipsec-render-fixes](ipsec-render-fixes.md) | X3–X8, X13 | P1 (X3, X4, X13), P2 | S | 5 | — |
| [docs-corrections](docs-corrections.md) | §3 doc errors, `iso` → `insomnia`, [vrrp](../vrrp.md) corrections (§8.4) | P1 | S | 2 | ipsec-render-fixes, fw-matchers |
| [ebpf-netfilter](ebpf-netfilter.md) | §4.7 | P1 | S | 4 | — |

Three Phase 0 items are the first milestone of a later plan:
- X14 (weekday names): [fw-matchers](fw-matchers.md) milestone 1.
- X15 (show routing on key values): [fw-opmode](fw-opmode.md)
  milestone 1.
- The VRRP-in-VRF spike: [vrrp-vrf](vrrp-vrf.md) milestone 1.

### Phase 1: platform

| Plan | Covers | Priority | Effort | Milestones | Hard deps |
|:--|:--|:--|:--|:--|:--|
| [multi-path-subscribe](multi-path-subscribe.md) | §4.3, D3 | P1 | M | 4 | — |
| [commit-validation](commit-validation.md) | §4.1, D1, FW3, every tree's verify rules | P1 | L | 9 | multi-path-subscribe |
| [exec-verbs](exec-verbs.md) | §4.2, D2, VICI encoder, retained models | P2 | M | 6 | — |
| [nft-common](nft-common.md) | shared `crate::nft`, X10, mark mask | P2 | S | 3 | fw-load-safety |
| [fw-global-options](fw-global-options.md) | §4.4, D4, FW4, FW5, FW6; `crate::sysctl`, `crate::links` | P2 | M | 6 | fw-load-safety, nft-common |
| [charon-lifecycle](charon-lifecycle.md) | §4.5, strongswan.d options | P2 | M | 7 | — |
| [secret-redaction](secret-redaction.md) | §4.6 | P2 (P1 with PKI) | M | 6 | — |

### Phase 2: P1 features

| Plan | Covers | Priority | Effort | Milestones | Hard deps |
|:--|:--|:--|:--|:--|:--|
| [nat](nat.md) | §6.2, NAT66, `show nat`, `show nat66` | P1 core, P2, P3 | L (P1 core M) | 9 | multi-path-subscribe, nft-common, fw-load-safety, commit-validation, conntrack |
| [fw-matchers](fw-matchers.md) | X14, FW2, FW15–FW18 | P1 (X14, FW2), P3 | L (each item S) | 9 | nft-common, fw-load-safety |
| [fw-zones](fw-zones.md) | FW1, `show firewall zone-policy` | P1 | M (L with VRF members) | 6 | nft-common, fw-load-safety, commit-validation, fw-global-options, ebpf-netfilter |
| [ipsec-vti](ipsec-vti.md) | §7.3 VTI, `vti traffic-selector`, X8 final | P1 | M | 7 | ipsec-render-fixes, exec-verbs |
| [pki-x509](pki-x509.md) | §7.3 PKI, x509, rsa, `use-x509-id`, `show`/`generate`/`import pki` | P1, P2, P3 | L | 10 | multi-path-subscribe, secret-redaction, commit-validation, exec-verbs, ipsec-render-fixes |

### Phase 3: P2

| Plan | Covers | Priority | Effort | Milestones | Hard deps |
|:--|:--|:--|:--|:--|:--|
| [conntrack](conntrack.md) | §6.4, FW13, `show`/`reset conntrack`, `ctread` | P2, P3 | L | 9 | fw-global-options, nft-common, exec-verbs, commit-validation, multi-path-subscribe, ebpf-netfilter |
| [fw-packet-modification](fw-packet-modification.md) | FW7, FW8 | P2 | M | 7 | nft-common, fw-load-safety, commit-validation |
| [fw-flowtable](fw-flowtable.md) | FW9 | P2 | M | 6 | fw-load-safety, fw-zones, fw-global-options, commit-validation, fw-opmode, nft-common |
| [fw-opmode](fw-opmode.md) | X11, X15, FW19, the §5 op-mode table | P2, P3 | M | 8 | fw-packet-modification, fw-zones, fw-load-safety, exec-verbs, nft-common |
| [ipsec-opmode](ipsec-opmode.md) | §7.4 | P2, P3 | M | 5 | exec-verbs, charon-lifecycle, secret-redaction |
| [ipsec-remote-access](ipsec-remote-access.md) | §7.2 remote access | P2 | L | 8 | pki-x509, charon-lifecycle, secret-redaction, ipsec-vti, ipsec-render-fixes, ipsec-syntax-parity, exec-verbs, ipsec-opmode, commit-validation, multi-path-subscribe |
| [ipsec-syntax-parity](ipsec-syntax-parity.md) | §7.2 *rolling* items, peer names, `dhcp-interface` | P2, P3 | M | 9 | ipsec-render-fixes, exec-verbs, secret-redaction, commit-validation |
| [vrrp-hardening](vrrp-hardening.md) | §8.1 checks and BDD breadth, §8.3 | P2, P3 | M | 6 | docs-corrections, commit-validation, exec-verbs |
| [vrrp-vrf](vrrp-vrf.md) | §8.1 VRF, [vrrp](../vrrp.md) §13 | P1 spike, P2 | S spike, then M or L | 10 | docs-corrections, fw-global-options |
| [pbr](pbr.md) | §6.6, D5 | P2 | L | 10 | nft-common, multi-path-subscribe, fw-packet-modification, fw-global-options, commit-validation, ebpf-netfilter |

### Phase 4: P3

| Plan | Covers | Priority | Effort | Milestones | Hard deps |
|:--|:--|:--|:--|:--|:--|
| [fw-dynamic-sources](fw-dynamic-sources.md) | FW10, FW11, FW14; `dynsets` | P2 (FW10, FW11), P3 | L | 9 | nft-common, fw-load-safety, fw-packet-modification, exec-verbs, commit-validation, secret-redaction |
| [fw-bridge](fw-bridge.md) | FW12 | P2 | L | 7 | nft-common, fw-load-safety, fw-global-options, commit-validation, fw-opmode |
| [conntrack-sync](conntrack-sync.md) | §6.5 | P3 | M | 9 | conntrack, exec-verbs, charon-lifecycle, commit-validation, vrrp-vrf, ebpf-netfilter |
| [nat-cgnat-nat64](nat-cgnat-nat64.md) | §6.3 CGNAT, NAT64 | P3 | M + M | 9 | nat, nft-common, conntrack, commit-validation |
| [vrrp-virtual-server](vrrp-virtual-server.md) | §8.2, D8 | P3 | M | 7 | multi-path-subscribe |
| [vrrp-snmp](vrrp-snmp.md) | §8.1 SNMP | P3 | M | 5 | vrrp-vrf |
| [ipsec-dmvpn-l2tp](ipsec-dmvpn-l2tp.md) | §7.2 `profile`, L2TP; §7.3 NHRP | P3 | L (mostly zebra-rs) | 8 | exec-verbs, ipsec-opmode, nft-common, multi-path-subscribe, commit-validation, secret-redaction, pki-x509 |
| [wan-load-balancing](wan-load-balancing.md) | §6.7 | P3 | L | 8 | pbr, nft-common, nat, multi-path-subscribe, conntrack, exec-verbs, commit-validation, fw-global-options |

Some rows put a plan's priority above its phase. Each such plan lists
the cheaper P2 alternative first, or the work is gated on its
dependencies:
- fw-bridge (P2, Phase 4);
- fw-dynamic-sources (P2 for FW10 and FW11, Phase 4).

**Dependency levels.** Hard dependencies only; each level depends only
on earlier levels. Plans within a level can proceed in parallel.

| Level | Plans |
|:--|:--|
| 0 | charon-lifecycle, ebpf-netfilter, exec-verbs, fw-load-safety, ipsec-render-fixes, multi-path-subscribe, secret-redaction |
| 1 | commit-validation, ipsec-opmode, ipsec-vti, nft-common, vrrp-virtual-server |
| 2 | fw-global-options, fw-matchers, fw-packet-modification, ipsec-syntax-parity, pki-x509 |
| 3 | conntrack, docs-corrections, fw-dynamic-sources, fw-zones, ipsec-dmvpn-l2tp, ipsec-remote-access, pbr |
| 4 | fw-opmode, nat, vrrp-hardening, vrrp-vrf |
| 5 | conntrack-sync, fw-bridge, fw-flowtable, nat-cgnat-nat64, vrrp-snmp, wan-load-balancing |

Two plans can still land early:
- **docs-corrections** has fallback text for both of its dependencies,
  so it can go first.
- **nat** depends on conntrack only for `show nat … translations`; its
  P1 core does not.

## 2. Gap ID → plan

| Gap IDs (vyos-gap) | Plan |
|:--|:--|
| X1, X2, X9, X12 | fw-load-safety |
| X3, X4, X5, X6, X7, X8 (interim), X13 | ipsec-render-fixes |
| X8 (final) | ipsec-vti |
| X10 | nft-common |
| X11, X15 | fw-opmode |
| X14 | fw-matchers (milestone 1) |
| §3 documentation errors | docs-corrections |
| FW1 | fw-zones |
| FW2, FW15, FW16, FW17, FW18 | fw-matchers |
| FW3 | commit-validation |
| FW4, FW5, FW6 | fw-global-options |
| FW7, FW8 | fw-packet-modification |
| FW9 | fw-flowtable |
| FW10, FW11, FW14 | fw-dynamic-sources |
| FW12 | fw-bridge |
| FW13 | conntrack |
| FW19 | fw-opmode |
| §4.1 / §4.2 / §4.3 / §4.4 | commit-validation / exec-verbs / multi-path-subscribe / fw-global-options |
| §4.5 / §4.6 / §4.7 | charon-lifecycle / secret-redaction / ebpf-netfilter |
| §6.2, NAT66 | nat |
| §6.3 CGNAT, NAT64 | nat-cgnat-nat64 |
| §6.4 | conntrack |
| §6.5 | conntrack-sync |
| §6.6 | pbr |
| §6.7 WAN load balancing (haproxy is out of scope) | wan-load-balancing |
| §7.2 `disable-route-autoinstall`, `log`, `interface`, `options …`, `retransmission` | charon-lifecycle |
| §7.2 x509, rsa, `use-x509-id`; §7.3 PKI | pki-x509 |
| §7.2 `vti bind`, `vti traffic-selector`; §7.3 VTI | ipsec-vti |
| §7.2 `trap`, `dhcp-interface`, `childless`, `unique`, `esn`, ML-KEM, `ppk`, `secret-type`, peer names | ipsec-syntax-parity |
| §7.2 remote access | ipsec-remote-access |
| §7.2 `profile`, L2TP; §7.3 NHRP | ipsec-dmvpn-l2tp |
| §7.4 | ipsec-opmode |
| §8.1 VRF | vrrp-vrf |
| §8.1 checks, tentative wait, completion, BDD breadth; §8.3 alias, `restart vrrp`, `show log vrrp` | vrrp-hardening |
| §8.1 SNMP | vrrp-snmp |
| §8.1 `virtual-server`; §8.2 | vrrp-virtual-server |
| §8.1 conntrack-sync hook / password masking / mDNS `vrrp-disable` | conntrack-sync / secret-redaction / out of scope (no mDNS tree) |
| §8.4 `design/vrrp.md` corrections | docs-corrections (the shim item depends on the vrrp-vrf branch) |

## 3. Shared infrastructure and its owners

All of these are proposed. Each one is defined in one plan; every
other plan consumes it by name.

| API or artefact | Owner |
|:--|:--|
| `crate::nft`: group-set renderer, matchers (`render_matchers`), rule renderer, `SetActions` / `render_set`, `Rendered` with an uncompared `fill`, `apply_if_changed`, `apply_loop`, `Fam` (incl. `Bridge`), `GroupKind`, bit-31 fragment mark, `check_user_mark` | [nft-common](nft-common.md) |
| Reference pass and chain graph: `RefIndex`, `ObjKind`, `plan_table`, `Origin`, the apply/exclude retry loop | [fw-load-safety](fw-load-safety.md) |
| `crate::sysctl` (`Setting`, `absent_baseline`); `crate::links`, the kernel link watcher (kind, master, VRF table) and the single source of VRF membership | [fw-global-options](fw-global-options.md) |
| `SubscribeMulti` RPC, `subscribe_json_multi(host, paths, Fallback)`, `parse_subtree`, `MultiUpdate.fallback` | [multi-path-subscribe](multi-path-subscribe.md) |
| `ConfigService.Validate`, `findings.rs` (severity + apply-time effect), `ext:startup-tolerant`, `--commit-validate`, the units table | [commit-validation](commit-validation.md) |
| `Register.exec`, SHOW/EXEC order kind, `ShowChunk.error`; zebra-rs `EXEC_ROUTES` and the `reset`/`restart`/`generate`/`update`/`import` containers; the shared `show log` container; insomnia `ROUTES` and `Answer`; VICI builder, `request`, `terminate`, `initiate`, `stats`, `subscribe`/`EventStream`; retained models | [exec-verbs](exec-verbs.md) |
| `ext:secret`, the `secrets` keyword, op-mode masking (S11) | [secret-redaction](secret-redaction.md) |
| `fsutil::write_private_atomic` (X13) | [ipsec-render-fixes](ipsec-render-fixes.md) |
| charon drop-in, `CharonSettings`, `RestartMode` | [charon-lifecycle](charon-lifecycle.md) |
| `pki` YANG, `x509-ref` grouping, `CredSet` credential writer | [pki-x509](pki-x509.md) |
| `ctread` conntrack reader (incl. `delete`) | [conntrack](conntrack.md) |
| `dynsets`, the out-of-band set updater | [fw-dynamic-sources](fw-dynamic-sources.md) |
| Group-use registry (who references a group) | [fw-opmode](fw-opmode.md) |
| `tests/scripts/insomnia_node.sh` (zebra-rs + insomnia in a private mount namespace, no extra daemon) | [fw-load-safety](fw-load-safety.md), first to land; others reuse it |

## 4. Reserved values

| What | Value | Owner / enforced by |
|:--|:--|:--|
| Fragment flag in the packet mark | bit 31 (`0x80000000`); user marks are masked `0x7fffffff`; fwmark `ip rule`s use `/0x7fffffff` | nft-common |
| cradle (eBPF) resources | fwmark `0x4c37`, `ip rule` pref 100, table 2047: never used | ebpf-netfilter; `check_user_mark` in nft-common |
| VRF table IDs | allocated from 1000 (zebra-rs), never 2047 | pbr |
| `ip rule` prefs | PBR 900; WAN-LB 910 and 920; kernel l3mdev 1000 | pbr, wan-load-balancing |
| nft hook priorities | as `vyos-gap.md` §6.1 (VyOS's exactly) | each nft plan |
| NAT tables | `ip/ip6 zebra_nat` only. Static rules first, then dynamic, then CGNAT maps; no `zebra_static_nat` or `zebra_cgnat` | nat, nat-cgnat-nat64 |
| keepalived notify slots | `notify_*` for user transition scripts; the generic `notify` for the conntrack-sync hook | vrrp (today), conntrack-sync |
| `SubscribeRequest` / multi-request field numbers | `secrets = 3`, `subtrees = 4` | multi-path-subscribe D-11, secret-redaction |

## 5. Book chapter allocation

New chapters append to their part, numbered in expected landing order.
If plans land in a different order, renumber at merge time and update
this table.

| Chapter | Plan |
|:--|:--|
| `ch-00-04-commit-validation.md` | commit-validation |
| `ch-01-12-nat66.md` | nat |
| `ch-01-13-system-conntrack.md` | conntrack |
| `ch-01-14-flowtables-and-offload.md` | fw-flowtable |
| `ch-01-15-cgnat.md` | nat-cgnat-nat64 |
| `ch-01-16-nat64.md` | nat-cgnat-nat64 |
| `ch-01-17-bridge-firewall.md` | fw-bridge |
| `ch-02-09-remote-access.md` | ipsec-remote-access |
| `ch-02-10-dmvpn.md` | ipsec-dmvpn-l2tp |
| `ch-03-03-operational-commands.md` | exec-verbs |
| `ch-03-04-show-nat.md` | nat |
| `ch-03-05-show-conntrack.md` | conntrack |
| `ch-03-06-show-policy-route.md` | pbr |
| `ch-03-07-show-conntrack-sync.md` | conntrack-sync |
| `ch-03-08-show-wan-load-balance.md` | wan-load-balancing |
| `ch-05-06-virtual-server.md` | vrrp-virtual-server |
| `ch-05-07-conntrack-sync.md` | conntrack-sync |
| `ch-06-00-policy-routing.md`, `ch-06-01-local-route.md` | pbr |
| `ch-06-02-wan-load-balancing.md` | wan-load-balancing |

`ch-06-00-vty-access.md`, `ch-06-01-session-design.md`,
`ch-06-02-show-config-commands.md` and `ch-16-00-ebpf.md`, cited by
secret-redaction and ebpf-netfilter, are **zebra-rs** book chapters.
