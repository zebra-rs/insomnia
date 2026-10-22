# eBPF fast path vs netfilter — implementation plan

Status: plan, 2026-10-21. Covers: §4.7 ([vyos-gap](../vyos-gap.md) §4.7).
Priority: P1 · Effort: S · Owner: both (zebra-rs check, both books; cradle only if outcome C)
Depends on: none · Unblocks: [nat](nat.md), [pbr](pbr.md),
[fw-zones](fw-zones.md), [fw-bridge](fw-bridge.md),
[wan-load-balancing](wan-load-balancing.md), [conntrack](conntrack.md),
[conntrack-sync](conntrack-sync.md), [nat-cgnat-nat64](nat-cgnat-nat64.md)
(each must state how it behaves on eBPF ports; the B-class trees are listed
in §4)

Baselines: zebra-rs `141da2fc` (pins cradle `1.1.9`, `cradle-version`),
cradle-rs `v1.1.9` (`7ab0822`), insomnia `ee4dfaa`. Below, `E` is
`cradle-rs/crates/cradle-ebpf/src/main.rs` and `C` is
`cradle-rs/crates/cradle/src/`.

## 1. Goal

- We know, from code reading and a netns experiment, which traffic cradle
  forwards past netfilter and which it hands to the kernel.
- Both books state the constraint. insomnia's nftables features filter, NAT
  and route only traffic that the kernel forwards.
- A commit can no longer combine an eBPF-forwarding interface with insomnia
  rules that cradle would bypass without the operator noticing. It is either
  refused (outcome B) or the overlap is made safe by punting (outcome C).
- Every later netfilter-based plan inherits one written rule for eBPF
  ports, instead of each rediscovering it.

## 2. Current state

**zebra-rs.**
- `system ebpf enabled` spawns a managed cradle (`config.yang:713-747`;
  `src/cradle/supervisor.rs:117-124`).
- `system cradle enabled` tees to an external cradle (`config.yang:642-665`).
- `interface <if> ebpf enabled` attaches the XDP and TC programs to a port
  (`config.yang:5773-5786`; `src/cradle/inst.rs:278-285`, `1078-1202`;
  `src/fib/cradle.rs:602-620`).
- BFD Echo and detect-offload attach a port **without** that leaf
  (`src/cradle/inst.rs:60-79`, `1153-1188`).
- The only commit check involving cradle is `etree_backend`
  (`src/config/check.rs:37-57`, called at `manager.rs:885-894`). It checks the
  whole candidate and only warns for the startup config. Nothing relates eBPF
  ports to `firewall`.
- The eBPF chapter, `book/src/ch-16-00-ebpf.md`, does not mention netfilter.

**cradle 1.1.9.** From code reading; [inf] marks inference.
- **Programs.** `cradle_xdp` (`E:3186`), `cradle_xdp_l3` (`E:3202`),
  `cradle_tc` on TC ingress (`E:545`) and `cradle_egress` on TC egress
  (`E:561`).
  - The default attach is `cradle_tc`, `cradle_egress` and `cradle_xdp`
    (`C/control.rs:800-933`).
  - `system ebpf mode tc-only` keeps only `cradle_tc`; `xdp-only` keeps only
    `cradle_xdp_l3`.
- **Plain IPv4/IPv6 unicast is forwarded in TC ingress.**
  - XDP passes it up (`E:3302-3330`).
  - `l3_forward` (`E:1921-1929`) looks the destination up in cradle's own
    LPM / DIR-24-8 maps per VRF (`E:2206-2213`). It never calls
    `bpf_fib_lookup`; grep finds none.
  - It then calls `bpf_redirect_neigh` to the egress port
    (`E:2339-2353` v4, `2515-2529` v6), after decrementing the TTL.
  - A packet redirected from TC ingress never enters `ip_rcv`. It therefore
    skips netfilter prerouting (raw, mangle, nat), forward and postrouting,
    and creates no conntrack entry.
- **Handed to the kernel** (`TC_ACT_PIPE`, which continues to the stack):
  - non-IP traffic, e.g. ARP (`E:1927`);
  - no route (`E:2212`);
  - a `FIB_F_LOCAL` destination, which covers only the attached ports' own
    addresses (`E:2219`; `C/kernel.rs:47-108`);
  - TTL ≤ 1 (`E:2308`);
  - an ECMP or nexthop miss, or any error (`E:549`, `2230`).
  - Fragments, IP options and multicast are **not** checked: they are
    forwarded too.
- **Handled in XDP:** MPLS swap/pop, SRv6 End.X, L2 overlay encap and BFD Echo
  (`XDP_TX`). Bridged member ports are switched in TC, bypassing the kernel
  bridge (`E:954`, `1152`).
- **No netfilter awareness at all.** There is no
  `bpf_skb_ct_lookup`/`bpf_xdp_ct_lookup`, `skb->mark` is never read, and there
  is no punt map and no per-flow or per-port "send to kernel" knob.
- **cradle's own NAT, policy and LB** stages (`E:322-366`, `1542-1671`) are
  Kubernetes-style service features configured over cradle gRPC. zebra-rs
  never programs them.
- **Policy routing.** Every `cradle serve` installs
  `ip -4 rule pref 100 fwmark 0x4c37 lookup 2047` with
  `local 0.0.0.0/0 dev lo` in table 2047, for its L7 proxy (`C/kernel.rs:111-147`;
  `cradle-common/src/lib.rs:1421`).
- **Tests.** No cradle or zebra-rs BDD feature forwards traffic through nft
  or iptables with eBPF enabled. zebra-rs's `isis_bfd_*` features only add an
  `iptables INPUT` drop for locally delivered BFD (`bdd/tests/cucumber.rs:3573-3580`).

**Consequence (from code; confirm in M1).** On a port with `ebpf enabled`,
routed traffic *entering* that port bypasses the following, whatever the
egress port is:
- the insomnia rules on the `ip`/`ip6 zebra_firewall` forward and prerouting
  chains;
- the future NAT and PBR tables, the zone policy and the bridge firewall.

Traffic to the router's own addresses on that port still reaches the input
chain. Two inferences follow. [inf] With eBPF on only one side of a flow,
the kernel sees only the replies, so state-policy may treat them as `new`
or `invalid`. [inf] Fwmark-based PBR is ignored for fast-pathed traffic,
because the kernel FIB and `ip rule` are never consulted.

VyOS has no XDP fast path for routed traffic, so there is nothing to
mirror. Its flowtable (FW9) is the analogue: it offloads only flows that
netfilter has already accepted.

## 3. Design

The investigation (M1) confirms the bypass and settles the four open
cases:
1. a router address that is not on an attached port (a loopback /32);
2. ports attached by BFD Echo;
3. `tc-only` and `xdp-only`;
4. asymmetric attachment.

Then pick one of three outcomes. The documentation constraint (A) ships in
every case.

| Outcome | What | Choose when | Cost |
|:--|:--|:--|:--|
| A. Documentation only | The books say that insomnia's forward and prerouting rules, NAT, PBR and zones do not apply to traffic entering an eBPF port; input/output rules do, for addresses on that port | M1 shows that netfilter does see the fast-pathed traffic (contradicting the code reading), **or** as the interim step while B or C is in review | S, both books |
| B. zebra-rs refuses the combination | A whole-candidate commit check, like `etree_backend`: error when cradle is enabled **and** some interface has `ebpf enabled` **and** the candidate has firewall rules on a forward or prerouting hook of either family, or any other B-class tree of §4 (`firewall zone`, `firewall bridge`, NAT, PBR, WLB, conntrack helpers and custom timeouts, as each lands). Startup config: warn only. Input/output-only firewalls stay allowed | **Default.** M1 confirms the bypass and no one needs both on one router now | S, zebra-rs |
| C. cradle punts what netfilter needs | C1: a per-port `l3-punt` flag in cradle that makes `l3_forward` return `TC_ACT_PIPE` for IP unicast, keeping MPLS, SRv6, overlay and BFD in BPF. zebra-rs sets it on every port while a B-class tree is non-empty. C2: conntrack-aware fast path through `bpf_skb_ct_lookup`, forwarding only flows the kernel has accepted, i.e. a software flowtable | A deployment needs eBPF overlay/MPLS performance **and** an insomnia forwarding firewall on the same ports. C1 if IP forwarding speed can be given up there, C2 only as a product goal | C1 M, cradle + zebra-rs; C2 L, cradle |

**Why B by default.**
- A config that promises forward filtering and silently does not filter is
  a security defect. Refusing it is honest and cheap.
- The precedent, a whole-candidate check with warn-only at startup, already
  exists (`check.rs:37-57`, `manager.rs:885-894`).
- Input-only firewalls (control-plane protection) still work, because local
  delivery punts. B does not refuse them.

**Rejected:**
- **Detecting active nft tables at runtime from zebra-rs.** zebra-rs owns
  both configs, so a config check is exact and runs before anything is
  applied.
- **An insomnia-side warning only.** insomnia cannot see eBPF ports: it
  subscribes only to its own trees (and [multi-path-subscribe](multi-path-subscribe.md)
  would be needed). A warning after the commit is weaker than refusing the
  commit.

**Hole in B: BFD Echo.** BFD Echo attaches ports without the `ebpf` leaf
(`inst.rs:60-79`). If M1 shows that such a port gets the full TC pipeline,
B must also refuse BFD `echo` / `detect-offload` on a port while B-class
trees exist. Otherwise cradle must attach only `cradle_xdp` for
BFD-acquired ports, which is a cradle change.

**Reserved resources to record**, whatever the outcome:
- cradle owns fwmark `0x4c37`, `ip rule` pref `100` and table `2047`.
- [nft-common](nft-common.md) (the mark helpers), [pbr](pbr.md),
  [wan-load-balancing](wan-load-balancing.md) and
  [fw-packet-modification](fw-packet-modification.md) must not use them.

**Module-doc note.** `src/firewall.rs` gets "rules apply to kernel-forwarded
traffic; zebra-rs refuses forward/prerouting rules together with eBPF
ports (or: cradle punts)".

## 4. Changes

### zebra-rs (outcome B)

- **`src/config/check.rs`:**
  - `pub fn ebpf_netfilter(leaves: &[(String, Vec<String>)]) -> Vec<String>`
    (proposed);
  - `ebpf_netfilter_line(line)` as the line filter, the same shape as
    `etree_backend_line`.
  - It reads `CRADLE_ENABLED_PATHS`, `/interface/ebpf/enabled` with
    arguments `[<if>, "true"]`, and any line under a B-class tree:

    | Tree (line prefix) | Why fast-pathed traffic misses it | Row added by |
    |:--|:--|:--|
    | `firewall ipv4\|ipv6 forward\|prerouting` | forward and prerouting hooks | this plan (M3) |
    | `firewall zone` | zone dispatch sits in the forward chain | [fw-zones](fw-zones.md) M1 |
    | `firewall bridge` | frames switched in TC skip the bridge hooks | [fw-bridge](fw-bridge.md) |
    | `nat`, `nat66` (incl. `nat cgnat`) | prerouting/postrouting NAT | [nat](nat.md), [nat-cgnat-nat64](nat-cgnat-nat64.md) |
    | `nat64` | Jool hooks prerouting | [nat-cgnat-nat64](nat-cgnat-nat64.md) |
    | `policy-route`, `policy-route6` | prerouting marks; the kernel FIB and `ip rule` are never consulted | [pbr](pbr.md) |
    | `load-balancing wan` | prerouting marks and masquerade | [wan-load-balancing](wan-load-balancing.md) |
    | `system conntrack modules`, `system conntrack timeout custom` | helpers and custom timeouts never see a flow that has no conntrack entry | [conntrack](conntrack.md) |

  - Each plan adds its row when its tree lands, with a unit test. The table
    lives in `check.rs` as `EBPF_BYPASSED_TREES` (proposed).
  - Still allowed: `firewall … input|output`, `policy-local-route*`, VRF ct
    zones, `firewall flowtable` (a no-op for fast-pathed flows, not a
    security gap) and `service conntrack-sync` (its plan documents the
    limit). Local delivery punts, as §2 shows.
  - One error per eBPF interface:

    ```
    interface eth1 ebpf enabled: routed traffic entering eth1 is forwarded by
    the eBPF data plane and bypasses the firewall forward/prerouting rules;
    disable ebpf on eth1 or remove those rules
    ```

    The phrase after "bypasses" names the matched tree (`firewall zone`,
    `nat`, …); one error per eBPF interface lists every matched tree.
- **`manager.rs`:** call it next to `etree_backend` (`885-894`), with the
  same startup rule (warn only). Collect the leaves with a helper that
  mirrors `etree_backend_leaves`.
- **YANG:** none. A `must` would not work: this tree does not evaluate it
  (`extension.yang`, `non-empty` description).
- **Book:** `ch-16-00-ebpf.md` gets a "Netfilter" section with the §2
  pass/redirect table and the B rule.

### insomnia

- **Book:**
  - `ch-01-00-what-is-firewall.md` gets a short "eBPF ports" note after the
    feature paragraph (`:11-19`).
  - The NAT and zone chapters (`ch-01-05`, `ch-01-08`, `ch-01-09`, `ch-01-10`,
    all marked planned) get a one-line pointer.
- **Module doc:** the note in §3.
- No code change.

### Worked example (outcome B)

```
set system ebpf enabled true
set interface eth1 ebpf enabled true
set firewall ipv4 forward filter default-action drop
set firewall ipv4 forward filter rule 10 action accept
set firewall ipv4 forward filter rule 10 state established
commit
```

Expected result: the commit is refused with the message above, naming
`eth1`.

These variants commit:
- the same config with `firewall ipv4 input filter …` instead of `forward`;
- the forward rules without `interface eth1 ebpf enabled`.

## 5. Tests

**M1 experiment** (manual netns script, kept under `scratchpad`, not in
CI). Topology:

```
h1 10.0.1.2/24 ── r-h1 10.0.1.1/24 [ebpf] ── r (zebra-rs + cradle + insomnia) ── r-h2 10.0.2.1/24 ── h2 10.0.2.2/24
                                              lo 10.255.0.1/32
```

1. **Baseline, no eBPF.**
   - `firewall ipv4 forward filter rule 10 action drop destination address 10.0.2.2`.
   - Expect `ping h1→h2` to fail and the `show firewall` counter to rise.
2. **`system ebpf enabled`, then `interface r-h1 ebpf enabled`.**
   - Expected from the code: the ping succeeds and the nft counter stays
     flat.
   - `conntrack -L` shows no entry for the flow, and the cradle forward
     counter rises.
3. **eBPF on `r-h2` only.**
   - Expect h1→h2 to be dropped (kernel path) and h2→h1 to bypass.
   - A stateful `default-action drop` + `state established` policy shows the
     asymmetric effect.
4. **Input rule dropping ICMP to `10.0.1.1`.** Expect it to drop, because
   the address is local and the packet is punted.
   - Repeat with a destination of `10.255.0.1` (on `lo`). The outcome is
     unknown, and it decides whether the A text can promise input filtering
     for every router address.
5. **Prerouting raw `drop` rule.** Expect it to be bypassed.
6. **BFD Echo on `r-h1` with no `ebpf` leaf.** Run
   `tc filter show dev r-h1 ingress` and `bpftool net`, then repeat step 2.
7. **Repeat step 2** under `system ebpf mode tc-only` and `xdp-only`.

**Unit tests (zebra-rs, outcome B):**
- `ebpf_netfilter_refuses_forward_rules`;
- `ebpf_netfilter_allows_input_only`;
- `ebpf_netfilter_refuses_each_bypassed_tree` (one case per §4 table row present at the time);
- `ebpf_netfilter_needs_engine`: no `system ebpf|cradle enabled` gives no
  error;
- `ebpf_netfilter_startup_warns`.

**BDD: none for A/B.** The check is a pure config predicate, and the unit
tests cover it. A standing feature would need cradle staged in insomnia's
`bdd/.stage` (`make -C bdd stage` copies only zebra-rs, vtyctl, vtyhelper
and the YANG). Outcome C needs one:
- tag `@fw_ebpf_punt`, with the M1 topology;
- scenarios: forward drop holds with eBPF on, MPLS or overlay is still
  fast-pathed, and teardown.

## 6. Docs

- **zebra-rs** `book/src/ch-16-00-ebpf.md`: a new "Netfilter interaction"
  section with the pass/redirect table, the BFD Echo caveat and the reserved
  mark/pref/table.
- **insomnia** `book/src/ch-01-00-what-is-firewall.md`: the eBPF ports note.
  The planned NAT and zone chapters get pointers.
- **`design/vyos-gap.md` §4.7:** replace "*unverified*" with the M1 result
  and a link to this plan.
- **`src/firewall.rs`** module doc (§3).

## 7. Milestones

| # | Scope | Repo | Effort | Done when |
|:--|:--|:--|:--|:--|
| M1 | Investigation: the experiment in §5 (steps 1–7), findings recorded in this plan and in gap §4.7, outcome chosen with the §3 criteria | — (scratch netns) | S (≤ 2 days) | every step has an observed result; the four open cases are answered |
| M2 | Outcome A: both books and the module doc | insomnia + zebra-rs | S | `mdbook build` clean in both |
| M3 | Outcome B: `check::ebpf_netfilter` and its unit tests (plus the BFD Echo rule if M1 step 6 shows the full pipeline) | zebra-rs | S | unit tests green; worked example refused |
| (M4) | Outcome C1 or C2, only if chosen: its own plan in cradle-rs and zebra-rs, plus the `@fw_ebpf_punt` BDD | cradle + zebra-rs + insomnia | M / L | out of scope for this S plan |

## 8. Risks and open questions

- **Whether a router address off the attached port (loopback) is punted**
  (M1 step 4). If it is not, the A text must narrow "input rules apply" to
  the attached port's own addresses.
- **BFD Echo auto-attach** (M1 step 6) may make B incomplete.
- **Users who already run both.** B turns a silently broken config into a
  refused commit. The startup config only warns, so no router boots
  unconfigured. Call it out in the zebra-rs CHANGELOG.
- **NAT to router-owned addresses.** [inf] SNAT/DNAT on router-owned
  addresses would still work, because the replies are local and punted.
  Pools that are routed but not local would break. [nat](nat.md) must
  restate this under B.
- **The cradle version is pinned** (`cradle-version` 1.1.9). A cradle
  release that adds conntrack awareness or punt flags reopens the choice.
  The check should cite the cradle version it was written against.
- The design doc that zebra-rs YANG cites
  (`docs/design/xdp-tc-fast-path.md`, `config.yang:737`) exists in neither
  repo. That is a dangling reference for zebra-rs to fix.

## 9. Acceptance criteria

- [ ] M1 results are recorded for all seven steps, and gap §4.7 has no
      *unverified* left.
- [ ] Both books state which traffic insomnia's nftables rules cover on
      eBPF ports.
- [ ] Outcome B: the worked example is refused, input-only firewalls
      commit, and the startup config warns.
- [ ] The BFD Echo case is either covered by the check or documented as a
      cradle follow-up.
- [ ] cradle's fwmark `0x4c37` / pref `100` / table `2047` are recorded as
      reserved in [nft-common](nft-common.md) and [pbr](pbr.md).
- [ ] Every later netfilter plan (NAT, NAT64/CGNAT, PBR, WLB, zones, bridge,
      conntrack, conntrack-sync) links this plan for eBPF behaviour, and each
      B-class tree of §4 is in `EBPF_BYPASSED_TREES` once it exists.
