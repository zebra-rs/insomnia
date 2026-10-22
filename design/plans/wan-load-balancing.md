# WAN load balancing — implementation plan

Status: plan, 2026-10-21. Covers: `load-balancing wan` and
`show wan-load-balance` ([vyos-gap](../vyos-gap.md) §6.7). `load-balancing
haproxy` is out of scope (an L7 proxy, §6.7).
Priority: P3 · Effort: L · Owner: both (zebra-rs: per-WAN routes and rules;
insomnia: health checks, nft, hooks, show)
Depends on: [pbr](pbr.md) Z1–Z3 (the ip-rule southbound, table-ID bands,
numbered tables), [nft-common](nft-common.md) (bit-31 mark scheme, group sets,
matchers), [nat](nat.md) (masquerade conventions, `insomnia_node.sh`),
[multi-path-subscribe](multi-path-subscribe.md),
[conntrack](conntrack.md) (`ctread::delete` by mark and `ctread::dump`),
[exec-verbs](exec-verbs.md) (`restart wan-load-balance`: `Register.exec`,
`EXEC_ROUTES`, `ROUTES`, `Answer`), [commit-validation](commit-validation.md)
(`findings.rs`), [fw-global-options](fw-global-options.md) (`crate::links`);
soft: [ebpf-netfilter](ebpf-netfilter.md) (reserved cradle resources, eBPF
ports) · Unblocks: none

## 0. Do first instead

Most multi-WAN needs are met by zebra-rs-native features. Ship these, in
this order, before starting the work in this plan:

1. **Floating static default** (`router static ipv4 route 0.0.0.0/0
   nexthop A distance 1` plus `… nexthop B distance 10`).
   - Exists today (`config-static.yang:130`).
   - Fails over on link down only.
2. **Weighted ECMP default** (`nexthop A weight 1`, `nexthop B weight 2`).
   - Exists today (`config-static.yang:120`).
   - Pair it with one masquerade rule per WAN
     (`nat source rule N outbound-interface name ethX translation address
     masquerade`, [nat](nat.md)).
   - Per-flow kernel hashing (`fib_multipath_hash_policy`).
   - Limitation: a nexthop change rehashes some flows onto the other WAN
     with the old SNAT binding, and the ISP drops them. That is
     acceptable for failover-grade setups.
3. **BFD on static nexthops.** This is **missing in zebra-rs**: BFD is
   per-protocol only (`config.yang:5396-5398`). It is the zebra-rs-native
   health check that turns 1 and 2 into real failover with sub-second
   detection.
   - Proposed as a separate zebra-rs feature, M.
   - It covers most "WAN failover" requests.
4. **PBR** ([pbr](pbr.md)) for deterministic per-source or per-service
   steering.

Build this plan only when someone needs one of:
- weighted per-flow balancing that stays sticky across health changes,
  through conntrack marks;
- probe targets beyond the nexthop (ping or TTL tests toward the
  internet);
- user scripts or hooks.

## 1. Goal

- `set load-balancing wan …` (VyOS schema) exists with
  `--feature insomnia`.
- **zebra-rs** installs, for every `interface-health` entry, a default
  route via its nexthop in that WAN's table, plus the fwmark rule. These
  are derived purely from config.
- **insomnia** runs:
  - the health checks (`ping`, `ttl`, `user-defined`, with
    failure/success hysteresis);
  - `ip zebra_wanloadbalance`, which does weighted and failover
    balancing of new flows, sticky inbound, and per-WAN masquerade;
  - on each state change: `flush-connections` and the `hook`.
- `show wan-load-balance [connection|status]` and
  `restart wan-load-balance` work.
- insomnia never writes a route or an `ip rule`.

## 2. Current state

- **insomnia and zebra-rs @ baselines:**
  - no schema and no code;
  - no numbered tables and no `ip rule` code ([pbr](pbr.md) §2);
  - no DHCP or PPP client, so `nexthop dhcp` has nothing to read. The
    `dhcp` address enum is schema-only (`config.yang:5795-5810`).
- **VyOS @ `7f2c893`, schema.** `interface-definitions/load-balancing_wan.xml.in`:
  - global leaves: `disable-source-nat`, `enable-local-traffic`,
    `flush-connections`, `only-default-route`, `hook`;
  - `interface-health IF`:
    - `failure-count` (1), `success-count` (1), `nexthop` (address or
      `dhcp`);
    - `test N {type ping|ttl|user-defined (ping), target, resp-time (5),
      ttl-limit (1), test-script}`;
  - `rule N`:
    - `description`, `exclude`, `failover`, `inbound-interface`,
      `interface IF weight (1)`;
    - `limit {burst 5, period second, rate 5, threshold below}`;
    - `per-packet-balancing`, `protocol (all)`;
    - `source|destination {address, port, group}`;
  - `sticky-connections inbound`.
- **VyOS daemon.** `src/helpers/vyos-load-balancer.py`, run by
  `vyos-wan-load-balance.service`; reloads on SIGHUP.
  - A 5 s loop (`:41`, `:380-450`) runs `health_check` (`:43-88`).
    Probes use `ping -c 1 -W resp -I IF target`, plus `-t ttl` for
    TTL tests (`python/vyos/wanloadbalance.py:173-182`).
  - `assign_tables` (`:206-228`) gives tables 201+ (`mark_offset 0xc8`)
    and persists them in `/run/wlb_tables.json`.
  - `take_over_config` (`:244-296`) does
    `ip route replace table T default dev IF via NH` and `ip rule add`
    (`ip_rules`, `:230-235`). With `only-default-route` this is a
    `main suppress_prefixlength 0` rule at pref T plus a table rule at
    pref T+100.
  - On a state change:
    - nft re-render;
    - `ip route flush cache`;
    - `conntrack --delete --mark T` when `flush-connections` is set;
    - hook `/config/scripts/<hook>`, with env `WLB_INTERFACE_NAME` and
      `WLB_INTERFACE_STATE=ACTIVE|FAILED` (`:90-103`).
- **VyOS nft.** `data/templates/load-balancing/nftables-wlb.j2:8-68`
  renders `ip vyos_wanloadbalance`:
  - `wlb_nat_postrouting` at `srcnat - 1`:
    `ct mark M oifname IF counter snat to <if addr>`;
  - `wlb_mangle_prerouting` at `mangle` (-150): sticky
    `iifname IF ct state new ct mark set M`, then per rule a balance line
    and a `meta mark set ct mark` restore line;
  - `wlb_mangle_output` (type *filter*, output -150) for
    `enable-local-traffic`;
  - `wlb_mangle_isp_IF`: `meta mark set M ct mark set M counter accept`.

  The rule renderer is `wanloadbalance.py:27-146`:
  - `ct state new`, unless `per-packet-balancing`;
  - `numgen random mod Σw vmap`;
  - `failover` picks the highest-weight active interface (`:148-171`);
  - when no WAN is healthy, the rule is omitted.
- **VyOS verify** (`src/conf_mode/load-balancing_wan.py:67-158`):
  - `interface-health` must exist;
  - each WAN needs a `nexthop`;
  - each test needs a type; `user-defined` needs a script; ping and ttl
    need a target;
  - a rule needs `interface` or `exclude`, and each of its interfaces
    must have health config;
  - `!all` is refused;
  - `failover` and `limit` are invalid with `exclude`;
  - port and group checks as in NAT.
- **VyOS op mode** (`src/op_mode/load-balancing_wan.py`):
  - the summary prints `status_format` (`:30-36`) from the status file;
  - `connection` runs `conntrack -L -n` filtered on `mark=[1-9]`;
  - `status` dumps the prerouting chain;
  - `restart wan-load-balance` restarts the service.
- **VyOS defects, by code reading:**
  1. WLB marks are raw table numbers (`'mark': hex(table_num)`,
     daemon `:273`), set with `meta mark set M` and matched by an
     unmasked `ip rule fwmark 0xc9`. This **clobbers the bit-31
     fragment mark** set at -450, so firewall `fragment` matchers stop
     matching balanced packets.
  2. `wlb_mangle_output` is `type filter`. nftables re-routes
     locally generated packets after a mark change only in a
     `type route` output chain, so `enable-local-traffic` probably
     does not steer anything. This is *unverified* at runtime.
  3. `vyos_wanloadbalance` and `vyos_mangle` (PBR) both sit at -150,
     so their relative order is unspecified.

## 3. Design

**W-1. Split by what changes.**
- **zebra-rs** owns the *static* half: tables, routes and rules. Like
  VyOS, routes for every WAN stay installed whatever its health.
- **insomnia** owns the *dynamic* half: health, the nft weights and vmap,
  conntrack flushes and hooks.
- Health never touches routing, so no health → zebra-rs API is needed.
- Rejected: insomnia running `ip route replace` / `ip rule` (VyOS's
  model). That makes two netlink writers, and insomnia's routes would be
  invisible to the RIB (vyos-gap §6.7).

**W-2. Table assignment is a pure function of config, computed
identically on both sides.**
- WAN interfaces sorted by name get T = 201, 202, … (band 201–599 from
  [pbr](pbr.md) D-2).
- An optional extension leaf `interface-health IF table <201..599>`
  pins a WAN's table; pinned tables are excluded from the sorted
  assignment.
- When a live change moves an unpinned WAN to a new T, insomnia flushes
  conntrack entries carrying that WAN's *old* mark, because they would
  otherwise route via the wrong table.
- Deviation: VyOS persists assignments in `/run/wlb_tables.json`.
- Rejected: zebra-rs allocates and publishes the map. That needs a new
  API, and persistence that zebra-rs (config-only state) lacks.

**W-3. Marks use the PBR encoding, `M = 0x7FFFFFFF − T`, and preserve
bit 31.**
- zebra-rs installs the rules at the WLB prefs reserved in
  [pbr](pbr.md) D-2:
  - `pref 920 fwmark M/0x7fffffff lookup T`;
  - with `only-default-route`, also
    `pref 910 fwmark M/0x7fffffff lookup main suppress_prefixlength 0`,
    so it is evaluated first.
- The `/0x7fffffff` mask is the nft-common mark contract.
- All WANs share these prefs; their marks are distinct.
- This avoids:
  - cradle's pref 100;
  - the PBR pref 900, which runs first, so policy wins, consistent with
    W-4;
  - the l3mdev pref 1000.
- VyOS's pref = T / T + 100 is not kept (deviation).
- The tables (201–599) and marks never touch cradle's table 2047 or
  fwmark `0x4c37` ([ebpf-netfilter](ebpf-netfilter.md)).
- insomnia sets the mark with `nft::frag::set_mark(M)`
  (`meta mark set meta mark & 0x80000000 | M`), then `ct mark set M`.
- The restore needs two rules. nft 1.0.9 refuses
  `meta mark set meta mark & 0x80000000 | ct mark` ("Right hand side of
  binary operation (|) must be constant", reproduced), so the restore is
  split on bit 31:
  - `meta mark & 0x80000000 == 0 … meta mark set ct mark`;
  - `meta mark & 0x80000000 != 0 … meta mark set ct mark | 0x80000000`.
- This fixes VyOS defect 1. Deviation.

**W-4. Hook placement.**
- **Prerouting** runs at **-149**: after PBR (-150), so an explicit
  `policy-route` decision wins. It is guarded by
  `meta mark & 0x7fffffff != 0 return`. This fixes VyOS defect 3, and is
  a deviation.
- **SNAT** stays at 99 (`srcnat − 1`, VyOS), before user source NAT.
- **Output**, for `enable-local-traffic`, is `type route hook output
  priority -150`. This fixes VyOS defect 2, *unverified* until BDD.
- The SNAT is **`masquerade`**, not `snat to <addr>`.
  - Why: no tracking of addresses that can change. The kernel also
    drops masquerade bindings when the interface goes down or its
    address changes.
  - Deviation.
  - `disable-source-nat` omits the chain.

**W-5. Health task (`src/wlb.rs`).** A single ticker (5 s, VyOS
`sleep_interval`) launches one probe future per WAN concurrently, each
bounded by its `resp-time`. VyOS probes sequentially, so one dead WAN
delays the others.
- **ping and ttl probes:**
  - Command: `ping -n -c 1 -W <resp> -I <IF> -m <M> <target>`; `ttl`
    adds `-t <limit>`.
  - A ttl probe succeeds on a reply or on "Time to live exceeded"
    (VyOS).
  - `-m M` (SO_MARK) makes the probe follow the WAN's own table.
    VyOS relies on `-I` alone, which fails when main's default points at
    another WAN (*unverified* for VyOS). Deviation.
- **user-defined probes:**
  - `test-script` must be an absolute path; there is no
    `/config/scripts` base. Deviation.
  - It runs with `WLB_INTERFACE_NAME` and `WLB_SCRIPT_IFACE`; exit 0 is
    healthy.
- An interface counts as failed when it is absent from the shared
  `crate::links` snapshot (fw-global-options), or when it has no IPv4
  address. The address check is the probe itself: `ping -I` fails
  without one. VyOS checks the address explicitly.
- Hysteresis follows VyOS's loop (`:384-412`): consecutive
  failures/successes reaching `failure-count`/`success-count` flip the
  state. The initial state is "has an address". The hook learns every
  initial state once (VyOS's `report`).

**W-6. On a state change:**
1. Re-render and apply through `nft::apply::apply_if_changed`.
2. If `flush-connections` is set, delete conntrack entries by each WAN's
   mark with `ctread::delete(&DeleteFilter { mark: Some(M), .. })`. That
   is [conntrack](conntrack.md)'s reader (§3.8, M5); the `src` arm of the
   same call serves [nat-cgnat-nat64](nat-cgnat-nat64.md) C-3. The W-2
   old-mark flush uses the same call.
3. Run `hook` (absolute path) with `WLB_INTERFACE_NAME` and
   `WLB_INTERFACE_STATE`.

`ip route flush cache` is dropped: the IPv4 route cache no longer exists
(removed in Linux 3.6). Deviation.

**W-7. `nexthop dhcp` is skipped with a warning** until zebra-rs has a
DHCP client. That client will then own the gateway, and zebra-rs fills
in the route itself; insomnia needs no lease parsing. PPPoE is deferred
the same way.

**W-8. Show and exec.**
- `show wan-load-balance` uses VyOS's `status_format` block per
  interface.
- `connection` lists the `ctread::dump` flows whose `mark` is a WLB
  mark, filtered in-process.
- `status` shows the rules with live counters, joined by comment.
- `restart wan-load-balance` arrives through
  [exec-verbs](exec-verbs.md) as an EXEC order. It resets health state,
  re-probes, reports every state to the hook again, and answers
  `Answer { error: false }`.
- **Verify rules are `Findings`.** The [commit-validation](commit-validation.md)
  unit is `wlb → [load-balancing wan], [firewall group]`, served by
  `wlb::validate`.

**Deviations for the module doc:** W-2 (table assignment and pinning),
W-3, W-4, the W-5 probe mark and absolute script paths, W-6 (no route
flush), W-7, and the VyOS lowercase chain names kept under the
`zebra_wanloadbalance` table.

**Constraints:**
- Traffic entering an `ebpf enabled` port bypasses netfilter, so neither
  the WLB marks nor its masquerade apply to it. The outcome is decided by
  [ebpf-netfilter](ebpf-netfilter.md), and the chapter links to it. Under
  its default outcome B, this plan adds the `load-balancing wan` row to
  that check's `EBPF_BYPASSED_TREES` with W1.
- Locality is the same as for [pbr](pbr.md) (D-6). insomnia must run on
  the zebra-rs host, in the same netns.

## 4. Changes

### zebra-rs

**New `yang/load-balancing.yang`.**
- `grouping load-balancing-wan`, a port of the VyOS schema in §2.
- Rule `source` and `destination` reuse `fw:l3-match-core-v4` from
  [nat](nat.md) M1.
- Plus the extension leaf `interface-health IF table` (`uint16`,
  `range 201..599`).
- `config.yang`:
  `container load-balancing { if-feature feat:insomnia; container wan { uses lb:load-balancing-wan; } }`.

**WAN routes and rules (in-process subscriber).** From `interface-health`
and `only-default-route`:
- compute T and M (W-2, W-3);
- install `0.0.0.0/0 via NH dev IF` in table T;
- add the rules through [pbr](pbr.md)'s `RuleTable`.

This lives in the RIB, as a table-only instance like `router static table N`
([pbr](pbr.md) Z3). The nexthop resolves on-link via IF.

**`exec.yang`.**
- `show wan-load-balance` with `connection` and `status`.
- `restart wan-load-balance`, on the [exec-verbs](exec-verbs.md)
  grammar.
- `SHOW_PROTOS`: `(is_wlb, "wlb", "WAN load balancing")`.
- `EXEC_ROUTES`: `(["restart", "wan-load-balance"], "wlb", "WAN load balancing")`.

### insomnia

**New `src/wlb.rs`.**
- Model `WlbConfig`.
- `fn tables(&WlbConfig) -> BTreeMap<String, u16>` (W-2). The same
  algorithm is unit-tested on both sides against shared fixtures.
- `render(&WlbConfig, &Groups, &Health, &nft::Exclusions) -> (String, Findings)`
  and `validate(parts) -> Findings`.
- `struct Health { per_if: BTreeMap<String, IfState> }`.
- `probe(...)`.
- The run loop `select!`s over:
  - `subscribe_json_multi(&host, &[&["load-balancing","wan"], &["firewall","group"]], Fallback::Refuse)`,
    with parts decoded by `parse_subtree`;
  - the health ticker;
  - show requests;
  - EXEC orders, which arrive on the same request channel
    (exec-verbs).

**Wiring.**
- `main.rs`: a `wlb` field in exec-verbs' `Backends`, plus the shared
  `Links` handle.
- `provider.rs`:
  - `"wlb"` in `Register.name` and in `EXEC_TREES`;
  - `ROUTES` rows `(Show, "/show/wan-load-balance", Backend::Wlb)` and
    `(Exec, "/restart/wan-load-balance", Backend::Wlb)`.
- The deb `depends` gains `iputils-ping`.

**Worked example.** Config:

```
set load-balancing wan interface-health eth0 nexthop 192.0.2.1
set load-balancing wan interface-health eth0 test 10 target 192.0.2.1
set load-balancing wan interface-health eth1 nexthop 198.51.100.1
set load-balancing wan interface-health eth1 failure-count 3
set load-balancing wan rule 10 inbound-interface lan0
set load-balancing wan rule 10 interface eth0 weight 1
set load-balancing wan rule 10 interface eth1 weight 2
set load-balancing wan sticky-connections inbound
set load-balancing wan flush-connections
```

Table assignment by sorted name: eth0 gets T=201 (M=`0x7fffff36`), eth1
gets T=202 (M=`0x7fffff35`).

zebra-rs installs:
- `default via 192.0.2.1 dev eth0 table 201 proto zebra`;
- `default via 198.51.100.1 dev eth1 table 202 proto zebra`;
- `920: from all fwmark 0x7fffff36/0x7fffffff lookup 201 proto zebra`;
- `920: from all fwmark 0x7fffff35/0x7fffffff lookup 202 proto zebra`.

insomnia renders the script below with both WANs healthy. It passed
`nft -c` (1.0.9) and was loaded in a scratch netns:

```
add table ip zebra_wanloadbalance
delete table ip zebra_wanloadbalance
table ip zebra_wanloadbalance {
    chain wlb_nat_postrouting {
        type nat hook postrouting priority 99; policy accept;
        ct mark 0x7fffff36 oifname "eth0" counter masquerade comment "WLB-SNAT-eth0"
        ct mark 0x7fffff35 oifname "eth1" counter masquerade comment "WLB-SNAT-eth1"
    }
    chain wlb_mangle_prerouting {
        type filter hook prerouting priority -149; policy accept;
        meta mark & 0x7fffffff != 0 return
        iifname "eth0" ct state new ct mark set 0x7fffff36
        iifname "eth1" ct state new ct mark set 0x7fffff35
        iifname "lan0" ct state new counter numgen random mod 3 vmap { 0 : jump wlb_mangle_isp_eth0, 1-2 : jump wlb_mangle_isp_eth1 } comment "WLB-10"
        iifname "lan0" meta mark & 0x80000000 == 0 counter meta mark set ct mark comment "WLB-10-restore"
        iifname "lan0" meta mark & 0x80000000 != 0 counter meta mark set ct mark | 0x80000000 comment "WLB-10-restore-frag"
    }
    chain wlb_mangle_isp_eth0 {
        meta mark set meta mark & 0x80000000 | 0x7fffff36 ct mark set 0x7fffff36 counter accept
    }
    chain wlb_mangle_isp_eth1 {
        meta mark set meta mark & 0x80000000 | 0x7fffff35 ct mark set 0x7fffff35 counter accept
    }
}
```

When eth1 fails three probes in a row:
- the vmap collapses to `jump wlb_mangle_isp_eth0`;
- entries with mark `0x7fffff35` are flushed (`flush-connections`);
- the hook runs with `WLB_INTERFACE_NAME=eth1 WLB_INTERFACE_STATE=FAILED`.

With no healthy WAN, rule 10's balance line is omitted (VyOS); its
restore lines stay.

`show wan-load-balance` (VyOS `status_format`):

```
Interface: eth0
Status: active
Last Status Change: 2026-10-21 10:02:11
Last Interface Success: 0:00:04
Last Interface Failure: N/A
Interface Failures: 0
```

## 5. Tests

**insomnia `wlb::tests`:**
- `tables_sorted_and_pinned`, sharing a fixture with zebra-rs;
- `golden_render` (the example);
- `golden_failover_highest_weight`;
- `golden_no_healthy_wan_omits_rule`;
- `golden_exclude_returns`;
- `golden_per_packet_no_ct_state`;
- `golden_limit_above_below`;
- `golden_disable_source_nat`;
- `golden_enable_local_traffic_route_chain`;
- `hysteresis_counts` (a pure state machine fed probe results);
- `findings` (severity and effect): no nexthop; `nexthop dhcp`; a test without a
  target; a relative script path; a rule interface without
  health config; `!all`; failover with `exclude`; a port without
  tcp/udp;
- `probe_argv` (the exact `ping` argv, including `-m`);
- show text and JSON.

**zebra-rs:**
- route and rule derivation from the fixture;
- pin and band validation;
- `only-default-route` pairs at prefs 910 and 920;
- deleting a WAN removes its table route and its rules.

**BDD `wlb_dual`:**
- Topology:
  - `lan` (10.0.0.2);
  - `r1` (zebra-rs + insomnia, `insomnia_node.sh` from [nat](nat.md));
  - `isp1` (192.0.2.1/24) and `isp2` (198.51.100.1/24), each owning
    `203.0.113.1/32` on a dummy (the "internet").
- Scenarios:
  1. **Setup.**
  2. **Balancing.** Twenty parallel `curl`s or pings from different
     source ports reach 203.0.113.1. `show wan-load-balance status`
     shows both ISP chains' counters > 0, and `show wan-load-balance`
     shows both `active`.
  3. **Failover.**
     - Drop ICMP to `isp2`'s probe target (an nft rule in `isp2`).
     - The status eventually shows `eth1` `failed`.
     - New flows all go via `isp1`; the counters move only there.
     - The hook file written by a test script contains `eth1 FAILED`.
  4. **Recovery.** Remove the drop. `eth1` returns to `active`.
  5. **Sticky inbound.** A connection opened from `isp2` to a port
     forward on r1 ([nat](nat.md) rule) gets its replies out of eth1.
  6. **`restart wan-load-balance`** (after exec-verbs). The hook sees
     both states again.
  7. **Teardown topology.**

## 6. Docs

- **New book chapter `ch-06-02-wan-load-balancing.md`**, in the Policy
  Routing part from [pbr](pbr.md):
  - start with §0 as "Before you use this";
  - the zebra-rs/insomnia split;
  - table assignment and pinning;
  - the mark encoding;
  - probe semantics and absolute script paths;
  - the hook environment;
  - the locality rule (insomnia on the zebra-rs host), as for PBR.
- **`ch-03-08-show-wan-load-balance.md`.**
- **zebra-rs docs:** the derived per-WAN tables. A cross-link from the
  static-routes chapter to §0's ECMP/floating/BFD recipes.
- **`src/wlb.rs` module doc:** the deviation list. Record the three VyOS
  defects as reasons.
- **`design/vyos-gap.md` §6.7:** status.

## 7. Milestones

| # | Scope | Repo | Effort | Done when |
|:--|:--|:--|:--|:--|
| W0 | (prerequisite, separate plan) static-nexthop BFD in zebra-rs — §0 item 3 | zebra-rs | M | ships first; re-evaluate demand for W1+ |
| W1 | `load-balancing.yang` + exec grammar + `is_wlb` | zebra-rs | S | parses only with `--feature insomnia` |
| W2 | Per-WAN table routes and rules from config (needs [pbr](pbr.md) Z1–Z3); shared assignment fixture | zebra-rs | M | `ip rule` and `ip route show table 201` match the example |
| W3 | `src/wlb.rs` render + goldens (static health input) | insomnia | M | goldens green; the example loads |
| W4 | Health task, hysteresis, probes, state-change actions (flush via [conntrack](conntrack.md), hooks) | insomnia | M | unit tests; manual netns probe test |
| W5 | Show views; `restart` via [exec-verbs](exec-verbs.md) | insomnia | S | show tests green |
| W6 | BDD `wlb_dual` scenarios 1–5, 7 (6 after exec-verbs) | both | M | passes twice in a row |
| W7 | Docs | both | S | `mdbook build` clean |

W3 can start against fixtures once [nft-common](nft-common.md) lands. W2
and W6 need [pbr](pbr.md) Z1–Z3.

## 8. Risks and open questions

- **Value vs cost.** This plan is L for a P3 feature, and most users are
  served by §0. Gate W1+ on W0 shipping and a concrete request.
- **Table reassignment.** With unpinned WANs, adding a WAN that sorts
  earlier shifts later WANs' tables and marks. W-2 flushes the affected
  flows, which drops their connections once.
  - Open: should the pin leaf be mandatory once there are two or more
    WANs?
- **Interaction with PBR and NAT.**
  - PBR wins at -150 (W-4).
  - WLB masquerade at 99 wins over user SNAT at 100 for balanced flows;
    this is VyOS's order, documented.
  - A user `nat source … exclude` cannot exempt balanced flows from WLB
    masquerade. Use a WLB `rule … exclude` instead.
- **Probe privilege.** `ping -m` needs `CAP_NET_ADMIN`. insomnia runs as
  root (`packaging/systemd/insomnia.service`), so this holds; containers
  may need the capability.
- **Probe load.** Spawning `ping` every 5 s per test is what VyOS does.
  A raw ICMP socket implementation can come later if it ever shows up in
  profiles.
- **IPv6.** VyOS WLB is IPv4-only. This plan keeps parity; an `ip6`
  table would be a later extension.

## 9. Acceptance criteria

- [ ] **§0 recipes documented.** The floating static, ECMP + per-WAN
      masquerade and BFD recipes are in the book. W0 is tracked before
      W1 starts.
- [ ] **Routes stay in zebra-rs.** Per-WAN routes and rules exist only
      through zebra-rs, and insomnia executes no `ip route` or `ip rule`
      (a code-search check).
- [ ] **Byte-for-byte render.** The render matches the worked example,
      and the bit-31 restore is split into two rules.
- [ ] **Health transitions.** Hysteresis, flush-by-mark and hook
      invocation are unit-tested and pass in BDD.
- [ ] **Show and restart.** `show wan-load-balance [connection|status]`
      and `restart wan-load-balance` answer.
- [ ] **BDD feature passes.** `wlb_dual` passes and ends with a clean
      teardown.
