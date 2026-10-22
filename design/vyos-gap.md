# VyOS feature gap — design

Status: research, 2026-10-21. Nothing here is implemented yet. This
document is the inventory and the proposed order of work.

Baselines (line numbers below refer to these commits):

| Repo | Commit |
|:--|:--|
| vyos-1x | `rolling` @ `7f2c893` (2026-10-20) |
| zebra-rs | `141da2fc` (2026-10-19, v26.10.3) |
| insomnia | `ee4dfaa` |

insomnia enforces three VyOS-shaped trees, `firewall`, `vpn ipsec` and
`vrrp`, and its renderers follow the VyOS templates line for line. This
document answers four questions:

1. How far is each tree from VyOS rolling: schema, rendering, show
   commands and commit-time checks?
2. What is wrong in what insomnia already renders?
3. Which neighbouring VyOS features belong in insomnia rather than in
   zebra-rs?
4. In what order should the gaps close?

Method:
- VyOS `interface-definitions/` (with `include/`), `data/templates/`,
  `src/conf_mode/` (verify/apply), `src/op_mode/` and
  `op-mode-definitions/` were read against zebra-rs
  `yang/{config,firewall,ipsec,vrrp,exec}.yang` and insomnia `src/`.
- Where the book disagrees with the code, the code wins.
- Claims that could not be confirmed are marked *unverified*.
- The defects in §3 were re-checked by hand: the nft behaviour with
  `nft -c` (nftables 1.0.9) in a scratch network namespace, the rest by
  reading the code.

## 1. Scope and legend

**In scope, compared leaf by leaf:**
- `firewall`, `vpn ipsec`, and `high-availability` (zebra-rs `vrrp`).
- The VyOS features built on the same engines, or required by them:
  `nat`, `nat66`, `nat64`, `nat cgnat`, `system conntrack`,
  `service conntrack-sync`, `policy route` / `local-route`,
  `load-balancing wan`, `pki`, `interfaces vti` and `protocols nhrp`.

The rest of the VyOS tree is mapped coarsely in §9.

| Status | Meaning |
|:--|:--|
| MISSING-SCHEMA | VyOS has it; zebra-rs has no YANG node, so insomnia has no code either |
| NOT-APPLIED | In the zebra-rs schema, but insomnia drops it (silently or with a warning) |
| PARTIAL | Some forms work; the row says which |
| DONE | Implemented |
| DEVIATION | A deliberate difference, documented or to be documented |

**Effort:** S ≤ 1 week, M 1–3 weeks, L > 3 weeks. This counts the YANG,
the renderer, golden tests, show commands, and a BDD feature where one
makes sense.

**Priority:**
- **P1:** most real deployments need it, or it is a correctness or
  security defect.
- **P2:** common.
- **P3:** niche.

**Owner:** **insomnia**, **zebra-rs**, or both.

**Syntax scope.** zebra-rs is VyOS-shaped only where insomnia enforces:
- `firewall` and `vpn ipsec` keep VyOS spelling.
- `vrrp` is VyOS's `high-availability vrrp` with the wrapper dropped
  (`design/vrrp.md`).
- Routing, interfaces and policy use zebra-rs's own models, so VyOS
  parity is not a goal there. Examples: `router bgp` for
  `protocols bgp`, `interface <name>` for `interfaces <type> <name>`,
  and `policy NAME entry N` for `policy route-map NAME rule N`.

**Version skew.** `firewall.yang` and `ipsec.yang` were ported from VyOS
1.5 (circinus, IPsec syntax v13). Rolling has moved on: IPsec syntax v14,
a new fragment-mark scheme, and new `time` matching. Rows marked
*rolling* are changes since 1.5. Exactly which of them landed before 1.5
is *unverified*, because no circinus checkout was compared.

## 2. Summary

| Area | Works today | Fix first (§3) | Largest P1 gaps |
|:--|:--|:--|:--|
| Firewall | Static groups; ipv4/ipv6 filter and raw hooks; named chains; nearly every rule matcher; state-policy; logging; `show firewall` chains and groups | Overlapping group members, or a reference to something undefined, each stop the whole ruleset from loading | Zone-based firewall; `ipsec` matcher; commit-time verify |
| NAT / conntrack / PBR | Only the firewall's `connection-status nat` matcher | Conntrack timeouts and sysctl toggles in `global-options` are dropped silently | NAT44 source, destination and `exclude`, plus `show nat` |
| IPsec | PSK site-to-site; IKEv1/v2; ESP/IKE groups; tunnels; transport mode; the swanctl side of `vti bind`; four `show vpn ipsec` views | A bypass child can turn off encryption; a PSK with no `id` is a wildcard; `ikev2-reauth` is ignored | charon lifecycle; route-based VTI; PKI and x509 |
| VRRP | Every VyOS VRRP leaf except `snmp`; `show vrrp`, `detail`, `statistics` | — | Only a VRF spike. The rest is checks, ops verbs, SNMP and IPVS |

**Counts.** Each DONE row groups many leaves.
- **Firewall, 52 feature groups compared** (condensed to the gap rows in
  §5): DONE 7, PARTIAL 10, NOT-APPLIED 3, MISSING-SCHEMA 26, MISSING
  outside the schema 2, DEVIATION 4.
- **Firewall op-mode:** DONE 2, PARTIAL 4, MISSING 11.
- **Entirely MISSING-SCHEMA:** NAT, NAT66, NAT64, CGNAT,
  `system conntrack`, conntrack-sync, PBR and WAN load balancing.
- **VRRP:** rolling has not changed the VRRP leaf set since
  `design/vrrp.md`. Missing are `snmp` and `virtual-server`.

**Three cross-cutting limits decide the order of work:**
- **Commits cannot be vetoed (§4.1).** zebra-rs cannot reject a commit on
  insomnia's behalf, so every VyOS `verify()` rule is at best a warning
  after the commit. In the firewall, a bad reference silently keeps the
  old ruleset loaded.
- **Only `show` reaches insomnia (§4.2).** `reset vpn ipsec`,
  `reset conntrack`, `restart vrrp` and `generate pki` have no path.
- **One subtree per subscription (§4.3).** NAT, PBR, x509 and zones each
  need two.

## 3. Fix first: defects in what insomnia renders today

None of these needs schema work. Paths are insomnia `src/` @ `ee4dfaa`
unless noted.

| # | Area | Defect | VyOS | Effect | Checked by | Effort | Pri |
|:--|:--|:--|:--|:--|:--|:--|:--|
| X1 | firewall | Group sets get `flags interval` but no `auto-merge`, and flattened `include` members are not de-duplicated (`firewall.rs:1431-1439`, `1446-1482`) | `nftables-defines.j2` adds `auto-merge`; `nft_nested_group` de-duplicates | Overlapping members (`10.0.0.0/8` + `10.1.0.0/16`, port `80` + `80-90`, an include overlapping its parent) give `conflicting intervals specified`. The whole `nft -f -` transaction fails, the previous ruleset stays, and one log line is the only sign | `nft -c` 1.0.9: fails without `auto-merge`, passes with it | S | P1 |
| X2 | firewall | References to groups, interface-groups, jump targets and default jump targets are only syntax-checked (`safe_name`; `firewall.rs:1536`, `1677`, `1736`, `1887`) | `verify()` rejects the commit | An undefined `@A_x` or `NAME_x`, or a jump loop, makes nft reject the whole script, and the old ruleset stays. Fix: a pre-pass indexes the defined sets and chains, and a rule that references something missing is skipped with a warning | code reading | S | P1 |
| X3 | IPsec | The bypass ("passthrough") child is added when the local and remote prefixes overlap in either direction, and `0/0` is not skipped (`ipsec.rs:1013-1032`; test `overlap_detection` asserts that `0.0.0.0/0` overlaps `192.168.1.0/24`) | Only when local ⊂ remote, and the default prefix is skipped (`vpn_ipsec.py:900-920`) | `local 0.0.0.0/0 remote 192.168.1.0/24`, or `local 10.0.0.0/8 remote 10.0.0.0/24`, renders a `mode = pass` child over the whole local prefix, which covers the tunnel's own traffic. strongSwan installs pass policies above IPsec policies, so that traffic leaves unencrypted | code reading; confirm in BDD | S | P1 |
| X4 | IPsec | `authentication psk <n>` with no `id`, or with only `dhcp-interface` (not supported yet), renders a bare `secret` (`ipsec.rs:563-586`) | `ConfigError` "missing id or secret" | A shared secret with no owner matches any identity in strongSwan: a wildcard PSK | code reading; confirm the wildcard match in BDD | S | P1 |
| X5 | IPsec | `ikev2-reauth` (peer and ike-group) is parsed and never read (`ipsec.rs:215`, `265`). `reauth_time` is written only as `0`, for `@` responder peers | `peer.j2` renders `reauth_time = <ike lifetime>s` | Reauthentication never happens. The book (ch-02-01, appendix A RFC 7296 row) says it does | code reading | S | P2 |
| X6 | IPsec | `disable-uniqreqids` gets a warning as "charon-level, not applied" (`ipsec.rs:548-558`) | `unique = never` per connection in swanctl | A missed feature that needs no charon restart | code reading | S | P2 |
| X7 | IPsec | `tunnel N protocol all` renders `[all/<port>]` (`ipsec.rs:929-941`) | `all` maps to empty | strongSwan 5.9 rejects `[all/]`, so that connection fails to load | code reading | S | P2 |
| X8 | IPsec | `updown = /etc/ipsec.d/vti-up-down vtiN` is rendered, but no such helper ships (`Cargo.toml` assets) | VyOS ships `src/etc/ipsec.d/vti-up-down` | charon's updown call fails on every SA up/down (exact charon behaviour *unverified*) | code reading | S | P1 with VTI (§7.3) |
| X9 | firewall | A `state-policy` entry with no `action` renders `accept` (`firewall.rs:1280-1284`) | Only log and counter, so the packet goes on through the chain | More permissive than VyOS | code reading | S | P2 |
| X10 | firewall | Fragment matching overwrites the whole packet mark with `0xffff1` at priority -450 and then matches it exactly (`firewall.rs:1256-1268`, `1793-1802`) | *rolling*: sets bit 31 (OR) and clears it at filter+10 | Fragments lose any mark set elsewhere (tc, policy routing). This blocks PBR and WAN-LB marking (§6) | code reading | S | P2 |
| X11 | firewall | `show firewall group` counts interface-group references twice; an ipv6-address-group's count includes IPv4 rules that name a group with the same name (`firewall.rs:537-584`); `-j` on a single chain returns the whole family (`480-482`, `498-500`) | — | Misleading show output | code reading | S | P3 |
| X12 | firewall | Every resubscribe (that is, every zebra-rs restart) re-applies the ruleset even when it is unchanged, which resets counters and `recent` sets (`firewall.rs:56-98`) | Reloads only on commit | Counters are lost. Fix: compare before applying, as `keepalived::apply` does | code reading | S | P3 |
| X13 | IPsec, VRRP | Files that hold secrets are created with default permissions and only then changed to `0600`: `swanctl.conf` (PSKs, `ipsec.rs:125-129`) and `keepalived.conf` (VRRP password, `keepalived.rs:229-241` `write_atomic`) | — | For a short window the file is readable under the process umask (`0644` with systemd's default `0022`). Fix: create the temp file with mode `0600` up front, in one helper shared by both backends | code reading | S | P1 |
| X14 | firewall | Rule `time weekdays` is passed through as written (`firewall.rs:1999-2011`), so the book's own example `weekdays Mon,Tue,Wed,Thu,Fri` (ch-01-02) renders `day {"Mon",…}` | VyOS expands the abbreviations | nft accepts only full day names (or numbers), so the whole ruleset fails to load. The fix is milestone 1 of [fw-matchers](plans/fw-matchers.md) (Phase 0), separate from the rest of FW17 | `nft -c` 1.0.9: `"Mon"` rejected ("did you mean `Monday`?"), `"Monday"` accepted | S | P1 |
| X15 | show routing (zebra-rs) | zebra-rs `SHOW_PROTOS` predicates (`is_bgp`, `is_ospf`, …, `manager.rs:1979-2091`) test `CommandPath.name` anywhere in the path. For a list key that field holds the value the user typed (`parse.rs:812-820`), and BGP is checked first | — | `show firewall ipv4 name bgp`, `show firewall group ospf` or `show vrrp detail group isis` is sent to the wrong daemon. Fix: match only path elements that are not key values (`key` empty), or match on the root. Milestone 1 of [fw-opmode](plans/fw-opmode.md) | code reading | S | P2 |

**Documentation that is wrong today:**
- **Feature rename.** `--feature iso` is now `--feature insomnia`
  (zebra-rs `ab1c0774`; `iso` is still accepted, with a deprecation
  warning). Stale in:
  - book ch-00-03, ch-01-00, ch-02-00, ch-04-00, ch-05-00, ch-05-05;
  - BDD `bdd/tests/scripts/vrrp_node.sh:72` and `ipsec_node.sh:88`;
  - `design/vrrp.md` §4, §9 and §10.

  The BDD scripts break once the alias is removed.
- **ch-01-06 (connection tracking):**
  - It says a commit that sets conntrack timeouts logs a warning. Nothing
    is logged.
  - It says notracked packets show `state invalid`. In nft they are
    `ct state untracked`, which `firewall.yang` cannot match.
- **ch-01-10 (static NAT):** it writes `inbound-interface name eth0`.
  VyOS static NAT uses a plain `inbound-interface eth0`.
- **ch-02-01 and appendix A:** they say `ikev2-reauth` works (X5).
- **`design/vrrp.md`:** corrections are listed in §8.4.

## 4. Cross-cutting gaps

### 4.1 Commit-time validation

What exists today:
- `proto/config.proto` has a single `Subscribe` RPC, so insomnia sees a
  commit only after it has happened.
- zebra-rs supports YANG `mandatory` (`src/config/configs.rs:552-571`)
  and has a commit-check hook (`manager.rs:849-878`), but `check.rs` has
  no rules for these trees.
- Every VyOS `verify()` rule therefore becomes an insomnia
  skip-with-warning. Many become nothing at all, and the firewall cases
  in X2 become a ruleset that silently fails to load.

Rules that are not enforced at commit:

| Tree | Rules |
|:--|:--|
| firewall | 29 families. A rule must have an action; references must exist (groups, chains, includes, interface-groups) and must not loop; a port needs tcp/udp; `icmp` vs `ipv6-icmp` per family; no `match-frag` together with `match-non-frag`; and so on |
| IPsec | PSK id and secret; ike-group set and existing; auth mode set; IKE PRF required for AEAD; transport-mode prefixes; VTI bind exists; later PKI references |
| VRRP | Password ≤ 8 characters; description ≤ 255; VIP is not a network address; health-check timeout ≥ 1; health-check and transition scripts exist and are executable |

Proposal, in three layers:

1. **YANG constraints for structural rules:** `mandatory`, `length`,
   `range` and enums. These cost nothing at runtime and work without
   insomnia. `firewall.yang` deliberately avoids `leafref`, so a
   reference can be staged before its target, and that stays.
2. **A dry-run validation RPC on insomnia for cross-reference rules.**
   zebra-rs sends the candidate subtree; insomnia runs the same `render`
   and returns errors (the X2 pre-pass, PKI references, VRF membership).
   The renderer stays the single source of truth. If insomnia is not
   connected, zebra-rs commits with a warning instead of blocking:
   availability over strictness. The alternative, re-implementing the
   rules in zebra-rs `check.rs`, duplicates logic that already lives in
   the renderers.
3. **Until layer 2 exists, render-time skip-with-warning for every
   rule**, so that one bad rule never stops the rest from loading (the
   X1/X2 fixes).

Owner: zebra-rs (layers 1 and 2, the RPC client) and insomnia (layer 2,
the server). Effort L. P1.

### 4.2 Operational verbs beyond `show`

- `ShowOrder` routing works by `/show/…` prefix (`src/provider.rs`).
  zebra-rs handles `clear` in-process and has no reply path for it
  (`manager.rs:1500-1536`). There is no `restart`, `reset` or `generate`
  grammar.
- Blocked by this:

  | Area | Blocked commands |
  |:--|:--|
  | IPsec | `reset vpn ipsec site-to-site …`, `restart ipsec` |
  | Conntrack | `reset conntrack`, `reset conntrack-sync …` |
  | VRRP | `restart vrrp` |
  | PKI | `generate pki …` |

- Proposal: extend `zebra.show.v1` with an exec order kind that keeps the
  same oneshot reply contract (answered exactly once, a dropped oneshot
  becomes an error chunk), or add a sibling `zebra.exec.v1`. Either way
  zebra-rs needs the grammar, plus routing of those verbs to providers.
- insomnia also needs a VICI request encoder with `terminate` and
  `initiate` (`src/vici.rs` is list-only today), and needs to keep the
  last committed IPsec model (`process()` drops it).
- Owner: both. Effort M. P2.

### 4.3 Subscriptions spanning several subtrees

`SubscribeRequest.path` names one subtree. These consumers need more:

| Consumer | Subtrees |
|:--|:--|
| NAT, PBR, conntrack | own tree + `firewall group` (nft sets are table-scoped, so each table re-renders the groups) |
| x509 IPsec | `vpn ipsec` + `pki` |
| Route-based VPN | `vpn ipsec` + VTI interfaces |
| Zone firewall with VRF members, VRF conntrack zones | VRF membership; the plans read it from the kernel through `crate::links` ([fw-global-options](plans/fw-global-options.md)) instead of a second subscription |
| `virtual-server` | `vrrp` + `virtual-server` (same keepalived file) |

- Two streams have no ordering guarantee, so one commit that touches both
  trees arrives as two events, with a transient mismatch in between.
- Proposal: a multi-path subscribe in zebra-rs that delivers one snapshot
  and then one event per commit, covering all the named subtrees
  atomically. This is the same contract as today, widened.
- Owner: zebra-rs (+ insomnia `subscribe.rs`). Effort M. P1, because NAT
  is the first consumer.

### 4.4 sysctl writer

- insomnia writes no sysctls today. Three features need them:
  - firewall `global-options` toggles (NOT-APPLIED, FW5);
  - conntrack timeouts (FW6);
  - `system conntrack` sizes (§6.4), plus `apply-to-bridged-traffic`.
- The keys are disjoint from zebra-rs's (`src/fib/netlink/sysctl.rs`:
  `ip_forward`, `rp_filter`, `forwarding`, `seg6`, `keep_addr_on_down`,
  `vrf.strict_mode`, `tcp_l3mdev_accept`, `mpls.platform_labels`).
- Per-interface `conf.<if>.*` keys must be re-applied when an interface
  appears, which needs either zebra-rs interface events or a netlink
  watch.
- zebra-rs forces `rp_filter=0`, so `source-validation` must stay nft
  `fib` rules, which is what VyOS rolling does too.
- Decision needed: VyOS always writes its defaults (directed-broadcast
  forwarding on, log-martians on, redirects off), and these differ from
  kernel defaults. Recommendation: write only what is configured, and
  record the difference as a deviation, so that a host with no
  `global-options` keeps its kernel behaviour.
- Owner: insomnia. Effort M. P2.

### 4.5 Daemon lifecycle

- **keepalived:** insomnia owns its instances (compare-before-reload,
  systemd or signal mode).
- **charon:** insomnia does not own it (`ipsec.rs:20-24`), so every
  strongswan.d setting is blocked: `disable-route-autoinstall`, `log`,
  `interface`, `flexvpn`, `virtual-ip`, `retransmission`, and the DHCP
  and RADIUS plugins.
- Proposal: an insomnia-owned `strongswan.d` drop-in with
  compare-before-restart, the same shape as `keepalived::apply`, and a
  signal mode for BDD.
- **conntrackd** (§6.5) would follow the same pattern.
- Owner: insomnia. Effort M. P2. Per strongSwan 5.9.13's source,
  charon installs no routes for children with an `if_id` (VTI), so
  route-based VTI does not strictly need `install_routes = no`
  ([charon-lifecycle](plans/charon-lifecycle.md),
  [ipsec-vti](plans/ipsec-vti.md)).

### 4.6 Secrets

- PSKs, the VRRP password, and future PKI private keys, passphrases and
  remote-access local-user passwords all appear in
  `show running-config` and in JSON output. zebra-rs has no masking
  (VyOS `strip-private`).
- insomnia writes them to files with mode `0600`.
- A `tcp:` `--host` carries them in clear.
- Proposal: a zebra-rs secret-leaf extension that redacts in show
  output. Document that `unix:` is required once PKI exists.
- Owner: zebra-rs. Effort M. P2, rising to P1 together with PKI.

### 4.7 eBPF fast path

- Interfaces with `ebpf enabled` forward in XDP/TC (cradle). A packet
  that XDP or TC redirects never traverses netfilter, so neither
  insomnia's firewall nor any future NAT or PBR table sees it.
- Reading cradle's code ([ebpf-netfilter](plans/ebpf-netfilter.md)): it
  forwards plain IPv4/IPv6 at TC ingress using its own route tables, with
  no conntrack awareness. So forward and prerouting rules are bypassed
  on those ports. A network-namespace experiment to confirm this is that
  plan's first milestone.
- Until that is settled, document insomnia's nftables features as
  applying to kernel-forwarded traffic only, or have zebra-rs refuse the
  combination. This needs a check, not a guess: S, P1.

## 5. Firewall

**DONE:**
- **Groups:** address, ipv6-address, network, ipv6-network, port, mac and
  interface groups, with `include` (cycle-safe).
- **Hooks and chains:** ipv4/ipv6 forward, input and output `filter`;
  output and prerouting `raw`; named chains.
- **State and verdicts:** state-policy established/invalid/related;
  accept, drop, reject, continue, return, jump, notrack and queue.
- **Logging and defaults:** `log` and `log-options`, with VyOS-identical
  prefixes; default-action, default-log and default-jump-target.
- **Matchers:** state, connection-status, protocol, address,
  address-mask, mac, port, groups, interface name/group, icmp/icmpv6,
  ttl, hop-limit, packet-length, packet-type, dscp, limit, recent, tcp
  flags/mss, connection-mark.

VyOS 7f2c893 has no reject types, so a bare `reject` is parity.

| # | Feature (VyOS path under `firewall`) | Status | Needs | Effort | Pri |
|:--|:--|:--|:--|:--|:--|
| FW1 | `zone <z>`: `member interface\|vrf`, `from <z> firewall name\|ipv6-name`, `default-firewall`, `intra-zone-filtering`, `local-zone`, `default-action`, `default-log` | MISSING-SCHEMA | nft only, following `nftables-zone.j2`: ZONE_FORWARD/LOCAL/OUTPUT at priority 1 and `VZONE_<z>` chains that jump to `NAME_`. `member vrf` needs VRF membership from the kernel (`crate::links`) and a re-render when an interface is enslaved. Plus `show firewall zone-policy` | M (L with vrf) | P1 |
| FW2 | rule `ipsec match-ipsec\|match-none` in/out | MISSING-SCHEMA | `meta ipsec exists\|missing`, `rt ipsec …`. Per-hook subsets: in on input/prerouting, out on output, both on forward/name | S | P1 |
| FW3 | commit-time verify (29 rule families) | MISSING | §4.1 | L | P1 |
| FW4 | `global-options source-validation`, `ipv6-source-validation` | NOT-APPLIED | nft only: `fib saddr . iif oif 0 drop` at prerouting -300, as rolling does. The fib/VRF interplay needs a BDD test | S | P2 |
| FW5 | `global-options` sysctl toggles (all-ping, broadcast-ping, directed-broadcast, ip-src-route, log-martians, receive/send-redirects, syn-cookies, twa-hazards-protection, ipv6 variants) | NOT-APPLIED (silent) | §4.4 | M | P2 |
| FW6 | `global-options timeout …` | NOT-APPLIED (silent) | sysctl `nf_conntrack_*_timeout` (§4.4, §6.4) | S | P2 |
| FW7 | rule `set dscp\|mark\|connection-mark\|ttl\|hop-limit\|tcp-mss` | MISSING-SCHEMA | nft statements before the verdict; `mark` uses the bit-31 mask (X10) | S | P2 (tcp-mss clamping on PPPoE and tunnels) |
| FW8 | `group dynamic-group` + rule `add-address-to-group` | MISSING-SCHEMA | `DA_`/`DA6_` sets with `flags dynamic, timeout`; `set update … @DA_x`; show of live members | S | P2 (port knocking, brute-force lists) |
| FW9 | `flowtable <n>`, `action offload`, `state-policy offload` | MISSING-SCHEMA | nft flowtables. The devices must exist when the script loads, otherwise the whole script fails, so gate on interface existence. Hardware offload needs ethtool `hw-tc-offload` | M | P2 |
| FW10 | `group domain-group`, rule `fqdn`, `global-options resolver-*` | MISSING-SCHEMA | A resolver task that refills the `D_` / FQDN sets after every atomic replace, because each apply recreates the table empty | M | P2 |
| FW11 | `global-options geoip`, rule `geoip`, op `update geoip` | MISSING-SCHEMA | DB download and refresh; bulk load of sets out of band | L | P2 |
| FW12 | `bridge …` hooks, `bridge name`; vlan/ether-type matchers; inet group references; `apply-to-bridged-traffic` | MISSING-SCHEMA | `table bridge zebra_firewall`; `br_netfilter` + sysctls | L | P2 |
| FW13 | per-VRF conntrack zones | MISSING | §6.4 | M | P2 |
| FW14 | `group remote-group` | MISSING-SCHEMA | HTTP fetch loop with an on-disk cache, on FW10's out-of-band set updater | M | P3 |
| FW15 | rule `conntrack-helper` | MISSING-SCHEMA | `ct helper` matcher; useful only with `system conntrack modules` (§6.4) | M | P3 |
| FW16 | rule `fib`, `gre`, `mac-address-mask`, `last-used`; `synproxy` action and options; `disable-conntrack` per hook | MISSING-SCHEMA | nft only | S each | P3 |
| FW17 | rule `time`: one hour range that may cross UTC midnight, weekday abbreviations, re-arm when the UTC offset changes | PARTIAL (*rolling*) | renderer | S | P3 |
| FW18 | group references with `address-mask`; `queue` as a range (the fanout case; `firewall.yang` has `uint16`); `recent` with only one of count/time (dropped); interface name together with group (name wins) | PARTIAL | renderer, schema union, verify | S | P3 |
| FW19 | custom-chain default-rule label (`NAM-<name>`) | DEVIATION (undocumented) | adopt VyOS's label so `show log firewall` matches | S | P3 |

| Op-mode (VyOS) | Status | Needs | Pri |
|:--|:--|:--|:--|
| `show firewall`, `show firewall ipv4\|ipv6`, per-chain views | DONE / PARTIAL | state-policy section; per-chain `-j` (X11) | P2 |
| `show firewall group` | PARTIAL | referencing rule paths (including nat/policy), description, live members of dynamic/domain/remote groups; X11 | P2 |
| `… rule <N> [detail]` | MISSING | exec key under each chain | P2 |
| `show log firewall [ipv4\|ipv6\|bridge …]` | MISSING | `journalctl -k` filtered on the prefixes, which already match VyOS's (except FW19) | P2 |
| `show firewall zone-policy [zone <z>]` | MISSING | with FW1 | P1 with FW1 |
| `show firewall group <name> [detail]`, `summary`, `statistics [detail]`, `… detail` | MISSING | exec keys; `last-used` for detail | P3 |
| `generate firewall rule-resequence` | MISSING | a zebra-rs config helper, not insomnia | P3 |

VyOS has no `clear` or `reset firewall` command.

Firewall order:
1. X1, X2, X9.
2. FW2.
3. FW3, with the design starting in parallel.
4. FW1 + zone-policy show.
5. FW4, then FW5 + FW6.
6. FW7 with X10, then FW8.
7. Op-mode.
8. FW9.
9. FW10, then FW14.
10. FW11.
11. FW12.
12. FW13.
13. The P3 tail.

## 6. NAT, connection tracking, policy routing

None of this exists in zebra-rs except FW5 and FW6 above. zebra-rs `src/`
has no NAT, conntrack or `ip rule` code.

### 6.1 Engine map

nft orders base chains by priority across tables. VyOS's priorities are
kept exactly. The proposed insomnia tables are each replaced atomically
with add+delete, like `zebra_firewall`.

| Priority | VyOS rolling | insomnia today | Proposed insomnia |
|:--|:--|:--|:--|
| -450 | VYOS_FRAG_MARK (bit-31 OR) | ZEBRA_FRAG_MARK (overwrites, X10) | bit-31 scheme |
| -300 | `vyos_conntrack` (ignore / notrack), `vrf_zones` ct zone, rpfilter | ZEBRA_PREROUTING_raw / ZEBRA_OUTPUT_raw | `zebra_conntrack`, `inet zebra_vrf_zones`, rpfilter (FW4) |
| -199 | custom `ct timeout` chains | — | `zebra_conntrack` |
| -150 | `vyos_mangle` (PBR), `vyos_wanloadbalance` | — | `ip/ip6 zebra_mangle` |
| -100 | `vyos_nat` / `vyos_static_nat` PREROUTING | — | `ip zebra_nat` (static rules ahead of dynamic), `ip6 zebra_nat` |
| -5 | conntrack helper chains | — | `zebra_conntrack` |
| 0 | `vyos_filter` | `zebra_firewall` | — |
| 99 | WLB snat, `vrf_zones_nat` anchor | — | `zebra_vrf_zones` NAT anchor |
| 100 | `vyos_nat` POSTROUTING, `cgnat` | — | `zebra_nat` (static, then dynamic rules, then CGNAT maps) |

- VyOS has no NAT OUTPUT chain, so DNAT never applies to traffic the
  router itself originates. Keep that.
- Tables are independent: an `accept` in one table's chain does not skip
  another table's chain, so NAT and the firewall need nothing beyond
  priorities.

### 6.2 NAT44: `nat source`, `nat destination`, `nat static`

**Design sketch:**
- **New backend.** A `nat` backend (`src/nat.rs`) subscribes to `nat`
  and `firewall group` (§4.3) and renders everything into `ip zebra_nat`
  in one `nft -f -` transaction. Static rules go first, so there is no
  `zebra_static_nat` table. VyOS hooks `vyos_nat` and `vyos_static_nat`
  at the same priority, which leaves their relative order unspecified.
  Details in [nat](plans/nat.md).
- **Shared code.** The group-set renderer, the token checks, the
  address/port/interface matchers and the rule sort move out of
  `firewall.rs` into a shared module. VyOS shares the same macros
  between the firewall, NAT, mangle and conntrack templates.
- **Schema.** zebra-rs `nat.yang` reuses the `firewall.yang` groupings
  (`match-interface-in/out`, `rule-base`, `l3-match-*`), uses
  `if-feature feat:insomnia`, and adds `exec.yang` show grammar plus a
  `SHOW_PROTOS` entry.
- **Deviations to record:**
  - Drop the empty VYOS_PRE_DNAT_HOOK / VYOS_PRE_SNAT_HOOK chains;
    nothing in vyos-1x fills them.
  - Static NAT and CGNAT live in `zebra_nat` (see above).
- **Hairpin.** VyOS has no hairpin or reflection knob; operators write a
  destination rule plus a masquerade rule. Document the pattern.

| Feature | Status | Needs | Effort | Pri |
|:--|:--|:--|:--|:--|
| source rule + masquerade; SNAT to address, range or prefix (+port) | MISSING-SCHEMA | `snat to`, `snat ip prefix to … map` at srcnat 100 | M (the core) | P1 |
| destination rule / port forward | MISSING-SCHEMA | `dnat to` at dstnat -100 | incl. | P1 |
| `exclude` | MISSING-SCHEMA | `return` | S | P1 (NAT exemption for the policy-based IPsec insomnia ships) |
| matchers: address/port/protocol, interface name or group, firewall groups | MISSING-SCHEMA | the shared matcher code | incl. | P1 |
| `show nat source\|destination rules\|statistics` | MISSING | nft JSON counters, like `show firewall` | S | P1 |
| `log`, `disable`, `description`; `redirect` | MISSING-SCHEMA | `log prefix "[SRC-NAT-n]"`; `redirect to :p` | S | P2 |
| `nat static` 1:1 | MISSING-SCHEMA | paired dnat/snat; prefix maps; `inbound-interface` is a plain, mandatory leaf | S | P2 |
| `show nat … translations`, `show conntrack table\|statistics` | MISSING | one ctnetlink (or `conntrack` CLI) reader | S | P2 |
| translation options, `load-balance` backends, `packet-type` | MISSING-SCHEMA | `persistent`/`random`; `jhash`/`numgen` maps | S | P3 |
| `fqdn` / `domain-group` | MISSING-SCHEMA | the FW10 resolver | M | P3 |

### 6.3 NAT66, NAT64, CGNAT

| Feature | Status | Engine / needs | Owner | Effort | Pri |
|:--|:--|:--|:--|:--|:--|
| `nat66 source\|destination` | MISSING-SCHEMA | `ip6 zebra_nat` in the same transaction as NAT44. VyOS's "NPTv6" is stateful `snat\|dnat prefix to`, not RFC 6296 stateless NPTv6 | insomnia `nat` | S (after §6.2) | P2 |
| `nat64` | MISSING-SCHEMA | Jool: an out-of-tree kernel module plus CLI, one JSON instance per rule, recreated when pool6 changes; packaging and hook priority *unverified*; DNS64 is out of scope | insomnia, new backend | M | P3 |
| `nat cgnat` | MISSING-SCHEMA | maps inside `zebra_nat` at srcnat, after `exclude` and static rules so a user `exclude` still exempts traffic ([nat-cgnat-nat64](plans/nat-cgnat-nat64.md)); deterministic port-block allocation; `conntrack -D` on pool change; `show nat cgnat allocation` | insomnia `nat` | M | P3 |

### 6.4 Connection tracking

| Feature | Status | Needs | Owner | Effort | Pri |
|:--|:--|:--|:--|:--|:--|
| global timeouts (FW6) and toggles (FW5) | NOT-APPLIED | sysctl writer, in the firewall backend (already subscribed) | insomnia | S | P2 |
| `system conntrack table-size \| hash-size \| expect-table-size` | MISSING-SCHEMA | sysctl; whether these are writable inside a non-init netns (BDD) is *unverified* | insomnia `conntrack` | S | P2 (busy NAT boxes overflow the default) |
| `system conntrack modules ftp\|sip\|tftp\|pptp\|h323\|rtsp\|nfs\|sqlnet` | MISSING-SCHEMA | modprobe/rmmod, `ct helper` objects, a chain at -5 | insomnia `conntrack` | M | P2 (FTP/SIP/PPTP through NAT) |
| per-VRF ct zones (derived in VyOS) | MISSING | `inet zebra_vrf_zones` iif→zone map + NAT anchor at 99. Membership comes from the kernel through `crate::links` ([fw-global-options](plans/fw-global-options.md)); the zone number can be any stable per-VRF value | insomnia `conntrack` | M | P2 (required before NAT or a stateful firewall across overlapping VRFs) |
| `tcp loose\|max-retrans\|half-open`, `flow-accounting`, `log timestamp` | MISSING-SCHEMA | sysctl | insomnia | S | P3 |
| `timeout custom` | MISSING-SCHEMA | `ct timeout` objects, chain at -199. VyOS's ip6 table renders `l3proto ip`, which is likely a bug, so check before porting | insomnia | M | P3 |
| `ignore` rules | MISSING-SCHEMA | VyOS itself points to `firewall … prerouting raw`, which is DONE | — | S | P3 |
| `log event …` | MISSING-SCHEMA | ctnetlink event listener → journal; `show log conntrack` | insomnia | M | P3 |
| notrack-by-default | n/a | VyOS ends the raw chains with `notrack` unless the firewall, NAT or WLB needs state | — | — | DEVIATION: do not port. It couples the conntrack table to three subtrees for a performance gain |

The new backend subscribes to `system conntrack`, which would be an
insomnia-gated child of the existing zebra-rs `container system`, plus
`firewall group`.

### 6.5 `service conntrack-sync`

- **What VyOS does:**
  - conntrackd in FTFW mode, over multicast or UDP unicast.
  - It reads the live `hashsize` and `nf_conntrack_max` at commit, so
    §6.4 must apply first.
  - `failover-mechanism vrrp sync-group <g>` adds
    `notify_master|backup|fault` lines that call
    `vyos-vrrp-conntracksync.sh` on that sync group.
- **Conflict.** insomnia renders `transition-script` as native `notify_*`
  lines (`src/vrrp.rs`), and the conntrack hook needs the same slots.
  VyOS avoids the clash because it uses a FIFO plus a dispatcher.
  keepalived 2.2.8 drops a second `notify_master` in the same block
  (tested while writing [conntrack-sync](plans/conntrack-sync.md)), so
  the hook uses keepalived's separate generic `notify` slot instead, and
  user transition scripts stay as they are.
- **Lifecycle.** The same render / compare / reload pattern as
  keepalived (§4.5).
- **VRF.** With per-VRF keepalived (`design/vrrp.md` §13), conntrackd
  needs the same shim or must stay in the default VRF.
- Owner: insomnia. Effort M. P3.

### 6.6 Policy-based routing: `policy route`, `route6`, `local-route`

**What VyOS does:**
- `policy route <n>` binds rule sets to interfaces. The rules use the
  firewall matcher set plus
  `set table|vrf|mark|connection-mark|dscp|tcp-mss|ttl|hop-limit`.
- They render into `vyos_mangle` at prerouting -150, so the policy covers
  forwarded and inbound traffic only.
- `set table T` marks `meta mark & 0x80000000 | (0x7FFFFFFF - T)`. VyOS
  then installs `ip rule pref T fwmark … table T`.
- `policy local-route` is pure `ip rule`.

**Proposed split:**
- **insomnia** owns the nft half: `ip/ip6 zebra_mangle` at -150, reusing
  the firewall rule renderer with the VyOS mark encoding. Prerequisite:
  X10.
- **zebra-rs** owns everything in the routing layer:
  1. the fwmark→table `ip rule`s implied by `set table|vrf`;
  2. `policy local-route` (pure `ip rule`);
  3. numbered static tables (`router static table N`);
  4. a VRF table-ID contract.

  zebra-rs is the only netlink route writer and allocates VRF table IDs.
  BGP flowspec redirect needs the same `ip rule` southbound.

**Rejected:** insomnia installing the `ip rule`s itself. That would mean
two netlink writers, and the rules would break whenever zebra-rs
re-allocates a VRF table.

**Blockers on the zebra-rs side:**
- **Name collision.** zebra-rs's top-level `list policy` is the route-map
  list, so `policy route FOO` parses as a route-map named `route`.
  `is_policy` (`manager.rs:2047-2061`) also sends any show path
  containing `policy` to the route-map module. The VyOS spelling cannot
  be used verbatim: rename (for example top-level `policy-route`,
  `policy-route6`, `policy-local-route`) or special-case the parser.
- **No `ip rule` code** and no numbered non-VRF tables
  (`config-static.yang` routes have no `table`).
- **VRF table IDs** are allocated smallest-free from 1 (`alloc.rs`),
  which collides with VyOS's 1–200 range for `set table`. Reserve a
  range, or publish the name→ID map.

PBR only makes sense on the same host as the FIB, while insomnia may run
remotely, so document that constraint.

| Feature | Owner | Effort | Pri |
|:--|:--|:--|:--|
| `ip rule` southbound, numbered static tables, VRF table-ID contract, schema rename | zebra-rs | M | P2 |
| `zebra_mangle` rule sets + interface binding + `set` actions; `show policy route` | insomnia | M | P2 |
| `policy local-route(6)` | zebra-rs | S (after the southbound) | P2 |
| geoip / domain-group in PBR | insomnia (shared with FW10/FW11) | M | P3 |

### 6.7 WAN load balancing, haproxy

**`load-balancing wan`:**
- VyOS runs a health-check daemon. It assigns tables 201+, installs
  `ip route replace` and `ip rule` itself, and renders nft mangle and
  snat.
- The routes and rules would have to go through zebra-rs (§6.6);
  insomnia must not write routes behind the RIB.
- Defer, and steer users to zebra-rs-native alternatives first: static
  routes with BFD or tracking, ECMP, and PBR.
- Effort L. P3.

**`load-balancing haproxy`:** out of scope. It is an L7 proxy with its
own daemon and certificates.

## 7. IPsec

**DONE**, verified line for line against `peer.j2` and `template.py`:
- **esp-group:** every leaf, including the full proposal lists and pfs
  groups 1–32.
- **ike-group:** every leaf except `ikev2-reauth` (X5), including DPD
  defaults and aggressive mode.
- **authentication psk:** deterministic `id-N` keys (DEVIATION).
- **site-to-site peer:** every leaf in the schema.
- **tunnels:** traffic selectors, `any` widening, transport-mode
  selectors.
- **`vti bind`, swanctl side:** `-vti` child, `if_id`, updown.
- **Proposal strings:** these match `_get_esp_ike_cipher` except for ESN.

### 7.1 Structural constraints

- **charon lifecycle:** not owned (§4.5).
- **`vici.rs`:** handles only streamed `list-sas` / `list-conns`, with
  no request encoder outside tests (§4.2).
- **IPsec model:** not retained after rendering (§4.2).
- **Subscriptions:** one subtree each (§4.3), which blocks `pki` and VTI
  interfaces.

### 7.2 Gaps in `vpn ipsec`

| Feature | Status | Needs | Owner | Effort | Pri |
|:--|:--|:--|:--|:--|:--|
| `options disable-route-autoinstall` | NOT-APPLIED | `charon.install_routes = no` + restart (§4.5) | insomnia | S | P2 (VTI children get no auto-installed routes anyway; matters for policy-based peers) |
| peer `authentication mode x509`, `x509 certificate\|passphrase\|ca-certificate` | MISSING-SCHEMA | PKI (§7.3); PEM files under `x509/`, `x509ca/`, `x509crl/`, `private/`; `auth = pubkey`, `certs`, `send_cert = always` | both | L (with PKI) | P1 |
| peer `vti bind` (the interface side) | PARTIAL | §7.3 VTI | both | M | P1 |
| peer `vti traffic-selector local\|remote` | MISSING-SCHEMA | swanctl only | both | S | P2 |
| peer `connection-type trap` (*rolling* rename of `respond`, migration 13→14) | DEVIATION (undocumented) | accept `trap` as an alias; the rendering is already identical | zebra-rs | S | P2 (pasting current VyOS configs) |
| peer and psk `dhcp-interface` | NOT-APPLIED (peer skipped, psk static ids only) | zebra-rs DHCP client (a schema stub today), plus a re-render on lease change | both | M | P2 |
| `remote-access` (connections, local-user / EAP-MSCHAPv2 / EAP-TLS / RADIUS authentication, address pools, DHCP pools) | MISSING-SCHEMA (insomnia always renders an empty `pools {}`) | swanctl `ra-<n>`; PKI for the default x509 server mode; eap and radius plugins + strongswan.d (§4.5); redaction of local-user passwords (§4.6) | both | M–L | P2 |
| peer `authentication mode rsa` (pki key-pair), `use-x509-id` | MISSING-SCHEMA | PKI key-pairs; `pubkey/` files | both | M | P2 |
| `log level\|subsystem`, `interface`, `options flexvpn\|virtual-ip\|interface` | NOT-APPLIED (warned) | strongswan.d + restart | insomnia | S | P3 |
| `options retransmission` (*rolling*) | MISSING-SCHEMA | `charon.retransmit_*` | both | S | P3 |
| peer `childless`, `unique`; proposal `esn`; DH groups 33–35 (ML-KEM); `authentication ppk`; psk `secret-type` (all *rolling*) | MISSING-SCHEMA | swanctl only. ML-KEM needs strongSwan ≥ 6.0 with the ml plugin (distro builds *unverified*) | both | S each | P3 (ML-KEM P2 if post-quantum is a goal) |
| peer names containing `.` or `:` | DEVIATION (undocumented; VyOS rejects them, insomnia dashes them) | document | — | S | P3 |
| `profile` (DMVPN) | MISSING-SCHEMA | GRE/mGRE interfaces + NHRP (§7.3) | both | L | P3 |
| `vpn l2tp remote-access ipsec-settings` | MISSING-SCHEMA | an L2TP LNS (accel-ppp) | other + insomnia | L | P3 |

### 7.3 Dependencies

**PKI** blocks x509, rsa, remote-access with x509 server mode, and
`generate ipsec profile`.
- **VyOS model:**
  - `pki ca`: certificate, private key, crl.
  - `pki certificate`: certificate, private key, ACME.
  - `pki key-pair`.
  - `pki dh`, `pki openssh`, `pki openvpn shared-secret`.
  - Values are base64 PEM bodies without the armour lines.
- **What VyOS does with them:**
  - On every commit, `vpn_ipsec.py` wipes the swanctl credential
    directories and rewrites them.
  - `pki.py` refuses to delete an object that something still
    references.
- **zebra-rs needs:**
  - `pki` YANG: at least `ca`, `certificate`, `key-pair`, `crl`;
  - redaction (§4.6);
  - commit checks: the PEM parses, and the reference exists and is not
    deleted while in use (§4.1).
- **insomnia needs:**
  - a `pki` subscription merged with `vpn ipsec` (§4.3);
  - a credential writer: `private/` at mode 0700 and keys at 0600, with
    stale-file cleanup that is idempotent on resync.
- **Show and generate:**
  - `show pki …` (X.509 parsing: expiry, subject, issuer) is P2.
  - `generate pki` / `import pki` need a config write path that
    `config.proto` lacks. They are P2, because VyOS users bootstrap x509
    this way.
- Out of scope: ACME/certbot, `system-install`, openvpn and ssh objects.
- Effort M + M. P1.

**VTI / XFRM interfaces** (route-based VPN).
- **VyOS:**
  - `interfaces vti vtiN` becomes `ip link add vtiN type xfrm if_id N+1`.
  - The link stays admin-down until an SA references it.
  - charon's `vti-up-down` helper flips it, under the commit lock.
- **zebra-rs** has no vti, xfrm, GRE or tunnel interface type. It needs:
  - a `vti` list (or an xfrm link kind);
  - netlink create with `IFLA_XFRM_IF_ID`;
  - addresses and VRF through the existing `interface` tree.
- **Link up/down. insomnia must pick one:**
  - (a) Link always up, as a DEVIATION. Simplest, and BGP/OSPF over VTI
    is unaffected, but a static route over a down SA blackholes traffic.
  - (b) A VICI `child-updown` subscription (needs VICI `register`) that
    asks zebra-rs to change link state through a new API.
  - (c) Ship a helper script. It would fight zebra-rs over link state.

  Recommendation: (a) first, then (b). Either way, stop rendering the
  dangling helper path (X8).
- **Does not strictly need** `disable-route-autoinstall`: charon
  installs no routes for children with an `if_id` (strongSwan 5.9.13
  source).
- **Workaround today:** create the xfrm link by hand. Whether zebra-rs
  applies `interface` config to a link that appears later is
  *unverified*.
- Effort M. P1.

**NHRP / DMVPN.**
- **VyOS** renders FRR `nhrpd`, which drives charon over VICI.
- **Blockers:**
  - FRR nhrpd needs FRR zebra and cannot run beside zebra-rs;
  - opennhrp is unmaintained;
  - zebra-rs has no GRE/mGRE interfaces. Those are also needed for
    GRE-over-IPsec, which is P2 on its own.
- **Realistic path:** native NHRP in zebra-rs (RFC 2332 + DMVPN
  shortcuts) plus insomnia rendering the `profile` connections. The
  NHRP NFLOG rules could live in insomnia's nft script.
- Effort L. P3.

### 7.4 Op-mode

zebra-rs has `show vpn ipsec sa|connections|policy|state` (all DONE).

| VyOS command | Needs | Owner | Pri |
|:--|:--|:--|:--|
| `reset vpn ipsec site-to-site all\|peer <p> [tunnel <n>\|vti]` | §4.2 verbs; VICI `terminate` / `initiate`; retained model (re-initiate only for `connection-type initiate`) | both | P2 |
| `show vpn ipsec sa detail`, `show vpn ike sa [nat-traversal\|peer <p>]`, `show vpn debug [peer …]` | grammar + VICI/`swanctl -l` formatting | both | P2 |
| `show pki …`, `generate pki …`, `import pki …` | §7.3 | zebra-rs (+ insomnia show) | P2 |
| `restart ipsec`, `show vpn ike status\|secrets`, `show vpn ipsec status`, `generate ipsec debug-archive`, `show log ipsec` | §4.2, §4.5 | both | P3 |
| remote-access views and resets, `generate ipsec profile ios\|windows-remote-access`, `reset vpn ipsec profile …`, `show ip nhrp …` | with remote-access / DMVPN | both | P3 |

## 8. VRRP / high availability

**Parity.** Rolling's `high-availability vrrp` leaf set matches
`design/vrrp.md` §4 exactly: no leaf added, renamed or removed, and the
wrapper has not moved. The comparison was by content, because the clone
has no history. What remains:

### 8.1 Gaps

| Feature | Status | Needs | Effort | Pri |
|:--|:--|:--|:--|:--|
| VRRP in a VRF (`design/vrrp.md` §13) | MISSING-SCHEMA + NOT-APPLIED | First a spike: a multicast group on a VRF-enslaved interface under today's `default` instance may already work, because advert sockets bind to the interface. That would shrink §13 to unicast peers, health checks and scripts | S spike, then L | P1 spike, P2 work |
| script existence/executable check (health-check and the four transition scripts) | PARTIAL (only quoting is checked) | insomnia shares a host with keepalived, so it can stat locally and warn | S | P2 |
| `password` ≤ 8, `description` ≤ 255, health-check `timeout` ≥ 1, VIP not a network address (VyOS `ip-host`) | PARTIAL | YANG `length`/`range` + a render check (§4.1 layer 1) | S | P2 |
| BDD breadth (IPv6 VRRPv3, unicast, auth, health-check → FAULT, track, sync-group, transition scripts, no-preempt) | MISSING (only the IPv4 multicast pair) | features | M | P2 |
| IPv6-tentative wait before reload (VyOS T5533) | NOT-APPLIED | poll `tentative` on the hello-source address | S | P3 |
| `ext:dynamic "rib:interface"` completion on the three `interface` leaves | PARTIAL | schema | S | P3 |
| `vrrp snmp` (AgentX subagent: `--snmp`), `vrrp snmp trap` (`enable_traps`) | MISSING-SCHEMA | Two features. Either change needs a keepalived *restart*. Per-VRF instances would register the same MIB OIDs. zebra-rs has no SNMP story | M | P3 |
| `virtual-server` (IPVS) | MISSING-SCHEMA | §8.2 | M | P3 |
| conntrack-sync failover hook; mDNS repeater `vrrp-disable`; password masking | MISSING (cross-feature) | §6.5, an mDNS tree, §4.6 | — | P3 |

### 8.2 `virtual-server` sketch

- **VyOS leaves:**
  - `address`, `port` or `fwmark`;
  - `algorithm` (rr, wrr, lc (default), wlc, sh, dh, lblc);
  - `forward-method` nat, direct or tunnel;
  - `protocol` tcp or udp;
  - `persistence-timeout`, `delay-loop`;
  - `real-server <ip>` with `port`, `connection-timeout` and
    `health-check script`.

  These render as `virtual_server` blocks in the same keepalived.conf.
- **Schema:** a new insomnia-gated top-level `virtual-server` list with
  the leaves verbatim, the same hoisting rule as `vrrp`.
- **Rendering:** the VRRP task takes a second subscription (§4.3) and
  appends the blocks after `vrrp_sync_group`, as the VyOS template does.
  - `is_empty()` must become "neither tree has content".
  - `vrrp disable` must drop only the VRRP blocks. VyOS's
    `high-availability disable` stops both.
- **fwmark services** cannot be fed from zebra-rs config until a
  mark-setting facility exists (FW7 or PBR). Render them, but warn.
- **Show:** `show virtual-server` from `ipvsadm -Ln`, or from
  `/proc/net/ip_vs`. keepalived's JSON dump covers VRRP only.
- **Scope:** default VRF only, because IPVS is per netns.
- **VyOS bug:** its real-server verify loop is dedented out of the
  per-server loop. Fix it rather than copy it.

### 8.3 Op-mode

| VyOS | zebra-rs / insomnia | Status |
|:--|:--|:--|
| `show vrrp`, `show vrrp detail`, `show vrrp statistics`, JSON | same | DONE. insomnia also lists DISABLED groups when keepalived has no data |
| `show vrrp <NAME> statistics\|detail` | `show vrrp statistics\|detail group <NAME>` | DEVIATION (word order + keyword), not recorded anywhere yet. An alias is possible but ambiguous for groups named `detail`, `statistics` or `vrf`: P3 |
| `restart vrrp` | — | MISSING (§4.2): P3 |
| `show log vrrp`, `monitor log vrrp` | — | MISSING. `journalctl -u insomnia-keepalived@<vrf>` would do it, but streaming does not fit the oneshot reply: P3 |
| `show virtual-server` | — | with §8.2 |

### 8.4 Corrections to `design/vrrp.md`

1. **Feature rename** (§4, §9, §10): `feat:iso` is now `feat:insomnia`,
   and `shipped_tree(&["iso"])` is now `shipped_vrrp_gated_on_insomnia`.
2. **§8 show grammar:** shipped is
   `show vrrp {statistics|detail} group <NAME>`. Record the word-order
   deviation there and in the `src/vrrp.rs` module doc.
3. **§13 shim name and failure mode:**
   - `LD_PRELOAD` needs a shared object, so the default
     `--vrf-preload /usr/lib/insomnia/vrf.o` should be `vrf.so` (or be
     documented as built with `-shared`).
   - ld.so prints "cannot be preloaded … ignored" and carries on, so a
     missing shim would silently run a VRF instance in the default VRF.
     insomnia must refuse to start a non-default instance unless the
     shim exists and is a shared object. P1 when the VRF work starts.
4. **§1 conf-mode and unit rows:**
   - Add the T5533 IPv6-tentative wait and the restart-on-`snmp`-change
     rule.
   - VyOS's unit override is `Type=simple`; `insomnia-keepalived@` is
     `Type=notify`. Record that as a deviation. Ubuntu 2.2.8 supports
     sd_notify; other distro builds are *unverified*.
5. **§6 rules:**
   - VyOS treats a sync-group member with its own health check as a hard
     `ConfigError` (smoketest-asserted); insomnia warns and ignores it.
     That is a stronger deviation than the other rows.
   - zebra-rs `master-refresh` 0..255 is a deliberate superset of VyOS's
     1-255.
6. **§14 deferred list:**
   - Split SNMP into the subagent and traps.
   - Add `restart vrrp`, `show log vrrp`, script validation, the tentative
     wait, the mDNS hook, password masking, interface completion, the
     show word order, and the BDD breadth.
7. **§1 reference:** change "verified against `current`" to
   "re-verified against `rolling` @ `7f2c893` (2026-10-21), by content".

## 9. Beyond the current backends

**Coverage.** One row per VyOS `interface-definitions/*.xml.in` (129
files). The status says whether an equivalent node exists, not whether
the VyOS syntax is matched.

| zebra-rs status | Count | Areas |
|:--|:--|:--|
| DONE | 9 | `interfaces loopback`, `protocols bgp\|isis\|ospf\|ospfv3\|pim\|pim6\|static\|static arp` (native models) |
| PARTIAL | 16 | firewall, high-availability, vpn ipsec (the insomnia trees); bridge, ethernet, vxlan, policy, bfd, mpls, segment-routing, traffic-engineering, router-advert, host-name, vrf; dhcp-server and dhcp-relay (schema only, see below) |
| ABSENT | 104 | 31 belong in zebra-rs core, 36 are insomnia-shaped, 37 are out of scope |

"Insomnia-shaped" means configuration for an external daemon or a
kernel subsystem that zebra-rs's routing core does not own, plus its
show commands. Ranked by value for a router/firewall appliance:

| # | VyOS area | Engine | Why it matters |
|:--|:--|:--|:--|
| 1 | `nat`, `nat66`, `nat cgnat` | nftables | §6; table stakes at the edge |
| 2 | `service dhcp-server`, `dhcpv6-server`, `dhcp-relay` | Kea, isc-relay | Essential on the LAN side. zebra-rs already has a `system dhcp` schema in an IETF-draft shape, with no backend, so the schema shape (VyOS or existing) must be chosen first |
| 3 | `interfaces wireguard` | kernel genetlink | The simplest modern VPN. zebra-rs could create the device while insomnia owns keys, peers and show |
| 4 | `service dns forwarding` | PowerDNS Recursor | The LAN resolver; pairs with DHCP. Needs `system name-server` / `static-host-mapping` from core |
| 5 | Firewall remainder + `system conntrack` | nftables, sysctl | §5, §6.4 |
| 6 | `vpn ipsec` remainder + `pki` | strongSwan | §7. PKI also gates OpenVPN and OpenConnect |
| 7 | `service conntrack-sync` | conntrackd | §6.5; stateful failover for the VRRP pair |
| 8 | `qos` (+ `interfaces input`/IFB) | tc | WAN shaping and policing |
| 9 | `interfaces pppoe` | pppd | DSL/FTTH uplinks; zebra-rs consumes the interface and the default route |
| 10 | `service ntp` | chrony | IKE, certificate validation and logs all need correct time |
| 11 | `system syslog`, `service snmp`, `service lldp`, `service ssh` | rsyslog, net-snmp, lldpd, sshd | Standard appliance management |
| 12 | `policy route` + `load-balancing wan` | nftables + zebra-rs rules | §6.6, §6.7 |

**Next tier:** `interfaces openvpn`, `vpn openconnect`,
`system flow-accounting`, `system sflow`, `nat64`, `virtual-server`.

**zebra-rs core (absent):**
- **Interfaces:** bonding, dummy, tunnel/GRE, vti, macvlan, veth,
  geneve, l2tpv3.
- **Routing:** `protocols nhrp`, `rpki`, `failover`, `igmp-proxy`, RIP,
  Babel, EIGRP, OpenFabric; `policy local-route`; `system ip`/`ipv6`
  forwarding knobs; `system sysctl`.
- **System basics:** login, name-server, domain, time-zone,
  static-host-mapping; config archive and commit-confirm.

**Out of scope:** containers, VPP, wireless/WWAN, haproxy, web proxy,
Suricata, the console server, LCD, cloud integrations, monitoring agents,
VyOS's HTTPS API, and image lifecycle.

Each new insomnia backend from this list gets its own design document,
in the shape of `design/vrrp.md`.

## 10. Roadmap

Phases are ordered by dependency. Within a phase, items are independent.

**Phase 0: correctness and docs.** S each; insomnia unless noted.
- X1–X4, X13 and X14 (the P1 defects), then X5–X12.
- The doc corrections in §3 and §8.4, including the `--feature insomnia`
  rename in the book and BDD scripts.
- The eBPF/netfilter check (§4.7).
- The VRRP-in-VRF spike (§8.1).

**Phase 1: platform prerequisites.**
- Multi-path subscribe (§4.3). zebra-rs + insomnia, M.
- Validation, layer 1 (YANG constraints across the three trees) and the
  design of layer 2 (§4.1). zebra-rs, M to start.
- Shared nft helper module, extracted from `firewall.rs`, and the bit-31
  fragment-mark scheme (X10). insomnia, S.
- sysctl writer (§4.4). insomnia, M.
- charon `strongswan.d` lifecycle (§4.5). insomnia, M.

**Phase 2: P1 features.**
- NAT44 source/destination/exclude + `show nat … rules|statistics`
  (§6.2). Both, M.
- Firewall `ipsec` matcher (FW2). Both, S.
- Zone-based firewall + `show firewall zone-policy` (FW1). Both, M;
  interface members first, VRF members once `crate::links` exists.
- Route-based VTI: zebra-rs xfrm links, link always up (§7.3).
  Both, M.
- PKI + x509 site-to-site (§7.3). Both, L.
- Validation layer 2 (§4.1). Both, L.

**Phase 3: P2.**
- **Conntrack and NAT follow-ons:** apply the global-options toggles and
  timeouts (FW4–FW6); `system conntrack` sizes and helpers; VRF ct zones;
  static NAT, NAT66, translations and `show conntrack`.
- **Firewall:** `set` actions, dynamic groups, flowtables, op-mode
  (`rule <N>`, `show log firewall`, group view).
- **IPsec:** `reset`, `show … detail` and `show vpn ike sa` (needs §4.2);
  remote access; rolling-syntax parity (`trap`, `vti traffic-selector`);
  `dhcp-interface` once zebra-rs has a DHCP client.
- **VRRP:** validation, BDD breadth, per-VRF instances as trimmed by the
  spike.
- **PBR:** the zebra-rs side first, then `zebra_mangle`.
- **Secret redaction** (§4.6).

**Phase 4: P3.**
- Firewall: DNS, remote and geoip groups; the bridge firewall; the
  long-tail matchers.
- conntrack-sync; CGNAT; NAT64.
- VRRP: SNMP; `virtual-server`.
- DMVPN; L2TP; WAN load balancing.

**New backends** (§9: DHCP, DNS forwarding, WireGuard, …) are scheduled
separately, each with its own design document. DHCP is the strongest
candidate after NAT.

## 11. Open decisions

| # | Decision | Recommendation |
|:--|:--|:--|
| D1 | How commits are vetoed (§4.1) | YANG constraints plus a dry-run validation RPC on insomnia; commit with a warning when insomnia is not connected |
| D2 | Non-show verbs (§4.2) | Extend `zebra.show.v1` with an exec order kind rather than add a new service |
| D3 | Multi-subtree consumers (§4.3) | Multi-path subscribe in zebra-rs, rather than a root subscription or several skewed streams |
| D4 | sysctl defaults (§4.4) | Write only what is configured; record the VyOS-defaults difference |
| D5 | PBR ownership and spelling (§6.6) | nft in insomnia; `ip rule`, tables and the VRF table-ID contract in zebra-rs; rename the top-level node away from `policy` |
| D6 | Conntrack notrack-by-default (§6.4) | Do not port |
| D7 | VTI link state (§7.3) | Always up first; a VICI-driven state API later |
| D8 | `virtual-server` placement (§8.2) | Top-level `virtual-server`, rendered into the VRRP keepalived instance |
| D9 | DHCP schema shape (§9) | Decide before any backend work: keep zebra-rs's IETF-draft `system dhcp`, or adopt VyOS's `service dhcp-server` |
| D10 | ML-KEM / post-quantum priority (§7.2) | P3 unless it becomes a product goal |

## 12. References

**vyos-1x `rolling` @ `7f2c893`:**
- `interface-definitions/`: `firewall.xml.in`, `nat*.xml.in`,
  `system_conntrack.xml.in`, `service_conntrack-sync.xml.in`,
  `policy_route.xml.in`, `policy_local-route.xml.in`,
  `load-balancing_wan.xml.in`, `vpn_ipsec.xml.in`, `pki.xml.in`,
  `interfaces_vti.xml.in`, `protocols_nhrp.xml.in`,
  `high-availability.xml.in`, plus `include/{firewall,ipsec,vrrp,nat,pki}/`.
- `data/templates/`: `firewall/nftables*.j2`, `conntrack/*`,
  `conntrackd/*`, `ipsec/**`, `high-availability/*`,
  `load-balancing/*`.
- `src/conf_mode/`: `firewall.py`, `nat*.py`, `system_conntrack.py`,
  `service_conntrack-sync.py`, `policy_route.py`,
  `policy_local-route.py`, `load-balancing_wan.py`, `vpn_ipsec.py`,
  `pki.py`, `interfaces_vti.py`, `protocols_nhrp.py`,
  `high-availability.py`.
- `python/vyos/`: `firewall.py`, `nat.py`, `template.py`.
- Op mode: `src/op_mode/`, `op-mode-definitions/`.

**zebra-rs @ `141da2fc`:**
- `zebra-rs/yang/`: `config.yang`, `firewall.yang`, `ipsec.yang`,
  `vrrp.yang`, `exec.yang`, `zebra-features.yang`.
- `zebra-rs/src/config/manager.rs`, `zebra-rs/src/rib/vrf/alloc.rs`,
  `zebra-rs/src/fib/netlink/sysctl.rs`.

**insomnia @ `ee4dfaa`:**
- `src/firewall.rs`, `src/ipsec.rs`, `src/vici.rs`, `src/vrrp.rs`,
  `src/keepalived.rs`, `src/provider.rs`, `proto/config.proto`,
  `proto/show.proto`.
- `design/vrrp.md`, `book/src/`.
