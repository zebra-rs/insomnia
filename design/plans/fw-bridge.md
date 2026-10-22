# Bridge firewall — implementation plan

Status: plan, 2026-10-21. Covers: FW12, which includes the
`firewall bridge …` hooks and `bridge name`, the vlan and ether-type matchers,
inet group references, the bridge state-policy copy, and
`global-options apply-to-bridged-traffic`; also `show firewall bridge …`
([vyos-gap](../vyos-gap.md) §5 FW12, §4.4, the §5 op-mode table).
Priority: P2 (P3 for `accept-invalid`) · Effort: L · Owner: both
Depends on: [nft-common](nft-common.md) (`crate::nft`: `Fam`, `Script`,
`group::render_sets`, `rule::render_rule`, `apply_if_changed`, extended
here with a bridge mode), [fw-load-safety](fw-load-safety.md) (the X2
reference pass and chain graph run for the bridge table; X1, X9),
[fw-global-options](fw-global-options.md) (`crate::sysctl`,
`Owner::Firewall`; `crate::links` for bridge ports),
[commit-validation](commit-validation.md) (`crate::findings`),
[fw-opmode](fw-opmode.md) (the FW19 default label; the `show log firewall
bridge` slot), [ebpf-netfilter](ebpf-netfilter.md) (behaviour on eBPF ports) ·
Soft: [fw-matchers](fw-matchers.md) and
[fw-packet-modification](fw-packet-modification.md). Their `ipsec`, `set …`
and `last-used` items reach bridge rules once both plans land.
Unblocks: none

## 1. Goal

- `set firewall bridge forward|input|output|prerouting filter …` and
  `set firewall bridge name <n> …` filter L2-forwarded and bridge-local
  frames in `table bridge zebra_firewall`. That table is loaded in the same
  atomic transaction as `ip/ip6 zebra_firewall`.
- Bridge rules match:
  - MAC, VLAN id/priority/ether type and `ethernet-type`;
  - IPv4 or IPv6 addresses and ports, and `ipv4-`/`ipv6-address-group` and
    `-network-group` references;
  - state, `connection-mark`, `connection-status`, and interfaces (bridge
    ports);
  - the rest of the common rule leaves.

  The actions are `accept|continue|drop|jump|return|queue`, plus `notrack` in
  prerouting. There is no `reject`, as in VyOS.
- `global-options state-policy` also applies to bridged traffic, with
  `reject` turned into `drop`.
- `global-options apply-to-bridged-traffic ipv4|ipv6` sends bridged traffic
  through the ip/ip6 firewall (`br_netfilter`). `accept-invalid
  ethernet-type …` accepts conntrack-invalid ARP, DHCP, PPPoE and VLAN frames.
- The following show the bridge table with counters, in text and `-j`:
  - `show firewall bridge`;
  - `show firewall bridge forward|input|output|prerouting filter`;
  - `show firewall bridge name <n>`.

## 2. Current state

**insomnia @ `ee4dfaa`:**
- `render` resets and renders `ip` and `ip6` only (`firewall.rs:1173-1191`,
  `for ip in ["ip", "ip6"]`).
- `Fam` is `V4 | V6` (`firewall.rs:1085-1110`; it moves unchanged to
  `crate::nft`).
- Matchers take their L3 keyword from `fam.ip()` (`firewall.rs:1617-1700`).
- Show handles `/show/firewall/ipv4|ipv6/…` only (`firewall.rs:195-285`).
  Counters are fetched per family (`firewall.rs:147-163`).
- The provider already routes any `/show/firewall…` path to the firewall
  backend (`provider.rs:91`).

**zebra-rs @ `141da2fc`:**
- It already models bridges:
  - top-level `list bridge` (`config.yang:382-399`);
  - `interface <if> bridge <br>` (`config.yang:5737-5752`);
  - `vxlan … bridge` (`config.yang:435-452`).
- `firewall.yang` has no `bridge` node (`:31-35` lists bridge as deferred),
  and its `global-options` has no `apply-to-bridged-traffic`.
- `exec.yang`'s `show firewall` has `ipv4|ipv6` only (`:310-406`).
  `is_firewall` matches any `firewall` segment (`manager.rs:2019-2021`).
- zebra-rs never touches `br_netfilter` or `net.bridge.*` (grep of `src/`).

**VyOS `7f2c893`:**
- **Schema** (`firewall.xml.in:379-389`):
  - hooks from `include/firewall/bridge-hook-{forward,input,output,prerouting}.xml.i`,
    each with only a `filter` priority;
  - `bridge-custom-name.xml.i`;
  - rule body `common-rule-bridge.xml.i`: dscp, mark, fragment, hop-limit,
    icmp/icmpv6, last-used, limit, log, `ethernet-type`, ipsec, `vlan`,
    queue, packet-length/type, protocol, tcp flags/mss, time, ttl;
  - source/destination: mac, mac-mask, `address-inet` (v4 or v6), mask,
    port, and `source-destination-group-inet` (ipv4-/ipv6-address-group,
    ipv4-/ipv6-network-group, mac-group, port-group);
  - `action-l2.xml.i`: accept|continue|jump|return|drop|queue;
  - prerouting uses `action-and-notrack`;
  - the forward/output hooks add `set` packet modifications.
- **Template** (`data/templates/firewall/nftables.j2:431-541`):
  - `table bridge vyos_filter`, with chains `VYOS_<HOOK>_<prio>` at
    `priority filter`;
  - `jump VYOS_STATE_POLICY` in forward, input and output;
  - groups rendered for both families with `is_l3=False`, so no `D_`, `R_`
    or `DA_` sets;
  - `accept_invalid` lines only at the head of the **output** chain;
  - default rules labelled `FWD-filter` / `NAM-<n>`;
  - `nft_state_policy(…, bridge=True)` turns `reject` into `drop`
    (`python/vyos/template.py:688-710`, T7148).
- **`parse_rule` with `ip_name='bri'`** (`python/vyos/firewall.py`):

  | Feature | Lines | Rendering |
  |:--|:--|:--|
  | Comment and log family | — | `bri` |
  | `ethernet_type` | `:156-168` | `802.1q`→`8021q`, `802.1ad`→`8021ad`, `ipv4`→`ip`, `ipv6`→`ip6` |
  | Addresses | `:208-223` | the family is chosen per address |
  | Groups | `:303-331` | `ip_name` and `def_suffix` are mutated in place by the first inet group, which leaks into later matchers of the same rule |
  | `dscp` | `:447-453` | always `ip dscp` |
  | `vlan` | `:543-560` | emitted **after** the L3/L4 matchers |
- **`accept_invalid`** (`template.py:749-769`):
  `ct state invalid [ether type] <x> counter accept`, with dhcp as
  `udp sport 67 udp dport 68`.
- **`sysctl-firewall.conf.j2:16-22`** always writes
  `net.bridge.bridge-nf-call-ip(6)tables`, as 1 or 0. VyOS does not load
  `br_netfilter` in vyos-1x; grep finds no occurrence, so where it is loaded
  is *unverified*.

**Tested for this plan** (Ubuntu 6.8.0-147, nftables 1.0.9, scratch netns):
1. **Kernel support.** `CONFIG_NF_TABLES_BRIDGE=m`,
   `CONFIG_NF_CONNTRACK_BRIDGE=m` and `CONFIG_BRIDGE_NETFILTER=m`. A bridge
   table with `ct state` loads, and loading it pulls in
   `nf_conntrack_bridge`.
2. **VyOS's matcher order fails.**
   `meta l4proto tcp tcp dport {22} ip daddr @A_SERVERS vlan id 100 …` is
   rejected: `Error: conflicting protocols specified: ether vs. vlan`. With
   `vlan id 100` first, it loads. Because a rejected rule rejects the whole
   script, a VyOS-ordered bridge rule that combines vlan with L3 matchers
   would block the whole firewall from loading.
3. **`br_netfilter` defaults to on.** Before the module loads,
   `net.bridge.bridge-nf-call-iptables` does not exist. Loading
   `br_netfilter` sets `bridge-nf-call-iptables` and `-ip6tables` to **1**
   in every netns. The keys are per-netns: writing 0 in a child netns left
   the host at 1. The module was unloaded again after the test.
4. The worked example in §4 passes `nft -c`.

## 3. Design

**3.1 One transaction, one more table.**
- The script prologue becomes `Script::reset_tables(&["ip", "ip6",
  "bridge"], "zebra_firewall")`, and `table bridge zebra_firewall { … }`
  follows the ip6 table. `apply_if_changed` is called with
  `("bridge", "zebra_firewall")` added to its `tables`.
- **The prologue is always emitted**, even with no bridge config, so removing
  the last bridge rule tears the table down. Every existing firewall golden
  gains two lines. That is a deliberate golden update, explained in its
  commit (AGENTS.md).
- **Kernel without nf_tables bridge.** `add table bridge` would fail the
  whole script. So `firewall::run` probes once at start, with `nft -c` of
  `add table bridge zebra_fw_probe`. The result is a pure render input,
  `bridge_supported: bool`. When it is false, the prologue omits `bridge`,
  and bridge config becomes one `Findings` error,
  `bridge firewall: kernel has no nf_tables bridge support`, with
  `Effect::NotApplied`.
- **Rejected:**
  - a separate transaction for the bridge table: a failure would leave the
    families inconsistent, and the groups are re-rendered anyway;
  - a prologue only when bridge config exists: it cannot tear down without
    remembered state.

**3.2 Chains and names.** These follow VyOS with the `ZEBRA_` prefix:
- `ZEBRA_FORWARD_filter`, `ZEBRA_INPUT_filter`, `ZEBRA_OUTPUT_filter` and
  `ZEBRA_PREROUTING_filter`, each `type filter hook <h> priority filter`
  (-200 in the bridge family);
- `NAME_<n>` for custom chains;
- `ZEBRA_STATE_POLICY`.
- Comments and log prefixes use family `bri`: `bri-FWD-filter-10`,
  `[bri-FWD-filter-10-A]`, `[bri-FWD-filter-default-D]`.
- The default-rule labels are `FWD-filter`, and `NAM-<n>` for custom chains
  ([fw-opmode](fw-opmode.md) O7 / FW19 applies the same label to ip/ip6).
- The [fw-load-safety](fw-load-safety.md) pre-pass runs as
  `plan_table(cfg, Fam::Bridge, &ex)`. Its `RefIndex` holds the bridge
  table's sets and `NAME_` chains, and the chain graph checks loops and depth
  inside the bridge table. Base hooks enter as forward, input, output and
  prerouting. No second index is built.

**3.3 Rule rendering in bridge mode** (extension of `crate::nft`, owned by
[nft-common](nft-common.md); implemented by this plan):
- **`Fam::Bridge`:** `ip()` = `"bridge"` (the table family), `label()` =
  `"bri"`. `RuleCtx { fam: Fam::Bridge, .. }` puts `render_rule` in bridge
  mode. Its matchers choose `ip`/`ip6` **per matcher**:
  - an address by parsing it;
  - `ipv4-address-group X` → `ip … @A_X`, and `ipv6-address-group X` →
    `ip6 … @A6_X` (likewise `N_`/`N6_`);
  - the rule's L3 family is then fixed. A rule that names both families
    skips with `bridge rule N: mixes IPv4 and IPv6 matchers`, which VyOS
    renders as a never-matching rule. VyOS's in-place `ip_name` mutation
    (`firewall.py:315-331`) is not copied.
- **`dscp`, `ttl`, `hop-limit`:** `dscp` renders `ip dscp`, or `ip6 dscp`
  when the rule's family is IPv6. Deviation: VyOS is always `ip`. `ttl` →
  `ip ttl`, `hop-limit` → `ip6 hoplimit`, `icmp` → `icmp`, `icmpv6` →
  `icmpv6`. Each fixes the family the same way.
- **Order (deviation):** `vlan id`, `vlan pcp` and `vlan type` are emitted
  **first**, before `ct state`, protocol and every L3/L4 matcher (fact 2).
  The rest keeps `parse_rule` order: state, connection-status, protocol,
  `ether type`, destination (address, mac, port, group), source, …
- **`ethernet-type`:** `ether type [!=] <t>` with VyOS's mapping. Numeric
  values pass through `tok`. An `ethernet-type` other than ip/ip6 combined
  with an L3 matcher skips the rule with a warning, because nft would reject
  it as a conflicting protocol.
- **Actions:** `reject` and `synproxy` are not in the schema. `notrack`
  exists only in prerouting (schema). `jump` → `NAME_<t>`, with the
  [fw-load-safety](fw-load-safety.md) chain index of the bridge table.
- **Sets.** `group::render_sets(&mut s, groups, Fam::Bridge, &ex)` emits the
  address/network kinds for **both** families (`A_`, `A6_`, `N_`, `N6_`) and
  the family-agnostic kinds (`P_`, `M_`, `I_`) once. It never emits the
  dynamic kinds ([fw-dynamic-sources](fw-dynamic-sources.md) `D_`/`R_`,
  [fw-packet-modification](fw-packet-modification.md) `DA_`), matching
  VyOS's `is_l3=False`. A bridge rule that references them skips with
  `domain-group "X" is not available in the bridge table`.
- **Later leaves.** `ipsec`, `last-used` ([fw-matchers](fw-matchers.md)) and
  `set …` ([fw-packet-modification](fw-packet-modification.md)) are part of
  VyOS's bridge rule. They join when those land, through the same
  `render_rule`, for the hooks where VyOS has them (`set` on forward and
  output).

**3.4 State policy.**
- `ZEBRA_STATE_POLICY` is rendered in the bridge table from the same
  `global-options state-policy`, with `reject` → `drop`. Forward, input and
  output jump to it; prerouting does not, as in VyOS.
- An entry with no action follows X9 ([fw-load-safety](fw-load-safety.md)):
  no verdict.
- **Prerouting `notrack` priority.** The prerouting chain runs at `priority
  filter` (-200). nf_conntrack_bridge's prerouting hook uses
  `NF_IP_PRI_CONNTRACK` (-200), from kernel source and *unverified*, so the
  order between the two hooks is not defined. The BDD checks that a
  prerouting `notrack` takes effect. If it does not, render the bridge
  prerouting chain at `priority -300` and record that as a deviation.

**3.5 `apply-to-bridged-traffic`** (through `crate::sysctl`, as
`Owner::Firewall`; the note in [fw-global-options](fw-global-options.md) §8):
- `ipv4` / `ipv6` are presence leaves. When the container exists, the
  firewall's sysctl list gains:

  ```rust
  Setting { key: Key::Global("net.bridge.bridge-nf-call-iptables"),  value: if ipv4 {"1"} else {"0"}.into(),
            module: Some("br_netfilter"), absent_baseline: Some("0") }
  Setting { key: Key::Global("net.bridge.bridge-nf-call-ip6tables"), value: if ipv6 {"1"} else {"0"}.into(),
            module: Some("br_netfilter"), absent_baseline: Some("0") }
  ```

- **D4 interplay.** With the container absent, nothing is written and the
  module is not loaded. Deviation: VyOS always writes 0.
- **Removal is the edge case.** If insomnia loaded `br_netfilter`, the
  keys' "baseline" is the module default, **1** (fact 3). Restoring it would
  keep bridged traffic in the ip hooks after the user removed the option.
- **[fw-global-options](fw-global-options.md) §3.2 provides the fix:** a
  node that appears only after the writer's own `modprobe` takes its
  baseline from `Setting.absent_baseline`, and restore writes that value.
  fw-bridge passes `Some("0")`.
- `br_netfilter` is never `rmmod`ed. Container runtimes may rely on it.
- Document: if anything else loads `br_netfilter` (Docker, for example), the
  kernel default 1 already sends bridged traffic through
  `ip/ip6 zebra_firewall` forward, whatever insomnia's config.
- **`accept-invalid ethernet-type`** puts lines at the head of
  `ZEBRA_OUTPUT_filter`, before the state-policy jump, only when that chain
  is configured. The placement is VyOS's, and the rationale is *unverified*.
  Mapping: `arp`, `dhcp` (`udp sport 67 udp dport 68`, no `ether type`),
  `pppoe-discovery` (`0x8863`), `pppoe` (`0x8864`), `802.1q` (`8021q`),
  `802.1ad` (`8021ad`), `wol` (`0x0842`).

**3.6 Bridge ports and host checks** (through `crate::links`, the
[fw-global-options](fw-global-options.md) watcher):
- `host_findings(cfg)` uses `Links::snapshot()`:
  - an `inbound-interface name X` / `outbound-interface name X` in a bridge
    rule whose `X` is neither a bridge (`kind == "bridge"`) nor enslaved to
    one (`master` is a bridge) → warning `bridge rule N: X is not a bridge
    port`, rendered as configured. Wildcards are skipped. A port may appear
    later, which is why this is a warning;
  - `apply-to-bridged-traffic` with no bridge present → warning.
- `render()` stays pure ([commit-validation](commit-validation.md)). Bridge
  membership never changes the script, so a link event never re-applies the
  firewall.

**3.7 Show.**
- Grammar:
  - `show firewall bridge` lists every chain;
  - `show firewall bridge forward|input|output|prerouting filter`;
  - `show firewall bridge name <n>`.
- The text uses the existing `chain_table_text` layout, with the header
  `bridge Firewall "forward filter"`. Counters come from
  `nft::counters::fetch("bridge", "zebra_firewall")`.
- `show firewall` (the overview) appends the bridge section after ipv6. JSON
  gains `"bridge": {…}`. VyOS's section order for the overview is
  *unverified*.
- `show log firewall bridge …` is [fw-opmode](fw-opmode.md)'s `show log
  firewall` child. This plan provides the `[bri-…]` prefixes it filters on.

**3.8 eBPF ports.** Frames that cradle switches in XDP/TC never reach the
bridge netfilter hooks ([ebpf-netfilter](ebpf-netfilter.md)). Under its
default outcome B, zebra-rs refuses `firewall bridge` together with eBPF
ports. That plan's B-class table names this plan for the `firewall bridge`
row, which M1 adds to `EBPF_BYPASSED_TREES`. The book says the bridge
firewall covers kernel-bridged traffic only.

**3.9 Deviations** to record in the `firewall.rs` module doc and the
`nft::rule` doc:
- The bridge table is always reset.
- `vlan` matchers come first.
- The L3 family is chosen per rule; mixed-family rules are skipped, and
  VyOS's `ip_name` mutation is not copied.
- `ip6 dscp` for IPv6 rules.
- Dynamic groups are not available in the bridge table (VyOS parity, but
  insomnia warns).
- `apply-to-bridged-traffic` is written only when configured, with explicit
  0 on removal.
- A possible prerouting priority -300.

## 4. Changes

### zebra-rs

`yang/firewall.yang` (sketch; the leaves are VyOS's):

```yang
grouping l3-match-inet {                     // address-inet + group-inet
  leaf address { ext:help "IPv4/IPv6 address, prefix or range; negate with !";
    type union { type inet:ipv4-address; type inet:ipv4-prefix;
                 type inet:ipv6-address; type inet:ipv6-prefix; type string; } }
  leaf address-mask { type union { type inet:ipv4-address; type inet:ipv6-address; } }
  leaf mac-address { type union { type yang:mac-address; type string; } }
  leaf port { type union { type uint16 { range "1..65535"; } type string; } }
  container group {
    leaf ipv4-address-group { type string; } leaf ipv6-address-group { type string; }
    leaf ipv4-network-group { type string; } leaf ipv6-network-group { type string; }
    leaf mac-group { type string; } leaf port-group { type string; } } }
grouping match-vlan {
  container vlan {
    leaf id { ext:help "VLAN id 0-4095 or range"; type union { type uint16 { range "0..4095"; } type string; } }
    leaf priority { ext:help "PCP 0-7 or range"; type union { type uint8 { range "0..7"; } type string; } }
    leaf ethernet-type { type string; } } }
grouping rule-bridge {
  uses rule-base;                            // dscp, fragment, limit, log, protocol, queue, tcp, time, …
  leaf action { type enumeration { enum accept; enum continue; enum drop;
                                   enum jump; enum queue; enum return; } }
  leaf jump-target { type string; }
  leaf ethernet-type { ext:help "ipv4|ipv6|arp|802.1q|802.1ad|<0xHHHH>; negate with !"; type string; }
  uses match-vlan;
  leaf mark { … }  container icmp { … }  container icmpv6 { … }
  container ttl { … }  container hop-limit { … }   // as rule-match-v4/v6
  leaf-list packet-length { … }  leaf packet-type { … }
  container source { uses l3-match-inet; } container destination { uses l3-match-inet; } }
grouping bridge-hooks {
  container forward { container filter { uses chain-base-head;
    list rule { key number; uses rule-key; uses rule-bridge; uses rule-state-common;
                uses match-interface-in; uses match-interface-out; } } }
  container input   { container filter { … match-interface-in … } }
  container output  { container filter { … match-interface-out … } }
  container prerouting { container filter { uses chain-base-head;
    list rule { key number; uses rule-key; uses rule-bridge; uses match-interface-in;
                /* action adds enum notrack; no state/connection-* (VyOS) */ } } }
  list name { key name; leaf name { type string; } uses chain-custom-head-l2;
    list rule { key number; uses rule-key; uses rule-bridge; uses rule-state-common;
                uses match-interface-in; uses match-interface-out; } } }
// grouping firewall:
container bridge { ext:help "Bridge firewall"; uses bridge-hooks; }
// container global-options:
container apply-to-bridged-traffic {
  ext:help "Apply the IPv4/IPv6 firewall to bridged traffic (br_netfilter)";
  leaf ipv4 { type empty; } leaf ipv6 { type empty; }
  container accept-invalid { leaf-list ethernet-type { type enumeration {
    enum arp; enum dhcp; enum pppoe; enum pppoe-discovery; enum 802.1q; enum 802.1ad; enum wol; } } } }
```

- **Groupings:**
  - `rule-state-common` (proposed) is the state, `connection-mark` and
    `connection-status` subset of today's `rule-common`.
  - `chain-custom-head-l2` is `chain-custom-head` without `reject`
    (VyOS `default-action-bridge.xml.i`: drop|jump|return|accept|continue).
- **Commit checks** ([commit-validation](commit-validation.md) layer 1):
  - the ranges above, and the action enums;
  - the "one family per rule" and the "ethernet-type vs L3" rules go to the
    layer-2 validator, which calls `firewall::validate`, which calls the
    same render.
- **`yang/exec.yang`**, under `show firewall`:

  ```yang
  container bridge { ext:help "Bridge firewall"; presence "All bridge firewall chains";
    container forward { container filter { presence "Forward filter chain"; } }
    container input { container filter { presence "Input filter chain"; } }
    container output { container filter { presence "Output filter chain"; } }
    container prerouting { container filter { presence "Prerouting filter chain"; } }
    list name { ext:presence "All custom chains"; key chain; leaf chain { type string; } } }
  ```

- **Routing.** `is_firewall` already routes these paths. No manager change.

### insomnia

- **`src/nft/*`** ([nft-common](nft-common.md) modules, extended here):
  - `Fam::Bridge`;
  - bridge mode in `matcher::endpoint`, plus the dscp/ttl/hop-limit/icmp
    family choice;
  - `vlan` and `ethernet-type` matchers in `rule.rs` (vlan first in bridge
    mode);
  - `group::render_sets` for `Fam::Bridge`;
  - `Script::reset_tables` with three families.
- **`src/firewall.rs`:**
  - model: `FirewallConfig.bridge: Option<BridgeFamily>`, where
    `BridgeFamily` holds `forward`, `input`, `output` and `prerouting` (each
    `{ filter: Option<Chain> }`) and `name`;
  - rule fields `ethernet_type` and `vlan { id, priority, ethernet_type }`;
  - group-ref fields `ipv4_address_group` and the three others;
  - `GlobalOptions.apply_to_bridged_traffic`;
  - `render_table_bridge(&mut Script, cfg, plan)`;
  - the bridge state-policy copy;
  - `host_findings` (§3.6);
  - the sysctl settings (§3.5) added to the `Owner::Firewall` list that
    [fw-global-options](fw-global-options.md) builds;
  - show: `/show/firewall/bridge…` arms and the bridge section in
    `show_json`;
  - `is_empty` covers `bridge`.
- **`src/main.rs`:** the bridge-support probe, at start, before the first
  apply.

**Worked example.**

```text
set bridge br0
set interface veth-h1 bridge br0
set interface veth-h2 bridge br0
set firewall group address-group SERVERS address 192.0.2.10
set firewall group ipv6-address-group SERVERS6 address 2001:db8::10
set firewall group interface-group LAN interface veth-h1
set firewall global-options state-policy established action accept
set firewall global-options state-policy invalid action reject
set firewall global-options apply-to-bridged-traffic ipv4
set firewall bridge forward filter default-action drop
set firewall bridge forward filter rule 10 action accept
set firewall bridge forward filter rule 10 vlan id 100
set firewall bridge forward filter rule 10 protocol tcp
set firewall bridge forward filter rule 10 destination port 22
set firewall bridge forward filter rule 10 destination group ipv4-address-group SERVERS
set firewall bridge forward filter rule 20 action accept
set firewall bridge forward filter rule 20 ethernet-type arp
set firewall bridge forward filter rule 30 action drop
set firewall bridge forward filter rule 30 destination group ipv6-address-group SERVERS6
set firewall bridge forward filter rule 40 action jump
set firewall bridge forward filter rule 40 jump-target CUSTOM
set firewall bridge forward filter rule 40 inbound-interface group LAN
set firewall bridge name CUSTOM default-action accept
set firewall bridge prerouting filter rule 10 action notrack
set firewall bridge prerouting filter rule 10 protocol udp
set firewall bridge prerouting filter rule 10 destination port 4789
```

The rendered prologue and bridge table follow. The ip/ip6 tables come in
between: they hold the same groups, plus their own state-policy chain, which
keeps `reject`. This text passed `nft -c` in a scratch netns.

```nft
add table ip zebra_firewall
delete table ip zebra_firewall
add table ip6 zebra_firewall
delete table ip6 zebra_firewall
add table bridge zebra_firewall
delete table bridge zebra_firewall
…
table bridge zebra_firewall {
    set A_SERVERS {
        type ipv4_addr
        flags interval
        auto-merge
        elements = { 192.0.2.10 }
    }
    set A6_SERVERS6 {
        type ipv6_addr
        flags interval
        auto-merge
        elements = { 2001:db8::10 }
    }
    set I_LAN {
        type ifname
        flags interval
        auto-merge
        elements = { "veth-h1" }
    }
    chain ZEBRA_FORWARD_filter {
        type filter hook forward priority filter; policy accept;
        jump ZEBRA_STATE_POLICY
        vlan id 100 meta l4proto tcp tcp dport {22} ip daddr @A_SERVERS counter accept comment "bri-FWD-filter-10"
        ether type arp counter accept comment "bri-FWD-filter-20"
        ip6 daddr @A6_SERVERS6 counter drop comment "bri-FWD-filter-30"
        iifname @I_LAN counter jump NAME_CUSTOM comment "bri-FWD-filter-40"
        counter drop comment "FWD-filter default-action drop"
    }
    chain ZEBRA_PREROUTING_filter {
        type filter hook prerouting priority filter; policy accept;
        meta l4proto udp udp dport {4789} counter notrack comment "bri-PRE-filter-10"
        counter accept comment "PRE-filter default-action accept"
    }
    chain NAME_CUSTOM {
        counter accept comment "NAM-CUSTOM default-action accept"
    }
    chain ZEBRA_STATE_POLICY {
        ct state established counter accept
        ct state invalid counter drop
        return
    }
}
```

The sysctl part of the `Owner::Firewall` list:

```
Global("net.bridge.bridge-nf-call-iptables")  = "1"   module br_netfilter
Global("net.bridge.bridge-nf-call-ip6tables") = "0"   module br_netfilter
```

`show firewall bridge forward filter`:

```
bridge Firewall "forward filter"

 Rule     Action     Protocol      Packets        Bytes  Conditions
 ----     ------     --------      -------        -----  ----------
 10       accept     tcp                12         1840  vlan id 100 meta l4proto tcp tcp dport {22} ip daddr @A_SERVERS
 20       accept     -                   4          168  ether type arp
 30       drop       -                   0            0  ip6 daddr @A6_SERVERS6
 40       jump       -                   7          588  iifname @I_LAN
 default  drop       -                   2          120
```

## 5. Tests

**Goldens and unit tests** (`firewall::tests`, `nft::*::tests`):

| Test | Asserts |
|:--|:--|
| `bridge_golden_render` | The worked example, byte for byte, including the findings |
| `bridge_prologue_always_present` | `{}` → six add/delete lines; every existing golden updated in one commit |
| `bridge_unsupported_kernel` | `bridge_supported = false` → no bridge prologue; bridge config → one `NotApplied` error |
| `bridge_vlan_first` | `vlan` matchers precede protocol and L3 (the fact-2 regression) |
| `bridge_mixed_family_rule_skipped` | An ipv4 address and an ipv6 group in one rule → skipped |
| `bridge_ether_type_vs_l3_skipped` | `ethernet-type arp` + `destination address` → skipped |
| `bridge_dscp_family` | v6 rule → `ip6 dscp`; no address → `ip dscp` |
| `bridge_state_policy_reject_is_drop` | `ip` keeps `reject`; `bridge` gets `drop` |
| `bridge_dynamic_group_ref_skipped` | `domain-group` → skipped with the bridge-specific message |
| `bridge_jump_loop` | `NAME_A` → `NAME_B` → `NAME_A` removed by the fw-load-safety graph in the bridge table |
| `ether_type_mapping` | All VyOS spellings, numeric pass-through, negation |
| `accept_invalid_lines` | The seven types, placed in output only |
| `apply_to_bridged_sysctls` | The two settings with `module` and `absent_baseline`; absent container → none |
| `bridge_host_findings` | A port not in any bridge (fake `Links` snapshot) → warning; wildcard ignored |
| `show_bridge_from_counters` | The table above from a fixture counter map; `-j` has `bridge` |

**BDD feature `@fw_bridge`.** It reuses `tests/scripts/insomnia_node.sh` from
[fw-load-safety](fw-load-safety.md).
- **Topology:**
  - namespace `sw` runs zebra-rs and insomnia; zebra-rs creates `br0` and
    enslaves `veth-h1` and `veth-h2`;
  - "I connect namespace "sw" interface "veth-h1" to namespace "h1"
    interface "eth0"", and the same for h2;
  - h1 = 10.0.0.1/24 and h2 = 10.0.0.2/24, on the same L2 segment.
- **Scenarios:**
  1. Setup; `ping` h1 → h2 succeeds.
  2. A bridge forward rule drops h1's MAC: the ping fails, and `show
     firewall bridge forward filter` counts the drop.
  3. A rule with `ipv4-address-group` (h2) and `protocol icmp`, with
     `default-action drop`: the ping succeeds, and TCP to h2 fails.
  4. State policy: `established accept` plus a `new` drop for TCP from h2:
     h1 → h2 TCP works, h2 → h1 does not.
  5. `apply-to-bridged-traffic ipv4`, then an `ipv4 forward filter` drop of
     h2: the ping fails. Remove the option: the ping succeeds, and
     `sysctl net.bridge.bridge-nf-call-iptables` in `sw` reads `0`.
  6. Prerouting `notrack` for UDP/4789: `conntrack -L` in `sw` shows no
     entry (the §3.4 priority question), if conntrack-tools is present.
  7. Teardown topology.

## 6. Docs

- **Book:**
  - new `ch-01-17-bridge-firewall.md`: hooks, actions, inet groups, the vlan
    and ether-type matchers, state policy, `apply-to-bridged-traffic` and
    its br_netfilter caveat, and eBPF;
  - `ch-01-06-connection-tracking.md`: bridged conntrack needs
    `nf_conntrack_bridge`;
  - `ch-03-00-show-firewall.md`: the bridge views;
  - `SUMMARY.md`.
- **Module docs:** the §3.9 list in `firewall.rs`, and the bridge mode in the
  `nft::rule` doc.

## 7. Milestones

| # | Scope | Repo | Effort | Done when |
|:--|:--|:--|:--|:--|
| M1 | `firewall bridge` YANG (hooks, `name`, `rule-bridge`, `l3-match-inet`, `match-vlan`), `apply-to-bridged-traffic`, `show firewall bridge` grammar | zebra-rs | M | Schema tests; JSON fixtures captured |
| M2 | `Fam::Bridge` and bridge mode in `crate::nft` (per-matcher family, vlan-first, ether type, both-family sets) | insomnia | M | `nft::*` unit tests; existing goldens untouched |
| M3 | `render_table_bridge`, the three-family prologue, the support probe, the pre-pass for the bridge table, `apply_if_changed` tables | insomnia | M | `bridge_*` goldens; every golden updated deliberately; the example passes `nft -c` |
| M4 | State-policy copy, `accept-invalid`, `apply-to-bridged-traffic` through `crate::sysctl` (`absent_baseline`) | insomnia | S | `accept_invalid_lines`, `apply_to_bridged_sysctls` |
| M5 | Show views and JSON; `host_findings` through `crate::links` | insomnia | S | Show tests |
| M6 | BDD `@fw_bridge` | insomnia | M | Passes twice in a row; the scenario-6 result decides the §3.4 priority |
| M7 | Book, module docs, CHANGELOG | insomnia | S | `mdbook build` clean |

## 8. Risks and open questions

- **Agreed with other plans** (each records it on its side):
  - [nft-common](nft-common.md) §3.1: `Fam::Bridge` and the bridge-mode
    matcher branches are extensions it owns and this plan implements;
    `render_sets` for `Fam::Bridge` never emits the dynamic kinds.
  - [fw-load-safety](fw-load-safety.md) §3.2: `plan_table(cfg,
    Fam::Bridge, &ex)`, with `NAME_` chains of the bridge table in its own
    graph.
  - [fw-global-options](fw-global-options.md) §3.2: `absent_baseline` on
    `Setting` (§3.5).
- **Requirement on [fw-opmode](fw-opmode.md):** the `show log firewall
  bridge` child, and the FW19 label for bridge custom chains.
- **VLAN-tagged frames.** Whether `ip daddr` after `vlan id` matches
  correctly on frames whose tag is in the packet data, not offloaded, is
  *unverified*. nft accepts the rule. Cover it with a tagged-VLAN BDD case
  before documenting VLAN + L3 rules.
- **`ct state` on bridges** needs `nf_conntrack_bridge` (kernel ≥ 5.3). It
  was loaded automatically here. A kernel without it fails the script, and
  the apply loop then excludes the rule.
- **Two `ZEBRA_STATE_POLICY` copies** (ip/ip6 and bridge) both count the
  same `established` packets when `apply-to-bridged-traffic` is on. Show
  makes it obvious; no change.
- **Interface names.** zebra-rs's `interface X bridge Y` is staged until both
  exist (`config.yang:5745-5751`), so a rule may name a port before it is
  enslaved. That is a warning only.
- **The prologue golden churn** touches every firewall golden once. Land
  M3 as its own commit.

## 9. Acceptance criteria

- [ ] `firewall bridge …` exists only with `--feature insomnia` and renders
      into `table bridge zebra_firewall` in the same transaction as
      ip/ip6.
- [ ] No bridge rule can make nft reject the script for a matcher-order
      reason. Mixed-family and ether-type conflicts are skipped with a
      warning.
- [ ] State policy applies to bridged traffic, with `reject` → `drop`.
- [ ] `apply-to-bridged-traffic` loads `br_netfilter` and sets both keys.
      Removing it writes 0. Absence touches nothing.
- [ ] `show firewall bridge …` text and `-j` show counters per rule.
- [ ] Goldens, BDD `@fw_bridge`, clippy and fmt are clean.
