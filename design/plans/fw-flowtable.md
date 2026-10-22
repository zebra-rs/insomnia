# Flowtables and offload — implementation plan

Status: plan, 2026-10-21. Covers: FW9 ([vyos-gap](../vyos-gap.md) §5), with
the VyOS verify rules V5, V26 and V28 handled as findings (§4.1 layers 2 and 3).
Priority: P2 · Effort: M · Owner: both
Depends on: [fw-load-safety](fw-load-safety.md) (`RefIndex`, `ChainGraph`,
apply loop, X12), [fw-zones](fw-zones.md) (`RenderCtx`, zone entries and edges),
[fw-global-options](fw-global-options.md) (`crate::links`),
[commit-validation](commit-validation.md) (`findings.rs`), [fw-opmode](fw-opmode.md)
(state-policy comment convention), [nft-common](nft-common.md) (`crate::nft`;
this plan adds `Origin::Flowtable` and `RuleCtx.offload` there)
· Unblocks: —

## 1. Goal

- `firewall flowtable <n> interface <if>… [offload software|hardware]
  [description]`, rule `action offload offload-target <n>` (forward filter and
  custom chains), and `global-options state-policy offload offload-target <n>`
  are enforced as VyOS renders them (`nftables-offload.j2`).
- None of these can fail the `nft -f` transaction:
  - a missing device, or a device claimed by two flowtables;
  - hardware offload on an incapable device;
  - an offload rule in a chain reachable from input or output.

  Each one is dropped and reported as a finding instead (severities in §3).
- A device that appears after the commit is added to its flowtable without
  replacing the table, so counters and dynamic sets survive. A device that
  disappears is dropped by the kernel, and the script stays loadable.
- Flowtables are visible in `show firewall summary`
  ([fw-opmode](fw-opmode.md)), with their live device list.

## 2. Current state

**insomnia @ ee4dfaa.**
- No flowtable model.
- `render_rule` rejects any unknown action (`src/firewall.rs:1906`), so
  `offload` would be skipped with a warning.
- One `ZEBRA_STATE_POLICY` chain (`1270-1299`), jumped from every base filter
  chain (`1235-1237`).
- `render(&cfg)` is pure and knows nothing about host interfaces (`1173-1191`).
- No link watcher; no `ethtool` use.
- Debian `depends = "$auto, nftables"`; Recommends strongSwan and keepalived
  only (`Cargo.toml`, `[package.metadata.deb]`).

**zebra-rs @ 141da2fc.**
- `firewall.yang` defers flowtable/offload (`yang/firewall.yang:33`).
- The action enum has no `offload` (`395-412`), and state-policy has no
  `offload` (`1182-1268`).
- `config.yang` has no knob to turn on an interface's `hw-tc-offload` (the only
  `offload` leaves are BFD `detect-offload`).

**VyOS @ 7f2c893.**
- Schema:
  - `interface-definitions/firewall.xml.in:10-41`: `offload` defaults to
    `software`; `interface` is `dependent-error-generic-interface-multi.xml.i`,
    so it must exist and takes no wildcard.
  - `offload-target` exists only in the forward filter and `name` rules
    (`include/firewall/ipv4-hook-forward.xml.i:33`,
    `ipv4-custom-name.xml.i:37`, and the ipv6 twins).
  - The `offload` action enum is in `action.xml.i`, which every filter hook
    uses.
  - `global-options state-policy offload` is at `global-options.xml.i:306-313`.
- Template:
  - `nftables-offload.j2:1-9`: `flowtable VYOS_FLOWTABLE_<n> { hook ingress
    priority 0; devices = { a, b }; [flags offload;] counter }`.
  - Flowtables are rendered first in a family table, but only inside
    `{% if ipv4 is vyos_defined %}` (`nftables.j2:37-42`), and likewise for
    ipv6 (`237-242`).
  - `VYOS_STATE_POLICY_FORWARD` (`216-230`) starts with `counter flow add
    @VYOS_FLOWTABLE_<t>` and is jumped from the forward base chains
    (`49-51`, `249-251`).
- Renderer: `python/vyos/firewall.py:641-643` puts `flow add
  @VYOS_FLOWTABLE_<t>` in the verdict position, with no verdict after it, so
  evaluation continues.
- Verify (`src/conf_mode/firewall.py`):
  - offload target set and existing: `273-282`;
  - a flowtable has at least one interface, every interface exists, and
    hardware offload requires ethtool `hw-tc-offload` (`523-531`, `534-546`);
  - the state-policy offload target exists: `567-575`;
  - no offload chain in the local zone or in a default-firewall: `697-700`,
    `714-716`.
- Holes in VyOS (code reading):
  - (a) State-policy offload without `firewall ipv6` renders `flow add` in the
    ip6 table, where no flowtable was rendered. That is a load failure
    (*unverified* end to end).
  - (b) A plain jump from input or output to a chain with an offload rule
    passes verify, and the kernel then rejects it (see below).
  - (c) Two flowtables sharing a device pass verify and then fail.

**Measured in a throwaway netns** (`sudo unshare -n`, nftables 1.0.9, kernel 6.8):

| Case | Result |
|:--|:--|
| device does not exist | whole transaction fails (ENOENT) |
| two flowtables in one family share a device | fails (EEXIST) |
| same device in the ip and ip6 flowtables | OK |
| `flags offload` on a device without hw-tc-offload (dummy) | fails (EOPNOTSUPP) |
| flowtable with no `devices` clause, rules referencing it | OK |
| `flow add` in a custom chain jumped from `input` | `nft -c` exits 0; the real apply fails (EOPNOTSUPP) |
| quoted device names (`devices = { "d0", "d1" }`) | OK |
| device deleted under a live flowtable | the kernel drops it from `devices`; re-applying the same script then fails (ENOENT) |
| `add flowtable … { hook ingress priority 0; devices = { "d1" }; counter; }` on a live flowtable | devices are unioned. Flags are replaced by the update's: omitting `counter;` clears the counter flag |

`nft -c` cannot be trusted for hook validation through jumps. Note for
[commit-validation](commit-validation.md): a dry run must apply the script
inside a scratch netns, not use `nft -c`, if it wants to catch this class of
error.

## 3. Design

**F1. VyOS shape, insomnia spelling.**
- Flowtables are named `ZEBRA_FLOWTABLE_<n>`, and the name must pass
  `safe_name`.
- Devices are quoted, which is the existing "interface names are always quoted"
  deviation (`firewall.rs:21`).
- Flowtables are the first objects in each table, as in VyOS.

**F2. Flowtables render in both tables whenever any flowtable is configured**,
whether or not `ipv4`/`ipv6` exist. This closes VyOS hole (a). The cost is one
ingress hook per family per device, and the same device in both families is
fine (measured). This is a deviation.

**F3. Device gating at render time.**
- The input is `RenderCtx.links`, a `crate::links` snapshot
  ([fw-global-options](fw-global-options.md) §3.2a). [fw-zones](fw-zones.md)
  owns the type. This plan adds `hw_tc_offload: BTreeMap<String, bool>`, which
  `process()` and `validate()` probe before rendering, so `render` stays a pure
  function of `(cfg, ctx)`.
- A device absent from the snapshot is omitted. This is a Warning, because it
  is host state (commit-validation's host-findings rule; VyOS makes it an
  error).
- If every device is missing, the flowtable renders without a `devices` clause.
  It loads, and its offload rules are no-ops.
- A wildcard (`*`) or unsafe name is omitted, as an Error.
- A device in two flowtables stays in the first by name and is omitted from the
  later ones, as an Error, identically in both families.
- `links: None` (tests only) disables gating.

**F4. Hardware offload.**
- `flags offload;` is rendered only if every present device reports
  `hw-tc-offload: on` (`ethtool -k`). Otherwise the flowtable renders software
  with a warning naming the devices.
- Backstop, inside fw-load-safety's apply-exclude-retry loop
  ([fw-load-safety](fw-load-safety.md) §3.3). The flowtable lines get a new
  `Origin::Flowtable { fam, name }`, and `Exclusions` gains `flowtables_soft` and
  `flowtables` ([nft-common](nft-common.md) §3.1).
  - On the first nft error mapped to it, the flowtable is downgraded to
    software.
  - On the second, it is excluded. `RefIndex` then lacks it, so its offload
    rules take the missing-target skip, which is a performance loss, never a
    semantic one (F5).
  - Each step is a warning. This covers drivers that advertise hw-tc-offload
    but reject flowtable offload, and any device race that F3 missed. No
    separate retry path is added.
- VyOS makes this a commit error. zebra-rs cannot turn the feature on, so the
  book documents `ethtool -K <if> hw-tc-offload on` as an out-of-band step. An
  interface leaf for it belongs to zebra-rs core and is out of scope.
- `ethtool` goes into the Debian Recommends. If it is missing, treat devices as
  incapable and warn once.
- Hardware-capability findings are Warnings (host state).

**F5. Offload action.**
- `action offload` renders `flow add @ZEBRA_FLOWTABLE_<t>` in the verdict
  position, with no verdict, so evaluation continues (VyOS). Skipping an offload
  rule therefore never changes accept/drop semantics, only speed; F6 relies on
  this.
- A missing or undefined `offload-target` skips the rule, as an Error (V5).
  For this, flowtable names are registered with fw-load-safety's
  `RefIndex::register(ObjKind::Flowtable, name)`. nft-common's
  `RuleCtx` gains an `offload` callback that resolves `<t>` to
  `ZEBRA_FLOWTABLE_<t>`, the same pattern as its `jump` callback.
- `offload-target` without `action offload` is ignored, as a Warning (VyOS
  warns too).
- `action offload` in input, output or raw rules can be entered, because the
  shared enum allows it as in VyOS. Those lists have no `offload-target`, so the
  rule takes the missing-target path.

**F6. Hook reachability.**
- The kernel validates `flow add` against each base chain through jumps; it is
  legal only under the forward hook. `nft -c` misses this (measured).
- Using `reaching_hooks(chain) -> HookSet` from fw-load-safety's `TablePlan`
  ([fw-load-safety](fw-load-safety.md) §3.2), every offload rule in a chain reachable
  from any non-forward hook is skipped. This is an Error finding
  (`Skipped("rule skipped")`) naming one path. The
  graph's edges are rule `jump-target`, `default-jump-target`, and the zone
  entries and edges from [fw-zones](fw-zones.md), registered through
  `ChainGraph::add_entry`/`add_edge`: `VZONE_<local>_IN` reaches from input and
  `_OUT` from output.
- This supersedes VyOS's zone-only checks and also covers hole (b).
- It is exact where VyOS is stricter. A zone `default-firewall` chain with an
  offload rule stays offloading when no local zone exists; VyOS always rejects
  it. Record this as a deviation.
- Rejected: skipping the jump from input or output instead. That changes
  filtering and can fail open.

**F7. State-policy offload.**
- When `state-policy offload offload-target <t>` is set, render
  `ZEBRA_STATE_POLICY_FORWARD`. It is a copy of `ZEBRA_STATE_POLICY` with
  `counter flow add @ZEBRA_FLOWTABLE_<t>` first, and the forward base chains
  jump it instead.
- `ZEBRA_ZONE_FORWARD` keeps jumping `ZEBRA_STATE_POLICY`, as the VyOS zone
  template does (`nftables-zone.j2:6-8`).
- Without offload nothing changes. VyOS always renders the `_FORWARD` copy;
  insomnia renders it only when it differs, which keeps every existing golden
  (deviation).
- Comments follow [fw-opmode](fw-opmode.md)'s convention:
  `STATE-POLICY-FWD-<state>`, and `STATE-POLICY-FWD-offload` for the flow line.
  The state-policy show sums both chains.
- A missing target leaves the `_FORWARD` chain unrendered, as an Error (V28).

**F8. Hot-plug without a table replace.**
- Events come from `Links::subscribe()` ([fw-global-options](fw-global-options.md)
  §3.2a), through the `select!` arm that [fw-zones](fw-zones.md) also uses.
  - `LinkEvent::Added(link)` for a gated-out device triggers a hot-add.
  - `Removed(name)` triggers a refresh.
  - `Changed` triggers a hot-add or refresh only on a rename.
  - `Resync` triggers a full render and apply.
- Events are coalesced for 500 ms in the firewall task.
- When a device named by a flowtable, and gated out, appears, insomnia runs one
  `nft -f -` transaction with
  `add flowtable ip|ip6 zebra_firewall ZEBRA_FLOWTABLE_<n> { hook ingress priority 0; devices = { "<dev>" }; counter; [flags offload;] }`.
  The flags must be repeated (measured).
- On success, refresh both halves of X12's `Applied`
  ([fw-load-safety](fw-load-safety.md) §3.5): `rendered` is the fresh render
  and `live` is a fresh `nft -s -t list table` listing. The next compare is
  then a no-op, and the hot-add does not register as hand-edit drift. On
  failure, including a hardware flowtable meeting an incapable device, do a
  full re-render and apply.
- When a device disappears, the kernel has already removed it, and the listing
  changed. Re-render and refresh both halves of `Applied`; no nft call.
- Rejected: a full re-render on every link event. That resets counters, RECENT
  sets and dynamic sets on every PPP reconnect.

**Link source.** This plan uses `crate::links`, owned by
[fw-global-options](fw-global-options.md):
- `Links::snapshot()` for gating;
- `Links::subscribe()` for hot-plug.

It sees kernel-only devices (`ppp0`, `wg0`), which is why that plan rejected
zebra-rs config as the source. No second netlink socket is added here.

**Deviations to record in the module doc:**
- `ZEBRA_FLOWTABLE_` names and quoted devices;
- flowtables in both tables;
- device gating and hot-add;
- the hardware fallback;
- the reachability skip;
- the `_FORWARD` state-policy copy only when offload is set.

## 4. Changes

### zebra-rs (`yang/firewall.yang`)

```yang
// in grouping firewall
list flowtable {
  ext:help "Flowtable (fast path for established flows)";
  key "name";
  leaf name { ext:help "Flowtable name"; type string; }
  leaf description { ext:help "Description"; type string { pattern '.*'; } }
  leaf-list interface { ext:help "Interface (must exist; no wildcard)";
                        ext:dynamic "rib:interface"; type string; }
  leaf offload { ext:help "Offload method (VyOS default: software)";
                 type enumeration { enum hardware; enum software; } }
}
// rule-common action enum (firewall.yang:397-408): add `enum offload;`
// ipv4/ipv6 forward filter rule lists and `name` rule lists:
leaf offload-target { ext:help "Flowtable for action offload"; type string; }
// global-options state-policy (firewall.yang:1182):
container offload {
  ext:help "Offload all stateful forward traffic to a flowtable";
  leaf offload-target { ext:help "Flowtable"; type string; }
}
```

Drop "flowtable/offload" from the deferred list. There is no exec grammar here;
the summary view is [fw-opmode](fw-opmode.md)'s.

### insomnia

Model (`src/firewall.rs`):
- `FirewallConfig.flowtable: Vec<Flowtable { name, description, interface: Vec<Flex>, offload: Option<Flex> }>`;
- `Rule.offload_target: Option<Flex>`;
- `StatePolicy.offload: Option<OffloadRef { offload_target }>`;
- `is_empty()` also checks `flowtable`.

Functions (proposed):
- `resolve_flowtables(cfg, ctx) -> Vec<FlowtablePlan { name, devices, hardware, gated: Vec<String> }>`:
  pure, applies F3/F4, and is shared by render, hot-plug and show.
- `render_table`: flowtables first; the `"offload"` arm in `render_rule`;
  `render_rules` receives the chain's reaching-hook set (F6); the `_FORWARD`
  state-policy variant (F7).
- `hw_tc_offload(dev) -> bool`: parses `ethtool -k <dev>` for
  `hw-tc-offload: on`. `lo` reports `off [fixed]`.
- `hotplug_script(plans, dev) -> String` (F8). It runs from the
  `links.subscribe()` arm of `firewall::run`, which [fw-zones](fw-zones.md)
  adds.
- `firewall::run` receives the `Links` handle from `main.rs`
  ([fw-global-options](fw-global-options.md) §4); fw-zones and this plan share it.
- Findings go through `findings.rs`, and `Findings::log("firewall")` at apply.

**Worked example** (golden `flowtable_golden`; the `ctx.links` fixture holds
`lo`, `eth0` and `eth1`):

```json
{"flowtable": [{"name": "FT0", "interface": ["eth0", "eth1", "eth9"]}],
 "ipv4": {"forward": {"filter": {"rule": [
            {"number": 10, "action": "offload", "offload-target": "FT0",
             "protocol": "tcp_udp", "state": ["established", "related"]}]}},
          "input": {"filter": {}}},
 "global-options": {"state-policy": {"offload": {"offload-target": "FT0"},
                                      "established": {"action": "accept"}}}}
```

Expected `ip` table. The `ip6` table carries the same flowtable and both
state-policy chains. Checked with `nft -f` in a netns with dummy `eth0` and
`eth1`:

```
table ip zebra_firewall {
    flowtable ZEBRA_FLOWTABLE_FT0 {
        hook ingress priority 0; devices = { "eth0", "eth1" };
        counter
    }
    chain ZEBRA_FORWARD_filter {
        type filter hook forward priority filter; policy accept;
        jump ZEBRA_STATE_POLICY_FORWARD
        ct state {established,related} meta l4proto {tcp, udp} counter flow add @ZEBRA_FLOWTABLE_FT0 comment "ipv4-FWD-filter-10"
        counter accept comment "FWD-filter default-action accept"
    }
    chain ZEBRA_INPUT_filter {
        type filter hook input priority filter; policy accept;
        jump ZEBRA_STATE_POLICY
        counter accept comment "INP-filter default-action accept"
    }
    chain ZEBRA_STATE_POLICY {
        ct state established counter accept comment "STATE-POLICY-established"
        return
    }
    chain ZEBRA_STATE_POLICY_FORWARD {
        counter flow add @ZEBRA_FLOWTABLE_FT0 comment "STATE-POLICY-FWD-offload"
        ct state established counter accept comment "STATE-POLICY-FWD-established"
        return
    }
}
```

The findings are one Warning: `flowtable FT0: interface "eth9" does not exist;
omitted until it appears`. When `eth9` appears, the hot-plug transaction is:

```
add flowtable ip zebra_firewall ZEBRA_FLOWTABLE_FT0 { hook ingress priority 0; devices = { "eth9" }; counter; }
add flowtable ip6 zebra_firewall ZEBRA_FLOWTABLE_FT0 { hook ingress priority 0; devices = { "eth9" }; counter; }
```

The reachability case (golden `offload_reachable_from_input`): `ipv4 name OFF`
holds rule 10 `action offload`, and `input filter` rule 5 jumps to `OFF`. The
offload line is absent, and the Error finding reads
`ipv4 NAM-OFF rule 10: offload in a chain reachable from input (INP-filter rule 5) — rule skipped`.

**Show.** [fw-opmode](fw-opmode.md)'s `show firewall summary` gains a
Flowtables section with Name, Offload, Configured and Live devices. Live
devices come from the `flowtable` objects' `dev` list in the
`nft --json list table` output already fetched; it is `"dev": ["eth0", "eth1"]`
on 1.0.9. Gated devices are marked `(absent)`. The Action column shows
`offload`.

## 5. Tests

**Golden render:**
- `flowtable_golden` (above) and `flowtable_all_devices_missing` (no `devices`
  clause).
- `flowtable_shared_device_first_wins`.
- `flowtable_wildcard_rejected`.
- `flowtable_hardware_capable` (renders `flags offload;`) and
  `flowtable_hardware_incapable_falls_back`.
- `flowtables_in_both_tables_without_families` (VyOS hole a).
- `offload_missing_target`, `offload_undefined_target`, and
  `offload_target_without_action_warns`.
- `offload_reachable_from_input`, `offload_via_default_jump_from_output`, and
  `offload_in_zone_default_firewall`: skipped with a local zone, kept without.
- `state_policy_offload_forward_variant`, and
  `state_policy_without_offload_unchanged`: the existing `golden_render` text
  is untouched by this plan.

**Unit tests:**
- `resolve_flowtables_*`.
- `hotplug_script_repeats_flags` (`counter;` and `flags offload;`).
- `parse_ethtool_k` (on, off, `off [fixed]`, missing line).
- `hotplug_updates_last_applied`, with an injected applier.
- `apply_loop_downgrades_then_excludes_flowtable`, through fw-load-safety's
  `NftRunner` fake failing on the `flags offload;` line, then on the flowtable.

**BDD** `@fw_flowtable`:
- Topology: h1 — r1 — h2. It needs the two-leg step from [fw-zones](fw-zones.md)
  and `insomnia_node.sh` from [fw-load-safety](fw-load-safety.md).
- Scenarios:
  1. FT0 on r1's two legs plus `ghost0`. The insomnia log has "nftables ruleset
     applied" and a warning naming `ghost0`, and
     `command "nft list flowtables"` contains both legs.
  2. `ip link add ghost0 type dummy` in r1, then `nft list flowtables`
     eventually contains `ghost0`. A forward rule counter shown before is not
     reset.
  3. `ip link del ghost0`, then a commit still applies.
  4. A UDP flow h1→h2 (`bash /dev/udp` loop) after a reply; `conntrack -L`
     shows `[OFFLOAD]` when conntrack-tools is installed, else the step is
     skipped.
  5. An input-filter jump to an offload chain still loads, and the warning is
     logged.
  6. Teardown.
- Hardware offload is unit-test only: dummy and veth devices have no
  hw-tc-offload.

## 6. Docs

- New `book/src/ch-01-14-flowtables-and-offload.md`, plus a SUMMARY entry (the
  number is allocated in [README](README.md)). It covers:
  - what a flowtable bypasses: the forward hook, and with it counters and
    `log` for offloaded packets;
  - TCP/UDP only, after the connection is established;
  - software versus hardware, including the `ethtool -K` step;
  - device gating and hot-plug;
  - the reachability rule;
  - every apply flushes offloaded flows back to the slow path.
- `ch-01-03-actions.md`: an `offload` row (forward and custom chains only;
  evaluation continues).
- `ch-01-06-connection-tracking.md`: `state-policy offload`.
- `ch-03-00-show-firewall.md`: the summary's flowtable section.
- Module doc: the deviations in §3.

## 7. Milestones

| # | Scope | Repo | Effort | Done when |
|:--|:--|:--|:--|:--|
| 1 | `list flowtable`, `enum offload`, `offload-target` (forward + name), `state-policy offload` YANG + parse tests | zebra-rs | S | `offload-target` refused on input rules |
| 2 | Model, `resolve_flowtables`, F1–F3, F5, F7 rendering, `RefIndex::register` of flowtables, goldens | insomnia | M | goldens pass; netns `nft -f` loads |
| 3 | F6 reachability skip (needs the fw-load-safety graph and fw-zones edges) | insomnia | S | reachability goldens |
| 4 | F4 hardware check + `Origin::Flowtable` in the fw-load-safety apply loop; `ethtool` in Debian Recommends | insomnia | S | unit tests; `make -C packaging amd64` builds |
| 5 | F8 link-watcher subscription, hot-add, last-applied update | insomnia | S | unit tests; BDD scenario 2 |
| 6 | BDD `@fw_flowtable`; book chapter | insomnia | S | feature green |

## 8. Risks and open questions

- **Link-watcher ordering.** Milestone 5 needs `crate::links`, which is
  [fw-global-options](fw-global-options.md) milestone 3. Without it,
  milestone 2 can gate on a one-shot snapshot, and hot-plug waits. Do not add a
  second netlink socket.
- **Offloaded packets skip the forward hook.**
  - A rule change does not affect already offloaded flows until the next apply
    flushes the flowtable. Every apply does flush, because the table is
    recreated.
  - Counters and `log` miss offloaded packets; the book must say so.
- **eBPF.** XDP runs before the ingress flowtable hook; flows redirected there
  never reach it ([ebpf-netfilter](ebpf-netfilter.md)).
- **Unverified behaviour.**
  - Flowtables on VRF slaves, and the interaction with IPsec (xfrm) paths. BDD
    covers only the plain case.
  - Whether `state-policy offload`'s unconditional `flow add` is safe for UDP
    flows before a reply. The kernel requires a confirmed conntrack entry and,
    for TCP, an established one; this is from source reading.
  - The hardware fallback path is reachable only on real NICs.
- **Open:** should the `_FORWARD` state-policy copy always be rendered, for
  strict VyOS parity? It would add churn to every golden with state-policy.
  The recommendation is no.

## 9. Acceptance criteria

- [ ] YANG for flowtable, offload action and target, and state-policy offload, insomnia-gated
- [ ] Render matches `nftables-offload.j2` and `parse_rule`, except the recorded deviations
- [ ] None of the cases measured in §2 can make `nft -f` fail; each yields a finding naming the object, with the severity in §3
- [ ] Hot-added devices appear without a table replace; counters are preserved
- [ ] Offload rules in chains reachable from input/output are skipped
- [ ] BDD `@fw_flowtable` green; book chapter and module-doc deviations written
