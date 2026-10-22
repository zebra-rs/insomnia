# CGNAT and NAT64 — implementation plan

Status: plan, 2026-10-21. Covers: `nat cgnat` and `nat64`
([vyos-gap](../vyos-gap.md) §6.3 rows `nat64` and `nat cgnat`; §10 Phase 4).
Priority: P3 (both) · Effort: M (CGNAT) + M (NAT64) · Owner: both (zebra-rs schema
and show grammar; insomnia renderers and lifecycle)
Depends on: [nat](nat.md) M1–M3 (the `nat` backend, `ip zebra_nat`, `show nat`
routing), [nft-common](nft-common.md), [conntrack](conntrack.md) (`ctread::delete`
by source prefix, M5), [commit-validation](commit-validation.md) (`findings.rs`);
soft: [exec-verbs](exec-verbs.md) (only for the optional nat64 show),
[ebpf-netfilter](ebpf-netfilter.md) (behaviour on eBPF ports; the `nat64`
row of its B-class tree list) · Unblocks: none

The two features share nothing but the word NAT. **CGNAT is part of the `nat`
backend:**
- it is a subtree of `nat`;
- it renders into the same `ip zebra_nat` table;
- it is engine-identical (nft maps).

**NAT64 is a separate backend:**
- it has its own top-level tree;
- it runs on its own engine (Jool, an out-of-tree kernel module plus CLI);
- it has its own lifecycle and packaging.

Ship either one independently.

## 1. Goal

- **CGNAT.**
  - `set nat cgnat pool external|internal …` and `set nat cgnat rule N
    source pool X translation pool Y` render a deterministic port-block
    allocation. Each internal host gets one external address plus a fixed
    port block, so the binding can be identified without per-flow logs
    (RFC 7422 style).
  - When an allocation changes, conntrack entries of the affected
    internal hosts are flushed.
  - `show nat cgnat allocation [external-address X | internal-address X]`
    answers from insomnia. `log-allocation` writes the mapping to the
    journal.
- **NAT64.**
  - `set nat64 source rule N source prefix <pool6/96> translation pool M
    address … port …` creates one Jool instance.
  - insomnia creates, updates, recreates and removes Jool instances
    idempotently across zebra-rs and insomnia restarts.
  - With Jool absent, the backend degrades to one warning, and no other
    backend is affected.

## 2. Current state

**insomnia and zebra-rs @ baselines:**
- no `cgnat` or `nat64` node or code;
- no Jool anywhere;
- the `nat` backend itself is planned in [nat](nat.md).

**VyOS CGNAT** (`interface-definitions/nat_cgnat.xml.in`,
`src/conf_mode/nat_cgnat.py`, `data/templates/firewall/nftables-cgnat.j2`,
`src/op_mode/cgnat.py`).
- **Schema:**
  - `pool external <n>`: `range <r> seq N`, `external-port-range` (default
    `1024-65535`), `per-user-limit port` (default 2000);
  - `pool internal <n>`: `range` (multi);
  - `rule N`: `source pool`, `translation pool`;
  - `log-allocation`.
- **Allocation** (`generate_port_rules`, `nat_cgnat.py:155-207`):
  - walk the internal hosts in order;
  - give each host the next `per-user` ports of the current external
    address;
  - move to the next external address when the range is exhausted.
  - Prefixes count their network and broadcast addresses as hosts, on
    both sides (`IPOperations.convert_prefix_to_list_ips`, `:84-121`).
  - External ranges are sorted by `seq` (`:363-366`); ties keep dict
    order.
- **verify** (`:246-348`):
  - pools and rules exist; ranges are present;
  - referenced pools exist;
  - each pool is used by at most one rule;
  - capacity: internal hosts ≤ ⌊ports/per-user⌋ × external hosts.
- **Render.** `add table ip cgnat` + `flush` (not add+delete).
  - The maps are `tcp_nat_map`, `udp_nat_map` and `icmp_nat_map`
    (`ipv4_addr : interval ipv4_addr . inet_service`, identical
    elements) plus `other_nat_map`.
  - POSTROUTING at `priority srcnat` (100) runs four
    `snat ip to ip saddr map @…` rules.
- **Same-priority conflict.** `vyos_nat` POSTROUTING also sits at 100, so
  whether CGNAT or a user source rule wins is unspecified.
- **Apply** (`:416-470`):
  - `conntrack -D -s <prefix>` runs for the *previous* (effective)
    internal ranges, and only when the `pool` node changed.
  - `log-allocation` sends every mapping to syslog on every commit.
- **Op mode.** `cgnat.py` reads `nft --json list table ip cgnat` at the
  fixed index `data['nftables'][2]` (`:36`), which is the TCP map only.

**VyOS NAT64** (`interface-definitions/nat64.xml.in`, `src/conf_mode/nat64.py`).
- **Schema.** `source rule N`:
  - `description`, `disable`, `match mark`, `source prefix`;
  - `translation pool M {address, port, protocol tcp|udp|icmp, disable,
    description}`.
- **verify** (`:59-154`):
  - `jool` kmod present;
  - pool6 is a `/96` with RFC 6052 bits 64–71 zero;
  - each pool has an address and a port;
  - the pool port range does not overlap `net.ipv4.ip_local_port_range`.
  - The "only one netfilter instance per netns" check filters on a
    `mode` leaf that the XML does not define, so it never fires.
- **generate** (`:156-213`). Writes `/run/jool/instance-N.json`:
  - `framework: netfilter`, `pool6`, `manually-enabled`;
  - pool4 entries per protocol (default all three), plus `mark`.
- **apply** (`:214-250`):
  - `jool instance remove` for deleted rules, and for rules whose pool6
    changed (Jool cannot change pool6 in place);
  - then `jool -i instance-N file handle <json>`;
  - `unload_kmod jool` when nat64 is gone.
- There are no show commands. DNS64 is not provided.
- **Packaging.** `jool-dkms` and `jool-tools` 4.1.11 are in Ubuntu noble
  universe (checked with `apt-cache policy` on the dev host). The Debian
  status is *unverified*.

## 3. Design

### CGNAT

**C-1. Render into `ip zebra_nat`, not a separate table.**
- The maps are `CGNAT_TCP`, `CGNAT_UDP`, `CGNAT_ICMP` and `CGNAT_OTHER`,
  with VyOS's types.
- A regular chain `ZEBRA_CGNAT` holds the four VyOS rules. The last rule
  of POSTROUTING is `counter jump ZEBRA_CGNAT`.
- Why:
  - User source rules, including `exclude` (`return`), are evaluated
    first, deterministically.
  - nft NAT statements are terminal, so a user SNAT wins.
  - An `exclude` exempts traffic from CGNAT as well. That is the only
    exemption mechanism CGNAT has, since VyOS CGNAT has no rule matchers.
- Rejected:
  - VyOS's own `table ip cgnat` at the same priority (order unspecified);
  - a table at 99 (CGNAT would override user rules, and `exclude` could
    not exempt);
  - a table at 101 (`exclude` returns only from `zebra_nat`, and CGNAT
    then translates anyway).

**C-2. Allocation is a pure function in a new `src/cgnat.rs`.** It ports
`generate_port_rules` exactly, including the network/broadcast counting.
- Ties in `seq` are broken by range text, so the result is deterministic
  (VyOS uses dict order).
- `nat.rs` calls it, so the same function feeds the render, the show
  view and the change detection.

**C-3. Flush by allocation diff, not by "pool node changed."**
- insomnia keeps the previous allocation in `ShowState`. After a
  successful apply, every internal host whose (external, port block) was
  added, changed or removed is collected and summarized into minimal
  prefixes.
- Those prefixes are flushed through [conntrack](conntrack.md)'s
  `ctread`, which shells out to conntrack-tools.
- That plan provides (its §3.8)
  `ctread::delete(&DeleteFilter { family, src: Option<String>, mark: Option<u32> })`,
  wrapping `conntrack -D -f F [-s P] [--mark M]`, next to `flush()`. It
  returns `CtError::NotInstalled` like the others. CGNAT uses the `src`
  arm; [wan-load-balancing](wan-load-balancing.md) uses the `mark` arm.
- Whether conntrack-tools 1.4.8 accepts a CIDR prefix after `-s` is
  *unverified*. If it does not, the caller passes single hosts (`/32`).
  The number of calls is then bounded by the number of changed hosts.
- Why this differs from VyOS:
  - VyOS misses rule edits (only `pool` changes trigger a flush);
  - VyOS misses newly added internal ranges (it flushes only the old
    ones);
  - VyOS flushes unchanged hosts.
- On the first snapshot after an insomnia start there is no previous
  allocation, so nothing is flushed. Kernel conntrack survived the
  restart, and the allocation function is deterministic.

**C-4. Verify rules are `Findings`** ([commit-validation](commit-validation.md)
`findings.rs`, D1). They ride the `nat` unit, because `cgnat` sits under
`[nat]`.
- An undefined pool, a pool shared by two rules, or insufficient
  capacity is `Severity::Error` with `Effect::Skipped("rule")`. With
  layer 2 live, such a commit is refused.
- A pool name must pass `safe_name`.
- A range must parse as host, prefix or `a-b`.
- An internal pool larger than 65536 hosts in one rule renders, with a
  size `Warning` (§8).

**C-5. `log-allocation` logs only changes.**
- One `tracing::info!` line per changed host:
  `nat: cgnat 100.64.0.5 -> 203.0.113.10 ports 1024-17151`.
- On the first snapshot after start, the full allocation is logged once,
  so the journal holds the current mapping after every restart.
- Deviation: VyOS logs everything on every commit.

**C-6. `show nat cgnat allocation` answers from the model** via C-2.
- VyOS reads only the TCP map at a fixed JSON index.
- The header states when the last apply failed, so the view never
  silently disagrees with the kernel.

### NAT64

**N-1. New backend `src/nat64.rs`.**
- Single-path subscription to `["nat64"]`; no groups are needed.
- One new `--jool-dir` flag (default `/run/insomnia/jool`, inside the
  preserved `RuntimeDirectory`, `packaging/systemd/insomnia.service`).
- The lifecycle has the shape of `keepalived::apply` and
  [charon-lifecycle](charon-lifecycle.md): render, compare, act.
  1. **Probe once at start.** Run `jool --version`. On failure, log once
     (`nat64: jool not installed; nat64 rules ignored`) and answer later
     snapshots with that warning only.
  2. **Per rule,** render `zebra-N.json`. The instance name is `zebra-N`
     (≤ 12 chars, below Jool's limit, which is *unverified*), not VyOS's
     `instance-N`, so operator-made instances are never touched.
     - Unchanged file → no-op.
     - Changed file → `jool -i zebra-N file handle <file>`.
     - Changed pool6 or framework → `jool instance remove zebra-N`, then
       `file handle`.
  3. **On every snapshot,** list `jool instance display --csv` and remove
     each `zebra-\d+` instance that is not configured. This is the
     resync after a zebra-rs restart.
  4. **`modprobe jool`** before the first instance. With nat64 empty,
     remove the instances and unload the module only if
     `jool instance display` is then empty. VyOS unloads
     unconditionally.

**N-2. One netfilter instance per netns** (Jool's restriction, which
VyOS's dead check intended to enforce). Only the lowest-numbered enabled
rule is instantiated. The others are `Error` findings with
`Effect::Skipped("rule")`.

**N-3. Verify rules are `Findings`** (`Error`/`Skipped`). The validator
gains the unit `nat64 → [nat64]`, served by `nat64::validate`. The
checks:
- pool6 is a `/96` with bits 64–71 zero;
- each pool has an address and a port or range;
- the port range does not overlap `ip_local_port_range`, read from
  `/proc` at render time.

**N-4. Hook and pipeline semantics are an explicit spike, not an
assumption.** Each of these is *unverified* and must be measured in M0
(a two-netns setup with Jool) before the book says anything:
- Jool's netfilter hook priority, relative to `zebra_nat` (-100) and
  `zebra_firewall` (0) on prerouting;
- whether translated packets then traverse the other family's FORWARD
  hook (insomnia's forward filter), or leave via the output path;
- whether `match mark` sees the bit-31 fragment mark from
  [nft-common](nft-common.md).

The results go into the module doc and ch-01-15.

**N-5. Packaging.** The deb gets `Suggests: jool-dkms, jool-tools`, not
`Recommends`, so DKMS and kernel headers are not pulled onto every
install. Secure Boot needs the DKMS module signed; that is documented
only. DNS64 stays out of scope (it needs a resolver).

**Module-doc deviations:**
- **CGNAT:** C-1, C-3, C-5, C-6, and the tie-break in C-2.
- **NAT64:** instance names (N-1); module unloading (N-1); the
  one-instance enforcement (N-2).

## 4. Changes

### zebra-rs

**`nat.yang`.** Add to `grouping nat` (sketch):

```yang
container cgnat {
  leaf log-allocation { type empty; }
  container pool {
    list external { key "name"; leaf name { type string; }
      leaf external-port-range { type string; }                       // default 1024-65535
      container per-user-limit { leaf port { type uint16 { range "1..65535"; } } }  // default 2000
      list range { key "range"; leaf range { type string; }           // host | prefix | a-b
                   leaf seq { type uint32 { range "1..999999"; } } } }
    list internal { key "name"; leaf name { type string; } leaf-list range { type string; } } }
  list rule { key "number"; uses fw:rule-key;
    container source { leaf pool { type string; } }
    container translation { leaf pool { type string; } } }
}
```

Add a new `grouping nat64`:

```yang
grouping nat64 { container source { list rule { key "number"; uses fw:rule-key;
  leaf description { type string { pattern '.*'; } }  leaf disable { type empty; }
  container match { leaf mark { type uint32 { range "1..2147483647"; } } }
  container source { leaf prefix { type inet:ipv6-prefix; } }
  container translation { list pool { key "number"; leaf number { type uint32 { range "1..999999"; } }
    leaf description { type string { pattern '.*'; } }  leaf disable { type empty; }
    leaf address { type union { type inet:ipv4-address; type inet:ipv4-prefix; } }
    leaf port { type string; }                                        // port or range
    container protocol { leaf tcp { type empty; } leaf udp { type empty; } leaf icmp { type empty; } } } } } } }
```

**`config.yang`.** Add
`container nat64 { if-feature feat:insomnia; uses "nat:nat64"; }`.

**`exec.yang`.**
- Under `container nat` ([nat](nat.md)), add `container cgnat { container
  allocation { presence; list external-address { key ip; … } list
  internal-address { key ip; … } } }`. It routes to `"nat"` through the
  existing `is_nat`.
- Optional (M-N4): `container nat64 { if-feature …; container session;
  container bib; }`. It is routed to a separate `"nat64"` provider key
  through `is_nat64` (see the insomnia wiring below).

### insomnia

**New `src/cgnat.rs`** (pure, no I/O):

```rust
pub struct Alloc { pub internal: Ipv4Addr, pub external: Ipv4Addr, pub ports: (u16, u16) }
pub fn hosts(range: &str) -> Result<Vec<Ipv4Addr>, String>;            // host | a/n | a-b, VyOS counting
pub fn allocate(ext: &[Ipv4Addr], int: &[Ipv4Addr], per_user: u16, port_range: (u16, u16))
    -> Result<Vec<Alloc>, String>;                                     // Err = capacity
pub fn changed_prefixes(old: &[Alloc], new: &[Alloc]) -> Vec<ipnet-like (Ipv4Addr, u8)>;
```

**`src/nat.rs`.**
- `NatConfig.cgnat: Option<Cgnat>`.
- The render emits the four maps and the `ZEBRA_CGNAT` chain when at
  least one rule allocates, and appends `counter jump ZEBRA_CGNAT` to
  POSTROUTING.
- `ShowState` keeps `Vec<Alloc>`.
- After apply: the C-3 flush, then the C-5 logging.

**Worked example (CGNAT):**

```
set nat cgnat pool external EXT range 203.0.113.10-203.0.113.11
set nat cgnat pool external EXT per-user-limit port 16128
set nat cgnat pool internal SUBS range 100.64.0.0/29
set nat cgnat rule 10 source pool SUBS
set nat cgnat rule 10 translation pool EXT
set nat source rule 10 outbound-interface name wan0
set nat source rule 10 source address 100.64.0.0/29
set nat source rule 10 destination address 198.51.100.0/24
set nat source rule 10 exclude
```

Capacity: 64512 ports / 16128 = 4 users per address × 2 addresses = 8 ≥
8 hosts. This was validated with `nft -c` and loaded in a scratch netns;
`CGNAT_UDP` and `CGNAT_ICMP` carry the same elements as `CGNAT_TCP`:

```
table ip zebra_nat {
    map CGNAT_TCP {
        type ipv4_addr : interval ipv4_addr . inet_service
        flags interval
        elements = { 100.64.0.0 : 203.0.113.10 . 1024-17151, 100.64.0.1 : 203.0.113.10 . 17152-33279, 100.64.0.2 : 203.0.113.10 . 33280-49407, 100.64.0.3 : 203.0.113.10 . 49408-65535, 100.64.0.4 : 203.0.113.11 . 1024-17151, 100.64.0.5 : 203.0.113.11 . 17152-33279, 100.64.0.6 : 203.0.113.11 . 33280-49407, 100.64.0.7 : 203.0.113.11 . 49408-65535 }
    }
    map CGNAT_OTHER {
        type ipv4_addr : interval ipv4_addr
        flags interval
        elements = { 100.64.0.0 : 203.0.113.10, 100.64.0.1 : 203.0.113.10, …, 100.64.0.7 : 203.0.113.11 }
    }
    chain POSTROUTING {
        type nat hook postrouting priority 100; policy accept;
        oifname "wan0" ip saddr 100.64.0.0/29 ip daddr 198.51.100.0/24 counter return comment "SRC-NAT-10"
        counter jump ZEBRA_CGNAT
    }
    chain ZEBRA_CGNAT {
        ip protocol tcp counter snat ip to ip saddr map @CGNAT_TCP comment "CGNAT-tcp"
        ip protocol udp counter snat ip to ip saddr map @CGNAT_UDP comment "CGNAT-udp"
        ip protocol icmp counter snat ip to ip saddr map @CGNAT_ICMP comment "CGNAT-icmp"
        counter snat ip to ip saddr map @CGNAT_OTHER comment "CGNAT-other"
    }
}
```

A source with no map entry fails the lookup, so the rule does not match
and the packet passes untranslated (VyOS semantics).

`show nat cgnat allocation internal-address 100.64.0.5`:

```
Internal IP    External IP    Port range
-------------  -------------  -----------
100.64.0.5     203.0.113.11   17152-33279
```

`-j` uses VyOS's keys: `internal_address`, `external_address` and
`port_range`.

**New `src/nat64.rs`.**
- `Nat64Config` model.
- `render(cfg) -> (BTreeMap<String /*zebra-N*/, String /*json*/>, Findings)`,
  `validate(parts) -> Findings` and `apply(&Jool, rendered)`.
- `struct Jool { dir: PathBuf, available: bool }`, with `probe()`,
  `instances()` (CSV), `handle(name, file)` and `remove(name)`.
- `main.rs`: `--jool-dir` and the spawn.
- Only if M-N4 ships:
  - a `nat64` field in [exec-verbs](exec-verbs.md)' `Backends`;
  - the row `(Show, "/show/nat64", Backend::Nat64)` in `ROUTES`. This
    needs segment-boundary matching, which exec-verbs D-8 provides.
  - `"nat64"` in `Register.name`.
  - zebra-rs `SHOW_PROTOS` gains `is_nat64` before `is_nat`, and
    `is_nat` no longer matches `nat64`.

Rendered `zebra-10.json` for `rule 10 source prefix 64:ff9b::/96
translation pool 1 address 192.0.2.1 port 61001-65535`:

```json
{ "instance": "zebra-10", "framework": "netfilter",
  "global": { "pool6": "64:ff9b::/96", "manually-enabled": true },
  "pool4": [ { "protocol": "TCP",  "prefix": "192.0.2.1", "port range": "61001-65535" },
             { "protocol": "UDP",  "prefix": "192.0.2.1", "port range": "61001-65535" },
             { "protocol": "ICMP", "prefix": "192.0.2.1", "port range": "61001-65535" } ] }
```

This follows VyOS's keys (`nat64.py:166-211`). Whether Jool 4.1 accepts
`"port range"` with a space is VyOS's claim; it is *unverified* here
(spike M-N0). The default Linux ephemeral range is 32768–60999, so the
pool above sits just past it.

## 5. Tests

**`cgnat::tests` (pure):**
- `hosts_counts_network_and_broadcast`;
- `allocate_matches_vyos_walk` (the 8-host example, and a 3-external,
  uneven case);
- `capacity_error`;
- `seq_ordering_and_tie_break`;
- `changed_prefixes_minimal` (one host moved → `/32`; a whole pool
  renumbered → the summarized prefixes).

**`nat::tests`:**
- `golden_cgnat` (the worked example, byte for byte);
- `golden_cgnat_with_masquerade_precedes`;
- `cgnat_findings` (undefined pool, pool reused by two rules,
  capacity, unsafe name);
- `show_cgnat_allocation_filters`.

**`nat64::tests`:**
- `golden_instance_json`;
- `protocols_subset`;
- `disabled_pool_omitted`;
- `one_netfilter_instance` (two rules → one instance + a warning);
- `pool6_validation` (`/64` rejected; bits 64–71 set rejected);
- `port_overlap_with_ephemeral` (the range injected for the test);
- `plan_actions`: the old and new rendered sets map to create, update,
  recreate and remove (a pure function, so no `jool` binary is needed).

**BDD:**
- **`cgnat_basic`.** Two subscriber namespaces (100.64.0.1, 100.64.0.5)
  sit behind r1; the `wan` server has no route to 100.64/10.
  - Pings from both subscribers succeed.
  - `show nat cgnat allocation` lists both hosts.
  - `conntrack -L` on r1 shows each reply tuple inside its port block.
  - Changing `per-user-limit` flushes their conntrack entries; a
    one-shot `conntrack -L | grep -c 100.64.0.5` drops to 0, then
    reconverges.
  - Teardown.
- **`nat64_basic`** (Makefile target documented as needing
  `jool-dkms` + `jool-tools` on the host).
  - v6-only `client` → r1 (pool6 64:ff9b::/96, pool4 192.0.2.1) → v4
    `server` 192.0.2.9.
  - `ping -6 64:ff9b::c000:209` from `client` succeeds.
  - `delete nat64` removes `zebra-10` (`jool instance display` lacks it).
  - Teardown.
  - The netns question: Jool instances are per-netns (Jool's model;
    *unverified* in BDD until M-N0).

## 6. Docs

- **New `book/src/ch-01-15-cgnat.md`:**
  - the allocation model, with a worked capacity calculation;
  - `exclude` as the exemption mechanism;
  - flushing on change;
  - `log-allocation` and attribution;
  - the 65536-host guidance.
- **New `ch-01-16-nat64.md`:**
  - Jool installation (DKMS, Secure Boot);
  - pool6 rules;
  - the ephemeral-port overlap;
  - the M-N0 findings on hook placement and firewall interplay;
  - DNS64 out of scope.
- **`ch-03-04-show-nat.md`:** add the `cgnat allocation` view (and the
  optional nat64 views).
- **`ch-00-01-install.md`:** add the optional Jool packages.
- **`Cargo.toml` deb:** add `suggests = "zebra-rs, jool-dkms, jool-tools"`.
- **Module docs:**
  - `src/nat.rs`: C-1, C-3, C-5, C-6;
  - `src/nat64.rs`: N-1, N-2, N-4 results.

## 7. Milestones

| # | Scope | Repo | Effort | Done when |
|:--|:--|:--|:--|:--|
| M-C1 | `cgnat` schema in `nat.yang`; `show nat cgnat allocation` grammar | zebra-rs | S | parses only with `--feature insomnia`; routes to `"nat"` |
| M-C2 | `src/cgnat.rs` allocation + tests | insomnia | S | the `cgnat::tests` suite green |
| M-C3 | render into `zebra_nat`, `Findings`, show view, `log-allocation` | insomnia | S | `golden_cgnat` green; the example loads in a netns |
| M-C4 | allocation-diff conntrack flush on the [conntrack](conntrack.md) helper; BDD `cgnat_basic` | insomnia | S | the BDD feature passes |
| M-N0 | spike: Jool in two netns; hook priority, forward-path traversal, mark/bit-31, `file handle` idempotence, the JSON `port range` key | insomnia | S | findings recorded in `src/nat64.rs` doc and in this plan |
| M-N1 | `nat64` schema + `config.yang` | zebra-rs | S | parses only with the feature |
| M-N2 | `src/nat64.rs`: probe, render, plan/apply, resync, unload rule; `--jool-dir`; unit tests | insomnia | M | unit tests green; absence of Jool yields exactly one warning |
| M-N3 | BDD `nat64_basic`; book ch-01-16; deb `suggests` | insomnia | S | the feature passes on a host with Jool |
| M-N4 | (optional) `show nat64 session\|bib` via `jool … display --csv` | both | S | show tests green |

The CGNAT (M-C*) and NAT64 (M-N*) tracks are independent. Each M-C
milestone needs [nat](nat.md) M2.

## 8. Risks and open questions

- **CGNAT scale.**
  - One element per internal host, in four maps.
  - 65536 hosts (/16) produced a 10.7 MB script that loaded in about 1.0 s
    on the dev VM (measured).
  - Every NAT or group commit re-applies it.
  - Mitigations if this hurts:
    1. Per-table compare-before-apply is not possible, because the maps
       live in `zebra_nat`.
    2. Instead, update the maps incrementally with `add element` /
       `delete element` when the rules are unchanged. That is the
       `apply::update_elements` hook [nft-common](nft-common.md) §8
       reserves. It is deferred until there is measured need.
- **Network and broadcast addresses as SNAT sources.** This is VyOS
  parity, but an upstream may drop traffic sourced from x.x.x.0 or
  x.x.x.255 of a /24. Open: offer a knob to skip them? That would be a
  deviation, and it changes capacity math relative to VyOS configs.
- **Jool lifetime.**
  - Out-of-tree modules break on kernel upgrades until DKMS rebuilds.
  - insomnia must keep working without Jool (N-1 probe).
  - Module unload while another netns still has instances: the
    "unload only if empty" check is per-netns, and module refcounts
    protect the module anyway. To verify in M-N0.
- **Remote insomnia.** Jool and CGNAT act on insomnia's own host, like
  every nft feature. Nothing new, but restate it in ch-01-16.
- **eBPF ports.** Traffic entering an `ebpf enabled` port bypasses
  netfilter, so neither the CGNAT maps nor Jool's prerouting hook see it
  ([ebpf-netfilter](ebpf-netfilter.md)). Under its default outcome B,
  `nat cgnat` is covered by the `nat` row that [nat](nat.md) adds to
  `EBPF_BYPASSED_TREES`, and this plan adds the `nat64` row with M-N1.
  ch-01-15 and ch-01-16 link to that plan.
- **`conntrack -D -s` with CIDR.** Support in 1.4.8 is *unverified*.
  The C-3 fallback to per-host deletes bounds the cost by the number of
  changed hosts.

## 9. Acceptance criteria

- [ ] **CGNAT renders** the worked example byte for byte; user `exclude`
      and SNAT rules take precedence over CGNAT.
- [ ] **Allocation matches VyOS** `generate_port_rules` on the example
      and on an uneven case. Capacity failures skip the rule with a
      warning.
- [ ] **A pool or rule edit flushes exactly the hosts whose allocation
      changed** (unit test plus BDD).
- [ ] **`show nat cgnat allocation`** answers, with both filters and
      `-j`.
- [ ] **NAT64 lifecycle.** Rules create, update, recreate and remove
      `zebra-N` Jool instances idempotently. Foreign instances are never
      touched, and a missing Jool yields one warning.
- [ ] **The M-N0 findings** (hook priority, firewall path) are written
      into the module doc and ch-01-16 before ch-01-16 claims anything.
- [ ] Clippy `-D warnings` and fmt are clean. No CI job needs `nft`,
      `conntrack` or `jool`.
