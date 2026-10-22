# Documentation corrections — implementation plan

Status: plan, 2026-10-21. Covers: §3 "Documentation that is wrong today" and
the `design/vrrp.md` corrections ([vyos-gap](../vyos-gap.md) §3, §8.3, §8.4).
Priority: P1 (the BDD scripts break once zebra-rs drops the `iso` alias) ·
Effort: S · Owner: insomnia
Depends on: none. The `ikev2-reauth` text is ordered after X5 in
[ipsec-render-fixes](ipsec-render-fixes.md) (§3 D3), and the ch-01-02
weekday example after X14 in [fw-matchers](fw-matchers.md) (§3 D7) · Unblocks:
[vrrp-vrf](vrrp-vrf.md) (shim requirement documented),
[vrrp-hardening](vrrp-hardening.md) (§14 deferred list)

Baselines: insomnia `ee4dfaa`, zebra-rs `141da2fc`, vyos-1x `7f2c893`.
Every line number below is at `ee4dfaa`.

## 1. Goal

- No insomnia document, book chapter, BDD script, feature file or module doc
  spells `--feature iso` or `feat:iso`.
- The BDD scripts run against zebra-rs both before and after the rename.
- The conntrack, static-NAT and `ikev2-reauth` text matches what insomnia
  renders.
- No book example makes insomnia render a ruleset that nft rejects (X14,
  ch-01-02's weekdays), whichever of this plan and the renderer fix lands
  first.
- `src/vrrp.rs` and `design/vrrp.md` record the shipped show grammar and
  the deviations listed in gap §8.4.
- The `--vrf-preload` documentation says the file must be a shared object,
  and what happens if it is not. The code change belongs to
  [vrrp-vrf](vrrp-vrf.md).

## 2. Current state

**The feature rename.**
- zebra-rs `ab1c0774` (2026-10-14) renamed the YANG feature `iso` to
  `insomnia` (`yang/zebra-features.yang:21-33`). It first shipped in v26.10.2:
  `git tag --contains ab1c0774` lists v26.10.2 and v26.10.3.
- `--feature iso` still enables it, through
  `RENAMED_FEATURES` (`src/config/manager.rs:367`), and logs
  `--feature iso is deprecated …` (`manager.rs:389-404`).
- The toolchain staged in this worktree (`bdd/.stage/bin/zebra-rs --version`)
  is **26.9.1**, which predates the rename. A BDD script that hard-codes
  `--feature insomnia` would therefore start zebra-rs without the
  `firewall`, `vpn` and `vrrp` trees.
- The tests that pin the gating are now
  `shipped_vrrp_gated_on_insomnia` (`manager.rs:7949`) and its firewall and
  ipsec siblings (`7245`, `7724`). The `shipped_tree(&["iso"])` call that
  `design/vrrp.md` names is now `shipped_tree(&["insomnia"])`.

**Other errors, each checked against the code:**

| Where | Says | Fact |
|:--|:--|:--|
| `book/src/ch-01-06-connection-tracking.md:69-72` | a commit that sets conntrack timeouts "logs a warning" | `GlobalOptions` keeps only `state_policy`, so the other leaves are dropped "without a log line" (`src/firewall.rs:22-25`, `1054-1060`) |
| `ch-01-06:61-62` | untracked packets "show `state invalid`" | nft gives them `ct state untracked`. `firewall.yang:465-472` allows only `established`, `invalid`, `new`, `related`, so they cannot be matched at all |
| `ch-01-10-static-nat.md:11` | `inbound-interface name eth0` | VyOS static NAT includes the plain leaf `include/inbound-interface.xml.i` (`nat.xml.in:132`). Source and destination NAT use the `firewall/…-interface.xml.i` node with `name`/`group` (`nat.xml.in:17`, `:69`), so `ch-01-08:11` and `ch-01-09:11` are right |
| `ch-02-01-ikev2.md:75-76`, `appendix-a-supported-rfcs.md:32` | `ikev2-reauth` performs re-authentication | it is parsed and never read (`src/ipsec.rs:215`, `265`); only `reauth_time = 0` is ever rendered, for `@` peers (`ipsec.rs:712-714`). This is X5 |
| `appendix-a-supported-rfcs.md:126-128` | `source-validation` needs "sysctl writes" | zebra-rs forces `rp_filter=0` (`zebra-rs/src/fib/netlink/sysctl.rs:14-15`), so this has to be nft `fib` rules (gap §4.4). Found while writing this plan; not in gap §3 |
| `src/vrrp.rs:15-30` module doc | lists the deviations | the show word order is missing. Shipped: `show vrrp {statistics\|detail} group <NAME>` (`zebra-rs/yang/exec.yang:102-129`). VyOS: `show vrrp <NAME> statistics\|detail` (`op-mode-definitions/vrrp.xml.in:5-41`) |
| `--vrf-preload` default `/usr/lib/insomnia/vrf.o` (`src/main.rs:71-73`; book `ch-00-03:20`, `:173-181`; `design/vrrp.md:328`, `:556`) | the default is a `.o` file | ld.so preloads only ET_DYN/ET_EXEC objects. Checked on this host: `LD_PRELOAD=vrf.o` built with `cc -c` prints `cannot be preloaded (only ET_DYN and ET_EXEC can be loaded): ignored` and the program runs normally. The same file built with `-shared` loads, whatever its name. A missing file is ignored with the same message. So a bad shim silently runs a VRF instance in the default VRF |

**Defects X13–X15 (gap §3) and the doc text they touch:**

| Defect | Doc text | Who changes it |
|:--|:--|:--|
| X13: secret files are created, then chmod'ed to `0600` | `ch-00-03:86`, `:124`, `ch-02-03:56-57` and `ch-05-04:15` say the files are mode `0600` | Nobody. That is the final mode, so the text stays true; [ipsec-render-fixes](ipsec-render-fixes.md) M1 closes the window |
| X14: weekdays pass through verbatim, and nft accepts only full names or 0–6 | `ch-01-02:95` `time weekdays Mon,Tue,Wed,Thu,Fri` renders `day {"Mon",…}`, and the whole ruleset fails to load | [fw-matchers](fw-matchers.md) X14 (scheduled in Phase 0) fixes the renderer and owns the ch-01-02 time section; fallback text here (D7) |
| X15: zebra-rs show routing matches user-typed key values | No book text describes the routing, and no `show firewall`/`show vrrp` example uses a protocol-named key (checked by grep) | [fw-opmode](fw-opmode.md) M1; no text change |

**`design/vrrp.md` details behind gap §8.4:**
- §1 says it was "verified against vyos-1x `current`" (`:23`, `:688`).
- §1 is missing two VyOS conf-mode rules:
  - the T5533 IPv6-tentative wait (`high-availability.py:218-227`);
  - the restart when `vrrp snmp` changes (`:62`).
- VyOS's unit override is `Type=simple`
  (`data/templates/high-availability/10-override.conf.j2`).
  `packaging/systemd/insomnia-keepalived@.service` is `Type=notify`. The
  host's keepalived 2.2.8 links `libsystemd` and calls `sd_notify` (checked
  with `ldd` and `strings`).
- VyOS rejects a sync-group member with its own health check: `ConfigError`
  at `high-availability.py:150-155`, asserted by
  `smoketest/.../test_high-availability_vrrp.py:317-322`. The §6 table row
  (`:302`) records only "ignored, warning".
- zebra-rs `master-refresh` is `0..255` (`zebra-rs/yang/vrrp.yang:80`). VyOS
  is `1-255` (`include/vrrp/garp.xml.i:58`). The §4 tree (`:175`) does not
  call this out.

## 3. Design

- **D1. Probe the feature name in the BDD scripts; do not hard-code it.**
  - Each node script reads the staged `zebra-features.yang`. It has just
    resolved `$YANG` (`vrrp_node.sh:71`, `ipsec_node.sh:87`).
  - It passes `--feature insomnia` when that file declares the feature, and
    `--feature iso` otherwise.
  - This keeps `make -C bdd stage` working with 26.9.1 and with
    26.10.2 or later. The staged 26.9.1 YANG declares `feature iso {` at
    `zebra-features.yang:20`, so the probe falls back correctly there.
  - Both scripts run under `set -e` (`vrrp_node.sh:27`, `ipsec_node.sh:20`).
    A failing `grep` on the left of `&&` does not exit the script.
  - Drop the probe once insomnia's minimum supported zebra-rs is 26.10.2 or
    later. Note that in the CHANGELOG entry.
  - Rejected: requiring 26.10.2 now. That breaks the staged toolchain in
    this tree and anyone testing against an installed 26.9.
- **D2. Book chapters name the new spelling and mention the old one once,
  in ch-00-03.** Only an operator with an old unit file needs to know about
  `iso`.
- **D3. `ikev2-reauth`: X5 lands first and owns the text.**
  - The PR that implements X5 in [ipsec-render-fixes](ipsec-render-fixes.md)
    must rewrite `ch-02-01:75-76` and `appendix-a:32` to describe exactly
    what it renders. That includes which peers get `reauth_time`, and the
    peer-level `ikev2-reauth yes|no|inherit`, which ch-02-01 does not mention
    today.
  - Doc text should change in the same commit as the behaviour it describes
    (AGENTS.md: update golden text deliberately).
  - **Fallback:** if X5 has not merged when PR 1 is reviewed, PR 1 lands the
    interim wording in §4.3, and X5 later replaces it.
- **D4. Fix ch-01-10 in place.** Do not leave the wrong spelling for the
  [nat](nat.md) work to change. A reader copying the planned syntax today
  should get VyOS's.
- **D5. The `vrf.o` default.** Document the shared-object requirement now.
  What happens next belongs to [vrrp-vrf](vrrp-vrf.md) and depends on its
  spike: branch B renames the default to `vrf.so` and adds the
  refuse-to-start check (gap §8.4 item 3); branch A removes `--vrf-preload`
  and the shim altogether. Either way the change is behavioural and gets a
  CHANGELOG entry there. The text here says only what is true today, so it
  holds until vrrp-vrf lands and vrrp-vrf rewrites or deletes it.
- **D6. Two PRs.**
  - Operator-facing text and scripts (book, BDD, the `src/vrrp.rs` doc
    comment).
  - The design record (`design/vrrp.md`).
  - Neither changes any rendered output, so no golden test changes.
- **D7. ch-01-02 weekdays: X14 lands first and owns the text.**
  - The example is VyOS syntax and stays correct once
    [fw-matchers](fw-matchers.md) milestone 1 (X14) expands abbreviations, so the fix
    belongs in the renderer, not in the book.
  - **Fallback:** if X14 has not merged when PR 1 is reviewed, PR 1 lands
    the interim wording in §4.8. It loads before X14 (full names pass
    through verbatim) and after it (X14 accepts full names), so X14 may
    restore the abbreviations but does not have to.

## 4. Changes

### zebra-rs

None.

### insomnia, PR 1: book, BDD, module doc

**4.1 Rename** (`iso` → `insomnia`):

- [ ] `book/src/ch-00-03-command-line-options.md:27`: heading →
      `## Before you start: zebra-rs \`--feature insomnia\``. Change `:30`
      "the optional ISO feature set of zebra-rs" → "the optional `insomnia`
      feature of zebra-rs", and `:34` → `$ zebra-rs --feature insomnia`. Add
      after `:38`: "zebra-rs before 26.10.2 calls this feature `iso`. 26.10.2
      and later still accept `--feature iso`, with a deprecation warning at
      startup."
- [ ] `ch-01-00-what-is-firewall.md:11` "optional ISO feature set" →
      "optional `insomnia` feature"; `:14`, `:17` `--feature iso` →
      `--feature insomnia`.
- [ ] `ch-02-00-what-is-ipsec.md:10`, `:14`, `:17`: the same three edits.
- [ ] `ch-05-00-what-is-vrrp.md:14`, `:18`, `:21`: the same.
- [ ] `ch-05-05-sample-configurations.md:9` → `zebra-rs --feature insomnia`.
- [ ] `ch-04-00-bdd-tests.md:97` → `(\`--feature insomnia\`)`, plus "the node
      scripts pick `iso` automatically when the staged zebra-rs predates the
      rename".
- [ ] `bdd/tests/scripts/vrrp_node.sh:3` and `ipsec_node.sh:3`: comment →
      `--feature insomnia`.
- [ ] `vrrp_node.sh:72` and `ipsec_node.sh:88`: replace `--feature iso`
      with the probe:

      ```sh
      # zebra-rs 26.10.2 renamed the feature `iso` to `insomnia`; older
      # releases only know `iso`. Drop this once 26.10.2 is the minimum.
      FEATURE=iso
      grep -q '^ *feature insomnia' "$YANG/zebra-features.yang" && FEATURE=insomnia
      "$ZEBRA" --feature "$FEATURE" --daemon \
      ```

- [ ] `bdd/tests/features/ipsec_s2s.feature:3` and `vrrp_pair.feature:3`:
      title "…, ISO feature)" → "…, insomnia feature)"; `:6` →
      `--feature insomnia`.
- [ ] Regenerate `bdd/docs/ipsec_s2s.md` and `bdd/docs/vrrp_pair.md` with
      `make -C bdd docs`. Do not edit them by hand.

**4.2 Conntrack chapter** (`ch-01-06`):

- [ ] Replace `:61-62` ("Untracked packets show `state invalid` … explicit
      accept for the same traffic.") with:

      > Untracked packets carry the conntrack state `untracked`, not
      > `invalid`. Neither a `state invalid` rule nor
      > `global-options state-policy invalid` sees them, and the `state`
      > matcher has no `untracked` value. They fall through to the filter
      > chain's ordinary rules and its default action, so pair every
      > `notrack` rule with an explicit accept for the same traffic.

- [ ] Replace `:72` "A commit touching them logs a warning." with "Nothing
      is logged: the values are dropped silently when the configuration is
      read."

**4.3 Static NAT** (`ch-01-10`):

- [ ] `:11` → `set nat static rule 10 inbound-interface eth0                (planned)`.
      Keep the column alignment of the `(planned)` marker.
- [ ] After the code block, add: "Unlike source and destination NAT, static
      NAT takes the interface name directly; there is no `name` or `group`
      level under `inbound-interface`."

**4.4 `ikev2-reauth`.** Owned by the X5 PR (D3). Fallback text only:

- [ ] `ch-02-01:75-76` → "- **ikev2-reauth**: accepted but not applied yet.
      insomnia renders no `reauth_time`, so the IKE SA is rekeyed but never
      re-authenticated."
- [ ] `appendix-a:32`: delete "reauthentication (`ikev2-reauth`)" from the
      RFC 7296 row. Under "Accepted but not yet applied" (`:124`), add a
      sentence, "IPsec: `ike-group … ikev2-reauth` and `site-to-site peer …
      ikev2-reauth` (RFC 7296 §2.8.3) are parsed but not rendered yet."

**4.5 Appendix A, the extra finding:**

- [ ] `:126-128` "applying them needs sysctl writes, a different mechanism
      from the nftables ruleset" → "applying them needs sysctl writes
      (`twa-hazards-protection`, `syn-cookies`) or nft `fib` rules
      (`source-validation`, `ipv6-source-validation`: zebra-rs pins
      `rp_filter` to 0, so the sysctl is not an option)."

**4.6 Module doc** (`src/vrrp.rs`, doc comment only):

- [ ] Insert after `:28`:

      ```rust
      //! - the per-group views are `show vrrp statistics group NAME` and
      //!   `show vrrp detail group NAME` (zebra-rs `exec.yang`
      //!   `vrrp-show-views`); VyOS spells them `show vrrp NAME statistics`
      //!   and `show vrrp NAME detail`;
      ```

**4.7 `--vrf-preload`:**

- [ ] `ch-00-03:20` table "Meaning" → "`LD_PRELOAD` shim for VRF keepalived
      instances; must be a shared object (reserved)".
- [ ] `ch-00-03:173-181`, add: "The file must be a shared object (built with
      `-shared`), whatever its name. ld.so ignores a relocatable `.o`, or a
      missing file, with only a `cannot be preloaded … ignored` message on
      stderr, and keepalived would then run in the default VRF. This option
      changes when VRF support lands: its default is renamed, or the option
      is removed."

**4.8 Weekdays** (`ch-01-02`). Owned by X14 (D7). Fallback text only:

- [ ] `:95` → `set firewall ipv4 forward filter rule 50 time weekdays Monday,Tuesday,Wednesday,Thursday,Friday`.
- [ ] After the code block, add: "Spell days in full (`Monday`) or as
      numbers (0–6). Until abbreviations are expanded, a rule
      with `Mon` makes nft reject the whole ruleset."

### insomnia, PR 2: `design/vrrp.md`

- [ ] `:23` heading → "## 1. What VyOS does (re-verified against vyos-1x
      `rolling` @ `7f2c893`, 2026-10-21, by content)". Change `:688`
      "vyos-1x `current`:" to the same wording.
- [ ] `:28` Conf-mode row: append "; before reloading, waits for an IPv6
      `hello-source-address` to leave the `tentative` state (T5533,
      `high-availability.py:218-227`); restarts instead of reloading when
      `vrrp snmp` changes (`:62`)".
- [ ] `:30` Unit-override row: append "`Type=simple`. insomnia's
      `insomnia-keepalived@.service` is `Type=notify` (deviation; Ubuntu's
      keepalived 2.2.8 links libsystemd and calls `sd_notify`; other distro
      builds *unverified*)".
- [ ] `:104` "insomnia's whole ISO surface" → "insomnia's whole configuration
      surface".
- [ ] §4 `:156` `if-feature feat:iso;` → `if-feature feat:insomnia;`.
- [ ] §4 `:175`: append to the `master-refresh` line "0 disables; VyOS
      allows 1-255 (deliberate superset)".
- [ ] §6 `:302` row → "a sync-group member's own `health-check` | ignored
      (the sync-group check wins), with a warning. **Stronger deviation:**
      VyOS rejects the commit (`ConfigError`, smoketest-asserted)".
- [ ] §7 `:328` `--vrf-preload` row: add "must be a shared object (ET_DYN),
      whatever its file name".
- [ ] §8 `:391` "gated on `feat:iso`" → "gated on `feat:insomnia`".
- [ ] §8 `:395-397`: grammar block → `show vrrp statistics [group <NAME>]`
      and `show vrrp detail [group <NAME>]`. Add below it: "Deviation:
      VyOS spells the per-group views `show vrrp <NAME> statistics|detail`.
      zebra-rs puts the keyword first and adds `group`, so a group named
      `detail` or `statistics` cannot be confused with a view. An alias is
      deferred (§14)."
- [ ] §8 `:400-401`: orders are `/show/vrrp`, `/show/vrrp/statistics`,
      `/show/vrrp/detail`, `/show/vrrp/statistics/group` and
      `/show/vrrp/detail/group`, with the group name in `args`
      (`src/vrrp.rs:1078-1082`).
- [ ] §9 `:442` "iso-gated" → "insomnia-gated". `:445` →
      "(`shipped_vrrp_gated_on_insomnia`, using `shipped_tree(&["insomnia"])`)".
      `:447` `feat:iso` → `feat:insomnia`.
- [ ] §10 `:495` `--feature iso` → `--feature insomnia` (the script probes;
      §4.1).
- [ ] §13 `:556-562`, the shim bullet: add "It must be a shared object
      (`cc -shared -fPIC`). ld.so ignores a relocatable `.o` or a missing file
      with only a stderr line, so a bad shim would silently run the instance
      in the default VRF. [vrrp-vrf] decides the fix by its spike: branch B
      renames the default to `vrf.so` and makes insomnia refuse to start a
      non-default instance unless the file exists and is ET_DYN; branch A
      drops the shim and `--vrf-preload`, and rewrites this section." Write
      that link relative from `design/` as `plans/vrrp-vrf.md`.
- [ ] §13 `:588` `if-feature feat:iso;` → `if-feature feat:insomnia;`.
- [ ] §14 (`:660-686`):
  - Split "`vrrp snmp trap`" into "SNMP subagent (`--snmp`, restart on
    change)" and "SNMP traps (`enable_traps`)".
  - Add bullets for `restart vrrp` (needs the exec verbs), `show log vrrp`,
    script existence checks, the T5533 tentative wait, the mDNS-repeater
    hook, password masking (link `plans/secret-redaction.md`),
    `ext:dynamic` interface completion, the show word-order alias, and BDD
    breadth (IPv6, unicast, auth, health-check FAULT, track, sync-group,
    scripts, no-preempt).

## 5. Tests

- **No golden or unit test changes.** The only Rust edit is a `//!` doc
  comment. `cargo fmt --all -- --check` and
  `cargo clippy --workspace --all-targets -- -D warnings` must stay clean.
- **BDD, PR 1:**
  - `make -C bdd ipsec_s2s` and `make -C bdd vrrp_pair` against the staged
    26.9.1, where the probe picks `iso`.
  - The same against a 26.10.2+ prefix
    (`make -C bdd stage ZEBRA_PREFIX=…`), where the probe picks `insomnia`.
    `bdd/logs/<tag>_<node>.log` must not contain `deprecated`. Check that by
    hand, or with the `the zebra-rs log … should contain` step inverted if a
    negative variant is added.
  - `make -C bdd docs` succeeds with no orphans.
- **Book:** `mdbook build` in `book/` succeeds.
- **Final grep**, which must print nothing:
  `grep -rnw -e 'feature iso' -e 'feat:iso' -e 'ISO feature' book/src bdd/tests bdd/docs design/vrrp.md src`.

## 6. Docs

This plan is documentation. Not touched here:
- `design/vyos-gap.md`. Its §3 and §8.4 stay as the record of what was wrong.
- `book/src/ch-02-03-authentication.md:56-58`, which is still true until
  [secret-redaction](secret-redaction.md) lands.
- The mode-`0600` claims (X13) and show routing (X15); see §2.

A CHANGELOG entry is optional for PR 2. PR 1 adds one line under the next
release: "docs: `--feature insomnia`; BDD scripts probe the feature name".

## 7. Milestones

| # | Scope | Repo | Effort | Done when |
|:--|:--|:--|:--|:--|
| 1 | §4.1–§4.8: book, BDD scripts and features, the regenerated BDD docs, the `src/vrrp.rs` doc comment, the `ikev2-reauth` fallback text only if X5 has not merged, and the weekday fallback only if X14 has not merged | insomnia | S (≤ 1 day) | §5 BDD runs green on both toolchains; final grep empty |
| 2 | §4 PR 2: every `design/vrrp.md` item | insomnia | S (≤ 1 day) | each checkbox done; the cited VyOS lines re-checked at review |

## 8. Risks and open questions

- **The probe pattern.** It assumes `feature insomnia` keeps its own line
  in `zebra-features.yang` (`:21`). If the YANG is reformatted, the probe
  falls back to `iso`. That works for as long as zebra-rs keeps the alias,
  and the deprecation warning in the log makes the fallback visible.
- **The X5 ordering.** If X5 lands after PR 1 with the fallback text, the X5
  PR must remove the fallback. Say so in its description.
- **The X14 ordering.** The same as X5: if X14 lands after PR 1 with the
  fallback text, the X14 PR decides whether to restore `Mon,Tue,…` and
  says so in its description.
- **How long the `iso` alias lives** is a zebra-rs decision and is not
  recorded anywhere. Ask zebra-rs to note the removal release in its
  CHANGELOG.

## 9. Acceptance criteria

- [ ] The final grep in §5 prints nothing.
- [ ] Both BDD features are green against zebra-rs 26.9.1 and 26.10.2 or
      later.
- [ ] ch-01-06, ch-01-10 and appendix A match the code facts in §2.
- [ ] `ikev2-reauth` text is either rewritten by the X5 PR or carries the
      interim "not applied" wording.
- [ ] ch-01-02's weekday example loads: X14 has merged, or the §4.8
      full-name text is in.
- [ ] `src/vrrp.rs` module doc lists the show word-order deviation.
- [ ] `design/vrrp.md` carries all seven gap §8.4 corrections; the shim
      requirement is documented and linked to [vrrp-vrf](vrrp-vrf.md).
