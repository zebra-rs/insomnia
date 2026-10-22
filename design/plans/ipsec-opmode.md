# IPsec op-mode — implementation plan

Status: plan, 2026-10-21. Covers: §7.4 rows 1, 2 and 4 — `reset vpn ipsec site-to-site …`,
`show vpn ipsec sa detail`, `show vpn ike sa …`, `show vpn debug …`, `restart ipsec`,
`show vpn ike status|secrets`, `show vpn ipsec status`, `generate ipsec debug-archive`,
`show log ipsec` ([vyos-gap](../vyos-gap.md) §7.4, §7.1, §4.2).
Priority: P2 (reset, `sa detail`, `ike sa`, `debug`), P3 (the rest) · Effort: M · Owner: both
Depends on: [exec-verbs](exec-verbs.md) (verb path, VICI request encoder, retained model),
[charon-lifecycle](charon-lifecycle.md) (`restart ipsec`, log source, daemon status),
[secret-redaction](secret-redaction.md) (policy for `show vpn ike secrets`) · Unblocks:
[ipsec-remote-access](ipsec-remote-access.md) (RA views and resets reuse the helpers here),
[ipsec-dmvpn-l2tp](ipsec-dmvpn-l2tp.md) (`reset vpn ipsec profile`)

Assumes D2 (non-show verbs ride an exec order kind on `zebra.show.v1`).

## 1. Goal

- `reset vpn ipsec site-to-site all | peer <p> [tunnel <n> | vti]` tears the SAs down over
  VICI and re-initiates exactly the children the rendered config would start itself.
- `show vpn ike sa [nat-traversal | peer <p>]`, `show vpn ipsec sa detail`,
  `show vpn debug [peer <p> [tunnel <n>]]`, `show vpn ike status`, `show vpn ike secrets`
  and `show vpn ipsec status` answer from insomnia, with VyOS's layout where VyOS has one.
- `restart ipsec` restarts charon and reloads the last rendered `swanctl.conf`.
- `generate ipsec debug-archive` writes a tarball on the IPsec host and names it.
- `show log ipsec` returns charon's recent log.
- Every order is answered exactly once; charon down gives `% IPsec process not running`,
  never a hang.

## 2. Current state

**zebra-rs @ 141da2fc**
- Grammar: `exec.yang:409-432` has only `show vpn ipsec sa|connections|policy|state`. The exec
  tree's top-level nodes are `show` (`exec.yang:131`) and `cli` (`:1568`). There is no
  `reset`, `restart`, `generate` or `show log`. `clear` lives in configure mode
  (`configure.yang:117`) and is fanned out in-process with no reply
  (`manager.rs:1500-1505`, `1532-1536`).
- Routing: `is_vpn` matches any path element named `vpn` (`manager.rs:2023-2028`) and maps
  to the `"ipsec"` provider key (`manager.rs:2089`). So `show vpn ike …` and
  `show vpn debug …` already reach the ipsec provider once the grammar exists.
  `show log ipsec` would not, because no predicate matches `ipsec` alone.

**insomnia @ ee4dfaa**
- `provider.rs:91-99` routes only the `/show/vpn/ipsec` prefix to the IPsec task. Anything
  else under `/show/vpn` gets `% Unknown show command`.
- `ipsec.rs:1046-1055` dispatches the four existing views. `show_sa` and `show_connections`
  use `vici::streamed_request` (`vici.rs:217-257`). That function sends an empty request
  body (`named_packet`, `vici.rs:188-192`); the encoders exist only under `cfg(test)`
  (`vici.rs:259-293`).
- `process()` renders and drops the model (`ipsec.rs:90-116`). The VRRP task already keeps
  one (`vrrp.rs:58-60`, `108`), which is the precedent.
- Conn names are the `@`-stripped peer name with `.`/`:` dashed (`conn_name`,
  `ipsec.rs:431-433`). Children are `<conn>-tunnel-<n>` (`ipsec.rs:945`) and `<conn>-vti`
  (`ipsec.rs:874`). Passthrough children are `<conn>-tunnel-<n>-passthrough` with
  `mode = pass` (`ipsec.rs:1026-1031`).
- `start_action` is `start` for an unset or `initiate` connection-type, `trap` for
  `respond`, and `none` for `@` peers (`ipsec.rs:807-817`).

**VyOS @ 7f2c893**
- Grammar: `op-mode-definitions/vpn-ipsec.xml.in`: reset 64-102, restart 109-118,
  `show vpn debug` 126-150, `show vpn ike` 151-189, `sa detail` 269-276, `ipsec status`
  284-289. Also `generate-ipsec-debug-archive.xml.in` and `show-log.xml.in:913-918`.
- Reset (`src/op_mode/ipsec.py`):
  - `_get_tunnel_sw_format` (566-582) maps tunnel names.
  - `_terminate_peer` (623-655) runs VICI `terminate {ike, child}`.
  - `reset_peer` (658-675) re-initiates **only when `connection-type` is literally
    `initiate`**.
  - `_initiate_peer_with_childsas` (585-620) initiates every child that `list-conns`
    reports, passthrough children included.
  - `reset_all_peers` (677-689) loops over the peers.
  - The VICI helpers are in `python/vyos/ipsec.py:142-206`.
- Views:
  - `show_sa_detail` (`ipsec.py:51-65`, `802-806`) shells `swanctl -l --ike-id N` once per
    SA.
  - `vpn_ike_sa.py` formats `list-sas`. Its `peer` filter compares the argument with
    `remote-host`, not with the peer name.
  - `src/op_mode/vpn_ipsec.py:38-70` builds `show vpn debug` from `ipsec statusall` (the stroke
    starter, absent on swanctl-only hosts) and `swanctl -L/-l/-P`, plus `ip` commands.
  - `show_psk` (`ipsec.py:1043-1053`) prints PSKs in clear.
  - `restart.py:52-55` maps the command to `systemctl restart strongswan`.
  - `generate_ipsec_debug_archive.py` writes `/tmp/ipsec_debug_<iso>.tar.bz2`.
  - `ike status` is `systemctl status strongswan`. `ipsec status` is `/usr/sbin/ipsec status`,
    which Ubuntu 24.04's `charon-systemd` does not ship (verified on this host:
    strongSwan 5.9.13, no `ipsec` binary).

## 3. Design

**Consumed from other plans.** These are the owners' proposed names, as of their plans
dated 2026-10-21. The Ref labels are local to this plan; the Owner column names the
owner's milestone that delivers each one:

| Ref | Need | Owner |
|:--|:--|:--|
| E1 | Wire: `show.proto` `Register.exec` (insomnia lists `"ipsec"` in `EXEC_TREES`), `ShowOrder.kind = EXEC`, `ShowOrder.user`, and `ShowChunk.error` on the eof chunk. insomnia side: `ShowRequest { kind: OrderKind::Exec, user, resp: oneshot::Sender<Answer> }`, with `Answer { text, error }` answered exactly once. Paths: `/reset/vpn/ipsec/…`, `/restart/ipsec`, `/generate/ipsec/…`. Audit logging of every exec order is exec-verbs' D-9; the handlers here do not repeat it | [exec-verbs](exec-verbs.md) E4 + E5 |
| E2 | Top-level `reset` / `restart` / `generate` in `exec.yang` (D-6), `EXEC_ROUTES` in `manager.rs` (D-5), and the shared, empty `show log` container (D-6). This plan adds only the grammar below them, the `reset vpn ipsec`, `restart ipsec` and `generate ipsec` route rows, and the `ipsec` child of `show log` | [exec-verbs](exec-verbs.md) E3 + E4 |
| E3 | `vici::Builder`, `vici::exchange` / `vici::request`, `vici::terminate(&Terminate)` → `Terminated { matches, terminated }`, `vici::initiate(&Initiate)`, `vici::stats`. Every call is bounded by `VICI_TIMEOUT` (10 s). `subscribe`/`EventStream` is not needed here | [exec-verbs](exec-verbs.md) E1 |
| E4 | `ShowState { model: Option<Arc<IpsecConfig>> }` in `ipsec.rs`; `conn_name` made `pub(crate)`. The rendered text is not retained: the handlers read `--swanctl-dir/swanctl.conf`, which `swanctl_apply` writes before every load (`ipsec.rs:122-129`) | [exec-verbs](exec-verbs.md) E2 |
| E5 | The existing BDD step `I run {string} in namespace {string}` (`bdd/tests/cucumber.rs:946-956`, via `vtyctl clear`) | [exec-verbs](exec-verbs.md) §5 (existing step) |
| C1 | The restart primitive in `src/charon.rs`. This verb calls `restart(ch, RestartMode::Always)`: systemd `systemctl restart <--charon-unit>`, which also starts a stopped charon, as VyOS's does; signal mode SIGTERM and a wait for the respawn; then `wait_vici`. Config-driven restarts keep `IfRunning` (`try-restart`) | [charon-lifecycle](charon-lifecycle.md) M3 |
| C2 | Log source. Systemd: `--charon-unit`. A charon with a file log, as in signal mode and the BDD (`ipsec_node.sh`), has no flag in charon-lifecycle, so **this plan adds `--charon-log-file PATH`** (default unset, meaning the journal) | this plan + [charon-lifecycle](charon-lifecycle.md) |
| C3 | `charon::Control` (systemd / signal), `--charon-unit`, and `CharonState.applied` (the effective drop-in) | [charon-lifecycle](charon-lifecycle.md) M3 |
| S1 | Whether op-mode output may print configured secrets or key material. Answered by its S11: never, because a `ShowOrder` carries no caller identity (S10); `generate pki` is the one exception | [secret-redaction](secret-redaction.md) S11 |

**Decisions.**

1. **Spelling is VyOS verbatim.** The only additions are the `-j` JSON forms of the
   read-only views.

2. **Name mapping lives in one function.** `fn sa_names(peer, tunnel) -> (ike, Option<child>)`
   reuses `conn_name`. `tunnel N` maps to `<conn>-tunnel-N`; `vti` maps to `<conn>-vti`.
   The peer argument is the configured name (`192.0.2.9`, `@branch`), not the swanctl
   name.

3. **The reset re-initiate rule follows the rendered `start_action`.** Re-initiate when
   `start_action(peer)` is `start`, which covers an unset or `initiate` connection-type.
   This refines the example in exec-verbs' goal ("re-initiate only `connection-type
   initiate` peers").
   - **DEVIATION:** VyOS re-initiates only for a literal `initiate`. For an unset
     connection-type it therefore leaves down a tunnel its own template starts at load
     time.
   - `trap`/`respond`, `none` and `@` peers are terminated only.

4. **Passthrough children are never initiated.** A `list-conns` child with `mode = PASS`
   is skipped. VyOS initiates them too (`ipsec.py:603-606`); what charon does with an
   initiate on a pass child is *unverified*. Its shunt policy is already installed at load
   (`start_action = trap`, `ipsec.rs:1029`).

5. **Every reset wait is bounded.**
   - `terminate` and `initiate` carry `timeout_ms = 8000` (`RESET_TIMEOUT`). That is
     below exec-verbs' 10 s `VICI_TIMEOUT` socket bound, so charon's own timeout answer
     arrives before the socket gives up.
   - VyOS terminates by name with no timeout, which blocks for the DELETE retransmits
     against a dead peer (about 165 s by default). exec-verbs' worked example uses `-1`
     (return at once); this plan waits instead, so "success" means something.
   - VICI semantics: 0 waits forever and -1 returns at once (strongSwan vici README;
     *unverified* on 5.9.13; the BDD confirms).
   - A timeout is reported as `WARNING: … timed out after 8s; continuing`.
   - Per exec-verbs (D-8), handlers run in a task spawned with the `Arc` model.
   - Subprocesses are bounded too. exec-verbs bounds VICI only, so the `Runner` here wraps
     each child (`swanctl`, `ip`, `journalctl`, `systemctl`, `tar`) in
     `tokio::time::timeout` with `kill_on_drop(true)`. The limit is `RUN_TIMEOUT` (10 s),
     or 30 s for `tar`. A timed-out command contributes
     `% <cmd> timed out after 10s` to the output and never holds the answer.
   - Net effect: every external call made by this plan is time-bounded (exec-verbs D-8).
   - `reset … all` resets the peers concurrently (`join_all`), so it finishes in at most
     about 16 s.
   - Failures set `Answer.error = true`.
   - zebra-rs must not time out an exec order sooner than that. exec-verbs §8 records that
     the bridge has no per-order timeout today, and that any ceiling added later is at
     least 60 s, above every bound here (30 s for `tar`, about 16 s for `reset … all`).

6. **Unknown targets are errors.**
   - `% Peer X is not configured` and `% Peer X tunnel N is not configured` (or not
     enabled).
   - DEVIATION: for an unknown peer VyOS prints a warning that there is nothing to
     terminate, and exits 0.

7. **`sa detail` shells out to swanctl, like VyOS.**
   - One call: `swanctl --list-sas`. `--uri unix://<vici_socket>` is added only when
     `--vici-socket` is not the default. VyOS runs one `swanctl -l --ike-id N` per SA;
     the text is the same apart from separators. DEVIATION.
   - stdout only. swanctl prints plugin-load noise on stderr (observed on 5.9.13).
   - If swanctl is missing or fails (AppArmor confines it to `/run/charon.vici`), fall back
     to an indented dump of the `list-sas` VICI tree.
   - `-j` returns the raw `list-sas` messages, the same as `sa -j`. That is VyOS's `raw`.

8. **`ike sa` is formatted natively from `list-sas`.**
   - The `vpn_ike_sa.py` format strings are used verbatim and each line is right-trimmed.
     DEVIATION: cosmetic.
   - The `nat-traversal` filter keeps SAs that have `nat-local` (VICI adds the key only
     when it is true).
   - `peer <p>` matches either `remote-host == p` (VyOS) or the IKE_SA name
     `== conn_name(p)`. DEVIATION: a superset, because insomnia peers are often named, not
     addressed.

9. **`debug` is a bundle of commands, with substitutions for the starter.**
   - Each command runs from an argv array, with no shell. `ip route | head -100` becomes
     `ip route` truncated to 100 lines in Rust.
   - `ipsec statusall` becomes `swanctl --stats` plus `swanctl --list-conns`.
   - `debug peer <p> [tunnel <n>]` prints:
     - `swanctl --list-sas --ike <conn> [--child <child>]`;
     - the `<conn> { … }` block cut from `--swanctl-dir/swanctl.conf` (E4). Connection
       blocks carry no secrets; secrets live only in the `secrets {}` section.
   - xfrm state output is key-redacted (S1; §8). DEVIATION: VyOS prints the keys.
   - VyOS greps `ipsec statusall`. DEVIATION.

10. **`ike secrets` reads the retained model, not charon.**
    - Columns are VyOS's `PSK / Id / Secret`. Multiple ids join with `,`, the same
      deviation as `ipsec.rs:1042-1043`.
    - Unconfigured: `VPN ipsec psk authentication is not configured`.
    - Per S1 (secret-redaction S11) the Secret cell is `********` and `-j` omits `secret`.
      DEVIATION: VyOS prints PSKs in clear. `psk_table(model, reveal)` keeps the flag, false
      on every path, until a show order carries a privileged caller.
    - A secret that reached insomnia as a `<redacted:…>` tag (secret-redaction's
      unprivileged-subscription case, detected with `json::redacted`) is printed as the
      tag. It is never treated as a value.

11. **`ike status` and `ipsec status`.**
    - `ike status`:
      - VICI `version` and `stats`, formatted as `key: value` lines (daemon, version,
        uptime, workers, queues, IKE_SA counts, loaded plugins).
      - Then the effective insomnia drop-in (C3 `CharonState.applied` via `to_text`).
        charon-lifecycle leaves this view to this plan.
      - When C3 says systemd, VyOS's `systemctl status <unit> --no-pager` comes first.
      - This works in signal mode (BDD), where there is no unit.
    - `ipsec status`:
      - The starter is absent, so this emulates the terse stroke listing from
        `list-sas`. The format is fixed in §4.
      - DEVIATION: the age prints as `seconds_to_human` instead of "2 minutes ago".

12. **`restart ipsec` restarts and then reloads.**
    - With no retained model the answer is `Service ipsec is not configured!` (VyOS
      `restart.py` `_verify`).
    - Otherwise call C1 (`RestartMode::Always`), wait at most 10 s for the VICI socket, then
      run `swanctl -q` with `SWANCTL_DIR=--swanctl-dir`. That covers a non-default
      `--swanctl-dir`, which the unit's `ExecStartPost=swanctl --load-all` (the Ubuntu
      `strongswan.service`) does not read.
    - **Concurrency.** The handler is a spawned task (exec-verbs), so a commit can apply
      during the restart. This is safe because the apply path writes the file before it
      runs `swanctl -q` (`ipsec.rs:126-129`):
      - an apply whose load fails while charon is down is covered by the restart's reload;
      - an apply after the reload loads normally.

      The last file on disk always ends up loaded. That replaces VyOS's commit-lock check.

13. **`generate ipsec debug-archive`.**
    - Contents, as in VyOS:
      - `ipsec_status.txt`: the `debug` bundle, each command framed by `### cmd ###`,
        `Exit code`, `Stdout`;
      - `journalctl_charon.txt`: from C2.
    - Path: `/tmp/ipsec_debug_<iso8601-seconds>.tar.bz2`, written with
      `tar -cjf <archive> -C <tmpdir> .`, or `.tar.gz` with `-czf` when `bzip2` is absent.
    - Mode `0600`. Its `ip xfrm state` output is key-redacted like `debug` (S1). DEVIATION:
      VyOS's archive keeps the keys.
    - The archive lands on insomnia's host, which is charon's host, even when `--host` is
      `tcp:`. The reply names the path.

14. **`show log ipsec`.**
    - Systemd: `journalctl --no-hostname --boot --unit <unit> --lines 1000`.
    - File log (`--charon-log-file`, C2): the last 1000 lines of that file.
    - DEVIATION: capped at 1000 lines, because the answer is one gRPC message. VyOS pages
      the whole boot's log.
    - `monitor log ipsec` (streaming) is out of scope: it does not fit the oneshot contract.

**Rejected alternatives.**
- A native `swanctl -l` re-implementation for `sa detail`: about 150 lines for byte-parity
  that swanctl already gives.
- Re-initiating on literal `initiate` only (VyOS): rejected by decision 3.
- Fire-and-forget (`timeout = -1`) resets: the operator would get "success" before
  anything happened.

**Module-doc deviations to add** (`ipsec.rs` show-section header, `ipsec.rs:1035-1044`):
decisions 3, 6, 7, 8, 9, 10, 11, 13 and 14.

## 4. Changes

### zebra-rs

`exec.yang`, under `show > vpn` (`exec.yang:409`), all insomnia-gated:

```yang
container debug {
  ext:help "Show VPN debugging information";
  presence "Debug bundle for all peers";
  list peer {
    ext:help "Show debugging information for a peer";
    ext:presence "Debug bundle for one peer";
    key "name";
    leaf name { type string; }
    list tunnel {
      ext:help "Show debug information for peer tunnel";
      ext:presence "Debug bundle for one tunnel";
      key "number";
      leaf number { type uint32; }
    }
  }
}
container ike {
  ext:help "Show Internet Key Exchange (IKE) information";
  container sa {
    ext:help "Show all currently active IKE Security Associations (SA)";
    presence "All IKE SAs";
    container nat-traversal { ext:help "…using NAT Traversal"; presence "NAT-T IKE SAs"; }
    list peer { ext:help "…for a peer"; ext:presence "IKE SAs of one peer";
                key "peer"; leaf peer { type string; } }
  }
  container secrets { ext:help "Show all the pre-shared key secrets"; presence "PSK table"; }
  container status  { ext:help "Show summary of IKE process information"; presence "charon status"; }
}
// inside the existing `container ipsec`:
//   container sa { …existing…  container detail { ext:help "…verbose…"; presence "swanctl -l"; } }
//   container status { ext:help "Show status of IPsec process"; presence "SA summary"; }
```

- **Nesting.** Whether a presence list nested in a presence list
  (`debug peer X tunnel N`) parses with today's exec parser is *unverified*. The fallback
  is a flat `list tunnel` beside `peer`, with the peer passed in args.
- **`show log ipsec`.**
  - Adds `leaf ipsec { ext:help "Show log for IPsec"; type empty; }` to the shared
    `show log` container, which [exec-verbs](exec-verbs.md) D-6 owns.
  - [fw-opmode](fw-opmode.md) (`firewall`) and [vrrp-hardening](vrrp-hardening.md)
    (`vrrp`) are siblings.
  - It is a SHOW order, not an EXEC order.
- **Routing.**
  - The show views under `vpn` need nothing: `is_vpn` already sends them to `"ipsec"`.
  - `show log ipsec` needs an exact predicate, `is_log_ipsec` (segments `show log ipsec`),
    placed in `SHOW_PROTOS` (`manager.rs:2078-2092`) ahead of the any-segment tests, as
    exec-verbs D-6 prescribes for every `show log` child. A widened any-segment test is
    avoided because those already misroute (exec-verbs D-5, `is_policy`).
  - Verbs: add the `EXEC_ROUTES` rows `reset vpn ipsec`, `restart ipsec` and
    `generate ipsec` → `ipsec` (E2).

Under exec-verbs' top-level containers (E2), insomnia-gated:

```yang
// reset
container vpn { ext:help "Reset Virtual Private Network (VPN) information";
  container ipsec { ext:help "Reset IPSec VPN sessions";
    container site-to-site { ext:help "Reset site-to-site IPSec VPN connections";
      container all { ext:help "Reset all site-to-site IPSec VPN sessions"; presence "all peers"; }
      list peer { ext:help "Reset all tunnels for given peer"; ext:presence "one peer";
        key "name"; leaf name { type string; }
        list tunnel { ext:help "Reset a specific tunnel for given peer"; ext:presence "one tunnel";
                      key "number"; leaf number { type uint32; } }
        container vti { ext:help "Reset the VTI tunnel for given peer"; presence "vti child"; } } } } }
// restart (exec-verbs' skeleton spells it as a leaf)
leaf ipsec { ext:help "Restart the IPsec VPN process"; type empty; }
// generate
container ipsec { container debug-archive { ext:help "Generate IPSec debug-archive"; presence "archive"; } }
```

- **Tests.** A grammar test in the style of the VRRP one (`manager.rs:8058`):
  `ipsec_opmode_grammar_parses_with_insomnia`. Every command above parses with
  `shipped_tree(&["insomnia"])` and none parses on a stock start.
- **Completion.** Peer names cannot be completed: `ext:dynamic` handlers reach in-process
  tasks only (`manager.rs:1554-1588`). See §8.

### insomnia

- **`provider.rs`:** the routes table from exec-verbs replaces the if-chain at `:91-99`.
  Change the row `(Show, "/show/vpn/ipsec", Ipsec)` to `(Show, "/show/vpn", Ipsec)`, and
  add:
  - `(Show, "/show/log/ipsec", Ipsec)`;
  - `(Exec, "/reset/vpn/ipsec", Ipsec)`, `(Exec, "/restart/ipsec", Ipsec)`,
    `(Exec, "/generate/ipsec", Ipsec)`;
  - `"ipsec"` in `EXEC_TREES`.
- **New `src/ipsec_op.rs`** keeps `ipsec.rs` focused on rendering. It holds:
  - `trait ViciOps` (`list_sas(filter)`, `list_conns(filter)`, `terminate(req)`,
    `initiate(req)`, `version()`, `stats()`), implemented over E3 and faked in tests;
  - `trait Runner` (`run(argv, limit: Duration) -> (code, stdout)`). The real one applies
    `tokio::time::timeout` + `kill_on_drop` (decision 5); faked in tests;
  - `async fn reset_s2s(v: &impl ViciOps, model: &IpsecConfig, target: ResetTarget) -> String`,
    where `ResetTarget = All | Peer { name, child: Option<ChildSel> }` and
    `ChildSel = Tunnel(u32) | Vti`;
  - `fn ike_sa_text(sas: &[vici::Value], filter: IkeFilter) -> String`;
  - `fn ipsec_status_text(sas) -> String`;
  - `fn ike_status_text(version, stats, unit_status: Option<String>) -> String`;
  - `fn psk_table(model, reveal: bool) -> String` / `psk_json`;
  - `async fn debug_bundle(r: &impl Runner, v: &impl ViciOps, sel: DebugSel, rendered: &str) -> String`,
    where `rendered` is the on-disk `swanctl.conf`;
  - `async fn debug_archive(r: &impl Runner, …) -> String`;
  - `async fn log_ipsec(src: LogSource) -> String`.
- **`ipsec.rs` `process_show`** (`1046-1055`) gains the new paths. Exec orders
  (`kind == Exec`) go to `ipsec_op::exec(req, Arc<IpsecConfig>)`. That function runs in a
  spawned task (exec-verbs), so the `select!` at `ipsec.rs:67-83` never waits on charon.

**Worked example: reset.** BDD z1 config, peer `192.0.2.9`, `connection-type initiate`,
tunnel 1, one SA up.

`reset vpn ipsec site-to-site peer 192.0.2.9` sends:

```
terminate { ike = 192-0-2-9  timeout = 8000 }                        → success = yes, matches = 1
list-conns { ike = 192-0-2-9 }  → children 192-0-2-9-tunnel-1 (mode TUNNEL)
initiate  { ike = 192-0-2-9  child = 192-0-2-9-tunnel-1  timeout = 8000 }  → success = yes
```

Reply:

```
Peer 192.0.2.9 terminate result: success
Peer 192.0.2.9 initiate result: success
```

- `… peer 192.0.2.9 tunnel 1` sends `child = 192-0-2-9-tunnel-1` on both calls and
  replies `Peer 192.0.2.9 tunnel 1 terminate result: success` /
  `… initiate result: success`.
- On z2 (`respond`): terminate only.
- `-j`:
  `{"peer":"192.0.2.9","terminated":true,"initiated":["192-0-2-9-tunnel-1"],"warnings":[]}`.
- `reset … all` prints each peer's lines, then `Peers reset result: success`. With no
  peers: `VPN IPSec site-to-site is not configured, aborting`.

**Worked example: `show vpn ike sa`** (z1, ECP_256 AEAD). The text is VyOS's, right-trimmed:

```
Peer ID / IP                            Local ID / IP
------------                            -------------
192.0.2.9 192.0.2.9                     192.0.2.1 192.0.2.1


    State  IKEVer  Encrypt      Hash          D-H Group      NAT-T  A-Time  L-Time
    -----  ------  -------      ----          ---------      -----  ------  ------
    up     IKEv2   AES_GCM_16_256 n/a           ECP_256        no     125     7075

```

`-j` returns the filtered raw `list-sas` messages.

**Worked example: `show vpn ipsec status`** (format owned by this plan):

```
Security Associations (1 up, 0 connecting):
192-0-2-9[1]: ESTABLISHED 2m5s ago, 192.0.2.1[192.0.2.1]...192.0.2.9[192.0.2.9]
192-0-2-9-tunnel-1{1}: INSTALLED, TUNNEL, reqid 1, ESP SPIs: c3a1b2c4_i c9d8e7f6_o
192-0-2-9-tunnel-1{1}:   10.0.1.0/24 === 10.0.2.0/24
```

The fields come from `list-sas`: `uniqueid`, `state`, `established`, `local-host`,
`local-id`, `remote-host`, `remote-id`; and per child `uniqueid`, `state`, `mode`,
`reqid`, `protocol`, `spi-in`, `spi-out`, `local-ts`, `remote-ts`.

**Worked example: `show vpn ike secrets`:**

```
PSK  Id                   Secret
---  -------------------  --------
GW   192.0.2.1,192.0.2.9  ********
```

## 5. Tests

**Unit tests** (in `ipsec_op.rs`; the fake `ViciOps`/`Runner` answers are built with
exec-verbs' `vici::Builder` and `parse_message`):
- `reset_peer_initiate_reinitiates_all_non_pass_children`: a passthrough child exists and
  is skipped.
- `reset_unset_connection_type_reinitiates`: deviation 3 is pinned.
- `reset_respond_and_at_peer_terminate_only`.
- `reset_tunnel_and_vti_child_names`, plus `reset_at_peer_maps_conn_name` (`@branch` →
  `branch`).
- `reset_unknown_peer_or_tunnel_errors`; `reset_disabled_tunnel_errors`.
- `reset_terminate_timeout_warns_and_continues`: the fake returns
  `success = no, errmsg = "timeout"`.
- `reset_all_concurrent_and_summary_line`; `reset_all_unconfigured`.
- `ike_sa_text_golden`, `ike_sa_nat_filter`, `ike_sa_peer_filter_by_host_or_name`.
- `ipsec_status_text_golden`, `ike_status_text_golden` (with and without unit status).
- `psk_table_reveal_and_masked`.
- `debug_bundle_command_list`: the argv list is asserted, including the 100-line
  truncation and the conn block cut from rendered text.
- `debug_archive_layout`: a fake runner, a temp dir, mode `0600`.
- `charon_down_answers_not_running`: every view and every reset; exec answers carry
  `error = true`.
- `runner_timeout_bounds_answer`: a fake child that never exits; the answer arrives after
  `RUN_TIMEOUT` with the timeout line.
- `provider_routes_show_vpn_and_log_ipsec` (`provider.rs`).

**BDD.** Extend `ipsec_s2s.feature`; same topology, no new namespaces. New scenarios after
"Traffic flows…":
- *Operational views:*
  - `show vpn ike sa` on z1 eventually contains `IKEv2` and `192.0.2.9`;
  - `show vpn ipsec sa detail` contains `ESTABLISHED`;
  - `show vpn debug` contains `### ip x sa show ###`;
  - `show vpn ike secrets` contains `GW`;
  - `show vpn ipsec status` contains `1 up`.
- *Reset on the responder only terminates:* `I run "reset vpn ipsec site-to-site peer 192.0.2.1" in namespace "z2"`
  (E5). Then `show vpn ipsec sa` on z1 eventually does not contain
  `192-0-2-9-tunnel-1`. z1 has DPD `restart`, but a DELETE is not a DPD failure, and
  `close_action` is `none`.
- *Verbs are refused on the show path:* `show command "reset vpn ipsec site-to-site all"`
  in z1 does not succeed (exec-verbs' requirement on its first consumer).
- *Reset on the initiator re-establishes:* `reset vpn ipsec site-to-site peer 192.0.2.9 tunnel 1`
  on z1. Then `show vpn ipsec sa` eventually contains `192-0-2-9-tunnel-1`, and the ping
  succeeds again.
- *Restart ipsec:* `restart ipsec` on z1, then `show vpn ipsec sa` eventually contains the
  tunnel. This needs charon-lifecycle's signal mode; tag it `@needs_charon_lifecycle` until
  that lands.
- The teardown scenario is unchanged.

`show log ipsec` gets a BDD check once `ipsec_node.sh` passes
`--charon-log-file /run/charon.$NS.log`, the bind-mounted file log (C2). `debug-archive`
gets unit tests only.

## 6. Docs

- `book/src/ch-03-01-show-ipsec.md`:
  - add sections for every new view, with the examples from §4;
  - a "Resetting tunnels" section (the re-initiate rule and the bounded waits);
  - extend the troubleshooting ladder (`:75-78`) with `show vpn ike sa` and
    `show vpn debug`.
- `book/src/ch-02-02-site-to-site.md`: add a line on `reset vpn ipsec site-to-site` under
  the connection-type description (`:72-73`).
- `ipsec.rs` module doc: the deviations listed in §3.
- zebra-rs `docs/design/vpn-ipsec-followups.md`: drop the "show completeness" item.

## 7. Milestones

| # | Scope | Repo | Effort | Done when |
|:--|:--|:--|:--|:--|
| 1 | Read-only show views that need neither the verb path nor the encoder beyond today's: `sa detail`, `ike sa [nat-traversal\|peer]`, `ipsec status`, `debug`; grammar, and widening the provider route to `/show/vpn` | zebra-rs + insomnia | S | Unit tests and the BDD view scenario are green. Only `list-sas`/`list-conns` with no filter are used, filtered client-side |
| 2 | `show vpn ike secrets` and `ike status` (needs E3 `version`/`stats` and E4) | insomnia (+ grammar) | S | Unit tests green; S1 honoured |
| 3 | `reset vpn ipsec site-to-site …` with its `EXEC_ROUTES` rows (needs E1–E5) | both | M | Reset unit tests, both reset BDD scenarios and the show-path refusal green |
| 4 | `restart ipsec`, `show log ipsec` (`is_log_ipsec`, `--charon-log-file`), `generate ipsec debug-archive` (needs C1–C3) | both | S | Unit tests green; the restart BDD scenario untagged |
| 5 | Book chapters and module-doc deviations | insomnia | S | `mdbook build` is clean |

## 8. Risks and open questions

- **Key material in kernel output.** Per S1 (secret-redaction S11), `ip xfrm state` output
  in `debug` and in the archive never carries ESP/AH keys: `ip xfrm state list nokeys`
  where iproute2 supports it (*unverified* on 6.1), and in any case the key of every
  `auth`, `auth-trunc`, `enc`, `aead` and `comp` line is replaced with `<redacted>` before
  output. S11 applies the same rule to today's `show vpn ipsec state`
  (`ipsec.rs:1094-1115`).
- **Order timeouts.** zebra-rs's exec-order timeout, if any, must exceed `RESET_TIMEOUT`×2.
  *Unverified*.
- **VICI timeout semantics** (`0` / `-1`) on 5.9.13 are *unverified*. The BDD reset
  scenarios confirm them.
- **Peer-name completion.** VyOS completes from `vpn ipsec site-to-site peer`. zebra-rs
  has no config-path completion, and providers cannot answer completions. Leave it
  uncompleted unless exec-verbs adds a completion RPC.
- **Exec parser.** Nested presence lists in exec grammar are *unverified* (§4 fallback).
- **swanctl and a custom socket.** With a non-default `--vici-socket`, swanctl is
  AppArmor-confined to `/run/charon.vici`; the fallback dump covers it.

## 9. Acceptance criteria

- [ ] Every command in §1 parses with `--feature insomnia` and is rejected on a stock start
      (zebra-rs grammar test).
- [ ] `/show/vpn/*`, `/show/log/ipsec` and the IPsec exec paths reach the IPsec task; no
      path yields `% Unknown show command`.
- [ ] Reset re-initiates exactly the non-PASS children of `start_action = start` peers;
      `trap`/`none`/`@` peers are only terminated; every VICI wait is bounded.
- [ ] `ike sa`, `ipsec status`, `ike status` and `ike secrets` match their goldens; JSON
      forms are valid JSON.
- [ ] Charon down: every command answers `% IPsec process not running`, and none hangs.
- [ ] Every VICI call goes through exec-verbs' bounded `vici` API, and every subprocess
      through the bounded `Runner`; no handler blocks the IPsec task's `select!`.
- [ ] Failed exec orders set `Answer.error`; `show log ipsec` hangs off exec-verbs' shared
      `show log` container.
- [ ] `restart ipsec` reloads the rendered config from a non-default `--swanctl-dir`.
- [ ] The debug archive has mode `0600`, and its path is in the reply; neither it nor
      `show vpn debug` contains an xfrm key or a PSK (S1).
- [ ] BDD: the views, both reset scenarios and the teardown are green.
- [ ] The deviations are recorded in the `ipsec.rs` module doc and the book.
