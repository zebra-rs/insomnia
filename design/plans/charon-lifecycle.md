# charon lifecycle — implementation plan

Status: plan, 2026-10-21. Covers: §4.5 (charon part); §7.2 rows `options disable-route-autoinstall`, `log level|subsystem`, `interface`, `options flexvpn|virtual-ip|interface`, `options retransmission` ([vyos-gap](../vyos-gap.md) §4.5, §7.1, §7.2).
Priority: P2 (lifecycle + `disable-route-autoinstall`, as [vyos-gap](../vyos-gap.md) §4.5 and §7.2 rate them: VTI children get no auto-installed routes anyway, §2), P3 (the other options) · Effort: M · Owner: insomnia (zebra-rs: one YANG container + a value check)
Depends on:
- [ipsec-render-fixes](ipsec-render-fixes.md) M1 (the X13 helper `fsutil::write_private_atomic`; a soft dependency, since it is small enough to land first in either order);
- [exec-verbs](exec-verbs.md) E1 (soft: `vici::request("reload-settings")` and `vici::stats`; until it lands, `swanctl --reload-settings` and a socket connect are the fallbacks);
- [commit-validation](commit-validation.md) C1 (soft: `Findings`). Also applies the D4 rule, "write only what is configured", to strongswan.d · Unblocks: [ipsec-vti](ipsec-vti.md) (soft: `disable-route-autoinstall`, only for hosts that mix policy-based and VTI peers), [ipsec-remote-access](ipsec-remote-access.md) (eap-radius / dhcp plugin settings), [ipsec-opmode](ipsec-opmode.md) (`restart ipsec`: the start-if-stopped restart, `Control`, `CharonState.applied`), [conntrack-sync](conntrack-sync.md) (same pattern)

## 1. Goal

- insomnia owns exactly one strongswan.d drop-in, rendered from `vpn ipsec`. No other strongSwan file is touched.
- A changed setting reaches charon by the cheapest correct means:
  - VICI `reload-settings` for keys charon re-reads;
  - a charon restart for keys it reads only at startup;
  - nothing at all when the file is unchanged. That includes every zebra-rs reconnect.
- `disable-route-autoinstall`, `log level`, `interface`, `options flexvpn|virtual-ip|interface` and `options retransmission` take effect. The "charon-level settings; not applied yet" warning (`src/ipsec.rs:548-558`) disappears.
- There are two control modes, as for keepalived: `systemd` (packaged hosts) and `signal` (containers, BDD).
- A config change never starts a stopped charon and never stops a running one. The one exception is the operator's `restart ipsec` ([ipsec-opmode](ipsec-opmode.md)), which starts a stopped charon in systemd mode, as VyOS's `systemctl restart` does.

## 2. Current state

**insomnia.**
- The module doc says charon's lifecycle is not managed (`src/ipsec.rs:20-27`).
- `log` and `options` are opaque `serde_json::Value`s (`:170-171`); `interface` is `Vec<Flex>` (`:168-169`). All of them only produce the warning at `:548-558`.
- `swanctl_apply` writes `swanctl.conf` and runs `swanctl -q` (`:122-149`).
- The keepalived pattern to copy:
  - `Control` (`src/keepalived.rs:32-39`);
  - `write_atomic` / `write_if_changed` (`:229-252`);
  - `systemctl` (`:254-275`);
  - `apply` (`:277-323`, compare, then reload or stop).
- CLI flags: `main.rs:37-74`.

**BDD.**
- `bdd/tests/scripts/ipsec_node.sh` puts tmpfs over `/run` and `/etc/swanctl` (`:33-35`).
- It bind-mounts a generated `strongswan.conf` that ends with `include /etc/strongswan.d/*.conf` (`:47-71`), which is the **host's** directory.
- It starts `charon-systemd` directly and writes `/tmp/$NS.charon.pid` (`:73-74`).
- A drop-in written there today would land on the host and be shared by both nodes.

**Host packaging, checked on Ubuntu 24.04 with strongSwan 5.9.13.**
- `strongswan.service` has `ExecReload=swanctl --reload` plus `swanctl --load-all --noprompt`, and `Restart=on-abnormal`.
- The stock `/etc/strongswan.conf` includes `strongswan.d/*.conf` after the plugin includes.
- `/etc/strongswan.d` holds the package files `charon-systemd.conf` and `swanctl.conf`. `charon.conf` comes from `strongswan-charon`, which is not installed here.
- The AppArmor profile `usr.sbin.charon-systemd` allows `/etc/strongswan.d/** r` and `/run/charon.* rw`, and nothing else under `/run`.

**strongSwan 5.9.13 source, read for this plan.**

| Fact | Where |
|:--|:--|
| `install_routes` and `kernel-netlink.install_routes_xfrmi` are read once | `kernel_netlink_ipsec_create` (`kernel_netlink_ipsec.c`) |
| A table-220 route is installed only when `install_routes && !proto && !ports && (install_routes_xfrmi \|\| !policy->if_id)`. `install_routes_xfrmi` defaults to no, so a VTI (`if_id`) child gets no route even with `install_routes = yes` | `kernel_netlink_ipsec.c`, read for [ipsec-vti](ipsec-vti.md) |
| `interfaces_use` / `interfaces_ignore` are read once | `kernel_interface_create` (`kernel_interface.c`) |
| Retransmission settings are parsed per IKE_SA | `task_manager_v2_create` → `retransmission_parse_default` |
| VICI `reload-settings` reloads the settings, then calls `charon->load_loggers()` and `lib->plugins->reload()` | `vici_control.c` |
| charon-systemd's SIGHUP does the same | `charon-systemd.c` |
| charon-systemd inherits the `charon` section through a namespace alias | `register_namespace` |

**VyOS.**
- It writes six files: `charon.conf`, `charon-systemd.conf`, `charon-logging.conf`, `interfaces_use.conf`, `charon/dhcp.conf` and `charon/eap-radius.conf` (`vpn_ipsec.py:63-70`, `:930-936`).
- `charon.conf` is always rendered with `install_routes` (`charon.j2:121`), and with `cisco_flexvpn = yes|no` whenever `options` exists (`:24`).
- `log level` defaults to 1 (`vpn_ipsec.xml.in:637-657`) and sets journal `default` (`charon_systemd.conf.j2:12-15`) plus syslog `default = -1`. `log subsystem` is never rendered.
- `apply()` runs `systemctl reload-or-restart strongswan.service` (`vpn_ipsec.py:940-946`), which reloads a running charon. Restart-class keys therefore wait for the next charon start in VyOS. vyos-1x ships no unit override; whether vyos-build does is *unverified*.

**zebra-rs.**
- `log` and `options` are in `ipsec.yang:376-435`.
- There is no `retransmission` container.
- The `log level` help says "VyOS default: 0" (`:380`); VyOS's default is 1.

## 3. Design

**One drop-in, `/etc/strongswan.d/insomnia.conf`** (`--charon-conf`).
- Not VyOS's file set:
  - `charon.conf` and `charon-systemd.conf` are package conffiles, and overwriting them fights dpkg;
  - one file means one compare and one atomic rename.
- The file is included by the stock `include strongswan.d/*.conf`. That include runs after the plugin includes, and `insomnia.conf` sorts after `charon*.conf`, so its keys win. strongSwan sorts glob results and the last definition wins: *unverified*, pinned by the BDD.
- An operator can still override with a later file (`zz-local.conf`). That is documented as the escape hatch.
- Mode `0600`. It holds no secrets yet, but RADIUS keys from [ipsec-remote-access](ipsec-remote-access.md) will land here.
- An empty render means the file is absent.

**Render model.**
- `CharonSettings`: an ordered list of `(dotted key, value)` in the fixed table order below, rendered into nested sections.
- Keys are owned `String`s. [ipsec-remote-access](ipsec-remote-access.md) builds per-server keys at runtime (`charon.plugins.eap-radius.servers.192-0-2-50.secret`) and appends its `ra_plugin_keys(cfg)` to `charon::render`'s output, so one `CharonSettings` and one `apply` cover the whole drop-in. `class(key)` matches on key prefixes (`charon.plugins.eap-radius.`, `charon.plugins.dhcp.`).
- Values are written as given. A caller that needs quoting (RA's quoted `secret`) passes the quoted form, and `parse_dropin` round-trips it.
- Only configured values are rendered (D4 spirit). Every key below defaults to the same value in strongSwan and VyOS, so omitting it is equivalent. One exception: VyOS's `log level` default 1 is also strongSwan's journal default.
- The renderer is pure, `charon::render(&IpsecConfig) -> (CharonSettings, Vec<String>)`, and golden-tested like `swanctl.conf`.
- Backends that come later add keys through the same type; [ipsec-remote-access](ipsec-remote-access.md) adds `charon.plugins.eap-radius.*` and `charon.plugins.dhcp.*`.

| zebra-rs leaf | Drop-in key | VyOS line | Class | Evidence |
|:--|:--|:--|:--|:--|
| `options disable-route-autoinstall` | `charon.install_routes = no` | `charon.j2:121` | restart | read once (verified). Affects policy-based children only; VTI children get no route either way (§2) |
| `options flexvpn` | `charon.cisco_flexvpn = yes` | `:24` | restart | read site not inspected: conservative |
| `options virtual-ip` | `charon.install_virtual_ip = yes` | `:26` | restart | not inspected; strongSwan's default is believed to be `yes` already (*unverified*), so this is likely a no-op, kept for parity |
| `options interface` | `charon.install_virtual_ip_on = <if>` | `:29` | restart | not inspected: conservative |
| `options retransmission attempts\|base\|timeout` | `charon.retransmit_tries\|base\|timeout` | `:207-213` | reload | per IKE_SA (verified call; key names in the helper not inspected). Applies to new IKE_SAs only |
| `interface` (leaf-list) | `charon.interfaces_use = a, b` | `interfaces_use.conf.j2` | restart | read once (verified) |
| `log level` | `charon-systemd.journal.default = N` | `charon_systemd.conf.j2:12-15` | reload | `load_loggers` on reload (verified call). That it re-levels the journal logger is *unverified*; BDD checks |
| `log subsystem` | — | not rendered by VyOS | — | finding: Warning, `NotApplied`, `log subsystem is not applied (VyOS renders nothing for it)` |
| `remote-access radius …` ([ipsec-remote-access](ipsec-remote-access.md)) | `charon.plugins.eap-radius.nas_identifier`, `.retransmit_timeout`, `.servers.<addr-dashed>.*` | `charon/eap-radius.conf.j2` | restart | not verified. `reload-settings` calls `lib->plugins->reload()` (§2), so eap-radius may re-read its servers; promote after a BDD case (rule 4 below) |
| `remote-access dhcp interface\|server` | `charon.plugins.dhcp.interface`, `.server` | `charon/dhcp.conf.j2` | restart | not inspected: conservative |

- Findings follow [commit-validation](commit-validation.md) §3.2. `render` returns `(CharonSettings, Findings)` once C1 lands, `Vec<String>` before.
- With `--charon-conf ""`, every charon-level leaf yields one Warning, `NotApplied`. That is today's message, now per leaf.
- No charon-level leaf can be an Error: every value the schema admits renders.

**Deciding what to do.**
1. `diff_keys(old, new)` lists the added, removed and changed keys.
2. If any key is restart-class: restart. Else, if any changed: reload. Else: do nothing.
3. A removed key counts in the class of that key, because reverting to the default needs the same action.
4. Unverified keys sit in the restart class until a BDD case proves they apply on reload. Moving one is a one-line table change with a test.

**State and failure.**
- `CharonState { applied: Option<CharonSettings>, pending_restart: bool }` lives in the IPsec task.
- At task start it is seeded by parsing the on-disk drop-in. `parse_dropin` round-trips the renderer's own format and is unit-tested. Absent means empty; unparseable means "unknown", which forces a restart if the content differs.
- A failed action leaves `pending_restart` / `applied` unchanged, so the next config event retries.
- There is no periodic retry in M1.
- The crash window between write and restart is accepted. Optional hardening (M5): in systemd mode compare `ActiveEnterTimestampMonotonic` with the file's mtime.

**Control modes** (`--charon-control`).

| | Reload | Restart | charon not running |
|:--|:--|:--|:--|
| `systemd` (default) | VICI `reload-settings` | `systemctl try-restart <--charon-unit>`, so it never starts a stopped unit; then `wait_vici` | file written, `NotRunning`, the next start reads it |
| `signal` | VICI `reload-settings` | `SIGTERM` to the pid in `--charon-pid-file`. Wait for exit (10 s), then for the pid file to name a new live pid and `wait_vici` to succeed (15 s); otherwise error "charon did not come back; signal mode needs a supervisor that respawns it" | as systemd |

- **Operator restart** (`restart ipsec`, [ipsec-opmode](ipsec-opmode.md)): `restart(ch, RestartMode::Always)`.
  - systemd: `systemctl restart <--charon-unit>`, which also starts a stopped unit; then `wait_vici`.
  - signal: SIGTERM and the respawn wait above. With no live pid, error `charon is not running; signal mode cannot start it (it needs a supervisor)`.
  - It returns `Applied::Restarted`, so the forced `swanctl -q` follows (pki-x509's load compare).
  - Config-driven restarts use `RestartMode::IfRunning` (`try-restart`, the table above).
- Reload goes through VICI in both modes, not `systemctl reload`. The unit's `ExecReload` also runs `--load-all` against `/etc/swanctl`, which may differ from `--swanctl-dir`.
- The call is `vici::request(socket, "reload-settings", &[])` from [exec-verbs](exec-verbs.md) E1. It is bounded by `VICI_TIMEOUT`, and `success = no` becomes an error. Until E1 lands, `swanctl --reload-settings` (same VICI command) is the fallback.
- `wait_vici` polls `vici::stats` (E1) every 200 ms until it answers. Before E1: a plain socket connect.

**Order inside `ipsec::process`.**
1. Render `swanctl.conf` and `CharonSettings`.
2. `charon::apply`.
3. If it restarted, `wait_vici`.
4. `swanctl_apply`.
- `swanctl -q` runs last, so a restarted charon is reloaded from insomnia's own directory even when `--swanctl-dir` is not the unit's default.
- The IPsec load compare (skip `swanctl -q` when nothing changed) is introduced by [pki-x509](pki-x509.md) I1. It must treat `Applied::Restarted` as "changed": a restart always forces the load.

**Restart blast radius.**
- A restart drops every IKE and CHILD SA. Initiators re-establish (`start_action = start` on load); responders wait.
- Logged at warn: `ipsec: restarting charon to apply charon.install_routes, …; all SAs will re-establish`. The line names keys, never values, so a RADIUS `secret` key appears without its value.
- `delete vpn ipsec` removes the file. If the file held a restart-class key, charon restarts once.

**Deviations recorded in the `src/charon.rs` module doc:**
- one drop-in, not VyOS's six files;
- package conffiles are never overwritten;
- only configured keys are rendered;
- syslog is not silenced (charon-systemd logs to the journal; VyOS's `charon.syslog.daemon.default = -1` is not copied);
- restart-class keys restart charon, where VyOS only reloads;
- charon is never stopped on delete (VyOS stops `strongswan.service`);
- `log subsystem` is not applied.

**Rejected alternatives.**
- **Always restart on any change:** a log-level tweak would drop every tunnel.
- **SIGHUP in signal mode:** equivalent to `reload-settings`, but it needs the pid where VICI needs none.
- **Supervising charon from insomnia:** an insomnia upgrade would kill every SA, the same reason keepalived stays separate (`keepalived.rs:12-15`).
- **Writing under `/run/insomnia`:** AppArmor denies charon-systemd reads there.

## 4. Changes

### zebra-rs

`ipsec.yang`, inside `options-config` (`:411-435`); VyOS `vpn_ipsec.xml.in:768-812`:

```yang
container retransmission {
  ext:help "IPsec retransmission settings";
  leaf attempts { ext:help "Maximum number of retransmissions (VyOS default: 5)";
                  type uint32 { range "1..65535"; } }
  leaf base     { ext:help "Base of exponential backoff, 1.0-5.0 (VyOS default: 1.8)";
                  type decimal64 { fraction-digits 1; } }
  leaf timeout  { ext:help "Timeout in seconds before the first retransmission (VyOS default: 4)";
                  type uint32 { range "1..1000"; } }
}
```

- `check.rs` `value_check` (`:64-85`): `/vpn/ipsec/options/retransmission/base` must be in 1.0..5.0. The check is needed because libyang extracts no decimal64 range (`check.rs:8-9`).
- Fix the `log level` help to "VyOS default: 1" (`ipsec.yang:380`).
- No exec grammar, no routing change.
- A schema test like the existing `vpn ipsec` one (`manager.rs:7932`) pins the new nodes.

### insomnia

New module **`src/charon.rs`** (proposed):

```rust
pub enum Control { Systemd, Signal }               // clap::ValueEnum, like keepalived::Control
pub struct Charon { conf: Option<PathBuf>, control: Control, unit: String,
                    pid_file: PathBuf, vici_socket: PathBuf }
pub struct CharonSettings(Vec<(String, String)>);   // table order; owned keys (RA servers)
pub enum Class { Reload, Restart }
pub fn class(key: &str) -> Class;
pub fn render(cfg: &IpsecConfig) -> (CharonSettings, Findings);   // Vec<String> before commit-validation C1
pub fn to_text(s: &CharonSettings) -> String;      // "" when empty
pub fn parse_dropin(text: &str) -> Option<CharonSettings>;
pub enum Applied { Unchanged, Reloaded, Restarted, NotRunning, Disabled }
pub async fn apply(ch: &Charon, st: &mut CharonState, new: &CharonSettings) -> anyhow::Result<Applied>;
pub enum RestartMode { IfRunning, Always }       // Always: the operator's `restart ipsec`
pub async fn restart(ch: &Charon, mode: RestartMode) -> anyhow::Result<Applied>;
pub async fn wait_vici(socket: &Path, timeout: Duration) -> bool;   // polls vici::stats (exec-verbs E1)
```

- The file helpers are shared with keepalived:
  - The drop-in is written with `fsutil::write_private_atomic(path, text, 0o600)`. That helper comes from [ipsec-render-fixes](ipsec-render-fixes.md) X13: the temp file is created with its final mode, so the file is never briefly readable under the umask.
  - `write_if_changed` (`keepalived.rs:245-252`) and `systemctl` (`:254-275`) move into the same `src/fsutil.rs`. Behaviour is unchanged.

`src/ipsec.rs`:
- typed `Log { level: Option<Flex>, subsystem: Vec<Flex> }` and `Options { disable_route_autoinstall, flexvpn, interface, virtual_ip, retransmission }`, replacing the `Value`s at `:170-171`;
- `run()` takes a `Charon` and owns a `CharonState`;
- `process()` follows the order in §3;
- the `:548-558` warning is deleted;
- the module doc (`:20-27`) is replaced by the deviation list.

`src/main.rs` — new flags:

| Flag | Default | Notes |
|:--|:--|:--|
| `--charon-conf PATH` | `/etc/strongswan.d/insomnia.conf` | `""` disables drop-in management. Charon-level leaves then warn as today. |
| `--charon-control systemd\|signal` | `systemd` | |
| `--charon-unit UNIT` | `strongswan.service` | systemd mode |
| `--charon-pid-file PATH` | `/var/run/charon.pid` | signal mode. Classic charon writes this path; charon-systemd writes none (*unverified*), so set it explicitly in signal mode |

[ipsec-opmode](ipsec-opmode.md) adds `--charon-log-file PATH` for `show log ipsec`; this plan reads no log.

**Worked example.** Config:

```
set vpn ipsec options disable-route-autoinstall
set vpn ipsec options retransmission attempts 3
set vpn ipsec options retransmission timeout 2
set vpn ipsec interface eth0
set vpn ipsec log level 2
```

Exact `/etc/strongswan.d/insomnia.conf`, mode 0600:

```
# Autogenerated by insomnia from vpn ipsec — do not edit
charon {
    install_routes = no
    retransmit_tries = 3
    retransmit_timeout = 2
    interfaces_use = eth0
}
charon-systemd {
    journal {
        default = 2
    }
}
```

- From an empty drop-in, all five keys change. `install_routes` and `interfaces_use` are restart-class, so charon restarts and the log reads `ipsec: restarting charon to apply charon.install_routes, charon.interfaces_use, …`.
- A later `set vpn ipsec log level 1` changes only `charon-systemd.journal.default`. That is a reload, and the log reads `ipsec: charon settings reloaded`.
- A zebra-rs restart re-delivers the same snapshot: `Unchanged`, nothing logged at info.

There is no show change. `show vpn ike status`, which prints the effective drop-in (`CharonState.applied`), belongs to [ipsec-opmode](ipsec-opmode.md) (its decision 11).

**Packaging.**
- `Cargo.toml` `recommends` is unchanged.
- `insomnia.service` needs no new capability; it already runs as root.
- Document that `/etc/strongswan.d/insomnia.conf` is owned by insomnia, and is not a conffile.

**BDD.** `bdd/tests/scripts/ipsec_node.sh`:
1. After `:35`, overlay the drop-in directory with a private copy:
   ```sh
   mkdir -p /run/strongswan.d.stock && cp -a /etc/strongswan.d/. /run/strongswan.d.stock/
   mount -t tmpfs tmpfs /etc/strongswan.d && cp -a /run/strongswan.d.stock/. /etc/strongswan.d/
   ```
   This keeps the stock path, insomnia's default flag and the AppArmor rules.
2. Replace `:73-74` with a respawn loop. It writes `/tmp/$NS.charon.pid` on every spawn and `/tmp/$NS.charon-loop.pid` once, and stops when `/tmp/$NS.charon.stop` exists.
3. insomnia gets `--charon-control signal --charon-pid-file /tmp/$NS.charon.pid`.

`ipsec_node_stop.sh` touches the stop file and kills `charon-loop` before `charon`. New helper `tests/scripts/charon_starts.sh NS` prints `starts=<N>`, the count of `Starting IKE charon daemon` in `logs/$NS.charon.log`, which `ipsec_node.sh:44` truncates per run.

## 5. Tests

Unit (`src/charon.rs`):
- **`charon_settings_golden`**: the worked example, exact text.
- **`all_options_golden`**: every row of the table, including `flexvpn`, `virtual-ip`, `options interface` and `retransmission base 2.5`.
- **`empty_is_absent`**: no `log` and no `options` gives `to_text == ""`.
- **`dropin_round_trip`**: `parse_dropin(to_text(s)) == s` for both goldens; foreign text gives `None`.
- **`classify_changes`**:
  - log level only → reload;
  - add `install_routes` → restart;
  - remove `install_routes` → restart;
  - retransmit only → reload;
  - identical → nothing.
- **`apply_state_machine`**: with a scratch dir and a stub control (a trait seam, as `keepalived.rs:412` tests with real files), cover:
  - unchanged gives `Unchanged` and no action;
  - a failed restart keeps `pending_restart`, and the next reload-class change still restarts;
  - the `NotRunning` path;
  - `RestartMode::Always` runs `systemctl restart` (starts a stopped unit) and `IfRunning` runs `try-restart`; signal mode with no live pid errors.
- **`classify_ra_plugin_keys`**: an owned `charon.plugins.eap-radius.servers.<s>.secret` key is restart-class; a quoted value round-trips through `parse_dropin`.
- **`subsystem_warns`**.
- `ipsec.rs` **`charon_warning_gone`**: no "charon-level" warning for any `log`/`options` input.

**BDD: new feature `ipsec_charon.feature` (`@serial @ipsec_charon`)**, on the `ipsec_s2s` topology and configs:
1. **Setup.** Responder first, SA up. `ip route show table 220` in z1 eventually contains `10.0.2.0/24`: charon's default `install_routes`.
2. **Reload-class change keeps the SAs.**
   - `set vpn ipsec log level 2` in z1;
   - insomnia log `charon settings reloaded`;
   - `charon_starts.sh` gives `starts=1`;
   - `show vpn ipsec sa` still contains `192-0-2-9-tunnel-1`.
3. **Restart-class change.**
   - Apply `set vpn ipsec options disable-route-autoinstall` and `set router static ipv4 route 10.0.2.0/24 nexthop 192.0.2.9` in z1. The static-route set form is to be confirmed against `config-static.yang`.
   - insomnia log `restarting charon`.
   - `starts=2`; the SA is eventually re-established.
   - Table 220 eventually does not contain `10.0.2.0/24`.
   - `kernel route "10.0.2.0/24"` eventually contains `via 192.0.2.9`.
   - The ping succeeds and the counters move. zebra-rs now routes, and the IPsec policy still encrypts.
4. **Removal.**
   - `delete vpn ipsec options` and `delete vpn ipsec log` in z1 → `starts=3`.
   - `nsenter -m -t <insomnia pid> test -e /etc/strongswan.d/insomnia.conf` fails. The drop-in lives in the node's mount namespace, so `ip netns exec` alone cannot see it.
5. **Teardown topology.**

## 6. Docs

- **ch-00-03:**
  - add the four flags to the quick-reference table;
  - new section "charon options" with the reload/restart table, the restart warning, and the AppArmor constraint (the file must sit under `/etc/strongswan.d`);
  - change "It does not start, stop or configure charon itself" (`:79-82`) to "configures charon through one drop-in; never starts or stops it".
- **ch-02-00:** update the prerequisites.
- **New subsection "Global options" in ch-02-02:** `options`, `interface`, `log`, `retransmission`, with the restart note.
- **ch-02-04:** a pointer to `disable-route-autoinstall` (see [ipsec-vti](ipsec-vti.md) for why VTI alone does not need it).
- **Module doc deviations:** §3.

## 7. Milestones

1. **Shared fs/systemctl helpers.** Move `write_if_changed` and `systemctl` from keepalived into the `src/fsutil.rs` that [ipsec-render-fixes](ipsec-render-fixes.md) M1 creates (X13); create it here if this lands first. insomnia, S. Done when: the keepalived tests pass unchanged and every secret file goes through `write_private_atomic`.
2. **`charon.rs` render, parse, classify and goldens; typed `Log`/`Options` in ipsec.rs.** insomnia, S. Done when: §5 unit tests pass and the old warning is gone.
3. **`apply` and both control modes; flags; `process()` ordering.** insomnia, M. Done when: `apply_state_machine` passes and a manual systemd-host check shows `try-restart` and `reload-settings`. Uses [exec-verbs](exec-verbs.md) E1's `vici::request`/`stats` if E1 has landed, else the swanctl/connect fallbacks, swapped in later with no behaviour change.
4. **zebra-rs `options retransmission` + `base` value check + help fix.** zebra-rs, S. Done when: schema test and value-check test pass; insomnia renders `retransmit_*` from a real commit.
5. **BDD: `ipsec_node.sh` overlay and respawn loop, `ipsec_charon` feature.** insomnia `bdd/`, M. Done when: `make -C bdd ipsec_charon ipsec_s2s` pass, and the host's `/etc/strongswan.d` is untouched after the run.
6. **Docs.** insomnia, S.
7. *(optional)* **Mtime vs unit-start hardening; promote verified keys to reload class.** insomnia, S.

## 8. Risks and open questions

- **Unverified reload behaviour.** Until it is verified, `flexvpn`, `virtual-ip` and `options interface` restart charon, which may be heavier than needed. The BDD can promote them.
- **The journal logger may not re-level on `reload-settings`.** Then `log level` must move to the restart class. Scenario 2 of the BDD only checks the decision, because in the BDD the journal is disabled (`ipsec_node.sh:53-55`). Verify on a systemd host before M3 lands.
- **`disable-route-autoinstall` also drops the table-220 routes remote-access pools rely on.** [ipsec-remote-access](ipsec-remote-access.md) warns when both are configured; route-based VTI alone does not need the option (§2).
- **Open: should an automatic restart be optional** (`--charon-restart auto|never`) for operators who prefer a maintenance window? Recommendation: not in M1. Log the pending restart and add the knob if asked.
- **Open: VyOS silences syslog when `log level` is set.** Ubuntu's charon-systemd ships no syslog logger config, so nothing is duplicated, but distro builds that do are *unverified*.
- **Classic `charon` (via `ipsec` starter) ignores `charon-systemd.*`.** Document that insomnia targets charon-systemd, as `Cargo.toml` `recommends` already says.
- **A drop-in edited by hand** is overwritten on the next change. It is parsed as "unknown" (restart) only when it differs from the render.

## 9. Acceptance criteria

- [ ] `/etc/strongswan.d/insomnia.conf` is the only strongSwan file insomnia writes besides `--swanctl-dir`; mode 0600; absent when nothing is configured.
- [ ] Unchanged settings never reload or restart charon, including across zebra-rs restarts.
- [ ] Restart-class changes restart charon via `try-restart` (systemd) or SIGTERM plus respawn (signal); reload-class changes use VICI `reload-settings` (`vici::request`, bounded); `swanctl -q` follows every restart.
- [ ] `restart(…, RestartMode::Always)` starts a stopped charon in systemd mode; config-driven restarts never do.
- [ ] `options retransmission` exists in zebra-rs with the `base` range check.
- [ ] The goldens and `classify_changes` / `apply_state_machine` pass; the old charon-level warning is gone.
- [ ] `make -C bdd ipsec_charon` passes; table 220 is empty after `disable-route-autoinstall`; the host `/etc/strongswan.d` is unchanged.
- [ ] ch-00-03 documents the four flags; the module doc lists the deviations.
