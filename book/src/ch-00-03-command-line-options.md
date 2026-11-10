# Command Line Options

insomnia takes a small set of command line options. Every one of them
has a default that matches the Debian package layout and the stock
strongSwan, keepalived and Kea paths, so the packaged `insomnia.service`
runs `/usr/bin/insomnia` with no arguments at all. `insomnia --help`
prints the authoritative list; this chapter explains what each option
does and when you would change it.

## Quick reference

| Option | Argument | Default | Purpose |
|---|---|---|---|
| `--host` | `unix:NAME \| unix:/PATH \| tcp:HOST:PORT \| HOST` | `unix:zebra-rs/vty` | zebra-rs management (VTY gRPC) endpoint |
| `--swanctl-dir` | `PATH` | `/etc/swanctl` | Directory `swanctl.conf` is rendered into |
| `--vici-socket` | `PATH` | `/var/run/charon.vici` | charon's VICI socket, for `show vpn ipsec` |
| `--keepalived-dir` | `PATH` | `/run/insomnia/vrrp` | Parent of the per-VRF keepalived instance directories |
| `--keepalived-control` | `systemd \| signal` | `systemd` | How a new `keepalived.conf` is loaded |
| `--keepalived-unit` | `UNIT` | `insomnia-keepalived@.service` | systemd template unit for keepalived instances |
| `--dhcp-relay-dir` | `PATH` | `/run/insomnia/dhcp-relay` | Directory `relay.json` is rendered into |
| `--dhcp-relay-control` | `systemd \| signal` | `systemd` | How the relay agent loads a new `relay.json` |
| `--dhcp-relay-unit` | `UNIT` | `insomnia-dhcp-relay.service` | systemd unit of the relay agent |
| `--dhcp-relay-socket` | `PATH` | `/run/insomnia-dhcp-relay/control` | The relay agent's control socket, for `show dhcp relay` |
| `--kea-dir` | `PATH` | `/run/insomnia/kea` | Parent of the per-VRF Kea instance directories |
| `--kea-state-dir` | `PATH` | `/var/lib/insomnia/kea` | Kea's leases and DHCPv6 server DUID, per VRF |
| `--kea-control` | `systemd \| socket` | `systemd` | Whether insomnia starts and stops Kea |
| `--kea-unit4` | `UNIT` | `insomnia-kea-dhcp4@.service` | systemd template unit for `kea-dhcp4` instances |
| `--kea-unit6` | `UNIT` | `insomnia-kea-dhcp6@.service` | systemd template unit for `kea-dhcp6` instances |
| `--kea-hooks-dir` | `PATH` | `/usr/lib/<multiarch>/kea/hooks` | Kea's hook libraries |
| `--kea-notify` | `PATH` | `/usr/lib/insomnia/kea-notify` | Program Kea calls on DHCPv6 lease events |
| `--vrf-bpf-dir` | `PATH` | `/sys/fs/bpf/insomnia/vrf` | Where the VRF socket programs are pinned |
| `--vrf-state-dir` | `PATH` | `/run/insomnia/vrf` | Bookkeeping for the pinned VRF programs |
| `--holds-dir` | `PATH` | `/run/insomnia/holds` | Operator holds (`stop process`) |
| `-h`, `--help` | — | — | Print the option list |
| `-V`, `--version` | — | — | Print the version |

The firewall backend has no options: it runs `nft` from `PATH` and
always owns the `zebra_firewall` tables.

## Before you start: zebra-rs `--feature insomnia`

The configuration trees insomnia enforces belong to an optional feature
set of zebra-rs. Unless zebra-rs is started with

```console
$ zebra-rs --feature insomnia
```

those subtrees do not exist in the schema, so insomnia has no
configuration to enforce. (`--feature iso`, the earlier name, still
works, with a warning at startup.)

The insomnia package sets this up for the packaged zebra-rs: it ships
`/usr/lib/systemd/system/zebra-rs.service.d/insomnia.conf`, a drop-in
that adds `--feature insomnia` to `zebra-rs.service`. It takes effect
the next time zebra-rs starts; installing insomnia does not restart
zebra-rs, so after a first install run `systemctl restart zebra-rs`. To
start zebra-rs differently, put a drop-in of the same name in
`/etc/systemd/system/zebra-rs.service.d/`, which replaces the
package's.

## Connecting to zebra-rs

### `--host ENDPOINT`

The zebra-rs management endpoint — the address zebra-rs listens on
with its `--vty-socket` option, and the same one `vtyctl` talks to.
insomnia opens one configuration subscription per subtree it enforces
(`firewall`, `vpn ipsec`, `vrrp` and the four `service dhcp…` trees)
and its show-provider registrations on it.

The spellings are the ones zebra-rs's `--vty-socket` and `vtyctl
--host` accept, so the value can be copied from the zebra-rs command
line unchanged.

- `unix:NAME` — a Linux abstract unix-domain socket. The default,
  `unix:zebra-rs/vty`, matches zebra-rs's default `--vty-socket`.
- `unix:/PATH` — a filesystem unix-domain socket; a name starting with
  `/` selects this form. `unix:@NAME` forces the abstract
  interpretation even when NAME starts with `/`.
- `tcp:HOST:PORT` or `tcp://HOST:PORT` — plain-text gRPC over TCP
  (`http://HOST:PORT` is accepted as a synonym).
- `HOST` — a bare host name or address, dialled on port 2666.

```console
$ insomnia --host unix:zebra-rs/vty
$ insomnia --host unix:/run/zebra-rs/vty.sock
$ insomnia --host tcp:192.0.2.1:2666
$ insomnia --host 192.0.2.1
```

insomnia never gives up on this connection. If zebra-rs is not
running yet, or restarts, each backend retries every three seconds and
logs a warning per attempt. When the subscription comes back, the first
message is a snapshot of the whole subtree, so the firewall, IPsec,
VRRP and DHCP state is re-rendered from scratch — nothing has to be
replayed by hand. The packaged unit is therefore ordered after `zebra-rs.service`
but does not require it.

## IPsec options

The IPsec backend renders a complete `swanctl.conf` on every commit
and loads it into a running charon. It does not start, stop or
configure charon itself. See [IPsec](ch-02-00-what-is-ipsec.md) for
the prerequisites.

### `--swanctl-dir PATH`

The directory insomnia writes `swanctl.conf` into (mode `0600`, since
it holds the pre-shared keys) before running `swanctl -q` with
`SWANCTL_DIR` set to it. The default, `/etc/swanctl`, is where the
`strongswan-swanctl` package and VyOS keep it, so a manual
`swanctl -q` loads the same file. If `swanctl` is not installed the
file is still written, and a warning says it was not loaded.

Change it only if your strongSwan installation keeps its configuration
somewhere else. Whatever the directory, `swanctl -q` makes charon's
loaded connections match that one file and unloads the rest, so
insomnia should be the only thing loading connections into that
charon.

### `--vici-socket PATH`

The charon VICI control socket that `show vpn ipsec sa` and
`show vpn ipsec connections` query. The default,
`/var/run/charon.vici`, is charon's compiled-in location.

This option affects the show commands only. Loading the configuration
goes through `swanctl`, which uses its own default socket, so moving
charon's socket elsewhere also needs a matching `swanctl` setting.

## VRRP options

The VRRP backend renders a `keepalived.conf` per VRF and has
keepalived load it. keepalived stays a separately supervised process
so that restarting or upgrading insomnia never moves a virtual address.
[How insomnia Drives keepalived](ch-05-04-keepalived-and-insomnia.md)
walks through the files and processes involved.

### `--keepalived-dir PATH`

The parent directory of the keepalived instances, one subdirectory per
VRF. The global routing table is the instance `default`:

```
/run/insomnia/vrrp/default/
├── keepalived.conf            rendered on every commit (mode 0600)
├── keepalived.pid             keepalived's parent pid
├── keepalived_vrrp.pid        its VRRP child
└── keepalived.json            the dump `show vrrp` requests (transient)
```

The packaged units hard-code `/run/insomnia/vrrp`, and
`insomnia.service` sets `RuntimeDirectoryPreserve=yes` so the
directory — and the keepalived processes using it — survive an
insomnia restart. If you change this option in systemd mode, change
the paths in `insomnia-keepalived@.service` to match.

### `--keepalived-control systemd|signal`

How a newly rendered configuration reaches keepalived.

- `systemd` (default) — insomnia runs
  `systemctl reload-or-restart insomnia-keepalived@<vrf>.service`
  after writing a changed, non-empty file, and `systemctl stop` on the
  same unit when the VRRP configuration is removed or disabled. The
  unit is never enabled on its own; insomnia starts it on demand.
- `signal` — insomnia only sends `SIGHUP` to the pid in the instance's
  `keepalived.pid`. It never starts or stops keepalived. An empty
  configuration is also a reload, after which keepalived withdraws
  every group and idles. Use this mode in containers, on hosts without
  systemd, and wherever you supervise keepalived yourself; the BDD
  harness runs this way.

An unchanged file is never reloaded. In `systemd` mode it only gets a
`systemctl start`, which does nothing when the instance is already up;
in `signal` mode it is left alone. In `signal` mode with no keepalived
running, or in `systemd` mode without `systemctl`, the file is still
written and a warning says it was not loaded. The next keepalived start
picks it up.

### `--keepalived-unit UNIT`

The systemd unit used in `systemd` mode. A template name containing
`@.` has the VRF name inserted, so the default
`insomnia-keepalived@.service` becomes
`insomnia-keepalived@default.service` for the global table. A name
without `@.` is used as-is for every instance. Ignored in `signal`
mode.

Point this at your own template if you need different keepalived
arguments. Keep `TMPDIR` set to the instance directory, because that is
where keepalived writes the JSON dump `show vrrp` reads.

## DHCP relay options

The DHCP relay backend renders one `relay.json` from both relay trees
and has `insomnia-dhcp-relay`, a separate unprivileged process, load
it. See [DHCP Relay](ch-06-03-dhcp-relay.md) and
[How insomnia Drives Kea and the Relay
Agent](ch-06-05-kea-and-insomnia.md).

### `--dhcp-relay-dir PATH`

The directory `relay.json` is written into. In `signal` mode it also
holds the agent's `relay.pid`. The packaged unit hard-codes
`/run/insomnia/dhcp-relay`; change the unit with the option.

### `--dhcp-relay-control systemd|signal`

How a newly rendered configuration reaches the relay agent.

- `systemd` (default) — insomnia starts the unit on the first relay
  configuration, runs `systemctl reload-or-restart` on a change, and
  stops the unit when the last relay is removed or disabled.
- `signal` — insomnia only sends `SIGHUP` to the pid in `relay.pid`.
  It never starts or stops the agent; start it yourself with
  `insomnia-dhcp-relay --pid-file <dir>/relay.pid`.

An unchanged file is never reloaded.

### `--dhcp-relay-unit UNIT`

The systemd unit used in `systemd` mode. There is one relay agent for
every VRF, so this is a plain unit, not a template.

### `--dhcp-relay-socket PATH`

The agent's control socket, which `show dhcp relay statistics` and
`show dhcpv6 relay statistics` query. It affects the show commands
only.

## DHCP server options

The DHCP server backend renders one Kea configuration per family per
VRF and talks to each Kea over its control socket. See
[DHCP](ch-06-00-what-is-dhcp.md) for the prerequisites.

### `--kea-dir PATH`

The parent directory of the Kea instances, one subdirectory per VRF:

```
/run/insomnia/kea/default/
├── kea-dhcp4.conf             rendered configuration (mode 0640, group _kea)
├── kea-dhcp6.conf
├── kea4-ctrl-socket           Kea's control socket
├── kea6-ctrl-socket
├── kea-notify                 link to the --kea-notify program
└── events                     where kea-notify reports lease events
```

### `--kea-state-dir PATH`

What must survive a reboot, one subdirectory per VRF: the lease files
(`kea-leases4.csv`, `kea-leases6.csv`) and the DHCPv6 server's DUID.
Moving it without moving the files makes every Kea forget its leases.

The packaged template units hard-code both directories. If you change
either option in `systemd` mode, change the units to match.

### `--kea-control systemd|socket`

Whether insomnia runs Kea.

- `systemd` (default) — insomnia starts
  `insomnia-kea-dhcp4@<vrf>.service` and
  `insomnia-kea-dhcp6@<vrf>.service` when an instance has something to
  serve, and stops them when it has not.
- `socket` — insomnia only talks to instances somebody else started on
  the instance's configuration file. With nothing to serve, the
  instance is given a configuration that listens nowhere. Start a
  VRF's instance under `ip vrf exec <vrf>`.

In both modes a changed configuration is checked by the running Kea
(`config-test`) and then reloaded in place (`config-reload`). A commit
never restarts Kea.

### `--kea-unit4 UNIT`, `--kea-unit6 UNIT`

The systemd template units used in `systemd` mode. `@.` has the VRF
name inserted, so `insomnia-kea-dhcp4@.service` becomes
`insomnia-kea-dhcp4@red.service` for VRF `red`. Ignored in `socket`
mode.

### `--kea-hooks-dir PATH`

Where Kea's hook libraries are (`libdhcp_lease_cmds.so`,
`libdhcp_stat_cmds.so`, `libdhcp_run_script.so`). The default is the
Debian multiarch path for the architecture insomnia was built for, for
example `/usr/lib/x86_64-linux-gnu/kea/hooks`. Set it when Kea was
installed somewhere else.

### `--kea-notify PATH`

The program Kea's run-script hook calls on DHCPv6 lease events, so that
insomnia can install and remove the routes of delegated prefixes. The
package installs it at the default path.

## Options shared by the daemons insomnia runs

### `--vrf-bpf-dir PATH`

Each per-VRF unit (`insomnia-keepalived@<vrf>`,
`insomnia-kea-dhcp4@<vrf>`, `insomnia-kea-dhcp6@<vrf>`) is bound to
its VRF by a small socket program that insomnia loads and pins in this
directory, one file per VRF, before it starts the unit. The units
attach it with `BPFProgram=sock_create:/sys/fs/bpf/insomnia/vrf/%i` and
refuse to start without it. The directory must be on a bpffs; the
units hard-code the default path.

The programs are pinned only when keepalived or Kea runs under
systemd. In `signal` and `socket` mode whoever starts the daemon binds
it, for example with `ip vrf exec`.

### `--vrf-state-dir PATH`

Where insomnia records which VRF device each pinned program was built
for. A VRF that is deleted and created again is a new device; insomnia
notices from this record, pins a new program and restarts the VRF's
instances.

### `--holds-dir PATH`

One file per process an operator stopped with `stop process <name>`.
A held process stays stopped across commits and across a restart of
insomnia, until `start process <name>`. The default is under `/run`,
so a reboot clears every hold.

## Logging

insomnia logs to standard output; under systemd that ends up in the
journal (`journalctl -u insomnia`). The level is set with the
`RUST_LOG` environment variable, using `tracing` filter syntax, and
defaults to `info`:

```console
$ RUST_LOG=debug insomnia
$ RUST_LOG=info,insomnia::vrrp=debug insomnia
```

At `info`, every commit logs one line per backend it touches
(`firewall: nftables ruleset applied`, `ipsec: swanctl configuration
loaded`, `vrrp: keepalived configuration loaded`,
`kea-dhcp4 default: config-reload: …`, `dhcp-relay: relay agent
loaded …`, or `… unchanged`). Every rule, peer, group, subnet or
interface the renderer had to skip is a `warn` line naming it and the
reason.

## External programs

insomnia does its work by running the standard tools, found through
`PATH`. Only the ones a configured backend actually uses need to be
installed:

| Program | Used by | For |
|---|---|---|
| `nft` | firewall | loading the ruleset, live counters for `show firewall` |
| `swanctl` | IPsec | loading `swanctl.conf` into charon |
| `ip` | IPsec | `show vpn ipsec state` / `policy` (`ip xfrm`) |
| `ip` | DHCPv6 server | routes for delegated prefixes (`ip -6 route`) |
| `keepalived` | VRRP | version and JSON-signal probe at startup |
| `kea-dhcp4`, `kea-dhcp6` | DHCP server | checking a configuration before an instance's first start (`-t`) |
| `systemctl` | VRRP, DHCP | start, reload and stop of the keepalived, Kea and relay agent units (`systemd` mode); state for `show process` |

The daemons themselves (charon, keepalived, Kea) are started by
systemd, not by insomnia. `insomnia-dhcp-relay` and `kea-notify` ship
in the insomnia package.

insomnia runs as root, as the packaged unit does: loading nftables
rulesets, writing `/etc/swanctl`, pinning the VRF programs and
installing routes all need it.
