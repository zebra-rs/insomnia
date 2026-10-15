# Command Line Options

insomnia takes a small set of command line options. Every one of them
has a default that matches the Debian package layout and the stock
strongSwan and keepalived paths, so the packaged `insomnia.service`
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
| `--vrf-preload` | `PATH` | `/usr/lib/insomnia/vrf.o` | `LD_PRELOAD` shim for VRF keepalived instances (reserved) |
| `-h`, `--help` | — | — | Print the option list |
| `-V`, `--version` | — | — | Print the version |

The firewall backend has no options: it runs `nft` from `PATH` and
always owns the `zebra_firewall` tables.

## Before you start: zebra-rs `--feature iso`

The `firewall`, `vpn ipsec` and `vrrp` configuration trees belong to
the optional ISO feature set of zebra-rs. Unless zebra-rs is started
with

```console
$ zebra-rs --feature iso
```

those subtrees do not exist in the schema, so insomnia has no
configuration to enforce.

## Connecting to zebra-rs

### `--host ENDPOINT`

The zebra-rs management endpoint — the address zebra-rs listens on
with its `--vty-socket` option, and the same one `vtyctl` talks to.
insomnia opens three configuration subscriptions (one per backend) and
one show-provider registration on it.

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
message is a snapshot of the whole subtree, so the firewall, IPsec and
VRRP state is re-rendered from scratch — nothing has to be replayed by
hand. The packaged unit is therefore ordered after `zebra-rs.service`
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
├── keepalived.json            the dump `show vrrp` requests (transient)
└── env                        per-instance environment (empty for default)
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

### `--vrf-preload PATH`

The `LD_PRELOAD` library written into the `env` file of a non-default
VRF instance, together with `VRF=<name>`, so that every socket the
keepalived process opens is bound to that VRF.

This option is reserved for the planned VRRP-in-a-VRF support. Today
insomnia only creates the `default` instance, whose `env` file is
empty, so the option has no effect. The shim itself does not ship yet.

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
loaded`, `vrrp: keepalived configuration loaded` or `… unchanged`). Every rule, peer or group the renderer had to
skip is a `warn` line naming it and the reason.

## External programs

insomnia does its work by running the standard tools, found through
`PATH`. Only the ones a configured backend actually uses need to be
installed:

| Program | Used by | For |
|---|---|---|
| `nft` | firewall | loading the ruleset, live counters for `show firewall` |
| `swanctl` | IPsec | loading `swanctl.conf` into charon |
| `ip` | IPsec | `show vpn ipsec state` / `policy` (`ip xfrm`) |
| `keepalived` | VRRP | version and JSON-signal probe at startup |
| `systemctl` | VRRP | reload/stop of the keepalived unit (`systemd` mode) |

insomnia runs as root, as the packaged unit does: loading nftables
rulesets, writing `/etc/swanctl` and signalling keepalived all need
it.
