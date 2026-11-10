# How insomnia Drives Kea and the Relay Agent

This chapter is for operators who want to see what happens on the
host, and for anyone running insomnia without systemd.

## The Kea instances

insomnia runs one `kea-dhcp4` and one `kea-dhcp6` per VRF, each only
while it has something to serve. `default` is the instance of the
global routing table.

```
/run/insomnia/kea/default/
├── kea-dhcp4.conf             rendered configuration, the file Kea runs on
├── kea-dhcp6.conf
├── kea4-ctrl-socket           Kea's control socket: how insomnia talks to it
├── kea6-ctrl-socket
├── kea-notify                 called by Kea on DHCPv6 lease events
└── events                     where kea-notify reports them to insomnia

/var/lib/insomnia/kea/default/
├── kea-leases4.csv            the leases
├── kea-leases6.csv
└── kea-dhcp6-serverid         the DHCPv6 server's DUID
```

The template units `insomnia-kea-dhcp4@<vrf>.service` and
`insomnia-kea-dhcp6@<vrf>.service` run Kea as the `_kea` user in a
systemd sandbox, with only the capabilities to bind the DHCP ports and
open raw sockets. They are never enabled; insomnia starts and stops
them. insomnia never uses Kea's control agent or a TCP port: the
control socket is the only channel.

Because Kea is its own service, restarting or upgrading insomnia never
interrupts DHCP. Kea keeps answering while insomnia is away, and the
new insomnia renders the same file and finds nothing to do.

## What a commit does

For each instance whose rendered configuration changed:

1. **Nothing left to serve**: the unit is stopped.
2. **Kea is running**: insomnia sends it the new configuration to
   check (`config-test`). If Kea accepts it, insomnia writes the file
   and tells Kea to reload it (`config-reload`). Leases are kept, and
   no request is lost to a restart.
3. **Kea is not running**: insomnia writes the file, checks it with
   `kea-dhcp4 -t`, and starts the unit.

A render identical to the file in place is not applied at all. This
matters because the configuration is also re-rendered on every link
and address change: the listen set depends on them.

### When Kea refuses a configuration

Most mistakes are caught earlier, by zebra-rs at commit or by insomnia
when it renders. If Kea itself still refuses a configuration, nothing
changes on the host: the file is not written and Kea keeps serving the
previous configuration.

```
kea-dhcp4 default: Kea refused the configuration and keeps running its previous one: …
```

The `show dhcp server` views then begin with Kea's reason, so the
mismatch between the committed configuration and what is served is
visible where you look for leases. The next commit that Kea accepts
clears it.

## The relay agent

`insomnia-dhcp-relay` is a separate, unprivileged process. It reads
packets from every client on every listen interface, so it does not run
inside the root insomnia daemon: its unit,
`insomnia-dhcp-relay.service`, uses a dynamic user and a systemd
sandbox.

```
/run/insomnia/dhcp-relay/relay.json     rendered on every commit
/run/insomnia-dhcp-relay/control        the agent's control socket
```

insomnia renders `relay.json` from both relay trees and has the agent
load it: started on the first configuration, reloaded on a change,
stopped when the last relay is removed. An unchanged file is not
reloaded. `show dhcp relay statistics` asks the control socket.

## Processes: `show process`, `start`, `stop`, `restart`

Every daemon insomnia drives is listed by `show process`:

```console
$ show process
Name               VRF      State    Admin  PID   Uptime   Restarts  Last error
-----------------  -------  -------  -----  ----  -------  --------  ----------
dhcp-relay         -        running  up     1412  2h13m5s  0
kea-dhcp4@default  default  running  up     1398  2h13m6s  0
kea-dhcp4@red      red      running  up     1405  2h13m6s  0
kea-dhcp6@default  default  stopped  held   -     -        0
```

`Admin` is what should be: `up` when the configuration wants the
process, `held` when an operator stopped it, `down` when nothing is
configured for it. A process that is neither wanted, held, running nor
in error is not listed; `show process <name>` still answers for it.

```console
$ stop process kea-dhcp6@default
Stopped kea-dhcp6@default; it stays stopped until start process kea-dhcp6@default
$ start process kea-dhcp6@default
Started kea-dhcp6@default
$ restart process kea-dhcp4@red
Restarted kea-dhcp4@red
```

- **`stop`** is an operator hold. Commits still render the
  configuration file, but the process stays stopped, also across a
  restart of insomnia. A reboot clears the hold. To switch a service
  off for good, use the `disable` leaf of its tree.
- **`restart`** restarts the process, which a commit never does. Kea's
  leases are on disk and survive it.

## Without systemd

Containers, the integration tests and hand-run setups start the daemons
themselves and tell insomnia so:

```console
$ insomnia --kea-control socket --dhcp-relay-control signal
```

- **Kea (`socket`)**: insomnia only talks to instances that are already
  running. Start each on the path insomnia renders to
  (`/run/insomnia/kea/<vrf>/kea-dhcp4.conf`) with a minimal
  configuration that opens the control socket; insomnia's first reload
  replaces it. With nothing to serve, the instance is given an idle
  configuration that listens nowhere.
- **Relay agent (`signal`)**: start `insomnia-dhcp-relay` with
  `--pid-file /run/insomnia/dhcp-relay/relay.pid`. insomnia writes
  `relay.json` and sends `SIGHUP` to that pid.

In these modes `show process` reports the processes it can see, and
`start`, `stop` and `restart` are refused: the processes are not
insomnia's to manage.

## What insomnia logs

```
kea-dhcp4 default: started: 2 shared networks, 2 subnets, interfaces [lan1 lan2]
kea-dhcp4 default: config-reload: 2 shared networks, 2 subnets, interfaces [lan1 lan2]
kea-dhcp4 default: configuration unchanged
kea-dhcp4 default: stopped (nothing to serve)
kea-dhcp4 default: stopped by an operator (stop process); configuration written, not loaded
dhcp-relay: relay agent loaded 2 DHCPv4 and 1 DHCPv6 listen interfaces
dhcp-relay: relay configuration unchanged
dhcp-relay: relay agent stopped (no configuration)
dhcp-server: service dhcp-server shared-network-name LAN subnet 10.1.0.0/24 range bad skipped: not inside the subnet
```

One line per instance and commit says what is being served. Everything
skipped is one `warn` line naming it and the reason. A render never
fails a commit.

## Differences from VyOS

- **Reload, not restart.** VyOS restarts Kea on every commit, which
  drops the requests that arrive meanwhile and lets a configuration Kea
  rejects take the service down.
- **Paths.** The configuration, control sockets and leases are under
  `/run/insomnia/kea` and `/var/lib/insomnia/kea`, not `/run/kea` and
  `/config/dhcp`. The distribution's Kea services are left alone.
- **The relay** is insomnia's own agent in a sandbox, not `dhcrelay`.
- **`show process`** and the process actions are additions.
