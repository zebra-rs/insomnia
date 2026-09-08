# How insomnia Drives keepalived

This chapter is for operators who want to see what happens on the
host, and for anyone running insomnia without systemd.

## One instance per VRF

Every keepalived that insomnia manages is an *instance* with its own
directory under `/run/insomnia/vrrp/`. The first release only creates
`default`, the instance for the global routing table; per-VRF
instances are the planned expansion.

```
/run/insomnia/vrrp/default/
├── keepalived.conf            rendered on every commit (mode 0600)
├── keepalived.pid             keepalived's parent pid
├── keepalived_vrrp.pid        its VRRP child
├── keepalived.json            the dump `show vrrp` requests (transient)
└── env                        per-instance environment (empty for default)
```

The template unit `insomnia-keepalived@default.service` starts
keepalived on that file with `TMPDIR` pointing into the directory, so
keepalived's dump files stay out of `/tmp`. It is never enabled:
insomnia runs `systemctl reload-or-restart` on it after writing a
non-empty file, and `systemctl stop` when the configuration goes away.
An unchanged file is not reloaded at all.

Because keepalived is its own service, restarting or upgrading insomnia
never moves a virtual address — the VRRP master keeps advertising
while insomnia is away, and the new insomnia re-renders the same file
and finds nothing to reload.

## Without systemd

Containers, the BDD harness and hand-run setups use signal mode:

```console
$ insomnia --keepalived-control signal
```

insomnia then only writes the file and sends `SIGHUP` to the pid in
`keepalived.pid`. Start keepalived yourself, on an empty file if no
configuration exists yet — it idles until the first reload:

```console
$ mkdir -p /run/insomnia/vrrp/default
$ : > /run/insomnia/vrrp/default/keepalived.conf
$ TMPDIR=/run/insomnia/vrrp/default keepalived --dont-fork \
    --use-file /run/insomnia/vrrp/default/keepalived.conf \
    --pid /run/insomnia/vrrp/default/keepalived.pid \
    --vrrp_pid /run/insomnia/vrrp/default/keepalived_vrrp.pid \
    --checkers_pid /run/insomnia/vrrp/default/keepalived_checkers.pid
```

An empty configuration in signal mode is also a reload: keepalived
withdraws every group and keeps running.

## What insomnia logs

```
vrrp: keepalived configuration loaded
vrrp: keepalived configuration unchanged
vrrp: keepalived stopped (no configuration)
vrrp: keepalived not running; configuration rendered to … but not loaded
vrrp: group WAN: vrid is required but not set; skipped
```

Every skipped group is one `warn` line naming the group and the reason;
the rest of the configuration is loaded regardless. A render never
fails a commit.

## Differences from VyOS

- The tree is rooted at `vrrp`; VyOS's `high-availability` wrapper,
  which only exists to co-locate VRRP with an IPVS load balancer, is
  dropped.
- Transition scripts are native keepalived `notify_*` lines rather than
  a FIFO and dispatcher.
- No SNMP traps, no conntrack-sync hook, no IPVS `virtual-server`.
- Three extensions VyOS lacks: per-group `version`,
  `v3-checksum-as-v2`, fractional `advertise-interval`.
- Defaults are applied by insomnia when rendering, so
  `show configuration` shows only what you set.
