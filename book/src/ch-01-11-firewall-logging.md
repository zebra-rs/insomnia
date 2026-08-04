# Firewall Logging

Any rule can log the packets it matches, and any rule set can log
what falls through to its default action:

```console
set firewall ipv4 forward filter rule 20 log
set firewall ipv4 forward filter default-log
```

Log entries go to the kernel log — read them with `journalctl -k`
or `dmesg`. Each entry carries a prefix identifying exactly which
rule fired, in the form
`[<family>-<hook>-<priority>-<rule>-<action letter>]`:

```
[ipv4-FWD-filter-20-D]        rule 20 (drop) in ipv4 forward filter
[ipv4-FWD-filter-default-D]   the default action of the same chain
```

Hook codes: `FWD` (forward), `INP` (input), `OUT` (output),
`PRE` (prerouting), `NAM` (custom chain).

## Log options

```console
set firewall ipv4 forward filter rule 20 log-options level warning
set firewall ipv4 forward filter rule 20 log-options group 2
set firewall ipv4 forward filter rule 20 log-options snapshot-length 128
set firewall ipv4 forward filter rule 20 log-options queue-threshold 100
```

`level` sets the syslog level. `group` switches the rule from plain
kernel logging to nflog — packets are multicast to a netlink group
where a collector such as `ulogd` can capture them (with up to
`snapshot-length` bytes of payload, batched by `queue-threshold`).

## Rate-limiting noisy rules

Combine logging with `limit` so a flood cannot drown the log:

```console
set firewall ipv4 input filter rule 90 action drop
set firewall ipv4 input filter rule 90 log
set firewall ipv4 input filter rule 90 limit rate 5/minute
```

Note that `limit` bounds the whole rule, not just its logging — for
log-everything-but-throttled designs use a `continue`-action logging
rule with a `limit`, followed by the enforcing rule.

## The state policy logs too

```console
set firewall global-options state-policy invalid log
set firewall global-options state-policy invalid log-level debug
```

## Counters are always on

Every rule — logging or not — keeps live packet/byte counters,
visible in `show firewall`; see the show-command chapter.
