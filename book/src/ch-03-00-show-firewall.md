# Show Firewall

The `show firewall` views join the configured ruleset with the live
packet/byte counters read from nftables at the moment of the query.

## The whole firewall

```console
$ show firewall
Firewall Groups

 Name                 Type                 References  Members
 ----                 ----                 ----------  -------
 SERVERS              address-group                 1  10.0.0.1
                                                       10.0.0.2-10.0.0.5
 WEB                  port-group                    1  80
                                                       443

ipv4 Firewall "forward filter"

 Rule     Action     Protocol      Packets        Bytes  Conditions
 ----     ------     --------      -------        -----  ----------
 10       accept     -                   0            0  ct state {established,related}
 20       jump       tcp                 0            0  meta l4proto tcp ip daddr @A_SERVERS tcp dport @P_WEB
 default  drop       -                   0            0  log

ipv4 Firewall "prerouting raw"

 Rule     Action     Protocol      Packets        Bytes  Conditions
 ----     ------     --------      -------        -----  ----------
 5        notrack    udp                 0            0  meta l4proto udp
 default  accept     -                   0            0

ipv4 Firewall "name WEB-IN"

 Rule     Action     Protocol      Packets        Bytes  Conditions
 ----     ------     --------      -------        -----  ----------
 10       accept     -                   0            0  tcp flags & (syn) == syn
 default  drop       -                   0            0
```

The `Conditions` column is the real nftables expression each rule
rendered to — group references appear as the named sets
(`@A_SERVERS`, `@P_WEB`), state matches as `ct state {…}`, and a
`log` note marks rules and defaults that log.

## Narrower views

Every level of the tree is addressable:

```console
$ show firewall group                      all groups with members and use counts
$ show firewall ipv4                       every ipv4 rule set
$ show firewall ipv6                       every ipv6 rule set
$ show firewall ipv4 forward filter        one rule set
$ show firewall ipv4 prerouting raw
$ show firewall ipv4 name                  all custom chains
$ show firewall ipv4 name WEB-IN           one custom chain
```

## Reading the counters

Counters are per rule, cumulative since the rule was last part of an
applied ruleset. Because every commit atomically replaces the whole
zebra-rs table, **any firewall commit resets all counters** — a
freshly committed ruleset showing zeros is expected. A rule whose
counter never moves while its traffic demonstrably flows means an
earlier rule (or the global state policy) is consuming the packets —
the counters of the earlier rows will show it.

The `default` row counts what fell through to `default-action`. With
`default-log` set, those packets also appear in the kernel log with
the `…-default-…` prefix described in the logging chapter.

## JSON

For scripting, request JSON through `vtyctl` (the same views the MCP
server uses):

```console
$ vtyctl show --json "show firewall"
$ vtyctl show --json "show firewall ipv4 forward filter"
```

The JSON view carries the same joined data — configuration plus live
counters — structured per family/hook/rule.
