# Firewall

zebra-rs provides a VyOS-compatible firewall configured with the
familiar `set firewall …` command tree and enforced by the kernel's
nftables engine. On every commit zebra-rs renders the whole
configuration into one nftables ruleset (tables `ip zebra_firewall`
and `ip6 zebra_firewall`) and applies it as a single atomic
transaction — the running ruleset always matches the config tree, and
a failed apply leaves the previous ruleset untouched.

Firewall support is part of the optional ISO feature set:

```console
$ zebra-rs --feature iso
```

Without `--feature iso` the `firewall` subtree is absent from the
schema. The `nft` binary (package `nftables`) must be installed;
no daemons beyond zebra-rs itself are involved.

## Structure

Packets are evaluated by **rule sets** attached to the points where
traffic passes the router:

```
firewall
├── group                    named sets: addresses, networks, ports, …
├── ipv4
│   ├── forward filter       traffic routed through this router
│   ├── input filter         traffic addressed to this router
│   ├── output filter        traffic originated by this router
│   ├── prerouting raw       before connection tracking (ingress)
│   ├── output raw           before connection tracking (egress)
│   └── name <chain>         custom chains, targets of jump rules
├── ipv6                     the same seven attachment points
└── global-options           state policy, sysctl-style toggles
```

Each rule set holds numbered rules evaluated in ascending order; the
first matching rule's action decides the packet's fate, and the rule
set's `default-action` applies when nothing matches.

## A first ruleset

Protect servers behind the router: allow established traffic, send
new web connections through a custom chain, drop the rest.

```console
set firewall group address-group SERVERS address 10.0.0.1
set firewall group port-group WEB port 80
set firewall group port-group WEB port 443

set firewall ipv4 forward filter default-action drop
set firewall ipv4 forward filter rule 10 action accept
set firewall ipv4 forward filter rule 10 state established
set firewall ipv4 forward filter rule 10 state related
set firewall ipv4 forward filter rule 20 action jump
set firewall ipv4 forward filter rule 20 jump-target WEB-IN
set firewall ipv4 forward filter rule 20 protocol tcp
set firewall ipv4 forward filter rule 20 destination group address-group SERVERS
set firewall ipv4 forward filter rule 20 destination group port-group WEB

set firewall ipv4 name WEB-IN default-action drop
set firewall ipv4 name WEB-IN rule 10 action accept
set firewall ipv4 name WEB-IN rule 10 tcp flags syn
```

Verify with live counters:

```console
$ show firewall ipv4 forward filter
ipv4 Firewall "forward filter"

 Rule     Action     Protocol      Packets        Bytes  Conditions
 ----     ------     --------      -------        -----  ----------
 10       accept     -                   0            0  ct state {established,related}
 20       jump       tcp                 0            0  meta l4proto tcp ip daddr @A_SERVERS tcp dport @P_WEB
 default  drop       -                   0            0
```

The next chapters cover each layer: rule sets and evaluation order,
the match criteria, actions, groups, connection tracking, and the
IPv6 tree. A rule that uses features the backend cannot express is
skipped with a logged warning naming the rule — one bad rule never
blocks the rest of the ruleset.
