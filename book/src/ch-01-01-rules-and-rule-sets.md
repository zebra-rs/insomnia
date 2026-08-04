# Rules and Rule Sets

## Attachment points

A rule set is named by address family, hook and priority:

```console
set firewall ipv4 forward filter …      routed through the router
set firewall ipv4 input   filter …      addressed to the router
set firewall ipv4 output  filter …      originated by the router
set firewall ipv4 prerouting raw …      all ingress, before conntrack
set firewall ipv4 output     raw …      all egress, before conntrack
set firewall ipv6 …                     the same six, for IPv6
```

The three `filter` chains are the stateful firewall. The two `raw`
chains run **before** connection tracking — use them to exempt flows
from tracking (`action notrack`) or to drop obviously unwanted
traffic as early as possible; state-based matchers do not exist
there.

## Rules

Rules are numbered 1–999999 and evaluated in ascending order. Leave
gaps (10, 20, 30 …) so rules can be inserted later.

```console
set firewall ipv4 input filter rule 10 action accept
set firewall ipv4 input filter rule 10 protocol tcp
set firewall ipv4 input filter rule 10 destination port 22
set firewall ipv4 input filter rule 10 description "management ssh"
```

All criteria in one rule must match (logical AND). The first matching
rule ends evaluation with its action; `continue` is the exception —
it counts the packet and keeps evaluating.

A rule can be taken out of service without deleting it:

```console
set firewall ipv4 input filter rule 10 disable
```

## Default action and description

```console
set firewall ipv4 forward filter default-action {accept | drop}
set firewall ipv4 forward filter default-log
set firewall ipv4 forward filter description <text>
```

The default action applies when no rule matched (VyOS default:
`accept`). `default-log` logs packets that fall through to it —
turn it on while developing a ruleset.

## Custom chains

A custom chain groups rules that several rule sets share, reached
with `action jump`:

```console
set firewall ipv4 name WEB-IN default-action drop
set firewall ipv4 name WEB-IN rule 10 action accept
set firewall ipv4 name WEB-IN rule 10 tcp flags syn
```

Custom chains accept the full action set as their `default-action`
(`accept`, `continue`, `drop`, `jump`, `reject`, `return`) and may
chain further with `default-jump-target <chain>`. `return` hands the
packet back to the calling rule set at the rule after the jump.

## Deleting

Deletion works at any depth of the tree — a rule, a whole rule set,
or everything:

```console
delete firewall ipv4 forward filter rule 20
delete firewall ipv4 forward filter
delete firewall
```

Deleting the last node removes the zebra-rs tables from nftables
entirely.
