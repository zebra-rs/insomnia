# Static (One-to-One) NAT

> **Status: planned.** Part of the not-yet-ported `set nat …` tree.

Static NAT binds one external address to one internal address in both
directions — inbound connections to the external address reach the
internal host, and that host's outbound traffic leaves with the
external address:

```console
set nat static rule 10 inbound-interface name eth0          (planned)
set nat static rule 10 destination address 203.0.113.7
set nat static rule 10 translation address 10.0.0.7
```

Equivalent to a destination-NAT rule plus the mirrored source-NAT
rule, generated as a pair.

Until the tree lands, the firewall side of a one-to-one mapping —
admitting the forwarded flows — is expressed exactly as in the
destination-NAT chapter: `state new` plus
`connection-status nat destination` accepts on the forward filter.
