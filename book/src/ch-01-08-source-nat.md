# Source NAT and Masquerade

> **Status: planned.** In VyOS, NAT is its own configuration tree
> (`set nat …`, distinct from `set firewall …`), and that tree has
> not been ported yet. This page records the target model.

Source NAT rewrites the source address of outbound traffic — the
classic "many private hosts behind one public address" setup:

```console
set nat source rule 100 outbound-interface name eth0     (planned)
set nat source rule 100 source address 192.168.0.0/24
set nat source rule 100 translation address masquerade
```

`masquerade` uses whatever address the outbound interface currently
has (right for dynamic addresses); a static deployment names the
address or a pool explicitly:

```console
set nat source rule 100 translation address 203.0.113.7
set nat source rule 110 translation address 203.0.113.8-203.0.113.15
```

## Interaction with the firewall

NAT and the filter chains see packets at different points: source NAT
happens **after** the forward filter, so filter rules always match
the original, pre-translation source address. Conntrack ties the two
together — reply packets are de-translated automatically and arrive
at the filter as `established`.

The `connection-status nat source` matcher (already implemented)
matches flows that have undergone source translation, which will be
the bridge between the two trees once NAT lands.
