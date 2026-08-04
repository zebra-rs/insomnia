# Zone-Based Firewall

> **Status: planned.** The `firewall zone` tree is not implemented
> yet. This chapter sketches the model so rule sets written today
> translate cleanly when it lands; until then, attach rule sets to
> the hooks directly and scope them with `inbound-interface` /
> `outbound-interface` matches.

In the zone model you stop thinking in hooks and start thinking in
**zones** — groups of interfaces with the same trust level (LAN, WAN,
DMZ, and the router itself as the built-in `local` zone). Traffic is
only permitted between a pair of zones if a policy names a rule set
for that direction:

```console
set firewall zone LAN member interface eth1        (planned)
set firewall zone WAN member interface eth0        (planned)
set firewall zone LAN from WAN firewall name WAN-TO-LAN
set firewall zone WAN from LAN firewall name LAN-TO-WAN
```

Everything not explicitly allowed between two zones is dropped —
default-deny falls out of the structure instead of being written per
hook.

The custom chains the zone policies reference (`firewall ipv4 name
WAN-TO-LAN` and friends) are exactly today's custom chains, so the
rule-writing part of a future zone migration is already covered by
the current implementation.

## The interim pattern

The same segmentation is expressible now with interface matches on
the forward filter:

```console
set firewall ipv4 forward filter rule 100 action jump
set firewall ipv4 forward filter rule 100 inbound-interface name eth0
set firewall ipv4 forward filter rule 100 outbound-interface name eth1
set firewall ipv4 forward filter rule 100 jump-target WAN-TO-LAN
set firewall ipv4 forward filter default-action drop
```

One jump rule per zone pair, then all policy lives in the custom
chains — which is precisely what the zone frontend will generate.
