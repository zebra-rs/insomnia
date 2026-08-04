# Destination NAT and Port Forwarding

> **Status: planned.** Like source NAT, destination NAT belongs to
> the not-yet-ported `set nat …` tree. This page records the target
> model.

Destination NAT rewrites the destination of inbound traffic — port
forwarding:

```console
set nat destination rule 10 inbound-interface name eth0     (planned)
set nat destination rule 10 protocol tcp
set nat destination rule 10 destination port 443
set nat destination rule 10 translation address 10.0.0.5
set nat destination rule 10 translation port 8443
```

Traffic arriving on eth0:443 is delivered to the internal server
10.0.0.5:8443.

## Interaction with the firewall

Destination NAT happens **before** the forward filter, so filter
rules match the translated (internal) destination — a forwarding
rule for the example above permits `destination address 10.0.0.5
port 8443`, not the public address. The
`connection-status nat destination` matcher (already implemented)
matches such flows generically:

```console
set firewall ipv4 forward filter rule 20 action accept
set firewall ipv4 forward filter rule 20 connection-status nat destination
set firewall ipv4 forward filter rule 20 state new
```

That pair — DNAT rule plus a state-new/connection-status accept — is
the canonical port-forward policy and will work unchanged once the
NAT tree lands.
