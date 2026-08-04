# Stateful Inspection and Connection Tracking

The kernel's connection tracker classifies every packet against the
table of known flows. The firewall's stateful matchers build on that
classification.

## Matching state

```console
set firewall ipv4 forward filter rule 10 action accept
set firewall ipv4 forward filter rule 10 state established
set firewall ipv4 forward filter rule 10 state related
```

States: `new` (would create a flow), `established` (belongs to one),
`related` (associated with one — an FTP data channel, an ICMP error
for a known flow), `invalid` (fits nothing). Several states on one
rule OR together. The rule above is the classic stateful opener: put
it first, and the rest of the rule set only ever sees the first
packet of each connection.

## Global state policy

Instead of repeating that opener in every rule set, set it once:

```console
set firewall global-options state-policy established action accept
set firewall global-options state-policy related     action accept
set firewall global-options state-policy invalid     action drop
```

The state policy is evaluated before all three filter rule sets of
both families. Each entry takes `action accept | drop | reject`, an
optional `log`, and `log-level`.

## Conntrack metadata

Filter rules can also match tracking metadata:

```console
set firewall ipv4 forward filter rule 20 connection-status nat destination
set firewall ipv4 forward filter rule 30 connection-mark 23
set firewall ipv4 forward filter rule 40 mark 100
set firewall ipv4 forward filter rule 50 packet-type broadcast
set firewall ipv4 forward filter rule 60 packet-length 1400-1500
set firewall ipv4 forward filter rule 60 packet-length-exclude 1450
```

## Bypassing conntrack: the raw chains

Tracking costs memory and CPU per flow. Flows that never need
stateful treatment can skip it in the `raw` chains, which run before
the tracker:

```console
set firewall ipv4 prerouting raw rule 5 action notrack
set firewall ipv4 prerouting raw rule 5 protocol udp
set firewall ipv4 prerouting raw rule 5 destination port 4789
```

Untracked packets show `state invalid` in the filter chains — pair a
`notrack` rule with an explicit accept for the same traffic. Because
raw chains precede the tracker, the state-dependent matchers (`state`,
`connection-mark`, `connection-status`, `mark`, `packet-*`) do not
exist there, and `notrack` exists only there.

## Timeouts

`set firewall global-options timeout …` (per-protocol conntrack
timeouts: `icmp`, `other`, and per-state `tcp` values) is accepted by
the schema but **not applied yet** — the values need a sysctl/nf
mechanism that is still open. A commit touching them logs a warning.
