# Match Criteria

All criteria set on a rule must match for the rule to fire. This
chapter lists the matchers common to IPv4 and IPv6 filter rules;
family-specific ones (`icmp`/`ttl` vs `icmpv6`/`hop-limit`) are
covered in the IPv6 chapter, and the conntrack-dependent matchers in
the connection-tracking chapter.

## Endpoints

`source` and `destination` take the same sub-tree:

```console
set firewall ipv4 forward filter rule 10 source address 192.168.1.10
set firewall ipv4 forward filter rule 10 source address 192.168.1.0/24
set firewall ipv4 forward filter rule 10 source address 10.0.0.1-10.0.0.5
set firewall ipv4 forward filter rule 10 source address !10.9.9.9
set firewall ipv4 forward filter rule 10 source address-mask 0.0.0.255
set firewall ipv4 forward filter rule 10 source mac-address 00:11:22:33:44:55
set firewall ipv4 forward filter rule 10 destination port 443
set firewall ipv4 forward filter rule 10 destination port 8000-8080
set firewall ipv4 forward filter rule 10 destination port http,https
set firewall ipv4 forward filter rule 10 destination group address-group SERVERS
```

`address` accepts a host, a prefix, a range, and `!`-negation.
`port` accepts numbers, service names, ranges and comma lists.
`group` references named groups (address-, network-, port-,
mac-group) — see the groups chapter.

## Protocol

```console
set firewall ipv4 forward filter rule 10 protocol tcp
set firewall ipv4 forward filter rule 10 protocol tcp_udp
set firewall ipv4 forward filter rule 10 protocol !udp
set firewall ipv4 forward filter rule 10 protocol 47
```

Any name from /etc/protocols or a number; `tcp_udp` matches both;
`all` matches everything; `!` negates.

## TCP flags and MSS

```console
set firewall ipv4 input filter rule 20 tcp flags syn
set firewall ipv4 input filter rule 20 tcp flags not ack
set firewall ipv4 input filter rule 20 tcp mss 1-500
```

Flags listed directly must be set, flags under `not` must be clear —
the example matches SYN-without-ACK (new connection attempts). Flags:
`syn ack fin rst urg psh ecn cwr`.

## Interfaces

```console
set firewall ipv4 forward filter rule 10 inbound-interface name eth0
set firewall ipv4 forward filter rule 10 outbound-interface group WAN
```

`inbound-interface` exists on forward and input, `outbound-interface`
on forward and output — matching VyOS hook semantics. Custom chains
accept both. `name` takes an interface (wildcards like `eth*` work),
`group` an interface-group.

## Packet properties

```console
set firewall ipv4 forward filter rule 10 dscp 46
set firewall ipv4 forward filter rule 10 dscp 40-47
set firewall ipv4 forward filter rule 10 dscp-exclude 46
set firewall ipv4 forward filter rule 10 fragment match-frag
set firewall ipv4 forward filter rule 10 fragment match-non-frag
```

## Rate limiting and hit tracking

```console
set firewall ipv4 input filter rule 30 limit rate 5/minute
set firewall ipv4 input filter rule 30 limit burst 10
set firewall ipv4 input filter rule 40 recent count 4
set firewall ipv4 input filter rule 40 recent time minute
```

`limit` caps how often the rule may fire; `recent` matches a source
seen more than `count` times within the window — the classic
brute-force throttle, typically paired with `action drop`.

## Time

```console
set firewall ipv4 forward filter rule 50 time starttime 09:00:00
set firewall ipv4 forward filter rule 50 time stoptime 17:00:00
set firewall ipv4 forward filter rule 50 time weekdays Mon,Tue,Wed,Thu,Fri
set firewall ipv4 forward filter rule 50 time startdate 2026-01-01
set firewall ipv4 forward filter rule 50 time stopdate 2026-12-31
```
