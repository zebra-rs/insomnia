# IPv6 Firewall

IPv6 has its own tree with exactly the same shape as IPv4 — the same
hooks, the same rule matchers, its own groups and custom chains:

```console
set firewall ipv6 forward filter default-action drop
set firewall ipv6 forward filter rule 10 action accept
set firewall ipv6 forward filter rule 10 state established
set firewall ipv6 forward filter rule 10 state related
set firewall ipv6 input filter rule 20 action accept
set firewall ipv6 input filter rule 20 source address 2001:db8::/32
set firewall ipv6 name V6-DMZ rule 1 action drop
```

The rendered rules live in a separate nftables table
(`ip6 zebra_firewall`), so the two families never interfere.

## What differs from IPv4

- **`icmpv6`** replaces `icmp`:

  ```console
  set firewall ipv6 input filter rule 30 action accept
  set firewall ipv6 input filter rule 30 icmpv6 type-name nd-router-advert
  set firewall ipv6 input filter rule 30 icmpv6 type 128
  set firewall ipv6 input filter rule 30 icmpv6 code 0
  ```

- **`hop-limit`** replaces `ttl`:

  ```console
  set firewall ipv6 input filter rule 40 hop-limit eq 255
  set firewall ipv6 input filter rule 40 hop-limit gt 64
  set firewall ipv6 input filter rule 40 hop-limit lt 10
  ```

- **Groups** use the IPv6 variants: `ipv6-address-group` and
  `ipv6-network-group` (rendered as `A6_*`/`N6_*` sets); port,
  interface and mac groups are shared spellings configured per
  family.

## Do not blanket-drop ICMPv6

IPv6 does not work without ICMPv6: neighbor discovery replaces ARP,
routers advertise themselves with RAs, and path MTU discovery is
mandatory because routers never fragment. A conservative input
policy admits at least:

```console
set firewall ipv6 input filter rule 10 action accept
set firewall ipv6 input filter rule 10 icmpv6 type-name nd-neighbor-solicit
set firewall ipv6 input filter rule 11 action accept
set firewall ipv6 input filter rule 11 icmpv6 type-name nd-neighbor-advert
set firewall ipv6 input filter rule 12 action accept
set firewall ipv6 input filter rule 12 icmpv6 type-name nd-router-advert
set firewall ipv6 input filter rule 13 action accept
set firewall ipv6 input filter rule 13 icmpv6 type-name packet-too-big
```

One CLI note: because commands complete by unambiguous prefix,
typing `icmp` inside the ipv6 tree completes to `icmpv6` — there is
no separate `icmp` node there.
