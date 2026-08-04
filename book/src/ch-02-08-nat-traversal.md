# NAT Traversal

When a NAT device sits between the peers, plain ESP (IP protocol 50)
usually does not survive the translation. NAT traversal (NAT-T,
RFC 3947/3948) detects this during the IKE exchange and switches ESP
to UDP encapsulation on port 4500.

Detection and switching are automatic — charon always supports
NAT-T, so in most deployments **no configuration is needed**. Two
knobs cover the special cases.

## Forcing UDP encapsulation

```console
set vpn ipsec site-to-site peer <p> force-udp-encapsulation
```

Encapsulates ESP in UDP even when no NAT is detected. Use it when a
middlebox drops protocol 50 without translating addresses, or when
NAT detection is unreliable (some CGNAT deployments).

When the peer's address is unknown in advance (a NATed initiator),
combine identity-based keying with a wildcard remote address:

```console
set vpn ipsec site-to-site peer @branch authentication local-id @branch
set vpn ipsec site-to-site peer @branch local-address any
set vpn ipsec site-to-site peer @branch connection-type respond
```

A peer whose name starts with `@` is matched by identity rather than
address and is never dialed — the NATed side must initiate.

## MOBIKE

MOBIKE (RFC 4555, IKEv2 only) lets an endpoint change its address —
a new NAT binding, a different uplink — without re-negotiating the
tunnel. It is on by default and disabled per IKE group:

```console
set vpn ipsec ike-group <name> disable-mobike
```

Disable it only for peers whose MOBIKE implementation misbehaves; a
liveness-triggered re-negotiation (see Dead Peer Detection) then
covers address changes.
