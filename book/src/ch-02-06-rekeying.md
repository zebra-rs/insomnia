# Rekeying and SA Lifetimes

Security associations are re-negotiated before they expire. Two
layers rekey independently: the IKE SA (the control channel) and each
CHILD SA (the ESP tunnels).

## IKE SA lifetime

```console
set vpn ipsec ike-group <name> lifetime <0-86400>
```

Seconds before the IKE SA is rekeyed. Default **28800** (8 hours).

## CHILD SA lifetimes

On the ESP group, three expiry triggers — whichever fires first wins:

```console
set vpn ipsec esp-group <name> lifetime <30-86400>
set vpn ipsec esp-group <name> life-bytes <1024-26843545600000>
set vpn ipsec esp-group <name> life-packets <1000-26843545600000>
```

`lifetime` defaults to **3600** seconds; the byte and packet limits
are unset unless configured. Rekeying is make-before-break: the
replacement SA is negotiated while the old one still carries traffic,
so nothing is dropped.

To leave rekeying entirely to the remote peer:

```console
set vpn ipsec esp-group <name> disable-rekey
```

The local end then never initiates a re-key; the SA is replaced only
when the peer rekeys (or expires). Useful when exactly one side
should own the rekey schedule.

## Perfect forward secrecy

```console
set vpn ipsec esp-group <name> pfs {enable | disable | dh-group19 | …}
```

- **enable** (default) — each CHILD SA rekey runs a fresh
  Diffie-Hellman exchange, inheriting the DH group from the IKE
  group's first proposal (falling back to group 2).
- **dh-group&lt;n&gt;** — as above, but with an explicit group
  independent of the IKE group.
- **disable** — no DH exchange on rekey; keys derive from the IKE
  SA's keying material. Cheaper, but a compromised IKE SA then
  exposes past traffic.

## ESP compression

```console
set vpn ipsec esp-group <name> compression
```

Negotiates IPComp compression inside the tunnel. Rarely a win on
modern links; leave it off unless the payload is highly compressible
and the path is slow.
