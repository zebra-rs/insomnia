# IKEv2 Configuration

An **IKE group** describes phase 1: which IKE version to speak, which
cryptographic proposals to offer, and how the control channel is
maintained. Peers reference the group by name, so several tunnels can
share one policy.

```console
set vpn ipsec ike-group IKE-A key-exchange ikev2
set vpn ipsec ike-group IKE-A lifetime 7200
set vpn ipsec ike-group IKE-A proposal 10 dh-group 19
set vpn ipsec ike-group IKE-A proposal 10 encryption aes256gcm128
set vpn ipsec ike-group IKE-A proposal 10 hash sha256
```

## Key exchange version

```console
set vpn ipsec ike-group <name> key-exchange {ikev1 | ikev2}
```

Prefer `ikev2`. When the leaf is unset the connection accepts either
version (it is offered as version 0 — "any" — to charon). IKEv1 also
takes a phase 1 mode:

```console
set vpn ipsec ike-group <name> mode {main | aggressive}
```

`main` (the default) is recommended; `aggressive` is faster but leaks
identity information and is widely considered insecure.

## Proposals

A group holds one or more numbered proposals, offered in ascending
order. A proposal needs at least `encryption` and `hash`; `dh-group`
and `prf` are optional:

```console
set vpn ipsec ike-group IKE-A proposal 10 encryption aes256gcm128
set vpn ipsec ike-group IKE-A proposal 10 hash sha256
set vpn ipsec ike-group IKE-A proposal 10 dh-group 19
set vpn ipsec ike-group IKE-A proposal 10 prf prfsha384
set vpn ipsec ike-group IKE-A proposal 20 encryption aes256
set vpn ipsec ike-group IKE-A proposal 20 hash sha512
```

- **encryption** — the full VyOS list is available: AES-CBC/CTR/CCM/GCM
  at 128/192/256 bits, ChaCha20-Poly1305, Camellia, 3DES and others.
  AEAD ciphers such as `aes256gcm128` carry their own integrity, and
  pair with a `hash` used as the PRF.
- **hash** — `md5`, `sha1`, `sha256`, `sha384`, `sha512`, `aesxcbc`,
  `aescmac` and GMAC variants.
- **dh-group** — Diffie-Hellman group `1`, `2`, `5` or `14`–`32`
  (MODP, ECP, brainpool and curve25519/448 groups). Defaults to
  group 2 when unset; pick at least group 14, ideally an ECP group
  such as `19` (ecp256) or `20` (ecp384).
- **prf** — explicit pseudo-random function (`prfsha256`,
  `prfsha384`, …) for peers that negotiate it separately.

## Control-channel maintenance

```console
set vpn ipsec ike-group <name> lifetime <0-86400>
set vpn ipsec ike-group <name> close-action {none | trap | start}
set vpn ipsec ike-group <name> ikev2-reauth
set vpn ipsec ike-group <name> disable-mobike
```

- **lifetime** — seconds before the IKE SA is rekeyed (default
  28800).
- **close-action** — what to do when the peer unexpectedly closes a
  child SA: `none` (default) does nothing, `trap` re-negotiates when
  matching traffic appears, `start` re-negotiates immediately.
- **ikev2-reauth** — perform a full re-authentication instead of a
  simple rekey (IKEv2 only).
- **disable-mobike** — turn off MOBIKE mobility support (IKEv2 only;
  see the NAT Traversal chapter).

Dead peer detection is also configured on the IKE group; it has its
own chapter.
