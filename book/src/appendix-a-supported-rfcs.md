# Appendix A: Supported RFCs and Internet-Drafts

insomnia does not implement protocols itself. It renders configuration
for the components that do: the Linux kernel (nftables, and XFRM for
IPsec data), strongSwan's charon (IKE) and keepalived (VRRP). This
appendix lists the IETF standards whose features you can reach from the
`firewall`, `vpn ipsec` and `vrrp` configuration trees, grouped by
area. Each entry gives a one-line summary and the configuration leaves
that select it.

A standard the underlying daemon supports but the configuration tree
does not expose is not listed. Neither is planned work (NAT, zone-based
firewall, X.509 authentication, VRRP in a VRF); the chapters for those
features record their status. Leaves that are accepted but not yet
applied are listed separately at the end.

## VRRP

| RFC / Internet-Draft | Description |
| --- | --- |
| RFC 5798 | Virtual Router Redundancy Protocol (VRRP) Version 3 for IPv4 and IPv6 — always used for IPv6 groups, and for IPv4 groups with `version 3` (globally or per group); centisecond `advertise-interval` values; `v3-checksum-as-v2` for peers that compute the IPv4 checksum without the pseudo-header. |
| RFC 3768 | Virtual Router Redundancy Protocol (VRRP) — VRRPv2, the default for IPv4 groups. `rfc3768-compatibility` runs the group on a virtual-MAC interface carrying the RFC's `00-00-5E-00-01-{VRID}` address. |
| RFC 2338 | Virtual Router Redundancy Protocol (the original specification) — its simple-text-password and IP Authentication Header authentication, which RFC 3768 removed, remain available to VRRPv2 groups as `authentication type plaintext-password` / `ah` for interoperability with older peers. |

Unicast VRRP (`peer-address`, `hello-source-address`) is a keepalived
extension with no IETF specification.

## IKE and IPsec

| RFC / Internet-Draft | Description |
| --- | --- |
| RFC 7296 | Internet Key Exchange Protocol Version 2 (IKEv2) — `key-exchange ikev2`, including the liveness check behind `dead-peer-detection`, reauthentication (`ikev2-reauth`) and virtual-IP requests through the configuration payload (`virtual-address`). |
| RFC 2409 | The Internet Key Exchange (IKEv1) — `key-exchange ikev1`, Main Mode and Aggressive Mode (`mode aggressive`). RFC 9395 deprecates IKEv1; use it only for peers that cannot run IKEv2. |
| RFC 4301 | Security Architecture for the Internet Protocol — the security policy database and traffic selectors (`tunnel <n> local` / `remote` prefix, protocol and port), tunnel and transport mode (`esp-group mode`). |
| RFC 4303 | IP Encapsulating Security Payload (ESP) — the only IPsec protocol used; `replay-window` sizes its anti-replay window. |
| RFC 3173 | IP Payload Compression Protocol (IPComp) — `esp-group compression`. |
| RFC 3706 | A Traffic-Based Method of Detecting Dead IKE Peers — `dead-peer-detection` for IKEv1 peers (IKEv2 uses the RFC 7296 liveness check with the same settings). |
| RFC 3947 | Negotiation of NAT-Traversal in the IKE — NAT detection during the IKE exchange. |
| RFC 3948 | UDP Encapsulation of IPsec ESP Packets — used automatically when a NAT is detected; `force-udp-encapsulation` forces it. |
| RFC 4555 | IKEv2 Mobility and Multihoming Protocol (MOBIKE) — enabled for IKEv2 peers unless `disable-mobike` is set. |

Peers authenticate with pre-shared keys (`authentication mode
pre-shared-secret`), as defined by RFC 7296 and RFC 2409 themselves.

## IPsec cryptographic algorithms

The `encryption`, `hash`, `prf` and `dh-group` values of an
`ike-group` or `esp-group` proposal, and the `pfs` setting of an
`esp-group`. Several are listed only for interoperability with old
peers; RFC 8221 (ESP) and RFC 8247 (IKEv2) give the current
recommendations.

### Encryption

| RFC / Internet-Draft | Description |
| --- | --- |
| RFC 3602 | AES-CBC — `aes128`, `aes192`, `aes256`. |
| RFC 3686 | AES-CTR — `aes128ctr`, `aes192ctr`, `aes256ctr`. |
| RFC 4106 | AES-GCM in ESP — `aes128gcm64` … `aes256gcm128` (8-, 12- and 16-octet ICV). |
| RFC 4309 | AES-CCM in ESP — `aes128ccm64` … `aes256ccm128` (8-, 12- and 16-octet ICV). |
| RFC 5282 | AES-GCM and AES-CCM in the IKEv2 encrypted payload — the same `aes…gcm…` / `aes…ccm…` values in an `ike-group`. |
| RFC 4543 | AES-GMAC, authentication-only ESP — `aes128gmac`, `aes192gmac`, `aes256gmac`. |
| RFC 7634 | ChaCha20 and Poly1305 in IKE and IPsec — `chacha20poly1305`. |
| RFC 4312 | Camellia-CBC — `camellia128`, `camellia192`, `camellia256`. |
| RFC 5529 | Camellia CTR and CCM modes — `camellia128ctr` …, `camellia128ccm64` … `camellia256ccm128`. |
| RFC 2451 | ESP CBC-mode ciphers — `3des`, `blowfish128`/`192`/`256`, `cast128`. |
| RFC 2410 | The NULL encryption algorithm — `null`. |

`serpent…` and `twofish…` have no RFC; strongSwan negotiates them with
private-use transform identifiers, so both peers must be strongSwan.

### Integrity (`hash`)

| RFC / Internet-Draft | Description |
| --- | --- |
| RFC 2403 | HMAC-MD5-96 — `md5`. |
| RFC 2404 | HMAC-SHA-1-96 — `sha1`. |
| RFC 4868 | HMAC-SHA-256-128, HMAC-SHA-384-192, HMAC-SHA-512-256 — `sha256`, `sha384`, `sha512`. |
| RFC 3566 | AES-XCBC-MAC-96 — `aesxcbc`. |
| RFC 4494 | AES-CMAC-96 — `aescmac`. |
| RFC 4543 | AES-GMAC as integrity — `aes128gmac`, `aes192gmac`, `aes256gmac`. |

`md5_128`, `sha1_160` and `sha256_96` are non-standard truncation
lengths that strongSwan offers for interoperability with older
implementations.

### Pseudo-random function (`prf`)

| RFC / Internet-Draft | Description |
| --- | --- |
| RFC 2104 | HMAC — `prfmd5`, `prfsha1`. |
| RFC 4868 | HMAC-SHA-2 PRFs — `prfsha256`, `prfsha384`, `prfsha512`. |
| RFC 4434 | AES-XCBC-PRF-128 — `prfaesxcbc`. |
| RFC 4615 | AES-CMAC-PRF-128 — `prfaescmac`. |

### Diffie-Hellman groups (`dh-group`, `pfs`)

| RFC / Internet-Draft | Description |
| --- | --- |
| RFC 2409 | 768- and 1024-bit MODP groups — groups 1 and 2. |
| RFC 3526 | More MODP groups — group 5 (1536-bit) and groups 14–18 (2048- to 8192-bit). |
| RFC 5114 | MODP groups with prime-order subgroups, groups 22–24, and random ECP groups 25–26 (192- and 224-bit). |
| RFC 5903 | Elliptic-curve groups over NIST primes — groups 19–21 (P-256, P-384, P-521). |
| RFC 6954 | Brainpool elliptic curves — groups 27–30. |
| RFC 8031 | Curve25519 and Curve448 — groups 31 and 32. |

## Firewall

The firewall matches on header fields defined by the base protocol
specifications. Connection tracking and the `state-policy` chain are
Linux netfilter features with no IETF specification.

| RFC / Internet-Draft | Description |
| --- | --- |
| RFC 791 | Internet Protocol (IPv4) — `ttl` matches and `fragment match-frag` / `match-non-frag`. |
| RFC 8200 | Internet Protocol, Version 6 (IPv6) — `hop-limit` matches; `fragment` matches use the Fragment extension header. |
| RFC 792 | Internet Control Message Protocol — `icmp type`, `code` and `type-name`. |
| RFC 4443 | ICMPv6 — `icmpv6 type`, `code` and `type-name`. |
| RFC 4861 | Neighbor Discovery for IPv6 — the `nd-*` ICMPv6 type names (`nd-router-advert`, `nd-neighbor-solicit`, …). |
| RFC 9293 | Transmission Control Protocol — `tcp flags` (`syn`, `ack`, `fin`, `rst`, `psh`, `urg`) and `tcp mss`, the Maximum Segment Size option. |
| RFC 3168 | Explicit Congestion Notification — the `ecn` (ECE) and `cwr` TCP flags. |
| RFC 2474 | Differentiated Services Field — `dscp` and `dscp-exclude`. |

## Accepted but not yet applied

These leaves are in the schema and survive a commit, but insomnia
ignores them for now: applying them needs sysctl writes, a different
mechanism from the nftables ruleset.

| RFC / Internet-Draft | Leaf |
| --- | --- |
| RFC 1337 | TIME-WAIT assassination hazards — `firewall global-options twa-hazards-protection`. |
| RFC 3704 | Ingress filtering for multihomed networks (reverse-path filtering) — `firewall global-options source-validation`, `ipv6-source-validation`. |
| RFC 4987 | TCP SYN flooding attacks and mitigations (SYN cookies) — `firewall global-options syn-cookies`. |
