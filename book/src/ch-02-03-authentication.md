# Authentication: Pre-Shared Keys and X.509

## Pre-shared keys

Pre-shared keys live in a table of their own, separate from the peers
that use them:

```console
set vpn ipsec authentication psk <name> id <id>
set vpn ipsec authentication psk <name> secret <secret>
```

A key entry lists the IKE identities it is valid for — typically both
endpoint addresses of a tunnel:

```console
set vpn ipsec authentication psk GW id 192.0.2.1
set vpn ipsec authentication psk GW id 192.0.2.9
set vpn ipsec authentication psk GW secret Zebra-Secret-1
```

During the IKE exchange charon selects the secret whose `id` list
matches the peer's identity. **List both ends**: the local identity is
needed to compute the authentication payload, the remote identity to
verify the peer's. One table can hold several named keys for different
peer sets.

The peer itself only declares that it authenticates with a pre-shared
key:

```console
set vpn ipsec site-to-site peer <p> authentication mode pre-shared-secret
```

> Note for VyOS 1.3 users: there is no per-peer
> `authentication pre-shared-secret` leaf. Since VyOS 1.5 (which this
> implementation follows) secrets live only in the
> `authentication psk` table, matched by identity.

## IKE identities

By default the peers identify themselves by their IP addresses. Both
can be overridden:

```console
set vpn ipsec site-to-site peer <p> authentication local-id <id>
set vpn ipsec site-to-site peer <p> authentication remote-id <id>
```

Overriding matters when an endpoint sits behind NAT (its source
address is not the address the peer sees) or when you key the psk
table by names such as `@branch` instead of addresses. `remote-id`
defaults to `%any`, accepting whatever identity the peer presents —
tighten it for production tunnels.

The generated `swanctl.conf` and the loaded secrets are written with
mode 0600; treat the running-config output with the same care, as it
contains the secrets in the clear.

## X.509 and RSA (planned)

Certificate-based authentication (`authentication mode x509`,
`authentication mode rsa`, and `use-x509-id`) requires the PKI
configuration tree (`set pki …`) which zebra-rs does not ship yet.
The `mode` enumeration will grow the `x509` and `rsa` values together
with that tree.
