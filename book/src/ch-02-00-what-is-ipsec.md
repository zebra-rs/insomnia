# IPsec

zebra-rs provides VyOS-compatible IPsec VPN configuration. You describe
tunnels with the familiar `set vpn ipsec …` command tree; on every
commit zebra-rs renders a complete strongSwan `swanctl.conf` and loads
it into the running charon IKE daemon. Loading is declarative: whatever
you removed from the configuration is unloaded from charon in the same
step, so there is never a drift between the config tree and the daemon.

IPsec support is part of the optional ISO feature set. Start the daemon
with the feature enabled:

```console
$ zebra-rs --feature iso
```

Without `--feature iso` the whole `vpn` subtree is absent from the
schema — the commands do not complete and do not parse.

## Prerequisites

zebra-rs drives strongSwan but does not manage its lifecycle. Two
packages must be installed, and charon must be running:

```console
$ sudo apt install charon-systemd strongswan-swanctl
$ sudo systemctl enable --now strongswan
```

If charon is not running, configuration is still validated, rendered
and written to `/etc/swanctl/swanctl.conf` — a warning is logged and
the config is picked up by the next `swanctl -q` or daemon start.

## What is supported

- **Site-to-site tunnels** with pre-shared key authentication,
  IKEv1 and IKEv2, policy-based (traffic-selector) tunnels.
- **ESP and IKE proposal groups** with the full VyOS cipher, hash,
  PRF and Diffie-Hellman group lists.
- **Dead peer detection**, rekey/lifetime tuning, PFS, transport
  mode, NAT traversal.
- **Operational visibility**: `show vpn ipsec sa | connections |
  state | policy` — live SA state is read back from charon over its
  VICI control socket, kernel state via `ip xfrm`.

Certificate (X.509/RSA) authentication, IKEv2 remote-access,
DMVPN profiles and route-based VTI tunnels are planned; see the notes
in each chapter.

## The configuration tree at a glance

```
vpn ipsec
├── authentication psk <name>       pre-shared keys, matched by id
├── esp-group <name>                ESP proposals, mode, lifetimes, PFS
├── ike-group <name>                IKE version, proposals, DPD
├── interface <name>                interfaces charon listens on
├── log                             charon logging (planned)
├── options                         global charon options (planned)
└── site-to-site peer <name>        one connection per peer
    ├── authentication              mode, local-id, remote-id
    ├── tunnel <n>                  traffic selectors per tunnel
    └── vti                         route-based binding (planned)
```

A minimal working configuration is three blocks: an IKE group, an ESP
group, and a peer that references both — plus a pre-shared key entry.
The next chapters build exactly that, starting with the IKE group.
