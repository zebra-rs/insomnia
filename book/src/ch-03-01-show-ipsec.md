# Show IPsec

Four operational views. The first two read live state from charon
over its VICI control socket — the same channel `swanctl` uses — and
answer `% IPsec process not running` when charon is unreachable. The
last two show the kernel's XFRM database and work without strongSwan.

Every command also takes `--json` for machine-readable output.

## show vpn ipsec sa

One row per CHILD SA, with live traffic counters:

```console
$ show vpn ipsec sa
Connection          State  Uptime  Bytes In/Out  Packets In/Out  Remote address  Remote ID  Proposal
------------------  -----  ------  ------------  --------------  --------------  ---------  --------------
192-0-2-9-tunnel-1  up     17s     252B/252B     3/3             192.0.2.9       192.0.2.9  AES_GCM_16_256
```

`State` is `up` once the SA is installed in the kernel; a tunnel
being re-negotiated shows `down` until the replacement installs. The
proposal column is the negotiated (not configured) algorithm set.

## show vpn ipsec connections

The loaded connections joined with their live state — one row for the
IKE SA, one per tunnel:

```console
$ show vpn ipsec connections
Connection          State  Type   Remote address  Local TS     Remote TS    Local id   Remote id  Proposal
------------------  -----  -----  --------------  -----------  -----------  ---------  ---------  ------------------------
192-0-2-9           up     IKEv2  192.0.2.9       -            -            192.0.2.1  192.0.2.9  AES_GCM/256/None/ECP_256
192-0-2-9-tunnel-1  up     IPsec  192.0.2.9       10.0.1.0/24  10.0.2.0/24  192.0.2.1  192.0.2.9  AES_GCM/256/None/None
```

This is the first place to look when a tunnel does not come up: a
connection that is loaded but `down` means charon knows the config
and the negotiation is failing (check identities and secrets); a
missing row means the config never reached charon (check the zebra-rs
log for render warnings).

## show vpn ipsec state

The kernel XFRM SA database (`ip xfrm state`):

```console
$ show vpn ipsec state
src 192.0.2.1 dst 192.0.2.9
	proto esp spi 0xc05c056a reqid 1 mode tunnel
	replay-window 0 flag af-unspec
	aead rfc4106(gcm(aes)) 0x48f1... 128
	...
```

## show vpn ipsec policy

The kernel XFRM policies (`ip xfrm policy`) — the traffic selectors
actually steering packets into the SAs:

```console
$ show vpn ipsec policy
src 10.0.1.0/24 dst 10.0.2.0/24
	dir out priority 375423
	tmpl src 192.0.2.1 dst 192.0.2.9
		proto esp spi 0xc05c056a reqid 1 mode tunnel
...
```

## Reading the views together

- config committed? → zebra-rs log shows
  `ipsec: swanctl configuration loaded`.
- charon accepted it? → `show vpn ipsec connections` lists the peer.
- negotiation succeeded? → `show vpn ipsec sa` row is `up`.
- kernel is encrypting? → `show vpn ipsec state` has the ESP SAs and
  the `sa` byte counters move with traffic.
