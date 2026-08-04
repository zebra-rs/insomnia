# Route-Based VPN (VTI)

> **Status: preview.** The `vti` configuration is accepted and
> rendered, but zebra-rs does not yet provide the `interfaces vti`
> tree that creates the kernel VTI device, nor the up/down helper the
> rendered configuration references. Until those land, use
> policy-based tunnels (the `tunnel <n>` traffic selectors) — this
> chapter documents the intended semantics.

A policy-based tunnel encrypts exactly what its traffic selectors
match. A **route-based** tunnel instead binds the peer to a virtual
tunnel interface (VTI): everything the routing table sends into the
interface is encrypted, so ordinary routing — static routes, IGPs,
BGP — decides what enters the VPN.

```console
set vpn ipsec site-to-site peer <p> vti bind vti0
set vpn ipsec site-to-site peer <p> vti esp-group ESP-A
```

With a `vti bind` and no `tunnel` entries, the connection gets a
single wildcard CHILD SA (`0.0.0.0/0, ::/0` on both sides) marked
with the interface key derived from the VTI number, and the kernel
routes — not the IPsec policies — steer traffic:

```console
set interfaces vti vti0 address 10.255.0.1/30      (planned)
set protocols static route 10.0.2.0/24 next-hop 10.255.0.2
```

The ESP group is taken from `vti esp-group`, falling back to the
peer's `default-esp-group`. `tunnel` entries and `vti` can coexist;
in that case the tunnels keep their selectors and the VTI interface
key is attached to each CHILD SA.
