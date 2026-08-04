# Transport Mode

Tunnel mode (the default) wraps the whole original packet in a new
IP header — the right choice for site-to-site VPNs between networks.
**Transport mode** protects only the payload between the two tunnel
endpoints themselves: the original addresses stay on the wire, and
the traffic selectors are the endpoint addresses, not configured
prefixes.

Transport mode is set on the ESP group:

```console
set vpn ipsec esp-group ESP-T mode transport
set vpn ipsec esp-group ESP-T proposal 10 encryption aes128
set vpn ipsec esp-group ESP-T proposal 10 hash sha1
```

and used by a tunnel like any other ESP group:

```console
set vpn ipsec site-to-site peer 192.0.2.9 tunnel 2 esp-group ESP-T
set vpn ipsec site-to-site peer 192.0.2.9 tunnel 2 protocol tcp
set vpn ipsec site-to-site peer 192.0.2.9 tunnel 2 local port 179
```

For a transport-mode tunnel the selectors are built from the peer's
`local-address` and `remote-address`; `protocol` and `port` narrow
them to one service. The example above protects a BGP session
(TCP/179) between the two routers while leaving other traffic
untouched.

The classic use is protecting host-to-host or router-to-router
control traffic, and carrying GRE for GRE-over-IPsec designs where a
routing protocol runs across the tunnel (the DMVPN `profile` tree,
which automates that pattern, is planned).
