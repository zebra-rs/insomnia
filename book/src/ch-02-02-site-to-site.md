# Site-to-Site VPN

A complete site-to-site tunnel between two routers: **left**
(192.0.2.1) protects 10.0.1.0/24, **right** (192.0.2.9) protects
10.0.2.0/24.

```
   10.0.1.0/24                                    10.0.2.0/24
       │                                              │
     left  192.0.2.1 ─────── ESP tunnel ─────── 192.0.2.9  right
                 10.0.1.0/24  <───────>  10.0.2.0/24
```

## Left router

```console
set vpn ipsec authentication psk GW id 192.0.2.1
set vpn ipsec authentication psk GW id 192.0.2.9
set vpn ipsec authentication psk GW secret Zebra-Secret-1

set vpn ipsec esp-group ESP-A lifetime 1800
set vpn ipsec esp-group ESP-A proposal 10 encryption aes256gcm128
set vpn ipsec esp-group ESP-A proposal 10 hash sha256

set vpn ipsec ike-group IKE-A key-exchange ikev2
set vpn ipsec ike-group IKE-A proposal 10 dh-group 19
set vpn ipsec ike-group IKE-A proposal 10 encryption aes256gcm128
set vpn ipsec ike-group IKE-A proposal 10 hash sha256

set vpn ipsec site-to-site peer 192.0.2.9 authentication mode pre-shared-secret
set vpn ipsec site-to-site peer 192.0.2.9 connection-type initiate
set vpn ipsec site-to-site peer 192.0.2.9 default-esp-group ESP-A
set vpn ipsec site-to-site peer 192.0.2.9 ike-group IKE-A
set vpn ipsec site-to-site peer 192.0.2.9 local-address 192.0.2.1
set vpn ipsec site-to-site peer 192.0.2.9 remote-address 192.0.2.9
set vpn ipsec site-to-site peer 192.0.2.9 tunnel 1 local prefix 10.0.1.0/24
set vpn ipsec site-to-site peer 192.0.2.9 tunnel 1 remote prefix 10.0.2.0/24
```

## Right router

The mirror image — addresses swapped, and the responder waits instead
of dialing out:

```console
set vpn ipsec site-to-site peer 192.0.2.1 connection-type respond
set vpn ipsec site-to-site peer 192.0.2.1 local-address 192.0.2.9
set vpn ipsec site-to-site peer 192.0.2.1 remote-address 192.0.2.1
set vpn ipsec site-to-site peer 192.0.2.1 tunnel 1 local prefix 10.0.2.0/24
set vpn ipsec site-to-site peer 192.0.2.1 tunnel 1 remote prefix 10.0.1.0/24
```

(psk, esp-group and ike-group blocks as on the left, with the psk ids
unchanged — the key table lists **both** endpoints.)

## Verify

```console
$ show vpn ipsec sa
Connection          State  Uptime  Bytes In/Out  Packets In/Out  Remote address  Remote ID  Proposal
------------------  -----  ------  ------------  --------------  --------------  ---------  --------------
192-0-2-9-tunnel-1  up     17s     252B/252B     3/3             192.0.2.9       192.0.2.9  AES_GCM_16_256
```

Traffic between the two prefixes now flows inside ESP. Routes to the
remote prefix are installed automatically by charon (routing table
220), so no static route is needed.

## Peer options

- **connection-type** — `initiate` (default: dial immediately and
  keep retrying), `respond` (wait for the peer; the tunnel is
  installed as a trap policy and comes up on demand), or `none` (load
  the connection but do not install anything).
- **default-esp-group** — the ESP group used by tunnels that do not
  name their own; a tunnel can override it with
  `tunnel <n> esp-group <name>`.
- **description** — free-form text for the connection.

## Tunnel (traffic-selector) options

Each numbered `tunnel` is one CHILD SA — one pair of traffic
selectors:

```console
set vpn ipsec site-to-site peer <p> tunnel <n> local prefix <net>
set vpn ipsec site-to-site peer <p> tunnel <n> remote prefix <net>
set vpn ipsec site-to-site peer <p> tunnel <n> local port <1-65535>
set vpn ipsec site-to-site peer <p> tunnel <n> remote port <1-65535>
set vpn ipsec site-to-site peer <p> tunnel <n> protocol <proto>
set vpn ipsec site-to-site peer <p> tunnel <n> priority <1-100>
set vpn ipsec site-to-site peer <p> tunnel <n> disable
```

`prefix` may be repeated for multiple subnets, and the value `any`
widens the selector to all IPv4 and IPv6 traffic. `protocol` and
`port` narrow the selector to one service. If a local prefix overlaps
a remote prefix, a pass-through policy is installed automatically so
hosts inside the overlap keep talking directly.

Two more per-peer knobs round out the CHILD SA behavior:

```console
set vpn ipsec site-to-site peer <p> replay-window <0-2040>
set vpn ipsec site-to-site peer <p> virtual-address <address>
```

`replay-window` sizes IPsec replay protection (default 32; 0 disables
it). `virtual-address` requests a virtual IP from the peer.
