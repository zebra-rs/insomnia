# DHCP Relay

A relay carries DHCP between clients on one network and a server on
another. `service dhcp-relay` configures it for DHCPv4 and
`service dhcpv6-relay` for DHCPv6. Both are served by one process,
`insomnia-dhcp-relay`, which insomnia starts when the first relay is
configured.

A relay in a VRF uses the same leaves under `vrf <name>`; see
[DHCP in a VRF](ch-06-04-dhcp-in-a-vrf.md).

## DHCPv4 relay

```console
set interface lan1 ipv4 address 10.1.0.1/24
set interface lan2 ipv4 address 10.2.0.1/24
set interface wan1 ipv4 address 192.0.2.1/24
set service dhcp-relay listen-interface lan1
set service dhcp-relay listen-interface lan2
set service dhcp-relay upstream-interface wan1
set service dhcp-relay server 192.0.2.10
commit
```

```
dhcp-relay: relay agent loaded 2 DHCPv4 and 0 DHCPv6 listen interfaces
```

| Leaf | Meaning |
|---|---|
| `listen-interface <name>` | Where clients are. Repeatable |
| `upstream-interface <name>` | Where servers are reached, and where their replies must arrive. Repeatable |
| `server <address>` | A DHCP server. Every request goes to every server. Repeatable |
| `relay-options hop-count` | Drop a request that has already passed this many relays. 1..255, default 10 |
| `relay-options max-size` | The relay does not grow a request beyond this many bytes: when adding option 82 would, the request goes out without it. 64..1400, default 576 |
| `relay-options relay-agents-packets` | What to do with a request that already carries option 82. Default `forward` |
| `disable` | Stop relaying DHCPv4 without deleting the configuration |

A relay needs at least one listen interface, one upstream interface and
one server.

### What the relay does to a request

1. It writes the listen interface's first IPv4 address into the
   request as the gateway address (`giaddr`). The server picks the
   subnet from it and sends its reply to it, so **the server needs a
   route back to that address**.
2. It adds the relay agent information option (option 82) with the
   listen interface's name as the circuit ID. A server can use that to
   tell the LANs apart; see
   [Client classes](ch-06-01-dhcp-server.md#client-classes).
3. It forwards the request to every configured server.

A reply is delivered to the client on the listen interface the circuit
ID names, with option 82 removed.

### A request that already has option 82

When another relay sits between the client and this one, the request
arrives with that relay's option 82. `relay-agents-packets` decides:

| Value | Effect |
|---|---|
| `forward` | Pass the request on unchanged (default) |
| `append` | Add this relay's option after the existing one |
| `replace` | Replace the existing option with this relay's |
| `discard` | Drop the request |

### Replies are only accepted from where servers are

Any host on a client LAN can send something that looks like a server's
reply. The relay therefore takes a reply only when it arrives on an
upstream interface. If an interface is both a listen and an upstream
interface, a reply there must also come from one of the configured
`server` addresses. Anything else is dropped and counted in
`show dhcp relay statistics`: as `wrong-upstream` when it arrived on
an interface that is not upstream, as `unknown-server` when its sender
is not a configured server.

## DHCPv6 relay

```console
set interface lan1 ipv6 address 2001:db8:1::1/64
set interface wan1 ipv6 address 2001:db8::1/64
set service dhcpv6-relay listen-interface lan1
set service dhcpv6-relay upstream-interface wan1 address 2001:db8::10
commit
```

| Leaf | Meaning |
|---|---|
| `listen-interface <name>` | Where clients are. Repeatable |
| `listen-interface <name> address <address>` | The link address to report for that interface. Default: its first global address |
| `upstream-interface <name> address <address>` | Send requests to this address through this interface. Both are repeatable |
| `max-hop-count` | Drop a message that has already passed this many relays. 1..255, default 10 |
| `use-interface-id-option` | Add the Interface-ID option, carrying the listen interface's name |
| `disable` | Stop relaying DHCPv6 without deleting the configuration |

A relay needs a listen interface and an upstream interface with at
least one address. An upstream interface without an address is dropped
with a warning.

- **The link address** tells the server which subnet the client is on.
  A listen interface with no global address and no `address` leaf has
  none to report: requests arriving there are dropped and counted as
  `no-link-address`.
- **The upstream address** is the server's address. It may be a
  multicast address: `ff02::1:2` reaches every server and relay on the
  upstream link, without naming one.
- **`use-interface-id-option`** lets the server tell apart clients on
  links that share a prefix, and lets the relay find the right
  interface for the reply.

A reply is accepted only on an upstream interface, and on an interface
that is also a listen interface only from a unicast upstream address
configured for it. Others are counted as `wrong-upstream` or
`unknown-server`, as for DHCPv4.

## What is checked

Each of these is skipped with a warning naming it; the rest of the
relay configuration is served:

- An interface that does not exist, or that is in another VRF than the
  relay instance.
- `lo` as a DHCPv4 listen or upstream interface.
- A second instance listening on an interface another instance already
  listens on.
- An instance left without a server (DHCPv4), an upstream address
  (DHCPv6), a listen interface or an upstream interface.

The relay follows the interfaces: one that appears later, or moves into
the right VRF, is picked up without a commit.

## Differences from VyOS

- The relay agent is insomnia's own, not ISC `dhcrelay`, which is no
  longer maintained. Its configuration leaves and defaults are VyOS's.
- `vrf <name>` instances. VyOS has no relay in a VRF.
- Replies are checked as described above. `dhcrelay` accepts a reply on
  any upstream interface from any sender.
- A request longer than `max-size` is forwarded whole, without this
  relay's option 82. `dhcrelay` cuts the client's options off at
  `max-size`.
- A DHCPv6 listen interface without a global address is a counted drop
  per request, not a commit error: addresses come and go while the
  configuration stays.
- `show dhcp relay statistics` and `show dhcpv6 relay statistics`.
  VyOS has no relay counters.
