#!/usr/bin/env python3
"""dhcp_forge.py MODE ARGS…: send one crafted DHCP message from a client
namespace, as a misbehaving client would. Run with `python3 -I`.

  bootreply  TO GIADDR    a BOOTREPLY (an OFFER for 10.1.0.77) to TO:67,
                          as if a server answered a relay at GIADDR
  bootrequest TO HOPS     a DISCOVER with `hops` HOPS, unicast to TO:67
  relayrepl  IFACE LINK   a Relay-repl for link-address LINK, multicast
                          to ff02::1:2 port 547 on IFACE

The relay must drop the first and third (a reply arriving on a listen
interface from a non-server) and count them; the second exercises the
hop limit. Each message is sent from the protocol's own port, which
needs root: the harness runs this under `sudo ip netns exec`.
"""
import socket
import struct
import sys

MAC = bytes.fromhex("02000000ee01")
COOKIE = bytes([99, 130, 83, 99])


def bootp(op, hops, yiaddr, giaddr, options):
    header = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        op, 1, 6, hops, 0x11223344, 0, 0,
        bytes(4), socket.inet_aton(yiaddr), bytes(4), socket.inet_aton(giaddr),
        MAC + bytes(10), bytes(64), bytes(128),
    )
    return header + COOKIE + options + bytes([255])


def send4(to, payload):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 67))
    s.sendto(payload, (to, 67))


def main(argv):
    mode = argv[1] if len(argv) > 1 else ""
    if mode == "bootreply" and len(argv) == 4:
        # DHCPOFFER from server 192.0.2.10.
        options = bytes([53, 1, 2, 54, 4, 192, 0, 2, 10])
        send4(argv[2], bootp(2, 1, "10.1.0.77", argv[3], options))
    elif mode == "bootrequest" and len(argv) == 4:
        options = bytes([53, 1, 1])
        send4(argv[2], bootp(1, int(argv[3]), "0.0.0.0", "0.0.0.0", options))
    elif mode == "relayrepl" and len(argv) == 4:
        advertise = bytes([2, 0xAB, 0xCD, 0xEF])
        repl = (
            bytes([13, 0])
            + socket.inet_pton(socket.AF_INET6, argv[3])
            + socket.inet_pton(socket.AF_INET6, "fe80::ff:fe00:ee01")
            + struct.pack("!HH", 9, len(advertise))
            + advertise
        )
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("::", 547))
        s.sendto(repl, ("ff02::1:2", 547, 0, socket.if_nametoindex(argv[2])))
    else:
        sys.exit(__doc__)
    print(f"sent {mode}")


if __name__ == "__main__":
    main(sys.argv)
