//! DHCPv4 relaying (RFC 1542 §4, RFC 3046), following `dhcrelay` 4.4
//! as VyOS runs it: `-a -c <hop-count> -A <max-size> -m <policy>
//! -id <listen>… -iu <upstream>… <server>…`.
//!
//! Pure functions: received bytes, the binding and an interface
//! snapshot in; the packet to send and how to deliver it out.
//! `relay.rs` owns the sockets.
//!
//! Requests (BOOTREQUEST on a listen interface):
//! - a request whose `giaddr` is one of our own addresses is dropped
//!   (a forwarding loop);
//! - `hops` at `hop-count` drops the request, otherwise it is
//!   incremented;
//! - a zero `giaddr` becomes the listen interface's first IPv4 address;
//! - with `agent-information`, a DHCP request (one with option 53) gets
//!   option 82 with circuit ID = the listen interface name, subject to
//!   `relay-agents-packets` when it already carries option 82; BOOTP
//!   requests pass unchanged;
//! - the result goes to every server, from the listen interface's first
//!   address.
//!
//! Replies (BOOTREPLY to one of our addresses):
//! - the binding is the listen interface named by our circuit ID, else
//!   the one holding `giaddr`;
//! - with `upstream-interfaces`, the reply must have arrived on one;
//! - a reply arriving on a listen interface is accepted only when that
//!   interface is also in `upstream-interfaces` and the sender is one
//!   of `servers`. Any client there can send a BOOTREPLY; without this
//!   check the relay would carry a client's forged offer onto another
//!   listen interface's segment;
//! - option 82 is stripped (when we add it);
//! - broadcast when the client asked for it, has no `yiaddr` yet or is
//!   not on Ethernet; otherwise unicast to `yiaddr` at `chaddr`. Both
//!   are built as whole IPv4 datagrams for the `AF_PACKET` socket, as
//!   `dhcrelay` sends them: a client cannot answer ARP before it has
//!   the address, and a broadcast must leave through the listen
//!   interface whatever the routing table says.
//!
//! Deviations from `dhcrelay`:
//! - A request already longer than `max-size` is forwarded whole,
//!   without our option 82. `dhcrelay` stops copying options at
//!   `max-size`, cutting the client's options off.
//! - Option 82 is recognised wherever it sits. `dhcrelay` leaves an
//!   option 82 that precedes option 53 alone.
//! - Every option 82 instance in a reply is stripped, not only the
//!   instance carrying our circuit ID: with `append` the server may
//!   merge the downstream relay's and ours into one (RFC 3396).
//! - The listen-interface check on replies above. `dhcrelay` accepts a
//!   reply on any upstream interface from any sender.

use std::net::Ipv4Addr;

use dhcp_packet::v4::{
    BOOTREPLY, BOOTREQUEST, CLIENT_PORT, DhcpOption, Packet, RelayAgentInfo, SERVER_PORT, opt,
};

use crate::config::{AgentPolicy, Binding4};
use crate::ifaces::{Arrival, Ifaces};

const BROADCAST_MAC: [u8; 6] = [0xff; 6];

/// Why a packet was not relayed; [`Drop::reason`] is the counter name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Drop {
    Malformed,
    HopLimit,
    OwnGiaddr,
    AgentOptionPresent,
    NoAddress,
    NoBinding,
    WrongUpstream,
    UnknownServer,
    InterfaceDown,
}

impl Drop {
    pub fn reason(self) -> &'static str {
        match self {
            Drop::Malformed => "malformed",
            Drop::HopLimit => "hop-limit",
            Drop::OwnGiaddr => "own-giaddr",
            Drop::AgentOptionPresent => "agent-option-present",
            Drop::NoAddress => "no-address",
            Drop::NoBinding => "no-binding",
            Drop::WrongUpstream => "wrong-upstream",
            Drop::UnknownServer => "unknown-server",
            Drop::InterfaceDown => "interface-down",
        }
    }
}

/// A request ready for the servers.
#[derive(Debug, PartialEq, Eq)]
pub struct Forward {
    pub packet: Vec<u8>,
    /// The listen interface's first address: the request leaves from
    /// it, so the servers answer there.
    pub source: Ipv4Addr,
    /// Option 82 was due but would have exceeded `max-size`.
    pub agent_option_omitted: bool,
}

/// A BOOTREQUEST received on `binding.interface`.
pub fn request(buf: &[u8], binding: &Binding4, ifaces: &Ifaces) -> Result<Forward, Drop> {
    let mut p = Packet::parse(buf).map_err(|_| Drop::Malformed)?;
    if p.op != BOOTREQUEST {
        return Err(Drop::Malformed);
    }
    if !p.giaddr.is_unspecified() && ifaces.is_local_v4(p.giaddr) {
        return Err(Drop::OwnGiaddr);
    }
    if p.hops >= binding.hop_count {
        return Err(Drop::HopLimit);
    }
    p.hops += 1;
    let source = ifaces
        .get(&binding.interface)
        .ok_or(Drop::InterfaceDown)?
        .primary_v4()
        .ok_or(Drop::NoAddress)?;
    if p.giaddr.is_unspecified() {
        p.giaddr = source;
    }

    let mut agent_option_omitted = false;
    if binding.agent_information && p.message_type().is_some() {
        let present = p.option(opt::RELAY_AGENT_INFORMATION).is_some();
        let add = match (present, binding.relay_agents_packets) {
            (false, _) | (true, AgentPolicy::Append) => true,
            (true, AgentPolicy::Forward) => false,
            (true, AgentPolicy::Replace) => {
                p.remove_options(opt::RELAY_AGENT_INFORMATION);
                true
            }
            (true, AgentPolicy::Discard) => return Err(Drop::AgentOptionPresent),
        };
        if add {
            // The interface name is at most 15 bytes, so this always fits.
            let data = RelayAgentInfo::with_circuit_id(binding.interface.as_bytes())
                .emit()
                .unwrap_or_default();
            if p.unpadded_len() + 2 + data.len() <= usize::from(binding.max_size) {
                p.push_option(DhcpOption {
                    code: opt::RELAY_AGENT_INFORMATION,
                    data,
                });
            } else {
                agent_option_omitted = true;
            }
        }
    }
    Ok(Forward {
        packet: p.emit(),
        source,
        agent_option_omitted,
    })
}

/// A reply for the client, to send through the `AF_PACKET` socket.
#[derive(Debug, PartialEq, Eq)]
pub struct Reply<'a> {
    pub binding: &'a Binding4,
    pub broadcast: bool,
    /// The client's MAC address, or all ones.
    pub mac: [u8; 6],
    /// The whole IPv4 datagram: UDP 67 → 68, to `yiaddr` or
    /// 255.255.255.255.
    pub datagram: Vec<u8>,
}

/// A BOOTREPLY addressed to one of our addresses. `bindings` is the
/// whole `dhcp4` list.
pub fn reply<'a>(
    buf: &[u8],
    from: &Arrival<Ipv4Addr>,
    bindings: &'a [Binding4],
    ifaces: &Ifaces,
) -> Result<Reply<'a>, Drop> {
    let mut p = Packet::parse(buf).map_err(|_| Drop::Malformed)?;
    if p.op != BOOTREPLY {
        return Err(Drop::Malformed);
    }
    if p.giaddr.is_unspecified() {
        return Err(Drop::NoBinding);
    }
    let in_vrf = || bindings.iter().filter(|b| b.vrf == from.vrf);
    let by_circuit = circuit_id(&p).and_then(|id| {
        in_vrf().find(|b| b.agent_information && b.interface.as_bytes() == id.as_slice())
    });
    let binding = by_circuit
        .or_else(|| {
            in_vrf().find(|b| {
                ifaces
                    .get(&b.interface)
                    .is_some_and(|i| i.v4.contains(&p.giaddr))
            })
        })
        .ok_or(Drop::NoBinding)?;
    check_upstream(binding, from)?;
    let iface = ifaces.get(&binding.interface).ok_or(Drop::InterfaceDown)?;
    if binding.agent_information {
        p.remove_options(opt::RELAY_AGENT_INFORMATION);
    }
    let source = if iface.v4.contains(&p.giaddr) {
        p.giaddr
    } else {
        iface.primary_v4().ok_or(Drop::NoAddress)?
    };
    let unicast = p
        .ethernet_address()
        .filter(|_| !p.broadcast() && !p.yiaddr.is_unspecified());
    let (mac, dst) = match unicast {
        Some(mac) => (mac, p.yiaddr),
        None => (BROADCAST_MAC, Ipv4Addr::BROADCAST),
    };
    let datagram =
        udp_datagram(source, dst, SERVER_PORT, CLIENT_PORT, &p.emit()).ok_or(Drop::Malformed)?;
    Ok(Reply {
        binding,
        broadcast: unicast.is_none(),
        mac,
        datagram,
    })
}

/// Whether `binding` takes replies from where this one came from.
fn check_upstream(binding: &Binding4, from: &Arrival<Ipv4Addr>) -> Result<(), Drop> {
    let listed = binding
        .upstream_interfaces
        .iter()
        .any(|u| u == from.interface);
    if from.listen {
        if !listed {
            return Err(Drop::WrongUpstream);
        }
        if !binding.servers.contains(&from.src) {
            return Err(Drop::UnknownServer);
        }
    } else if !binding.upstream_interfaces.is_empty() && !listed {
        return Err(Drop::WrongUpstream);
    }
    Ok(())
}

/// The circuit ID of the first parseable option 82 that has one.
fn circuit_id(p: &Packet) -> Option<Vec<u8>> {
    p.options()
        .iter()
        .filter(|o| o.code == opt::RELAY_AGENT_INFORMATION)
        .find_map(|o| {
            RelayAgentInfo::parse(&o.data)
                .ok()?
                .circuit_id()
                .map(<[u8]>::to_vec)
        })
}

/// An IPv4 + UDP datagram around `payload`, for the `AF_PACKET` reply
/// path where the kernel adds only the link-layer header. TOS is
/// low-delay and TTL 64, as `dhcrelay` sends them. `None` when the
/// payload does not fit one datagram.
pub fn udp_datagram(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let udp_len = u16::try_from(8 + payload.len()).ok()?;
    let total = udp_len.checked_add(20)?;
    let mut out = Vec::with_capacity(usize::from(total));
    out.extend_from_slice(&[0x45, 0x10]);
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0, 64, libc::IPPROTO_UDP as u8, 0, 0]);
    out.extend_from_slice(&src.octets());
    out.extend_from_slice(&dst.octets());
    let ip_sum = checksum(&[&out[..20]]);
    out[10..12].copy_from_slice(&ip_sum.to_be_bytes());

    out.extend_from_slice(&sport.to_be_bytes());
    out.extend_from_slice(&dport.to_be_bytes());
    out.extend_from_slice(&udp_len.to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(payload);
    let mut pseudo = [0; 12];
    pseudo[..4].copy_from_slice(&src.octets());
    pseudo[4..8].copy_from_slice(&dst.octets());
    pseudo[9] = libc::IPPROTO_UDP as u8;
    pseudo[10..].copy_from_slice(&udp_len.to_be_bytes());
    let udp_sum = match checksum(&[&pseudo, &out[20..]]) {
        // RFC 768: a computed zero is sent as all ones.
        0 => 0xffff,
        sum => sum,
    };
    out[26..28].copy_from_slice(&udp_sum.to_be_bytes());
    Some(out)
}

/// The Internet checksum over the concatenation of `parts`.
fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum = 0u64;
    let mut high = true;
    for &byte in parts.iter().flat_map(|p| p.iter()) {
        sum += if high {
            u64::from(byte) << 8
        } else {
            u64::from(byte)
        };
        high = !high;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::ifaces::Iface;
    use dhcp_packet::v4::{Body, FLAG_BROADCAST, HTYPE_ETHERNET, SubOption};

    const MAC: [u8; 6] = [0x52, 0x54, 0, 0x12, 0x34, 0x56];

    fn binding(json: &str) -> Binding4 {
        let text = format!(r#"{{"dhcp4": [{json}]}}"#);
        let (mut config, warnings) = Config::parse(&text).unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");
        config.dhcp4.remove(0)
    }

    fn eth1() -> Binding4 {
        binding(r#"{"interface": "eth1", "servers": ["192.0.2.10", "192.0.2.11"]}"#)
    }

    fn ifaces() -> Ifaces {
        let mut ifaces = Ifaces::default();
        ifaces.insert(
            "eth0",
            Iface {
                index: 2,
                up: true,
                v4: vec![Ipv4Addr::new(192, 0, 2, 1)],
                v6: vec![],
            },
        );
        ifaces.insert(
            "eth1",
            Iface {
                index: 3,
                up: true,
                v4: vec![Ipv4Addr::new(10, 1, 0, 1), Ipv4Addr::new(10, 2, 0, 1)],
                v6: vec![],
            },
        );
        ifaces
    }

    fn option(code: u8, data: &[u8]) -> DhcpOption {
        DhcpOption {
            code,
            data: data.to_vec(),
        }
    }

    fn discover() -> Packet {
        let mut chaddr = [0; 16];
        chaddr[..6].copy_from_slice(&MAC);
        Packet {
            op: BOOTREQUEST,
            htype: HTYPE_ETHERNET,
            hlen: 6,
            hops: 0,
            xid: 0x0102_0304,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr,
            sname: [0; 64],
            file: [0; 128],
            body: Body::Options(vec![option(53, &[1]), option(55, &[1, 3, 6])]),
        }
    }

    fn ours() -> DhcpOption {
        option(82, &[1, 4, b'e', b't', b'h', b'1'])
    }

    fn theirs() -> DhcpOption {
        option(82, &[2, 3, b'f', b'o', b'o'])
    }

    fn forwarded(f: &Forward) -> Packet {
        Packet::parse(&f.packet).unwrap()
    }

    #[test]
    fn request_sets_giaddr_hops_and_option_82() {
        let f = request(&discover().emit(), &eth1(), &ifaces()).unwrap();
        assert!(!f.agent_option_omitted);
        assert_eq!(f.source, Ipv4Addr::new(10, 1, 0, 1));
        let p = forwarded(&f);
        assert_eq!(p.giaddr, Ipv4Addr::new(10, 1, 0, 1));
        assert_eq!(p.hops, 1);
        assert_eq!(
            p.options(),
            [option(53, &[1]), option(55, &[1, 3, 6]), ours()]
        );
    }

    #[test]
    fn request_from_downstream_relay_keeps_giaddr() {
        let mut d = discover();
        d.giaddr = Ipv4Addr::new(172, 16, 0, 1);
        d.hops = 3;
        let f = request(&d.emit(), &eth1(), &ifaces()).unwrap();
        // Sent from our address; the server answers the downstream relay.
        assert_eq!(f.source, Ipv4Addr::new(10, 1, 0, 1));
        let p = forwarded(&f);
        assert_eq!(p.giaddr, Ipv4Addr::new(172, 16, 0, 1));
        assert_eq!(p.hops, 4);
    }

    #[test]
    fn request_drops() {
        let mut d = discover();
        d.hops = 10;
        assert_eq!(request(&d.emit(), &eth1(), &ifaces()), Err(Drop::HopLimit));
        let mut d = discover();
        d.hops = 1;
        let b = binding(r#"{"interface": "eth1", "servers": ["192.0.2.10"], "hop-count": 1}"#);
        assert_eq!(request(&d.emit(), &b, &ifaces()), Err(Drop::HopLimit));

        let mut d = discover();
        d.giaddr = Ipv4Addr::new(10, 2, 0, 1);
        assert_eq!(request(&d.emit(), &eth1(), &ifaces()), Err(Drop::OwnGiaddr));

        let mut d = discover();
        d.op = BOOTREPLY;
        assert_eq!(request(&d.emit(), &eth1(), &ifaces()), Err(Drop::Malformed));
        assert_eq!(request(&[1; 100], &eth1(), &ifaces()), Err(Drop::Malformed));

        let mut bare = ifaces();
        bare.insert("eth1", Iface::default());
        assert_eq!(
            request(&discover().emit(), &eth1(), &bare),
            Err(Drop::NoAddress)
        );
        assert_eq!(
            request(&discover().emit(), &eth1(), &Ifaces::default()),
            Err(Drop::InterfaceDown)
        );
    }

    #[test]
    fn agent_option_policies() {
        let mut d = discover();
        d.push_option(theirs());
        let wire = d.emit();
        let with = |policy: &str| {
            binding(&format!(
                r#"{{"interface": "eth1", "servers": ["192.0.2.10"],
                     "relay-agents-packets": "{policy}"}}"#
            ))
        };
        let codes82 = |f: Forward| -> Vec<DhcpOption> {
            forwarded(&f)
                .options()
                .iter()
                .filter(|o| o.code == 82)
                .cloned()
                .collect()
        };
        let f = request(&wire, &with("forward"), &ifaces()).unwrap();
        assert_eq!(codes82(f), [theirs()]);
        let f = request(&wire, &with("append"), &ifaces()).unwrap();
        assert_eq!(codes82(f), [theirs(), ours()]);
        let f = request(&wire, &with("replace"), &ifaces()).unwrap();
        assert_eq!(codes82(f), [ours()]);
        assert_eq!(
            request(&wire, &with("discard"), &ifaces()),
            Err(Drop::AgentOptionPresent)
        );
        // Without agent-information the policy does not apply at all.
        let off = binding(
            r#"{"interface": "eth1", "servers": ["192.0.2.10"],
                "agent-information": false, "relay-agents-packets": "discard"}"#,
        );
        let f = request(&wire, &off, &ifaces()).unwrap();
        assert_eq!(codes82(f), [theirs()]);
        let f = request(&discover().emit(), &off, &ifaces()).unwrap();
        assert_eq!(codes82(f), []);
    }

    #[test]
    fn bootp_passes_unchanged() {
        let mut d = discover();
        d.body = Body::Bootp(vec![0; 64]);
        let p = forwarded(&request(&d.emit(), &eth1(), &ifaces()).unwrap());
        assert_eq!(p.body, Body::Bootp(vec![0; 64]));
        // A DHCP-format message without option 53 is left alone too.
        let mut d = discover();
        d.body = Body::Options(vec![option(55, &[1])]);
        let p = forwarded(&request(&d.emit(), &eth1(), &ifaces()).unwrap());
        assert_eq!(p.options(), [option(55, &[1])]);
    }

    #[test]
    fn max_size_omits_option_82() {
        // discover(): 240 + 3 + 5 + end = 249 bytes; option 82 adds 8.
        let fits = binding(r#"{"interface": "eth1", "servers": ["192.0.2.10"], "max-size": 257}"#);
        let f = request(&discover().emit(), &fits, &ifaces()).unwrap();
        assert!(!f.agent_option_omitted);
        assert_eq!(forwarded(&f).unpadded_len(), 257);
        let tight = binding(r#"{"interface": "eth1", "servers": ["192.0.2.10"], "max-size": 256}"#);
        let f = request(&discover().emit(), &tight, &ifaces()).unwrap();
        assert!(f.agent_option_omitted);
        assert!(forwarded(&f).option(82).is_none());
        // replace still removes the downstream option when ours is omitted.
        let mut d = discover();
        d.push_option(theirs());
        let replace = binding(
            r#"{"interface": "eth1", "servers": ["192.0.2.10"], "max-size": 64,
                "relay-agents-packets": "replace"}"#,
        );
        let f = request(&d.emit(), &replace, &ifaces()).unwrap();
        assert!(f.agent_option_omitted);
        assert!(forwarded(&f).option(82).is_none());
    }

    fn offer(giaddr: Ipv4Addr, flags: u16, extra: Vec<DhcpOption>) -> Vec<u8> {
        let mut p = discover();
        p.op = BOOTREPLY;
        p.hops = 1;
        p.flags = flags;
        p.yiaddr = Ipv4Addr::new(10, 1, 0, 50);
        p.giaddr = giaddr;
        let mut options = vec![option(53, &[2]), option(54, &[192, 0, 2, 10])];
        options.extend(extra);
        p.body = Body::Options(options);
        p.emit()
    }

    const SERVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);

    /// From the first server, on `interface` (not a listen interface).
    fn upstream(interface: &str) -> Arrival<'_, Ipv4Addr> {
        Arrival {
            vrf: "default",
            interface,
            listen: false,
            src: SERVER,
        }
    }

    /// The DHCP message inside a reply's datagram.
    fn payload(r: &Reply) -> Packet {
        Packet::parse(&r.datagram[28..]).unwrap()
    }

    #[test]
    fn reply_by_circuit_id_strips_option_82() {
        let bindings = [eth1()];
        // giaddr is not ours, but the circuit ID names eth1.
        let wire = offer(Ipv4Addr::new(10, 9, 9, 9), 0, vec![ours()]);
        let r = reply(&wire, &upstream("eth0"), &bindings, &ifaces()).unwrap();
        assert_eq!(r.binding.interface, "eth1");
        assert!(payload(&r).option(82).is_none());
        // Unicast, sourced from the primary address since giaddr is not on eth1.
        assert!(!r.broadcast);
        assert_eq!(r.mac, MAC);
        assert_eq!(&r.datagram[12..16], &[10, 1, 0, 1]);
        assert_eq!(&r.datagram[16..20], &[10, 1, 0, 50]);
    }

    #[test]
    fn reply_by_giaddr() {
        let bindings = [eth1()];
        let wire = offer(Ipv4Addr::new(10, 2, 0, 1), 0, vec![]);
        let r = reply(&wire, &upstream("eth0"), &bindings, &ifaces()).unwrap();
        // giaddr is on eth1, so it is the source.
        assert_eq!(&r.datagram[12..16], &[10, 2, 0, 1]);
        assert_eq!(payload(&r), Packet::parse(&wire).unwrap());
    }

    #[test]
    fn reply_broadcast() {
        let bindings = [eth1()];
        let giaddr = Ipv4Addr::new(10, 1, 0, 1);
        let from = upstream("eth0");
        let broadcast = |r: &Reply| {
            assert!(r.broadcast);
            assert_eq!(r.mac, [0xff; 6]);
            assert_eq!(&r.datagram[12..16], &[10, 1, 0, 1]);
            assert_eq!(&r.datagram[16..20], &[255; 4]);
        };
        let r = reply(
            &offer(giaddr, FLAG_BROADCAST, vec![]),
            &from,
            &bindings,
            &ifaces(),
        )
        .unwrap();
        broadcast(&r);
        // A NAK carries no yiaddr.
        let mut nak = Packet::parse(&offer(giaddr, 0, vec![])).unwrap();
        nak.yiaddr = Ipv4Addr::UNSPECIFIED;
        broadcast(&reply(&nak.emit(), &from, &bindings, &ifaces()).unwrap());
        // Not Ethernet: no MAC to unicast to.
        let mut ib = Packet::parse(&offer(giaddr, 0, vec![])).unwrap();
        ib.htype = 32;
        ib.hlen = 0;
        broadcast(&reply(&ib.emit(), &from, &bindings, &ifaces()).unwrap());
    }

    #[test]
    fn reply_drops() {
        let bindings = [eth1()];
        let ours_giaddr = Ipv4Addr::new(10, 1, 0, 1);
        let from = upstream("eth0");
        // giaddr 0: a server answering its own segment, not a relay.
        let wire = offer(Ipv4Addr::UNSPECIFIED, 0, vec![]);
        assert_eq!(
            reply(&wire, &from, &bindings, &ifaces()),
            Err(Drop::NoBinding)
        );
        // Neither our circuit ID nor our giaddr.
        let wire = offer(Ipv4Addr::new(10, 9, 9, 9), 0, vec![theirs()]);
        assert_eq!(
            reply(&wire, &from, &bindings, &ifaces()),
            Err(Drop::NoBinding)
        );
        // Another VRF's binding is not a match.
        let wire = offer(ours_giaddr, 0, vec![]);
        let blue = Arrival {
            vrf: "blue",
            ..from
        };
        assert_eq!(
            reply(&wire, &blue, &bindings, &ifaces()),
            Err(Drop::NoBinding)
        );
        // upstream-interfaces limits where replies may come from.
        let b = [binding(
            r#"{"interface": "eth1", "servers": ["192.0.2.10"], "upstream-interfaces": ["eth0"]}"#,
        )];
        assert!(reply(&wire, &from, &b, &ifaces()).is_ok());
        assert_eq!(
            reply(&wire, &upstream("eth5"), &b, &ifaces()),
            Err(Drop::WrongUpstream)
        );
        // A request is not a reply.
        assert_eq!(
            reply(&discover().emit(), &from, &bindings, &ifaces()),
            Err(Drop::Malformed)
        );
    }

    /// A client on a listen interface forging an offer for another
    /// listen interface's segment.
    #[test]
    fn reply_on_listen_interface() {
        let both = r#"{"interface": "eth2", "servers": ["192.0.2.10"]}"#;
        let bindings = Config::parse(&format!(
            r#"{{"dhcp4": [{{"interface": "eth1", "servers": ["192.0.2.10"]}}, {both}]}}"#
        ))
        .unwrap()
        .0
        .dhcp4;
        let wire = offer(Ipv4Addr::new(10, 1, 0, 1), 0, vec![ours()]);
        let mut from = Arrival {
            vrf: "default",
            interface: "eth2",
            listen: true,
            src: Ipv4Addr::new(10, 2, 0, 66),
        };
        assert_eq!(
            reply(&wire, &from, &bindings, &ifaces()),
            Err(Drop::WrongUpstream)
        );
        // Spoofing the server's address is not enough either.
        from.src = SERVER;
        assert_eq!(
            reply(&wire, &from, &bindings, &ifaces()),
            Err(Drop::WrongUpstream)
        );
        // A listen interface that is also upstream takes replies from a
        // configured server only.
        let b = [binding(
            r#"{"interface": "eth1", "servers": ["192.0.2.10"], "upstream-interfaces": ["eth1"]}"#,
        )];
        from.interface = "eth1";
        assert!(reply(&wire, &from, &b, &ifaces()).is_ok());
        from.src = Ipv4Addr::new(10, 1, 0, 66);
        assert_eq!(reply(&wire, &from, &b, &ifaces()), Err(Drop::UnknownServer));
    }

    #[test]
    fn reply_without_agent_information_keeps_option_82() {
        let off = [binding(
            r#"{"interface": "eth1", "servers": ["192.0.2.10"], "agent-information": false}"#,
        )];
        let wire = offer(Ipv4Addr::new(10, 1, 0, 1), 0, vec![theirs()]);
        let r = reply(&wire, &upstream("eth0"), &off, &ifaces()).unwrap();
        assert_eq!(payload(&r).option(82), Some(&theirs()));
    }

    #[test]
    fn circuit_id_from_merged_option() {
        // A server that merged the downstream option and ours (RFC 3396).
        let rai = RelayAgentInfo {
            sub_options: vec![
                SubOption {
                    code: 2,
                    data: b"foo".to_vec(),
                },
                SubOption {
                    code: 1,
                    data: b"eth1".to_vec(),
                },
            ],
        };
        let mut p = discover();
        p.push_option(option(82, &rai.emit().unwrap()));
        assert_eq!(circuit_id(&p), Some(b"eth1".to_vec()));
    }

    #[test]
    fn datagram_checksums() {
        let payload: Vec<u8> = (0..=300u16).map(|i| i as u8).collect();
        let src = Ipv4Addr::new(10, 1, 0, 1);
        let dst = Ipv4Addr::new(10, 1, 0, 50);
        let d = udp_datagram(src, dst, 67, 68, &payload).unwrap();
        assert_eq!(d.len(), 28 + payload.len());
        assert_eq!(u16::from_be_bytes([d[2], d[3]]) as usize, d.len());
        // A correct checksum sums the covered data to zero.
        assert_eq!(checksum(&[&d[..20]]), 0);
        let mut pseudo = [0; 12];
        pseudo[..4].copy_from_slice(&src.octets());
        pseudo[4..8].copy_from_slice(&dst.octets());
        pseudo[9] = 17;
        pseudo[10..].copy_from_slice(&((d.len() - 20) as u16).to_be_bytes());
        assert_eq!(checksum(&[&pseudo, &d[20..]]), 0);
        assert_eq!(udp_datagram(src, dst, 67, 68, &vec![0; 65536]), None);
        // RFC 1071 §3 example: 0001 f203 f4f5 f6f7 sums to ddf2.
        assert_eq!(
            checksum(&[&[0x00, 0x01, 0xf2, 0x03], &[0xf4, 0xf5, 0xf6, 0xf7]]),
            !0xddf2
        );
    }
}
