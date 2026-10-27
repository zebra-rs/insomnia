//! DHCPv6 relaying (RFC 8415 §19), following `dhcrelay -6` as VyOS
//! runs it: `-l [addr%]<listen>… -u <addr>%<upstream>… -c <hops> [-I]`.
//!
//! Pure functions, like `v4.rs`.
//!
//! Upward (a message received on a listen interface):
//! - from a client: wrapped in a Relay-forw with hop-count 0,
//!   link-address = the binding's `link-address`, else the interface's
//!   first global address, and peer-address = the sender. Interface-ID
//!   (18) = the interface name is added with `interface-id`;
//! - from a downstream relay (a Relay-forw): dropped at
//!   `max-hop-count`, else wrapped with hop-count + 1, link-address
//!   `::` and always an Interface-ID, because `::` cannot identify the
//!   link (§19.1.2);
//! - server-to-client types (Advertise, Reply, Reconfigure, the
//!   Leasequery replies, DHCPv4-response) and Relay-repl are not
//!   relayed upward. Types this relay does not know are, as RFC 7283
//!   requires.
//!
//! Downward (a Relay-repl): the binding is the one named by
//! Interface-ID, else the one owning link-address. When every server
//! names an interface, the Relay-repl must have arrived on one of them
//! (`dhcrelay -u addr%if`). A Relay-repl arriving on a listen interface
//! must come from a unicast server pinned to that interface: any client
//! there can send one, and the relay would otherwise carry it onto
//! another listen interface (a deviation; `dhcrelay` checks neither).
//! The Relay-Message payload goes to peer-address on the binding's
//! interface, port 547 when it is itself a Relay-repl for a downstream
//! relay, else 546.

use std::net::Ipv6Addr;

use dhcp_packet::v6::{CLIENT_PORT, Dhcp6Option, Message, RelayMessage, SERVER_PORT, msg, opt};

use crate::config::{Binding6, Server6};
use crate::ifaces::{Arrival, Ifaces};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Drop {
    Malformed,
    HopLimit,
    UnexpectedType,
    NoLinkAddress,
    NoBinding,
    WrongUpstream,
    UnknownServer,
    InterfaceDown,
    TooLong,
}

impl Drop {
    pub fn reason(self) -> &'static str {
        match self {
            Drop::Malformed => "malformed",
            Drop::HopLimit => "hop-limit",
            Drop::UnexpectedType => "unexpected-type",
            Drop::NoLinkAddress => "no-link-address",
            Drop::NoBinding => "no-binding",
            Drop::WrongUpstream => "wrong-upstream",
            Drop::UnknownServer => "unknown-server",
            Drop::InterfaceDown => "interface-down",
            Drop::TooLong => "too-long",
        }
    }
}

fn from_server(msg_type: u8) -> bool {
    matches!(
        msg_type,
        msg::ADVERTISE
            | msg::REPLY
            | msg::RECONFIGURE
            | msg::LEASEQUERY_REPLY
            | msg::LEASEQUERY_DONE
            | msg::LEASEQUERY_DATA
            | msg::DHCPV4_RESPONSE
    )
}

/// A message received on `binding.interface` from `peer`; returns the
/// Relay-forw for the servers.
pub fn upward(
    buf: &[u8],
    peer: Ipv6Addr,
    binding: &Binding6,
    ifaces: &Ifaces,
) -> Result<Vec<u8>, Drop> {
    let message = Message::parse(buf).map_err(|_| Drop::Malformed)?;
    let (hop_count, link_address, interface_id) = match &message {
        Message::Relay(r) if r.msg_type == msg::RELAY_FORW => {
            if r.hop_count >= binding.max_hop_count {
                return Err(Drop::HopLimit);
            }
            (r.hop_count + 1, Ipv6Addr::UNSPECIFIED, true)
        }
        Message::Relay(_) => return Err(Drop::UnexpectedType),
        Message::Client(c) if from_server(c.msg_type) => return Err(Drop::UnexpectedType),
        Message::Client(_) => {
            let link_address = match binding.link_address {
                Some(addr) => addr,
                None => ifaces
                    .get(&binding.interface)
                    .ok_or(Drop::InterfaceDown)?
                    .global_v6()
                    .ok_or(Drop::NoLinkAddress)?,
            };
            (0, link_address, binding.interface_id)
        }
    };
    let mut options = Vec::with_capacity(2);
    if interface_id {
        options.push(Dhcp6Option {
            code: opt::INTERFACE_ID,
            data: binding.interface.as_bytes().to_vec(),
        });
    }
    options.push(Dhcp6Option {
        code: opt::RELAY_MSG,
        data: buf.to_vec(),
    });
    Message::Relay(RelayMessage {
        msg_type: msg::RELAY_FORW,
        hop_count,
        link_address,
        peer_address: peer,
        options,
    })
    .emit()
    .map_err(|_| Drop::TooLong)
}

/// The unwrapped message and where it goes.
#[derive(Debug, PartialEq, Eq)]
pub struct Downward<'a> {
    pub binding: &'a Binding6,
    pub packet: Vec<u8>,
    pub peer: Ipv6Addr,
    pub port: u16,
}

/// A Relay-repl addressed to us. `bindings` is the whole `dhcp6` list.
pub fn downward<'a>(
    buf: &[u8],
    from: &Arrival<Ipv6Addr>,
    bindings: &'a [Binding6],
    ifaces: &Ifaces,
) -> Result<Downward<'a>, Drop> {
    let Message::Relay(r) = Message::parse(buf).map_err(|_| Drop::Malformed)? else {
        return Err(Drop::UnexpectedType);
    };
    if r.msg_type != msg::RELAY_REPL {
        return Err(Drop::UnexpectedType);
    }
    let in_vrf = || bindings.iter().filter(|b| b.vrf == from.vrf);
    let by_interface_id = r
        .interface_id()
        .and_then(|id| in_vrf().find(|b| b.interface.as_bytes() == id));
    let binding = by_interface_id
        .or_else(|| {
            if r.link_address.is_unspecified() {
                return None;
            }
            in_vrf().find(|b| match b.link_address {
                Some(addr) => addr == r.link_address,
                None => ifaces
                    .get(&b.interface)
                    .is_some_and(|i| i.v6.contains(&r.link_address)),
            })
        })
        .ok_or(Drop::NoBinding)?;
    let here = |s: &Server6| s.interface.as_deref() == Some(from.interface);
    if from.listen {
        if !binding
            .servers
            .iter()
            .any(|s| here(s) && s.address == from.src)
        {
            return Err(Drop::UnknownServer);
        }
    } else if binding.servers.iter().all(|s| s.interface.is_some())
        && !binding.servers.iter().any(here)
    {
        return Err(Drop::WrongUpstream);
    }
    if ifaces.get(&binding.interface).is_none() {
        return Err(Drop::InterfaceDown);
    }
    let inner = r.relay_message().ok_or(Drop::Malformed)?;
    let (&inner_type, _) = inner.split_first().ok_or(Drop::Malformed)?;
    let port = if inner_type == msg::RELAY_REPL {
        SERVER_PORT
    } else {
        CLIENT_PORT
    };
    Ok(Downward {
        binding,
        packet: inner.to_vec(),
        peer: r.peer_address,
        port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::ifaces::Iface;
    use dhcp_packet::v6::ClientMessage;

    fn bindings(json: &str) -> Vec<Binding6> {
        let (config, warnings) = Config::parse(&format!(r#"{{"dhcp6": [{json}]}}"#)).unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");
        config.dhcp6
    }

    fn eth1() -> Vec<Binding6> {
        bindings(
            r#"{"interface": "eth1", "servers": [{"address": "ff05::1:3", "interface": "eth0"}]}"#,
        )
    }

    fn ifaces() -> Ifaces {
        let mut ifaces = Ifaces::default();
        ifaces.insert(
            "eth0",
            Iface {
                index: 2,
                up: true,
                v4: vec![],
                v6: vec!["fe80::1".parse().unwrap(), "2001:db8::1".parse().unwrap()],
            },
        );
        ifaces.insert(
            "eth1",
            Iface {
                index: 3,
                up: true,
                v4: vec![],
                v6: vec!["fe80::2".parse().unwrap(), "2001:db8:1::1".parse().unwrap()],
            },
        );
        ifaces
    }

    fn client() -> Ipv6Addr {
        "fe80::5054:ff:fe12:3456".parse().unwrap()
    }

    fn solicit() -> Vec<u8> {
        Message::Client(ClientMessage {
            msg_type: msg::SOLICIT,
            transaction_id: 0xabcdef,
            options: vec![Dhcp6Option {
                code: 1,
                data: vec![0, 3, 0, 1, 0x52, 0x54, 0, 0x12, 0x34, 0x56],
            }],
        })
        .emit()
        .unwrap()
    }

    fn relay(packet: &[u8]) -> RelayMessage {
        match Message::parse(packet).unwrap() {
            Message::Relay(r) => r,
            Message::Client(c) => panic!("not a relay message: {c:?}"),
        }
    }

    fn wrap(
        msg_type: u8,
        hop_count: u8,
        link: &str,
        interface_id: Option<&str>,
        inner: &[u8],
    ) -> Vec<u8> {
        let mut options = Vec::new();
        if let Some(id) = interface_id {
            options.push(Dhcp6Option {
                code: opt::INTERFACE_ID,
                data: id.as_bytes().to_vec(),
            });
        }
        options.push(Dhcp6Option {
            code: opt::RELAY_MSG,
            data: inner.to_vec(),
        });
        Message::Relay(RelayMessage {
            msg_type,
            hop_count,
            link_address: link.parse().unwrap(),
            peer_address: client(),
            options,
        })
        .emit()
        .unwrap()
    }

    #[test]
    fn client_message_is_wrapped() {
        let b = &eth1()[0];
        let r = relay(&upward(&solicit(), client(), b, &ifaces()).unwrap());
        assert_eq!(r.msg_type, msg::RELAY_FORW);
        assert_eq!(r.hop_count, 0);
        assert_eq!(r.link_address, "2001:db8:1::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(r.peer_address, client());
        assert_eq!(r.interface_id(), None);
        assert_eq!(r.relay_message(), Some(solicit().as_slice()));
    }

    #[test]
    fn configured_link_address_and_interface_id() {
        let b = &bindings(
            r#"{"interface": "eth1", "link-address": "2001:db8:9::1", "interface-id": true,
                "servers": [{"address": "2001:db8::547"}]}"#,
        )[0];
        let r = relay(&upward(&solicit(), client(), b, &ifaces()).unwrap());
        assert_eq!(r.link_address, "2001:db8:9::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(r.interface_id(), Some(&b"eth1"[..]));
        assert_eq!(r.options[1].code, opt::RELAY_MSG);
    }

    #[test]
    fn relay_forw_is_nested() {
        let b = &eth1()[0];
        let downstream = wrap(msg::RELAY_FORW, 2, "2001:db8:7::1", None, &solicit());
        let r = relay(&upward(&downstream, client(), b, &ifaces()).unwrap());
        assert_eq!(r.hop_count, 3);
        assert!(r.link_address.is_unspecified());
        assert_eq!(r.interface_id(), Some(&b"eth1"[..]));
        assert_eq!(r.relay_message(), Some(downstream.as_slice()));
        let at_limit = wrap(msg::RELAY_FORW, 10, "::", None, &solicit());
        assert_eq!(
            upward(&at_limit, client(), b, &ifaces()),
            Err(Drop::HopLimit)
        );
    }

    #[test]
    fn upward_drops() {
        let b = &eth1()[0];
        let reply = Message::Client(ClientMessage {
            msg_type: msg::REPLY,
            transaction_id: 1,
            options: vec![],
        })
        .emit()
        .unwrap();
        assert_eq!(
            upward(&reply, client(), b, &ifaces()),
            Err(Drop::UnexpectedType)
        );
        let repl = wrap(msg::RELAY_REPL, 0, "::", None, &solicit());
        assert_eq!(
            upward(&repl, client(), b, &ifaces()),
            Err(Drop::UnexpectedType)
        );
        assert_eq!(
            upward(&[1, 0], client(), b, &ifaces()),
            Err(Drop::Malformed)
        );
        let mut no_global = ifaces();
        no_global.insert(
            "eth1",
            Iface {
                index: 3,
                up: true,
                v4: vec![],
                v6: vec!["fe80::2".parse().unwrap()],
            },
        );
        assert_eq!(
            upward(&solicit(), client(), b, &no_global),
            Err(Drop::NoLinkAddress)
        );
        assert_eq!(
            upward(&solicit(), client(), b, &Ifaces::default()),
            Err(Drop::InterfaceDown)
        );
        // Unknown types are relayed upward (RFC 7283).
        let unknown = [99, 0, 0, 1];
        assert!(upward(&unknown, client(), b, &ifaces()).is_ok());
    }

    fn advertise() -> Vec<u8> {
        Message::Client(ClientMessage {
            msg_type: msg::ADVERTISE,
            transaction_id: 0xabcdef,
            options: vec![],
        })
        .emit()
        .unwrap()
    }

    /// From a server, on `interface` (not a listen interface).
    fn up(interface: &str) -> Arrival<'_, Ipv6Addr> {
        Arrival {
            vrf: "default",
            interface,
            listen: false,
            src: "2001:db8::547".parse().unwrap(),
        }
    }

    #[test]
    fn relay_repl_by_link_address() {
        let bs = eth1();
        let wire = wrap(msg::RELAY_REPL, 0, "2001:db8:1::1", None, &advertise());
        let d = downward(&wire, &up("eth0"), &bs, &ifaces()).unwrap();
        assert_eq!(d.binding.interface, "eth1");
        assert_eq!(d.packet, advertise());
        assert_eq!(d.peer, client());
        assert_eq!(d.port, CLIENT_PORT);
    }

    #[test]
    fn relay_repl_by_interface_id_to_downstream_relay() {
        let bs = eth1();
        let inner = wrap(msg::RELAY_REPL, 0, "2001:db8:7::1", None, &advertise());
        let wire = wrap(msg::RELAY_REPL, 1, "::", Some("eth1"), &inner);
        let d = downward(&wire, &up("eth0"), &bs, &ifaces()).unwrap();
        assert_eq!(d.packet, inner);
        assert_eq!(d.port, SERVER_PORT);
    }

    #[test]
    fn downward_drops() {
        let bs = eth1();
        let good = wrap(msg::RELAY_REPL, 0, "2001:db8:1::1", None, &advertise());
        // Servers are pinned to eth0.
        assert_eq!(
            downward(&good, &up("eth2"), &bs, &ifaces()),
            Err(Drop::WrongUpstream)
        );
        // A server without an interface opens every ingress.
        let open = bindings(
            r#"{"interface": "eth1", "servers": [{"address": "2001:db8::547"},
                {"address": "ff05::1:3", "interface": "eth0"}]}"#,
        );
        assert!(downward(&good, &up("eth2"), &open, &ifaces()).is_ok());
        assert_eq!(
            downward(
                &good,
                &Arrival {
                    vrf: "blue",
                    ..up("eth0")
                },
                &bs,
                &ifaces()
            ),
            Err(Drop::NoBinding)
        );
        let unknown = wrap(
            msg::RELAY_REPL,
            0,
            "2001:db8:5::1",
            Some("eth9"),
            &advertise(),
        );
        assert_eq!(
            downward(&unknown, &up("eth0"), &bs, &ifaces()),
            Err(Drop::NoBinding)
        );
        let unspecified = wrap(msg::RELAY_REPL, 0, "::", None, &advertise());
        assert_eq!(
            downward(&unspecified, &up("eth0"), &bs, &ifaces()),
            Err(Drop::NoBinding)
        );
        let forw = wrap(msg::RELAY_FORW, 0, "2001:db8:1::1", None, &advertise());
        assert_eq!(
            downward(&forw, &up("eth0"), &bs, &ifaces()),
            Err(Drop::UnexpectedType)
        );
        assert_eq!(
            downward(&advertise(), &up("eth0"), &bs, &ifaces()),
            Err(Drop::UnexpectedType)
        );
        let empty = wrap(msg::RELAY_REPL, 0, "2001:db8:1::1", None, &[]);
        assert_eq!(
            downward(&empty, &up("eth0"), &bs, &ifaces()),
            Err(Drop::Malformed)
        );
        let mut no_msg = relay(&good);
        no_msg.options.clear();
        let no_msg = Message::Relay(no_msg).emit().unwrap();
        assert_eq!(
            downward(&no_msg, &up("eth0"), &bs, &ifaces()),
            Err(Drop::Malformed)
        );
    }

    /// A client on a listen interface forging a Relay-repl for another
    /// listen interface's segment.
    #[test]
    fn relay_repl_on_listen_interface() {
        let wire = wrap(msg::RELAY_REPL, 0, "2001:db8:1::1", None, &advertise());
        let mut from = Arrival {
            vrf: "default",
            interface: "eth0",
            listen: true,
            src: "2001:db8::66".parse().unwrap(),
        };
        // eth0 is pinned for ff05::1:3 only: no unicast server to match.
        assert_eq!(
            downward(&wire, &from, &eth1(), &ifaces()),
            Err(Drop::UnknownServer)
        );
        let bs = bindings(
            r#"{"interface": "eth1", "servers": [{"address": "2001:db8::547", "interface": "eth0"}]}"#,
        );
        assert_eq!(
            downward(&wire, &from, &bs, &ifaces()),
            Err(Drop::UnknownServer)
        );
        from.src = "2001:db8::547".parse().unwrap();
        assert!(downward(&wire, &from, &bs, &ifaces()).is_ok());
        // The server's address, but not pinned to this interface.
        from.interface = "eth2";
        assert_eq!(
            downward(&wire, &from, &bs, &ifaces()),
            Err(Drop::UnknownServer)
        );
    }
}
