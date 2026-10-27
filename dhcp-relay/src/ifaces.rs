//! A snapshot of the host's interfaces: index, up flag and addresses,
//! read with getifaddrs(3).
//!
//! The relay re-reads it on every resync tick, on reload, and when a
//! packet arrives on an interface index the snapshot does not know. A
//! new address or a re-created interface is therefore picked up within
//! one tick, without a netlink subscription.

use std::collections::BTreeMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::sys::{self, IfAddr, IfEntry};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Iface {
    pub index: u32,
    pub up: bool,
    /// In kernel order: the primary address of the oldest prefix first.
    pub v4: Vec<Ipv4Addr>,
    pub v6: Vec<Ipv6Addr>,
}

impl Iface {
    /// The address `dhcrelay` uses as giaddr: the first IPv4 address.
    pub fn primary_v4(&self) -> Option<Ipv4Addr> {
        self.v4.first().copied()
    }

    /// The first global or ULA IPv6 address: the default Relay-forw
    /// link-address.
    pub fn global_v6(&self) -> Option<Ipv6Addr> {
        self.v6.iter().copied().find(|a| {
            !(a.is_unspecified()
                || a.is_loopback()
                || a.is_multicast()
                || a.is_unicast_link_local())
        })
    }
}

/// Where a reply came from: the interface it arrived on, in which VRF,
/// and its sender.
#[derive(Clone, Copy, Debug)]
pub struct Arrival<'a, A> {
    pub vrf: &'a str,
    pub interface: &'a str,
    /// `interface` is a listen interface. It carries clients, any of
    /// whom can send a reply, so a reply arriving there passes stricter
    /// checks.
    pub listen: bool,
    pub src: A,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ifaces {
    by_name: BTreeMap<String, Iface>,
}

impl Ifaces {
    pub fn read() -> io::Result<Ifaces> {
        Ok(Ifaces::from_entries(sys::interfaces()?))
    }

    pub fn from_entries(entries: Vec<IfEntry>) -> Ifaces {
        let mut by_name: BTreeMap<String, Iface> = BTreeMap::new();
        for entry in entries {
            let iface = by_name.entry(entry.name).or_default();
            match entry.addr {
                IfAddr::Link(index) => {
                    iface.index = index;
                    iface.up = entry.flags & libc::IFF_UP as u32 != 0;
                }
                IfAddr::V4(addr) => iface.v4.push(addr),
                IfAddr::V6(addr) => iface.v6.push(addr),
            }
        }
        Ifaces { by_name }
    }

    pub fn get(&self, name: &str) -> Option<&Iface> {
        self.by_name.get(name)
    }

    pub fn name_of(&self, index: u32) -> Option<&str> {
        self.by_name
            .iter()
            .find(|(_, iface)| iface.index == index)
            .map(|(name, _)| name.as_str())
    }

    /// Whether `addr` is assigned to any interface.
    pub fn is_local_v4(&self, addr: Ipv4Addr) -> bool {
        self.by_name.values().any(|i| i.v4.contains(&addr))
    }

    #[cfg(test)]
    pub fn insert(&mut self, name: &str, iface: Iface) {
        self.by_name.insert(name.to_string(), iface);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_entries() {
        let entry = |name: &str, flags: u32, addr: IfAddr| IfEntry {
            name: name.to_string(),
            flags,
            addr,
        };
        let ifaces = Ifaces::from_entries(vec![
            entry("eth1", libc::IFF_UP as u32, IfAddr::Link(3)),
            entry("eth2", 0, IfAddr::Link(4)),
            entry("eth1", 0, IfAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            entry("eth1", 0, IfAddr::V4(Ipv4Addr::new(198, 51, 100, 1))),
            entry("eth1", 0, IfAddr::V6("fe80::1".parse().unwrap())),
            entry("eth1", 0, IfAddr::V6("2001:db8::1".parse().unwrap())),
        ]);
        let eth1 = ifaces.get("eth1").unwrap();
        assert_eq!((eth1.index, eth1.up), (3, true));
        assert_eq!(eth1.primary_v4(), Some(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(eth1.global_v6(), Some("2001:db8::1".parse().unwrap()));
        let eth2 = ifaces.get("eth2").unwrap();
        assert!(!eth2.up);
        assert_eq!((eth2.primary_v4(), eth2.global_v6()), (None, None));
        assert_eq!(ifaces.name_of(4), Some("eth2"));
        assert_eq!(ifaces.name_of(9), None);
        assert!(ifaces.is_local_v4(Ipv4Addr::new(198, 51, 100, 1)));
        assert!(!ifaces.is_local_v4(Ipv4Addr::new(198, 51, 100, 2)));
    }

    /// The real snapshot of the test host has a loopback interface.
    #[test]
    fn read_host() {
        let ifaces = Ifaces::read().unwrap();
        let lo = ifaces.get("lo").unwrap();
        assert!(lo.index > 0);
        assert!(lo.v4.contains(&Ipv4Addr::LOCALHOST));
    }
}
