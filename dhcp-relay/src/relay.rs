//! The relay's sockets and packet dispatch.
//!
//! Sockets:
//! - DHCPv4, per listen interface: UDP `255.255.255.255:67`,
//!   `SO_BINDTODEVICE` to the interface. It receives client broadcasts
//!   and nothing else.
//! - DHCPv4, per IPv4 address of a listen interface: UDP `<address>:67`,
//!   bound to the VRF device (unbound for `default`). A request leaves
//!   through the socket of its listen interface's first address, the
//!   giaddr, so servers' replies arrive on these sockets, as does
//!   unicast from downstream relays.
//! - DHCPv4 replies to clients, broadcast and unicast alike, leave
//!   through one `AF_PACKET` socket as whole IPv4 datagrams. It is
//!   opened with protocol 0, so it receives nothing.
//! - DHCPv6, per listen interface: UDP `[::]:547`, `SO_BINDTODEVICE` to
//!   the interface and joined to ff02::1:2. Replies to clients leave
//!   through it.
//! - DHCPv6, per VRF: UDP `[::]:547` bound to the VRF device (unbound
//!   for `default`), with `IPV6_MULTICAST_ALL` off so that it sees no
//!   client multicast. Relay-forw leaves through it, routing picking
//!   the egress interface and source address, and Relay-repl comes back
//!   to it.
//!
//! The relay never binds `0.0.0.0:67`. A DHCPv4 server serving another
//! interface binds `<its address>:67` without `SO_REUSEADDR` (Kea
//! 2.4.1's raw-mode fallback socket does, to hold the port), and the
//! kernel refuses that bind next to any wildcard socket on the port,
//! device-bound or not. Kea 2.4.1 sets `SO_REUSEADDR` on its DHCPv6
//! sockets, so `[::]:547` coexists with it in either start order.
//!
//! A datagram is judged by the interface it arrived on (packet info),
//! not by the socket that received it: unicast to a DHCPv6 listen
//! interface in a VRF matches its listen socket and the VRF's socket
//! equally well, and the kernel picks one. Arriving on a listen
//! interface, a message is a request, or a reply that must pass the
//! stricter checks of `v4::reply` / `v6::downward`. Arriving anywhere
//! else, it is a reply or not the relay's business.
//!
//! Interface state comes from a periodic snapshot (`ifaces.rs`). A
//! listen interface that does not exist yet, or a VRF device that is
//! missing, is logged once and retried on every tick; a socket whose
//! interface was re-created under a new index is reopened, and the
//! per-address sockets follow the addresses.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::sync::{Arc, Mutex};

use dhcp_packet::{v4 as packet4, v6 as packet6};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::config::{Binding4, Binding6, Config, DEFAULT_VRF};
use crate::ifaces::{Arrival, Ifaces};
use crate::stats::{Counters, Family, Stats};
use crate::{sys, v4, v6};

/// Largest datagram read; a UDP payload never exceeds it.
const RECV_BUFFER: usize = 65536;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SockKey {
    /// Client broadcasts on a DHCPv4 listen interface.
    Broadcast4(String),
    /// One address of a DHCPv4 listen interface, in a VRF.
    Unicast4(String, Ipv4Addr),
    /// A DHCPv6 listen interface.
    Listen6(String),
    /// A VRF's DHCPv6 upstream socket.
    Server6(String),
}

impl SockKey {
    fn family(&self) -> Family {
        match self {
            SockKey::Broadcast4(_) | SockKey::Unicast4(..) => Family::V4,
            SockKey::Listen6(_) | SockKey::Server6(_) => Family::V6,
        }
    }
}

impl fmt::Display for SockKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SockKey::Broadcast4(ifname) => write!(f, "dhcp4 listen {ifname}"),
            SockKey::Unicast4(vrf, addr) => write!(f, "dhcp4 vrf {vrf} address {addr}"),
            SockKey::Listen6(ifname) => write!(f, "dhcp6 listen {ifname}"),
            SockKey::Server6(vrf) => write!(f, "dhcp6 server vrf {vrf}"),
        }
    }
}

/// One datagram from a reader task.
pub struct Incoming {
    key: SockKey,
    data: Vec<u8>,
    received: sys::Received,
}

struct Sock {
    fd: Arc<AsyncFd<OwnedFd>>,
    /// Index of the device the socket is bound to; 0 when unbound.
    device_index: u32,
    reader: JoinHandle<()>,
}

impl Sock {
    fn raw(&self) -> RawFd {
        self.fd.get_ref().as_raw_fd()
    }
}

impl Drop for Sock {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

pub struct Relay {
    config: Config,
    ifaces: Ifaces,
    sockets: BTreeMap<SockKey, Sock>,
    /// Sockets that could not be opened, so the warning is logged once.
    failed: BTreeSet<SockKey>,
    link: Option<OwnedFd>,
    stats: Arc<Mutex<Stats>>,
    tx: mpsc::Sender<Incoming>,
}

impl Relay {
    pub fn new(stats: Arc<Mutex<Stats>>, tx: mpsc::Sender<Incoming>) -> Relay {
        Relay {
            config: Config::default(),
            ifaces: Ifaces::default(),
            sockets: BTreeMap::new(),
            failed: BTreeSet::new(),
            link: None,
            stats,
            tx,
        }
    }

    /// Re-reads the config file. A file that does not parse leaves the
    /// running config in place.
    pub fn reload(&mut self, path: &Path) {
        match Config::load(path) {
            Ok((config, warnings)) => {
                for warning in warnings {
                    tracing::warn!("{}: {warning}", path.display());
                }
                tracing::info!(
                    "{}: {} DHCPv4 and {} DHCPv6 listen interfaces",
                    path.display(),
                    config.dhcp4.len(),
                    config.dhcp6.len()
                );
                self.config = config;
                self.resync();
            }
            Err(e) => tracing::error!("{e:#}; keeping the running config"),
        }
    }

    /// Brings the socket set in line with the config and the current
    /// interfaces.
    pub fn resync(&mut self) {
        self.refresh_ifaces();
        let wanted = self.wanted();
        self.sockets.retain(|key, _| wanted.contains_key(key));
        self.failed.retain(|key| wanted.contains_key(key));
        for (key, device) in wanted {
            let index = match &device {
                None => 0,
                Some(name) => match self.ifaces.get(name) {
                    Some(iface) => iface.index,
                    None => {
                        self.sockets.remove(&key);
                        if self.failed.insert(key.clone()) {
                            tracing::warn!("{key}: no interface {name}; waiting for it");
                        }
                        continue;
                    }
                },
            };
            if self
                .sockets
                .get(&key)
                .is_some_and(|s| s.device_index == index)
            {
                continue;
            }
            self.sockets.remove(&key);
            match self.open(&key, device.as_deref(), index) {
                Ok(sock) => {
                    self.failed.remove(&key);
                    tracing::info!("{key}: open");
                    self.sockets.insert(key, sock);
                }
                Err(e) => {
                    if self.failed.insert(key.clone()) {
                        tracing::warn!("{key}: {e}; retrying");
                    }
                }
            }
        }
        if self.config.dhcp4.is_empty() {
            self.link = None;
        } else if self.link.is_none() {
            match sys::packet_socket() {
                Ok(fd) => self.link = Some(fd),
                Err(e) => tracing::warn!("AF_PACKET socket: {e}; DHCPv4 replies will fail"),
            }
        }
    }

    fn refresh_ifaces(&mut self) {
        match Ifaces::read() {
            Ok(ifaces) => self.ifaces = ifaces,
            Err(e) => tracing::warn!("reading interfaces: {e}"),
        }
    }

    /// Every socket the config calls for, with the device to bind to.
    fn wanted(&self) -> BTreeMap<SockKey, Option<String>> {
        let vrf_device = |vrf: &str| (vrf != DEFAULT_VRF).then(|| vrf.to_string());
        let mut wanted = BTreeMap::new();
        for b in &self.config.dhcp4 {
            wanted.insert(
                SockKey::Broadcast4(b.interface.clone()),
                Some(b.interface.clone()),
            );
            let addrs = self.ifaces.get(&b.interface).map(|i| i.v4.as_slice());
            for addr in addrs.unwrap_or_default() {
                wanted.insert(SockKey::Unicast4(b.vrf.clone(), *addr), vrf_device(&b.vrf));
            }
        }
        for b in &self.config.dhcp6 {
            wanted.insert(
                SockKey::Listen6(b.interface.clone()),
                Some(b.interface.clone()),
            );
            wanted.insert(SockKey::Server6(b.vrf.clone()), vrf_device(&b.vrf));
        }
        wanted
    }

    fn open(&self, key: &SockKey, device: Option<&str>, index: u32) -> io::Result<Sock> {
        let any6 = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, packet6::SERVER_PORT, 0, 0);
        let fd = match key {
            SockKey::Broadcast4(_) => sys::udp4(
                device,
                SocketAddrV4::new(Ipv4Addr::BROADCAST, packet4::SERVER_PORT),
            )?,
            SockKey::Unicast4(_, addr) => {
                sys::udp4(device, SocketAddrV4::new(*addr, packet4::SERVER_PORT))?
            }
            SockKey::Listen6(_) => {
                let fd = sys::udp6(device, any6)?;
                sys::join6(
                    fd.as_raw_fd(),
                    packet6::ALL_DHCP_RELAY_AGENTS_AND_SERVERS,
                    index,
                )?;
                fd
            }
            SockKey::Server6(_) => {
                let fd = sys::udp6(device, any6)?;
                sys::multicast_all6(fd.as_raw_fd(), false)?;
                fd
            }
        };
        let fd = Arc::new(AsyncFd::new(fd)?);
        let reader = tokio::spawn(read_loop(key.clone(), fd.clone(), self.tx.clone()));
        Ok(Sock {
            fd,
            device_index: index,
            reader,
        })
    }

    pub fn handle(&mut self, incoming: Incoming) {
        let ifindex = incoming.received.ifindex;
        if ifindex != 0 && self.ifaces.name_of(ifindex).is_none() {
            self.refresh_ifaces();
        }
        let ingress = match self.ifaces.name_of(ifindex) {
            Some(name) => name.to_string(),
            None => format!("ifindex-{ifindex}"),
        };
        let data = &incoming.data;
        match (&incoming.key, incoming.received.src) {
            // Only broadcasts land here. A BOOTREPLY broadcast on a
            // client segment is some other server's business.
            (SockKey::Broadcast4(ifname), _) => {
                if data.first() == Some(&packet4::BOOTREQUEST)
                    && let Some(binding) = self.config.dhcp4.iter().find(|b| b.interface == *ifname)
                {
                    self.request4(binding, data);
                }
            }
            (SockKey::Unicast4(vrf, _), IpAddr::V4(src)) => {
                let listen = self
                    .config
                    .dhcp4
                    .iter()
                    .find(|b| b.vrf == *vrf && b.interface == ingress);
                match (data.first(), listen) {
                    (Some(&packet4::BOOTREQUEST), Some(binding)) => self.request4(binding, data),
                    (Some(&packet4::BOOTREPLY), _) => {
                        let from = Arrival {
                            vrf,
                            interface: &ingress,
                            listen: listen.is_some(),
                            src,
                        };
                        self.reply4(&from, data);
                    }
                    _ => {}
                }
            }
            (SockKey::Listen6(ifname), IpAddr::V6(src)) => {
                if let Some(binding) = self.config.dhcp6.iter().find(|b| b.interface == *ifname) {
                    self.dispatch6(&binding.vrf, &ingress, src, data);
                }
            }
            (SockKey::Server6(vrf), IpAddr::V6(src)) => self.dispatch6(vrf, &ingress, src, data),
            _ => {}
        }
    }

    fn dispatch6(&self, vrf: &str, ingress: &str, src: Ipv6Addr, data: &[u8]) {
        let listen = self
            .config
            .dhcp6
            .iter()
            .find(|b| b.vrf == vrf && b.interface == ingress);
        match (data.first(), listen) {
            (Some(&packet6::msg::RELAY_REPL), _) => {
                let from = Arrival {
                    vrf,
                    interface: ingress,
                    listen: listen.is_some(),
                    src,
                };
                self.reply6(&from, data);
            }
            (Some(_), Some(binding)) => self.request6(binding, data, src),
            _ => {}
        }
    }

    fn count(&self, family: Family, vrf: &str, interface: &str, f: impl FnOnce(&mut Counters)) {
        if let Ok(mut stats) = self.stats.lock() {
            f(stats.entry(family, vrf, interface));
        }
    }

    fn request4(&self, binding: &Binding4, data: &[u8]) {
        let (vrf, ifname) = (binding.vrf.as_str(), binding.interface.as_str());
        self.count(Family::V4, vrf, ifname, |c| c.received += 1);
        let forward = match v4::request(data, binding, &self.ifaces) {
            Ok(forward) => forward,
            Err(drop) => {
                tracing::debug!("dhcp4 {ifname}: request dropped: {}", drop.reason());
                return self.count(Family::V4, vrf, ifname, |c| c.drop(drop.reason()));
            }
        };
        let Some(sock) = self
            .sockets
            .get(&SockKey::Unicast4(vrf.to_string(), forward.source))
        else {
            return self.count(Family::V4, vrf, ifname, |c| c.drop("no-socket"));
        };
        let mut errors = 0;
        for server in &binding.servers {
            let dst = SocketAddrV4::new(*server, packet4::SERVER_PORT);
            if let Err(e) = sys::send4(sock.raw(), &forward.packet, dst) {
                tracing::debug!("dhcp4 {ifname}: to {dst}: {e}");
                errors += 1;
            }
        }
        let sent = errors < binding.servers.len();
        tracing::debug!(
            "dhcp4 {ifname}: request relayed to {} servers",
            binding.servers.len() - errors
        );
        self.count(Family::V4, vrf, ifname, |c| {
            c.send_errors += errors as u64;
            c.agent_option_omitted += u64::from(forward.agent_option_omitted);
            if sent {
                c.forwarded += 1;
            } else {
                c.drop("send-error");
            }
        });
    }

    fn reply4(&self, from: &Arrival<Ipv4Addr>, data: &[u8]) {
        let (vrf, ingress) = (from.vrf, from.interface);
        self.count(Family::V4, vrf, ingress, |c| c.received += 1);
        let reply = match v4::reply(data, from, &self.config.dhcp4, &self.ifaces) {
            Ok(reply) => reply,
            Err(drop) => {
                tracing::debug!(
                    "dhcp4 {ingress}: reply from {} dropped: {}",
                    from.src,
                    drop.reason()
                );
                return self.count(Family::V4, vrf, ingress, |c| c.drop(drop.reason()));
            }
        };
        let out = reply.binding.interface.as_str();
        let (Some(link), Some(iface)) = (&self.link, self.ifaces.get(out)) else {
            return self.count(Family::V4, vrf, ingress, |c| c.drop("no-socket"));
        };
        match sys::send_link(link.as_raw_fd(), iface.index, reply.mac, &reply.datagram) {
            Ok(()) => {
                let how = if reply.broadcast {
                    "broadcast"
                } else {
                    "unicast"
                };
                tracing::debug!("dhcp4 {ingress}: reply relayed to {out} ({how})");
                self.count(Family::V4, vrf, ingress, |c| c.forwarded += 1);
            }
            Err(e) => {
                tracing::debug!("dhcp4 {ingress}: reply to {out}: {e}");
                self.count(Family::V4, vrf, ingress, |c| {
                    c.send_errors += 1;
                    c.drop("send-error");
                });
            }
        }
    }

    fn request6(&self, binding: &Binding6, data: &[u8], peer: Ipv6Addr) {
        let (vrf, ifname) = (binding.vrf.as_str(), binding.interface.as_str());
        self.count(Family::V6, vrf, ifname, |c| c.received += 1);
        let packet = match v6::upward(data, peer, binding, &self.ifaces) {
            Ok(packet) => packet,
            Err(drop) => {
                tracing::debug!("dhcp6 {ifname}: dropped: {}", drop.reason());
                return self.count(Family::V6, vrf, ifname, |c| c.drop(drop.reason()));
            }
        };
        let Some(sock) = self.sockets.get(&SockKey::Server6(vrf.to_string())) else {
            return self.count(Family::V6, vrf, ifname, |c| c.drop("no-socket"));
        };
        let mut errors = 0;
        for server in &binding.servers {
            let index = match &server.interface {
                None => 0,
                Some(name) => match self.ifaces.get(name) {
                    Some(iface) => iface.index,
                    None => {
                        tracing::debug!(
                            "dhcp6 {ifname}: to {}: no interface {name}",
                            server.address
                        );
                        errors += 1;
                        continue;
                    }
                },
            };
            let dst = SocketAddrV6::new(server.address, packet6::SERVER_PORT, 0, index);
            if let Err(e) = sys::send6(sock.raw(), &packet, dst, index) {
                tracing::debug!("dhcp6 {ifname}: to {dst}: {e}");
                errors += 1;
            }
        }
        let sent = errors < binding.servers.len();
        self.count(Family::V6, vrf, ifname, |c| {
            c.send_errors += errors as u64;
            if sent {
                c.forwarded += 1;
            } else {
                c.drop("send-error");
            }
        });
    }

    fn reply6(&self, from: &Arrival<Ipv6Addr>, data: &[u8]) {
        let (vrf, ingress) = (from.vrf, from.interface);
        self.count(Family::V6, vrf, ingress, |c| c.received += 1);
        let down = match v6::downward(data, from, &self.config.dhcp6, &self.ifaces) {
            Ok(down) => down,
            Err(drop) => {
                tracing::debug!(
                    "dhcp6 {ingress}: relay-reply from {} dropped: {}",
                    from.src,
                    drop.reason()
                );
                return self.count(Family::V6, vrf, ingress, |c| c.drop(drop.reason()));
            }
        };
        let out = down.binding.interface.as_str();
        let (Some(sock), Some(iface)) = (
            self.sockets.get(&SockKey::Listen6(out.to_string())),
            self.ifaces.get(out),
        ) else {
            return self.count(Family::V6, vrf, ingress, |c| c.drop("no-socket"));
        };
        let dst = SocketAddrV6::new(down.peer, down.port, 0, iface.index);
        match sys::send6(sock.raw(), &down.packet, dst, iface.index) {
            Ok(()) => {
                tracing::debug!("dhcp6 {ingress}: relay-reply delivered to {dst}");
                self.count(Family::V6, vrf, ingress, |c| c.forwarded += 1);
            }
            Err(e) => {
                tracing::debug!("dhcp6 {ingress}: to {dst}: {e}");
                self.count(Family::V6, vrf, ingress, |c| {
                    c.send_errors += 1;
                    c.drop("send-error");
                });
            }
        }
    }
}

/// Reads datagrams from one socket and hands them to the main loop
/// until the socket is dropped (the task is aborted then) or the main
/// loop is gone.
async fn read_loop(key: SockKey, fd: Arc<AsyncFd<OwnedFd>>, tx: mpsc::Sender<Incoming>) {
    let v6 = key.family() == Family::V6;
    let mut buf = vec![0; RECV_BUFFER];
    loop {
        let Ok(mut guard) = fd.readable().await else {
            return;
        };
        let received = match guard.try_io(|fd| {
            let raw = fd.get_ref().as_raw_fd();
            if v6 {
                sys::recv6(raw, &mut buf)
            } else {
                sys::recv4(raw, &mut buf)
            }
        }) {
            Ok(Ok(received)) => received,
            Ok(Err(e)) => {
                tracing::debug!("{key}: receive: {e}");
                continue;
            }
            Err(_would_block) => continue,
        };
        let incoming = Incoming {
            key: key.clone(),
            data: buf[..received.len].to_vec(),
            received,
        };
        if tx.send(incoming).await.is_err() {
            return;
        }
    }
}
