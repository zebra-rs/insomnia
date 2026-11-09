//! The kernel link and address watcher (`crate::links`).
//!
//! One `NETLINK_ROUTE` socket, subscribed to `RTMGRP_LINK`,
//! `RTMGRP_IPV4_IFADDR` and `RTMGRP_IPV6_IFADDR`, tells the process
//! that something changed; a fresh `RTM_GETLINK` + `RTM_GETADDR` dump
//! on a second socket then builds a complete [`Snapshot`], which is
//! published on a `watch` channel when it differs from the last one.
//! A burst of events (an interface moved into a VRF, its addresses
//! re-added) is coalesced into one dump, and a lost event (`ENOBUFS`)
//! is no different from any other: the next dump is complete either
//! way. Subscribers therefore never resync; they re-derive what they
//! need from the latest snapshot.
//!
//! The messages are parsed by hand, as `vici.rs` speaks VICI: only
//! `ifinfomsg` (index, flags), `IFLA_IFNAME`, `IFLA_MASTER`,
//! `IFLA_LINKINFO`/`IFLA_INFO_KIND`, and `ifaddrmsg` (family, prefix
//! length, index) with `IFA_LOCAL`, `IFA_ADDRESS` and `IFA_FLAGS`. The
//! constants come from `linux/rtnetlink.h`, `linux/if_link.h` and
//! `linux/if_addr.h`, and the tests pin them.
//!
//! The DHCP server backend is the first subscriber: Kea's listen set is
//! the set of interfaces carrying an address inside an enabled subnet
//! (design/dhcp.md §7.3), and Kea's DHCPv6 sockets need a link-local
//! address that is no longer tentative. The plans for firewall zones,
//! flowtables and per-VRF VRRP (design/plans/fw-global-options.md
//! §3.2a) read VRF membership from here too.

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::unix::AsyncFd;
use tokio::sync::watch;

/// One network device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    pub index: u32,
    pub name: String,
    /// `IFLA_INFO_KIND`: `vrf`, `bridge`, `veth`, …; `None` for a
    /// physical device.
    pub kind: Option<String>,
    /// `IFLA_MASTER`: the index of the VRF or bridge it is enslaved to.
    pub master: Option<u32>,
    /// `IFF_UP`.
    pub up: bool,
}

/// One interface address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Addr {
    pub index: u32,
    pub addr: IpAddr,
    pub prefix_len: u8,
    /// Still in duplicate address detection, or failed it: not usable
    /// as a source address yet.
    pub tentative: bool,
}

/// Every device and address in insomnia's network namespace.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub links: BTreeMap<u32, Link>,
    pub addrs: Vec<Addr>,
}

/// The VRF name of interfaces that are in no VRF.
pub const DEFAULT_VRF: &str = "default";

impl Snapshot {
    #[cfg(test)]
    pub fn link(&self, name: &str) -> Option<&Link> {
        self.links.values().find(|l| l.name == name)
    }

    /// The VRF `link` belongs to: its master when that is a VRF device,
    /// the VRF itself for a VRF device, else [`DEFAULT_VRF`].
    pub fn vrf_of<'a>(&'a self, link: &'a Link) -> &'a str {
        if link.kind.as_deref() == Some("vrf") {
            return &link.name;
        }
        match link.master.and_then(|m| self.links.get(&m)) {
            Some(master) if master.kind.as_deref() == Some("vrf") => &master.name,
            _ => DEFAULT_VRF,
        }
    }

    /// The addresses of the interface with index `index`.
    pub fn addrs_of(&self, index: u32) -> impl Iterator<Item = &Addr> {
        self.addrs.iter().filter(move |a| a.index == index)
    }

    /// The interfaces of `vrf` (VRF devices themselves excluded), in
    /// index order.
    pub fn members(&self, vrf: &str) -> impl Iterator<Item = &Link> {
        self.links
            .values()
            .filter(move |l| l.kind.as_deref() != Some("vrf") && self.vrf_of(l) == vrf)
    }
}

/// Start the watcher: the first snapshot is dumped before this returns,
/// so subscribers start from the real state. Failures to open the
/// socket are logged and leave the receiver on the first snapshot (or
/// an empty one), which is what a host without netlink can offer.
pub async fn spawn() -> watch::Receiver<Arc<Snapshot>> {
    let first = match tokio::task::spawn_blocking(dump).await {
        Ok(Ok(snapshot)) => snapshot,
        Ok(Err(err)) => {
            tracing::error!("links: initial netlink dump failed: {err}");
            Snapshot::default()
        }
        Err(err) => {
            tracing::error!("links: initial netlink dump panicked: {err}");
            Snapshot::default()
        }
    };
    let (tx, rx) = watch::channel(Arc::new(first));
    match events_socket() {
        Ok(fd) => {
            tokio::spawn(watch_loop(fd, tx));
        }
        Err(err) => tracing::error!("links: netlink event socket failed: {err}"),
    }
    rx
}

/// How long a burst of events may run on before the dump: moving an
/// interface into a VRF flushes and re-adds its addresses in several
/// messages.
const SETTLE: Duration = Duration::from_millis(100);
/// Back-off after a failed dump.
const RETRY: Duration = Duration::from_secs(1);

async fn watch_loop(fd: OwnedFd, tx: watch::Sender<Arc<Snapshot>>) {
    let fd = match AsyncFd::new(fd) {
        Ok(fd) => fd,
        Err(err) => {
            tracing::error!("links: netlink event socket: {err}");
            return;
        }
    };
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        // Wait for any event (or ENOBUFS, which means events were lost:
        // the dump below covers them as well).
        match fd.readable().await {
            Ok(mut guard) => {
                drain(guard.get_inner().as_raw_fd(), &mut buf);
                guard.clear_ready();
            }
            Err(err) => {
                tracing::error!("links: netlink event socket: {err}");
                return;
            }
        }
        tokio::time::sleep(SETTLE).await;
        drain(fd.as_raw_fd(), &mut buf);
        loop {
            match tokio::task::spawn_blocking(dump).await {
                Ok(Ok(snapshot)) => {
                    if **tx.borrow() != snapshot {
                        tracing::debug!(
                            "links: {} links, {} addresses",
                            snapshot.links.len(),
                            snapshot.addrs.len()
                        );
                        tx.send_replace(Arc::new(snapshot));
                    }
                    break;
                }
                Ok(Err(err)) => tracing::warn!("links: netlink dump failed: {err}; retrying"),
                Err(err) => tracing::warn!("links: netlink dump panicked: {err}; retrying"),
            }
            tokio::time::sleep(RETRY).await;
        }
    }
}

/// Read and discard everything queued on the non-blocking event socket.
fn drain(fd: RawFd, buf: &mut [u8]) {
    loop {
        // SAFETY: `buf` is a valid writable buffer of `buf.len()` bytes.
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                // Overrun: events were dropped; the dump covers them.
                Some(libc::ENOBUFS) | Some(libc::EINTR) => continue,
                _ => return,
            }
        }
        if n == 0 {
            return;
        }
    }
}

// ---------------------------------------------------------------
// Netlink plumbing
// ---------------------------------------------------------------

const NETLINK_ROUTE: i32 = 0;
const RTMGRP_LINK: u32 = 0x1;
const RTMGRP_IPV4_IFADDR: u32 = 0x10;
const RTMGRP_IPV6_IFADDR: u32 = 0x100;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_DUMP: u16 = 0x300;

const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;

const IFLA_IFNAME: u16 = 3;
const IFLA_MASTER: u16 = 10;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_FLAGS: u16 = 8;
const IFA_F_DADFAILED: u32 = 0x08;
const IFA_F_TENTATIVE: u32 = 0x40;

/// `nla_type` without `NLA_F_NESTED` / `NLA_F_NET_BYTEORDER`.
const NLA_TYPE_MASK: u16 = 0x3fff;

const NLMSG_HDRLEN: usize = 16;
const IFINFOMSG_LEN: usize = 16;
const IFADDRMSG_LEN: usize = 8;

fn cvt(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

fn netlink_socket(flags: libc::c_int, groups: u32) -> io::Result<OwnedFd> {
    // SAFETY: plain socket(2); the fd is owned by OwnedFd from here on.
    let fd = cvt(unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | flags,
            NETLINK_ROUTE,
        )
    })?;
    // SAFETY: `fd` was just returned by socket(2) and is not shared.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: an all-zero sockaddr_nl is valid; the fields set below are
    // the ones bind(2) reads.
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    addr.nl_groups = groups;
    // SAFETY: `addr` is a valid sockaddr_nl of the size passed.
    cvt(unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&addr as *const libc::sockaddr_nl).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    })?;
    Ok(fd)
}

fn events_socket() -> io::Result<OwnedFd> {
    let fd = netlink_socket(
        libc::SOCK_NONBLOCK,
        RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR,
    )?;
    // A large buffer makes overruns rare; they are harmless anyway.
    let size: libc::c_int = 1 << 20;
    // SAFETY: SO_RCVBUF takes an int of the size passed.
    unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&size as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
    Ok(fd)
}

/// A dump request: `nlmsghdr` followed by a zeroed `ifinfomsg` or
/// `ifaddrmsg` (family `AF_UNSPEC`: every family).
fn dump_request(kind: u16, body_len: usize, seq: u32) -> Vec<u8> {
    let len = NLMSG_HDRLEN + body_len;
    let mut msg = Vec::with_capacity(len);
    msg.extend_from_slice(&(len as u32).to_ne_bytes());
    msg.extend_from_slice(&kind.to_ne_bytes());
    msg.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    msg.extend_from_slice(&seq.to_ne_bytes());
    msg.extend_from_slice(&0u32.to_ne_bytes());
    msg.resize(len, 0);
    msg
}

/// Send one dump request and collect the payloads of every reply
/// message of type `want` until `NLMSG_DONE`.
fn dump_one(fd: RawFd, kind: u16, body_len: usize, want: u16) -> io::Result<Vec<Vec<u8>>> {
    let req = dump_request(kind, body_len, u32::from(kind));
    // SAFETY: `req` is a valid buffer of `req.len()` bytes.
    let sent = unsafe { libc::send(fd, req.as_ptr().cast(), req.len(), 0) };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut out = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        // SAFETY: `buf` is a valid writable buffer of `buf.len()` bytes.
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        for (ty, payload) in messages(&buf[..n as usize]) {
            match ty {
                NLMSG_DONE => return Ok(out),
                NLMSG_ERROR => {
                    let code = payload
                        .get(..4)
                        .map(|b| i32::from_ne_bytes(b.try_into().unwrap()))
                        .unwrap_or(0);
                    if code != 0 {
                        return Err(io::Error::from_raw_os_error(-code));
                    }
                }
                ty if ty == want => out.push(payload.to_vec()),
                _ => {}
            }
        }
    }
}

/// A complete snapshot: every link, then every address.
pub fn dump() -> io::Result<Snapshot> {
    let fd = netlink_socket(0, 0)?;
    let mut snapshot = Snapshot::default();
    for payload in dump_one(fd.as_raw_fd(), RTM_GETLINK, IFINFOMSG_LEN, RTM_NEWLINK)? {
        if let Some(link) = parse_link(&payload) {
            snapshot.links.insert(link.index, link);
        }
    }
    for payload in dump_one(fd.as_raw_fd(), RTM_GETADDR, IFADDRMSG_LEN, RTM_NEWADDR)? {
        if let Some(addr) = parse_addr(&payload) {
            snapshot.addrs.push(addr);
        }
    }
    Ok(snapshot)
}

/// Split a datagram into `(nlmsg_type, payload)` pairs.
fn messages(mut buf: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    while buf.len() >= NLMSG_HDRLEN {
        let len = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
        let ty = u16::from_ne_bytes(buf[4..6].try_into().unwrap());
        if len < NLMSG_HDRLEN || len > buf.len() {
            break;
        }
        out.push((ty, &buf[NLMSG_HDRLEN..len]));
        let aligned = (len + 3) & !3;
        buf = buf.get(aligned..).unwrap_or_default();
    }
    out
}

/// Split attributes into `(type, value)` pairs.
fn attrs(mut buf: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    while buf.len() >= 4 {
        let len = u16::from_ne_bytes(buf[0..2].try_into().unwrap()) as usize;
        let ty = u16::from_ne_bytes(buf[2..4].try_into().unwrap()) & NLA_TYPE_MASK;
        if len < 4 || len > buf.len() {
            break;
        }
        out.push((ty, &buf[4..len]));
        let aligned = (len + 3) & !3;
        buf = buf.get(aligned..).unwrap_or_default();
    }
    out
}

fn c_string(value: &[u8]) -> String {
    let end = value.iter().position(|&b| b == 0).unwrap_or(value.len());
    String::from_utf8_lossy(&value[..end]).into_owned()
}

fn ne_u32(value: &[u8]) -> Option<u32> {
    Some(u32::from_ne_bytes(value.get(..4)?.try_into().ok()?))
}

/// An `RTM_NEWLINK` payload: `ifinfomsg` then attributes.
fn parse_link(payload: &[u8]) -> Option<Link> {
    if payload.len() < IFINFOMSG_LEN {
        return None;
    }
    let index = i32::from_ne_bytes(payload[4..8].try_into().ok()?);
    let flags = u32::from_ne_bytes(payload[8..12].try_into().ok()?);
    let mut link = Link {
        index: u32::try_from(index).ok()?,
        name: String::new(),
        kind: None,
        master: None,
        up: flags & libc::IFF_UP as u32 != 0,
    };
    for (ty, value) in attrs(&payload[IFINFOMSG_LEN..]) {
        match ty {
            IFLA_IFNAME => link.name = c_string(value),
            IFLA_MASTER => link.master = ne_u32(value).filter(|&m| m != 0),
            IFLA_LINKINFO => {
                for (ty, value) in attrs(value) {
                    if ty == IFLA_INFO_KIND {
                        link.kind = Some(c_string(value));
                    }
                }
            }
            _ => {}
        }
    }
    (!link.name.is_empty()).then_some(link)
}

/// An `RTM_NEWADDR` payload: `ifaddrmsg` then attributes. `IFA_LOCAL`
/// is the interface's own address when present (it differs from
/// `IFA_ADDRESS` only on a point-to-point link); `IFA_FLAGS` carries
/// the full flag word that `ifa_flags` truncates to 8 bits.
fn parse_addr(payload: &[u8]) -> Option<Addr> {
    if payload.len() < IFADDRMSG_LEN {
        return None;
    }
    let family = i32::from(payload[0]);
    let prefix_len = payload[1];
    let mut flags = u32::from(payload[2]);
    let index = u32::from_ne_bytes(payload[4..8].try_into().ok()?);
    let (mut address, mut local) = (None, None);
    for (ty, value) in attrs(&payload[IFADDRMSG_LEN..]) {
        match ty {
            IFA_ADDRESS => address = ip(family, value),
            IFA_LOCAL => local = ip(family, value),
            IFA_FLAGS => flags = ne_u32(value).unwrap_or(flags),
            _ => {}
        }
    }
    Some(Addr {
        index,
        addr: local.or(address)?,
        prefix_len,
        tentative: flags & (IFA_F_TENTATIVE | IFA_F_DADFAILED) != 0,
    })
}

fn ip(family: i32, value: &[u8]) -> Option<IpAddr> {
    match family {
        libc::AF_INET => {
            let octets: [u8; 4] = value.get(..4)?.try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        libc::AF_INET6 => {
            let octets: [u8; 16] = value.get(..16)?.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(ty: u16, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&((4 + value.len()) as u16).to_ne_bytes());
        out.extend_from_slice(&ty.to_ne_bytes());
        out.extend_from_slice(value);
        out.resize((out.len() + 3) & !3, 0);
        out
    }

    fn ifinfomsg(index: i32, flags: u32) -> Vec<u8> {
        let mut out = vec![0u8; 4];
        out.extend_from_slice(&index.to_ne_bytes());
        out.extend_from_slice(&flags.to_ne_bytes());
        out.extend_from_slice(&0u32.to_ne_bytes());
        out
    }

    fn message(ty: u16, payload: &[u8]) -> Vec<u8> {
        let len = NLMSG_HDRLEN + payload.len();
        let mut out = Vec::new();
        out.extend_from_slice(&(len as u32).to_ne_bytes());
        out.extend_from_slice(&ty.to_ne_bytes());
        out.extend_from_slice(&[0u8; 10]);
        out.extend_from_slice(payload);
        out.resize((out.len() + 3) & !3, 0);
        out
    }

    /// The constants are linux/rtnetlink.h, if_link.h and if_addr.h.
    #[test]
    fn constants() {
        assert_eq!(
            (RTM_NEWLINK, RTM_GETLINK, RTM_NEWADDR, RTM_GETADDR),
            (16, 18, 20, 22)
        );
        assert_eq!((IFLA_IFNAME, IFLA_MASTER, IFLA_LINKINFO), (3, 10, 18));
        assert_eq!((IFA_ADDRESS, IFA_LOCAL, IFA_FLAGS), (1, 2, 8));
        assert_eq!(IFA_F_TENTATIVE, 0x40);
        assert_eq!(std::mem::size_of::<libc::ifaddrmsg>(), IFADDRMSG_LEN);
        assert_eq!(std::mem::size_of::<libc::nlmsghdr>(), NLMSG_HDRLEN);
    }

    #[test]
    fn link_with_vrf_master() {
        let mut payload = ifinfomsg(7, libc::IFF_UP as u32);
        payload.extend(attr(IFLA_IFNAME, b"lanred\0"));
        payload.extend(attr(IFLA_MASTER, &5u32.to_ne_bytes()));
        payload.extend(attr(
            IFLA_LINKINFO | 0x8000,
            &attr(IFLA_INFO_KIND, b"veth\0"),
        ));
        let link = parse_link(&payload).unwrap();
        assert_eq!(
            link,
            Link {
                index: 7,
                name: "lanred".into(),
                kind: Some("veth".into()),
                master: Some(5),
                up: true,
            }
        );
    }

    #[test]
    fn tentative_v6_address() {
        let mut payload = vec![libc::AF_INET6 as u8, 64, 0, 253];
        payload.extend_from_slice(&3u32.to_ne_bytes());
        let ll: Ipv6Addr = "fe80::1".parse().unwrap();
        payload.extend(attr(IFA_ADDRESS, &ll.octets()));
        payload.extend(attr(IFA_FLAGS, &(IFA_F_TENTATIVE | 0x80).to_ne_bytes()));
        let addr = parse_addr(&payload).unwrap();
        assert_eq!(
            addr,
            Addr {
                index: 3,
                addr: IpAddr::V6(ll),
                prefix_len: 64,
                tentative: true,
            }
        );
    }

    #[test]
    fn v4_local_wins_over_peer() {
        let mut payload = vec![libc::AF_INET as u8, 32, 0, 0];
        payload.extend_from_slice(&4u32.to_ne_bytes());
        payload.extend(attr(IFA_ADDRESS, &[192, 0, 2, 2]));
        payload.extend(attr(IFA_LOCAL, &[192, 0, 2, 1]));
        let addr = parse_addr(&payload).unwrap();
        assert_eq!(addr.addr, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert!(!addr.tentative);
    }

    #[test]
    fn messages_split_and_vrf_membership() {
        let mut vrf = ifinfomsg(5, libc::IFF_UP as u32);
        vrf.extend(attr(IFLA_IFNAME, b"red\0"));
        vrf.extend(attr(IFLA_LINKINFO, &attr(IFLA_INFO_KIND, b"vrf\0")));
        let mut lan = ifinfomsg(7, 0);
        lan.extend(attr(IFLA_IFNAME, b"lanred\0"));
        lan.extend(attr(IFLA_MASTER, &5u32.to_ne_bytes()));
        let mut wan = ifinfomsg(8, 0);
        wan.extend(attr(IFLA_IFNAME, b"wan9\0"));
        let mut buf = message(RTM_NEWLINK, &vrf);
        buf.extend(message(RTM_NEWLINK, &lan));
        buf.extend(message(RTM_NEWLINK, &wan));
        buf.extend(message(NLMSG_DONE, &[0, 0, 0, 0]));

        let parsed = messages(&buf);
        assert_eq!(
            parsed.iter().map(|(ty, _)| *ty).collect::<Vec<_>>(),
            [RTM_NEWLINK, RTM_NEWLINK, RTM_NEWLINK, NLMSG_DONE]
        );
        let mut snapshot = Snapshot::default();
        for (_, payload) in &parsed[..3] {
            let link = parse_link(payload).unwrap();
            snapshot.links.insert(link.index, link);
        }
        let lan = snapshot.link("lanred").unwrap();
        assert_eq!(snapshot.vrf_of(lan), "red");
        assert_eq!(snapshot.vrf_of(snapshot.link("red").unwrap()), "red");
        assert_eq!(snapshot.vrf_of(snapshot.link("wan9").unwrap()), DEFAULT_VRF);
        let red: Vec<&str> = snapshot.members("red").map(|l| l.name.as_str()).collect();
        assert_eq!(red, ["lanred"]);
        let default: Vec<&str> = snapshot
            .members(DEFAULT_VRF)
            .map(|l| l.name.as_str())
            .collect();
        assert_eq!(default, ["wan9"]);
    }

    /// The real dump of the test host has a loopback with 127.0.0.1/8.
    #[test]
    fn dump_host() {
        let snapshot = dump().unwrap();
        let lo = snapshot.link("lo").unwrap();
        assert!(lo.up);
        assert!(snapshot.addrs_of(lo.index).any(|a| {
            a.addr == IpAddr::V4(Ipv4Addr::LOCALHOST) && a.prefix_len == 8 && !a.tentative
        }));
    }
}
