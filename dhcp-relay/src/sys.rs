//! The system calls the relay needs and std does not offer:
//! `SO_BINDTODEVICE`, `IP_PKTINFO` / `IPV6_PKTINFO` ancillary data,
//! `AF_PACKET` sends and getifaddrs(3). Every `unsafe` block of the
//! crate is in this module.

use std::ffi::CStr;
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;

use libc::{c_int, c_void, socklen_t};

fn cvt(ret: c_int) -> io::Result<c_int> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

fn setsockopt<T>(fd: RawFd, level: c_int, name: c_int, value: &T) -> io::Result<()> {
    // SAFETY: `value` is a live `T` and the length passed is its size.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            ptr::from_ref(value).cast::<c_void>(),
            mem::size_of::<T>() as socklen_t,
        )
    };
    cvt(ret).map(|_| ())
}

fn socket(domain: c_int, ty: c_int, protocol: c_int) -> io::Result<OwnedFd> {
    // SAFETY: plain syscall; a non-negative return is a new descriptor
    // that nothing else owns.
    let fd = cvt(unsafe {
        libc::socket(
            domain,
            ty | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            protocol,
        )
    })?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn bind_device(fd: RawFd, device: &str) -> io::Result<()> {
    // SAFETY: the kernel reads `device.len()` bytes; no NUL is needed.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            device.as_ptr().cast::<c_void>(),
            device.len() as socklen_t,
        )
    };
    cvt(ret).map(|_| ())
}

fn bind<T>(fd: RawFd, addr: &T) -> io::Result<()> {
    // SAFETY: `addr` is a sockaddr_* of the socket's family.
    let ret = unsafe {
        libc::bind(
            fd,
            ptr::from_ref(addr).cast::<libc::sockaddr>(),
            mem::size_of::<T>() as socklen_t,
        )
    };
    cvt(ret).map(|_| ())
}

fn sockaddr_v4(addr: SocketAddrV4) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: addr.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from(*addr.ip()).to_be(),
        },
        sin_zero: [0; 8],
    }
}

fn sockaddr_v6(addr: SocketAddrV6) -> libc::sockaddr_in6 {
    libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: addr.port().to_be(),
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr {
            s6_addr: addr.ip().octets(),
        },
        sin6_scope_id: addr.scope_id(),
    }
}

/// A UDP socket bound to `addr` with `IP_PKTINFO`, and to `device`
/// when given. Callers never pass the wildcard address; see `relay.rs`
/// for why. `SO_REUSEADDR` lets the relay's own sockets share the
/// port.
pub fn udp4(device: Option<&str>, addr: SocketAddrV4) -> io::Result<OwnedFd> {
    let fd = socket(libc::AF_INET, libc::SOCK_DGRAM, 0)?;
    let raw = fd.as_raw_fd();
    let one: c_int = 1;
    setsockopt(raw, libc::SOL_SOCKET, libc::SO_REUSEADDR, &one)?;
    setsockopt(raw, libc::IPPROTO_IP, libc::IP_PKTINFO, &one)?;
    if let Some(device) = device {
        bind_device(raw, device)?;
    }
    bind(raw, &sockaddr_v4(addr))?;
    Ok(fd)
}

/// A UDP socket bound to `addr` with `IPV6_RECVPKTINFO`, and to
/// `device` when given. Our own multicasts are not looped back.
pub fn udp6(device: Option<&str>, addr: SocketAddrV6) -> io::Result<OwnedFd> {
    let fd = socket(libc::AF_INET6, libc::SOCK_DGRAM, 0)?;
    let raw = fd.as_raw_fd();
    let (one, zero): (c_int, c_int) = (1, 0);
    setsockopt(raw, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, &one)?;
    setsockopt(raw, libc::SOL_SOCKET, libc::SO_REUSEADDR, &one)?;
    setsockopt(raw, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, &one)?;
    setsockopt(raw, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_LOOP, &zero)?;
    if let Some(device) = device {
        bind_device(raw, device)?;
    }
    bind(raw, &sockaddr_v6(addr))?;
    Ok(fd)
}

/// Joins `group` on interface `ifindex`.
pub fn join6(fd: RawFd, group: Ipv6Addr, ifindex: u32) -> io::Result<()> {
    let mreq = libc::ipv6_mreq {
        ipv6mr_multiaddr: libc::in6_addr {
            s6_addr: group.octets(),
        },
        ipv6mr_interface: ifindex,
    };
    setsockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_ADD_MEMBERSHIP, &mreq)
}

/// `IPV6_MULTICAST_ALL`: whether the socket receives every group some
/// other socket on the host joined (the kernel default), or only its
/// own.
pub fn multicast_all6(fd: RawFd, on: bool) -> io::Result<()> {
    setsockopt(
        fd,
        libc::IPPROTO_IPV6,
        libc::IPV6_MULTICAST_ALL,
        &c_int::from(on),
    )
}

/// One received datagram: its length in the caller's buffer, the
/// sender, and from the packet-info ancillary data the interface it
/// arrived on.
#[derive(Clone, Copy, Debug)]
pub struct Received {
    pub len: usize,
    pub src: IpAddr,
    pub ifindex: u32,
}

/// 8-byte aligned room for one packet-info control message.
type Control = [u64; 16];

fn recvmsg<A>(
    fd: RawFd,
    buf: &mut [u8],
    name: &mut A,
    control: &mut Control,
) -> io::Result<(usize, libc::msghdr)> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast::<c_void>(),
        iov_len: buf.len(),
    };
    // SAFETY: msghdr is plain data; every pointer set below outlives
    // the call.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_name = ptr::from_mut(name).cast::<c_void>();
    msg.msg_namelen = mem::size_of::<A>() as socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast::<c_void>();
    msg.msg_controllen = mem::size_of::<Control>() as _;
    // SAFETY: as above.
    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((n as usize, msg))
}

/// Calls `f` with the level, type and data pointer of each control
/// message `recvmsg` returned.
fn each_cmsg(msg: &libc::msghdr, mut f: impl FnMut(c_int, c_int, *const u8)) {
    // SAFETY: `msg` came back from recvmsg, so its control fields
    // describe a valid control buffer that is still alive.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            f((*cmsg).cmsg_level, (*cmsg).cmsg_type, libc::CMSG_DATA(cmsg));
            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
    }
}

pub fn recv4(fd: RawFd, buf: &mut [u8]) -> io::Result<Received> {
    // SAFETY: sockaddr_in is plain data.
    let mut src: libc::sockaddr_in = unsafe { mem::zeroed() };
    let mut control: Control = [0; 16];
    let (len, msg) = recvmsg(fd, buf, &mut src, &mut control)?;
    let mut ifindex = 0;
    each_cmsg(&msg, |level, ty, data| {
        if level == libc::IPPROTO_IP && ty == libc::IP_PKTINFO {
            // SAFETY: an IP_PKTINFO message carries an in_pktinfo.
            let info: libc::in_pktinfo = unsafe { ptr::read_unaligned(data.cast()) };
            ifindex = info.ipi_ifindex as u32;
        }
    });
    Ok(Received {
        len,
        src: IpAddr::V4(Ipv4Addr::from(u32::from_be(src.sin_addr.s_addr))),
        ifindex,
    })
}

pub fn recv6(fd: RawFd, buf: &mut [u8]) -> io::Result<Received> {
    // SAFETY: sockaddr_in6 is plain data.
    let mut src: libc::sockaddr_in6 = unsafe { mem::zeroed() };
    let mut control: Control = [0; 16];
    let (len, msg) = recvmsg(fd, buf, &mut src, &mut control)?;
    let mut ifindex = 0;
    each_cmsg(&msg, |level, ty, data| {
        if level == libc::IPPROTO_IPV6 && ty == libc::IPV6_PKTINFO {
            // SAFETY: an IPV6_PKTINFO message carries an in6_pktinfo.
            let info: libc::in6_pktinfo = unsafe { ptr::read_unaligned(data.cast()) };
            ifindex = info.ipi6_ifindex;
        }
    });
    Ok(Received {
        len,
        src: IpAddr::V6(Ipv6Addr::from(src.sin6_addr.s6_addr)),
        ifindex,
    })
}

fn sendto<T>(fd: RawFd, buf: &[u8], addr: &T) -> io::Result<()> {
    // SAFETY: `buf` and `addr` are live for the call.
    let n = unsafe {
        libc::sendto(
            fd,
            buf.as_ptr().cast::<c_void>(),
            buf.len(),
            0,
            ptr::from_ref(addr).cast::<libc::sockaddr>(),
            mem::size_of::<T>() as socklen_t,
        )
    };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn send4(fd: RawFd, buf: &[u8], dst: SocketAddrV4) -> io::Result<()> {
    sendto(fd, buf, &sockaddr_v4(dst))
}

/// Sends to `dst`; a non-zero `ifindex` picks the outgoing interface
/// through `IPV6_PKTINFO`, which works for unicast and multicast alike.
pub fn send6(fd: RawFd, buf: &[u8], dst: SocketAddrV6, ifindex: u32) -> io::Result<()> {
    if ifindex == 0 {
        return sendto(fd, buf, &sockaddr_v6(dst));
    }
    let mut name = sockaddr_v6(dst);
    let mut iov = libc::iovec {
        iov_base: buf.as_ptr().cast_mut().cast::<c_void>(),
        iov_len: buf.len(),
    };
    let mut control: Control = [0; 16];
    let info = libc::in6_pktinfo {
        ipi6_addr: libc::in6_addr { s6_addr: [0; 16] },
        ipi6_ifindex: ifindex,
    };
    // SAFETY: msghdr is plain data; the control buffer has room for one
    // in6_pktinfo message (CMSG_SPACE(20) is 40 bytes) and every pointer
    // outlives sendmsg.
    let n = unsafe {
        let mut msg: libc::msghdr = mem::zeroed();
        msg.msg_name = ptr::from_mut(&mut name).cast::<c_void>();
        msg.msg_namelen = mem::size_of::<libc::sockaddr_in6>() as socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast::<c_void>();
        msg.msg_controllen = libc::CMSG_SPACE(mem::size_of::<libc::in6_pktinfo>() as u32) as _;
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::IPPROTO_IPV6;
        (*cmsg).cmsg_type = libc::IPV6_PKTINFO;
        (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<libc::in6_pktinfo>() as u32) as _;
        ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::in6_pktinfo>(), info);
        libc::sendmsg(fd, &msg, 0)
    };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// An `AF_PACKET` datagram socket for sending IPv4 frames to a given
/// MAC address. Protocol 0 means it is attached to no protocol, so it
/// receives nothing.
pub fn packet_socket() -> io::Result<OwnedFd> {
    socket(libc::AF_PACKET, libc::SOCK_DGRAM, 0)
}

/// Sends the IPv4 datagram `ip` out of interface `ifindex` to `mac`;
/// the kernel adds the link-layer header.
pub fn send_link(fd: RawFd, ifindex: u32, mac: [u8; 6], ip: &[u8]) -> io::Result<()> {
    let mut sll_addr = [0; 8];
    sll_addr[..6].copy_from_slice(&mac);
    let addr = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: (libc::ETH_P_IP as u16).to_be(),
        sll_ifindex: ifindex as c_int,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 6,
        sll_addr,
    };
    sendto(fd, ip, &addr)
}

/// One getifaddrs(3) entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IfEntry {
    /// The interface name, with an IPv4 address label's `:suffix` cut.
    pub name: String,
    pub flags: u32,
    pub addr: IfAddr,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IfAddr {
    /// The link entry every interface has, carrying its index.
    Link(u32),
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

pub fn interfaces() -> io::Result<Vec<IfEntry>> {
    let mut head: *mut libc::ifaddrs = ptr::null_mut();
    // SAFETY: on success `head` is a list we own until freeifaddrs.
    cvt(unsafe { libc::getifaddrs(&mut head) })?;
    let mut out = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is a node of the list, alive until freeifaddrs;
        // `ifa_addr` points at a sockaddr of the family it names, sized
        // for that family by libc.
        let entry = unsafe {
            let ifa = &*cur;
            cur = ifa.ifa_next;
            if ifa.ifa_addr.is_null() || ifa.ifa_name.is_null() {
                continue;
            }
            let addr = match c_int::from((*ifa.ifa_addr).sa_family) {
                libc::AF_PACKET => {
                    let ll: libc::sockaddr_ll = ptr::read_unaligned(ifa.ifa_addr.cast());
                    IfAddr::Link(ll.sll_ifindex as u32)
                }
                libc::AF_INET => {
                    let sin: libc::sockaddr_in = ptr::read_unaligned(ifa.ifa_addr.cast());
                    IfAddr::V4(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)))
                }
                libc::AF_INET6 => {
                    let sin6: libc::sockaddr_in6 = ptr::read_unaligned(ifa.ifa_addr.cast());
                    IfAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr))
                }
                _ => continue,
            };
            let name = CStr::from_ptr(ifa.ifa_name).to_string_lossy();
            IfEntry {
                name: name.split(':').next().unwrap_or_default().to_string(),
                flags: ifa.ifa_flags,
                addr,
            }
        };
        out.push(entry);
    }
    // SAFETY: `head` came from getifaddrs and is freed once.
    unsafe { libc::freeifaddrs(head) };
    Ok(out)
}
