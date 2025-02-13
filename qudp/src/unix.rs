use std::{cmp, io::IoSlice, mem, net::SocketAddr, os::fd::AsRawFd};

use socket2::SockAddr;

use crate::{
    cmsghdr::CmsgHdr, io, msg::Message, Io, PacketHeader, UdpSocketController, BATCH_SIZE,
    DEFAULT_TTL,
};

const OPTION_ON: libc::c_int = 1;
const OPTION_OFF: libc::c_int = 0;

pub trait Gso: Io {
    fn max_gso_segments(&self) -> u16;

    fn set_segment_size(encoder: &mut CmsgHdr<libc::msghdr>, segment_size: u16);
}

pub trait Gro: Io {
    #[allow(unused)] // TODO: use GRO
    fn max_gro_segments(&self) -> u16;
}

macro_rules! handle_io_error {
    ($e:expr, $n:expr) => {
        match $e.raw_os_error() {
            Some(libc::EINTR) => continue,
            #[cfg(any(target_os = "macos", target_os = "ios", target_os = "openbsd",))]
            Some(libc::EWOULDBLOCK)
            | Some(libc::EBADF)
            | Some(libc::EPIPE)
            | Some(libc::ENOTCONN) => return Err($e),
            #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "openbsd",)))]
            Some(libc::EWOULDBLOCK)
            | Some(libc::EBADE)
            | Some(libc::EPIPE)
            | Some(libc::ENOTCONN) => return Err($e),
            _ => break,
        }
    };
}

impl Io for UdpSocketController {
    fn config(&self) -> io::Result<()> {
        let io = socket2::SockRef::from(&self.io);
        io.set_nonblocking(true)?;

        let addr = io.local_addr()?;
        let is_ipv4 = addr.family() == libc::AF_INET as libc::sa_family_t;
        if is_ipv4 || !io.only_v6()? {
            //  If enabled, the IP_TOS ancillary message is passed with
            //  incoming packets.  It contains a byte which specifies the
            //  Type of Service/Precedence field of the packet header.
            self.setsockopt(libc::IPPROTO_IP, libc::IP_RECVTOS, OPTION_ON);
        }

        if is_ipv4 {
            #[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "ios"))]
            {
                // IP_DONTFRAG  may	 be used to set	the Don't Fragment flag	on IP packets.
                self.setsockopt(libc::IPPROTO_IP, libc::IP_DONTFRAG, OPTION_ON);
                // If the IP_RECVDSTADDR	option	is enabled on a	SOCK_DGRAM socket, the
                // recvmsg(2) call will return the destination IP address for a UDP	 datagram.
                self.setsockopt(libc::IPPROTO_IP, libc::IP_RECVDSTADDR, OPTION_ON);
            }
            self.setsockopt(libc::IPPROTO_IP, libc::IP_PKTINFO, OPTION_ON);
            self.setsockopt(libc::IPPROTO_IP, libc::IP_TTL, DEFAULT_TTL);
            // When this flag is set, pass a IP_TTL control message with
            // the time-to-live field of the received packet as a 32 bit
            // integer.  Not supported for SOCK_STREAM sockets.
            self.setsockopt(libc::IPPROTO_IP, libc::IP_RECVTTL, OPTION_ON);
        }
        // Options standardized in RFC 3542
        else {
            //  If this flag is set to false (zero), then the socket can
            //  be used to send and receive packets to and from an IPv6
            //  address or an IPv4-mapped IPv6 address.
            self.setsockopt(libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, OPTION_OFF);
            // Set delivery of the IPV6_PKTINFO control message on incoming datagrams.
            self.setsockopt(libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, OPTION_ON);
            self.setsockopt(libc::IPPROTO_IPV6, libc::IPV6_RECVTCLASS, OPTION_ON);
            self.setsockopt(libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG, OPTION_ON);
            self.setsockopt(libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, OPTION_ON);
            // The received hop limit is returned as ancillary data by recvmsg()
            // only if the application has enabled the IPV6_RECVHOPLIMIT socket option
            self.setsockopt(libc::IPPROTO_IPV6, libc::IPV6_RECVHOPLIMIT, OPTION_ON);
            self.setsockopt(libc::IPPROTO_IP, libc::IP_RECVTTL, OPTION_ON);
            self.setsockopt(libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS, DEFAULT_TTL);
        }

        use core::sync::atomic::Ordering::Release;
        self.gso_size.store(self.max_gso_segments(), Release);
        self.gro_size.store(self.max_gro_segments(), Release);

        Ok(())
    }

    fn setsockopt(&self, level: libc::c_int, name: libc::c_int, value: libc::c_int) {
        let _ = setsockopt(&self.io.as_raw_fd(), level, name, value);
    }

    fn sendmsg(&self, bufs: &[IoSlice<'_>], send_hdr: &PacketHeader) -> io::Result<usize> {
        let io = socket2::SockRef::from(&self.io);

        let gso_size = if send_hdr.gso {
            let max_gso = self.max_gso_segments();
            let max_payloads = u16::MAX / send_hdr.seg_size;
            cmp::min(max_gso, max_payloads)
        } else {
            1
        };

        let dst: SockAddr = if self.local_addr()?.is_ipv6() && !io.only_v6()? {
            match send_hdr.dst.ip() {
                std::net::IpAddr::V4(ip) => SocketAddr::new(
                    std::net::IpAddr::V6(ip.to_ipv6_mapped()),
                    send_hdr.dst.port(),
                )
                .into(),
                std::net::IpAddr::V6(_) => send_hdr.dst.into(),
            }
        } else {
            send_hdr.dst.into()
        };

        #[cfg(feature = "gso")]
        return sendmmsg(&self.io, bufs, send_hdr, &dst, gso_size);

        #[cfg(not(feature = "gso"))]
        return sendmsg(&self.io, bufs, send_hdr, &dst, gso_size);
    }

    fn recvmsg(
        &self,
        bufs: &mut [std::io::IoSliceMut<'_>],
        recv_hdrs: &mut [PacketHeader],
    ) -> io::Result<usize> {
        let mut msg = Message::default();
        let max_msg_count = (bufs.len()).min(BATCH_SIZE);

        msg.prepare_recv(bufs, max_msg_count);
        let ret: io::Result<Rcvd>;
        #[cfg(feature = "gso")]
        {
            ret = unsafe {
                recvmmsg(
                    self.io.as_raw_fd(),
                    msg.hdrs.as_mut_ptr(),
                    max_msg_count as _,
                )
            };
        }

        #[cfg(not(feature = "gso"))]
        {
            ret = recvmsg(self.io.as_raw_fd(), &mut msg.hdrs[0]);
        }
        let msg_count = match ret {
            Ok(rcvd) => match rcvd {
                Rcvd::MsgCount(n) => n,
                Rcvd::MsgSize(n) => {
                    recv_hdrs[0].seg_size = n as u16;
                    1
                }
            },
            Err(e) => {
                return Err(e);
            }
        };

        msg.decode_recv(recv_hdrs, msg_count, self.local_addr()?.port());
        Ok(msg_count)
    }
}

#[cfg(feature = "gso")]
pub(super) fn sendmmsg(
    io: &impl AsRawFd,
    bufs: &[IoSlice<'_>],
    send_hdr: &PacketHeader,
    dst: &SockAddr,
    gso_size: u16,
) -> io::Result<usize> {
    use std::iter;
    let mut iovecs: Vec<Vec<IoSlice>> = iter::repeat_with(|| Vec::with_capacity(gso_size as usize))
        .take(BATCH_SIZE)
        .collect();

    let mut message = Message::default();
    message.prepare_sent(send_hdr, dst, gso_size, BATCH_SIZE);

    let mut sent_packets = 0;
    for batch in bufs.chunks(gso_size as usize * BATCH_SIZE) {
        let mut mmsg_batch_size: usize = 0;
        let mut packet_count = 0;
        for (i, gso_batch) in batch.chunks(gso_size as usize).enumerate() {
            mmsg_batch_size += 1;
            let hdr = &mut message.hdrs[i].msg_hdr;
            let iovec = &mut iovecs[i];
            packet_count += gso_batch.len();
            iovec.clear();
            iovec.extend(gso_batch.iter().map(|payload| IoSlice::new(payload)));
            hdr.msg_iov = iovec.as_ptr() as *mut _;
            hdr.msg_iovlen = iovec.len() as _;
        }

        let mut msgvec = message.hdrs.as_mut_ptr();
        let mut vlen = mmsg_batch_size as u32;
        loop {
            let ret =
                to_result(unsafe { libc::sendmmsg(io.as_raw_fd(), msgvec, vlen, 0) } as isize);

            match ret {
                // On success, sendmmsg() returns the number of messages sent from
                // msgvec; if this is less than vlen, the caller can retry with a
                // further sendmmsg() call to send the remaining messages.
                Ok(n) => {
                    sent_packets += packet_count;
                    if n != vlen as usize {
                        log::warn!("sendmmsg : only {} messages sent out of {}", n, vlen);
                        vlen = n as u32 - vlen;
                        msgvec = message.hdrs[n..].as_mut_ptr();
                        continue;
                    }
                    break;
                }
                Err(e) => match e.raw_os_error() {
                    Some(libc::EINTR) => continue,
                    Some(libc::EWOULDBLOCK) if sent_packets > 0 => return Ok(sent_packets),
                    Some(libc::EWOULDBLOCK) if sent_packets == 0 => return Err(e),
                    Some(libc::EBADE) | Some(libc::EPIPE) | Some(libc::ENOTCONN) => return Err(e),
                    _ => break,
                },
            }
        }
    }
    Ok(sent_packets)
}

#[cfg(not(feature = "gso"))]
pub(super) fn sendmsg(
    io: &impl AsRawFd,
    bufs: &[IoSlice<'_>],
    send_hdr: &PacketHeader,
    dst: &SockAddr,
    gso_size: u16,
) -> io::Result<usize> {
    let mut msg = Message::default();
    msg.prepare_sent(send_hdr, dst, gso_size, 1);

    let mut sent_packets = 0;
    for batch in bufs.chunks(gso_size as usize) {
        let mut iovec: Vec<IoSlice> = Vec::with_capacity(gso_size as usize);
        iovec.extend(batch.iter().map(|buf| IoSlice::new(buf)));

        let hdr = &mut msg.hdrs[0];
        hdr.msg_iov = iovec.as_ptr() as *mut _;
        hdr.msg_iovlen = iovec.len() as _;

        loop {
            let ret = to_result(unsafe { libc::sendmsg(io.as_raw_fd(), hdr, 0) });
            match ret {
                Ok(_n) => {
                    sent_packets += 1;
                    break;
                }
                Err(e) => match e.raw_os_error() {
                    Some(libc::EINTR) => continue,
                    Some(libc::EWOULDBLOCK) if sent_packets > 0 => return Ok(sent_packets),
                    Some(libc::EWOULDBLOCK) if sent_packets == 0 => return Err(e),
                    Some(libc::EBADF) | Some(libc::EPIPE) | Some(libc::ENOTCONN) => return Err(e),
                    _ => break,
                },
            }
        }
    }

    Ok(sent_packets)
}

#[allow(dead_code)]
enum Rcvd {
    MsgCount(usize),
    MsgSize(usize),
}

/// recvmmsg wrapper with ENOSYS handling
#[cfg(feature = "gso")]
unsafe fn recvmmsg(
    sockfd: libc::c_int,
    msgvec: *mut libc::mmsghdr,
    vlen: libc::c_uint,
) -> io::Result<Rcvd> {
    let flags = 0;

    use std::ptr;
    let timeout = ptr::null_mut::<libc::timespec>();
    loop {
        let ret = libc::syscall(libc::SYS_recvmmsg, sockfd, msgvec, vlen, flags, timeout);
        match to_result(ret as isize) {
            Ok(n) => return Ok(Rcvd::MsgCount(n)),
            Err(e) => {
                // ENOSYS indicates that recvmmsg is not supported
                if let Some(libc::ENOSYS) = e.raw_os_error() {
                    return recvmsg(sockfd, &mut (*msgvec).msg_hdr);
                }
                handle_io_error!(e, Rcvd::MsgCount(0))
            }
        }
    }
    Ok(Rcvd::MsgCount(0))
}

fn recvmsg(sockfd: libc::c_int, msghdr: *mut libc::msghdr) -> io::Result<Rcvd> {
    let flags = 0;
    loop {
        let ret = to_result(unsafe { libc::recvmsg(sockfd, msghdr, flags) });
        match ret {
            Ok(n) => return Ok(Rcvd::MsgSize(n)),
            Err(e) => handle_io_error!(e, Rcvd::MsgSize(0)),
        };
    }
    Ok(Rcvd::MsgSize(0))
}

fn to_result(code: isize) -> io::Result<usize> {
    if code == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(code as usize)
    }
}

#[cfg(feature = "gso")]
static GSO_GRO_SIZE: std::sync::LazyLock<(u16, u16)> = std::sync::LazyLock::new(|| {
    const GSO_SIZE: libc::c_int = 1500;
    let socket = match std::net::UdpSocket::bind("[::]:0")
        .or_else(|_| std::net::UdpSocket::bind("127.0.0.1:0"))
    {
        Ok(socket) => socket,
        Err(_) => return (1, 1),
    };
    let gso_size = match setsockopt(&socket, libc::SOL_UDP, libc::UDP_SEGMENT, GSO_SIZE) {
        Ok(()) => 64,
        Err(_) => 1,
    };
    let gro_size = match setsockopt(&socket, libc::SOL_UDP, libc::UDP_GRO, OPTION_ON) {
        Ok(()) => 64,
        Err(_) => 1,
    };
    (gso_size, gro_size)
});

#[cfg(feature = "gso")]
impl Gso for UdpSocketController {
    fn max_gso_segments(&self) -> u16 {
        GSO_GRO_SIZE.0
    }

    fn set_segment_size(cmsg: &mut CmsgHdr<libc::msghdr>, segment_size: u16) {
        cmsg.append(libc::SOL_UDP, libc::UDP_SEGMENT, segment_size);
    }
}

#[cfg(feature = "gso")]
impl Gro for UdpSocketController {
    fn max_gro_segments(&self) -> u16 {
        GSO_GRO_SIZE.1
    }
}

#[cfg(not(feature = "gso"))]
impl Gso for UdpSocketController {
    fn max_gso_segments(&self) -> u16 {
        1
    }

    fn set_segment_size(_: &mut CmsgHdr<libc::msghdr>, _: u16) {
        log::error!("set_segment_size is not supported on this platform");
    }
}

#[cfg(not(feature = "gso"))]
impl Gro for UdpSocketController {
    fn max_gro_segments(&self) -> u16 {
        1
    }
}

fn setsockopt(
    socket: &impl AsRawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            &value as *const _ as _,
            mem::size_of_val(&value) as _,
        )
    };

    match result {
        0 => Ok(()),
        _ => {
            let err = io::Error::last_os_error();
            log::error!(
                "set socket option level: {} name: {} value {} error: {}",
                level,
                name,
                value,
                err
            );
            Err(err)
        }
    }
}
