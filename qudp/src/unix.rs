use std::{
    io::{self, IoSlice},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::fd::{AsFd, AsRawFd},
};

use nix::{
    cmsg_space,
    sys::socket::{
        ControlMessageOwned, SockaddrLike, SockaddrStorage,
        sockopt::{self},
    },
};
use socket2::Socket;

use crate::{DEFAULT_TTL, DatagramHeader, Io, UdpSocketController};

const OPTION_ON: bool = true;
const OPTION_OFF: bool = false;

impl Io for UdpSocketController {
    fn config(socket: &Socket, addr: SocketAddr) -> io::Result<()> {
        let io = socket.as_fd();
        nix::sys::socket::setsockopt(&io, sockopt::RcvBuf, &(2 * 1024 * 1024))?;
        match addr {
            SocketAddr::V4(_) => {
                #[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "ios"))]
                {
                    nix::sys::socket::setsockopt(&io, sockopt::IpDontFrag, &OPTION_ON)?;
                    nix::sys::socket::setsockopt(&io, sockopt::Ipv4RecvDstAddr, &OPTION_ON)?;
                }
                #[cfg(any(
                    target_os = "android",
                    target_os = "linux",
                    target_os = "freebsd",
                    target_os = "netbsd"
                ))]
                nix::sys::socket::setsockopt(&io, sockopt::Ipv4Ttl, &DEFAULT_TTL)?;
                nix::sys::socket::setsockopt(&io, sockopt::Ipv4PacketInfo, &OPTION_ON)?;
            }
            SocketAddr::V6(_) => {
                nix::sys::socket::setsockopt(&io, sockopt::Ipv6V6Only, &OPTION_OFF)?;
                nix::sys::socket::setsockopt(&io, sockopt::Ipv6RecvPacketInfo, &OPTION_ON)?;
                nix::sys::socket::setsockopt(&io, sockopt::Ipv6DontFrag, &OPTION_ON)?;
                nix::sys::socket::setsockopt(&io, sockopt::Ipv6Ttl, &DEFAULT_TTL)?;
            }
        }
        if let Err(e) = socket.bind(&addr.into()) {
            tracing::error!("   Cause by: failing to bind socket address");
            return Err(io::Error::new(io::ErrorKind::AddrInUse, e));
        }
        Ok(())
    }

    #[cfg(any(
        target_os = "android",
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd"
    ))]
    fn sendmsg(&self, buffers: &[IoSlice<'_>], hdr: &DatagramHeader) -> io::Result<usize> {
        use nix::sys::socket::{MsgFlags, SockaddrIn, SockaddrIn6};

        use super::BATCH_SIZE;
        let slices: Vec<_> = buffers
            .iter()
            .take(BATCH_SIZE)
            .map(std::slice::from_ref)
            .collect();

        let batch_size = slices.len();
        if batch_size == 0 {
            return Ok(0);
        }
        #[cfg(feature = "gso")]
        let (cmsgs, space) = (
            vec![nix::sys::socket::ControlMessage::UdpGsoSegments(
                &hdr.seg_size,
            )],
            Some(cmsg_space!(libc::c_int)),
        );
        #[cfg(not(feature = "gso"))]
        let (cmsgs, space) = (Vec::new(), None);

        macro_rules! send_batch {
            ($ty:ty, $addr:expr) => {{
                let sock_addr = <$ty>::from($addr);
                let addrs = vec![Some(sock_addr); BATCH_SIZE];
                let mut data =
                    nix::sys::socket::MultiHeaders::<$ty>::preallocate(BATCH_SIZE, space);
                match nix::sys::socket::sendmmsg(
                    self.io.as_raw_fd(),
                    &mut data,
                    &slices,
                    &addrs,
                    &cmsgs,
                    MsgFlags::empty(),
                ) {
                    Ok(ret) => Ok(ret.count()),
                    Err(e) if e == nix::errno::Errno::EINVAL || e == nix::errno::Errno::EAGAIN => {
                        Err(io::Error::new(io::ErrorKind::WouldBlock, e))
                    }
                    Err(e) => Err(e.into()),
                }
            }};
        }

        match hdr.dst {
            SocketAddr::V4(v4) => send_batch!(SockaddrIn, v4),
            SocketAddr::V6(v6) => send_batch!(SockaddrIn6, v6),
        }
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "watchos",
        target_os = "tvos"
    ))]
    fn sendmsg(&self, slices: &[IoSlice<'_>], send_hdr: &DatagramHeader) -> io::Result<usize> {
        use nix::sys::socket::{MsgFlags, SockaddrIn, SockaddrIn6};
        let mut sent_packet = 0;
        for slice in slices.iter() {
            macro_rules! send_batch {
                ($ty:ty, $addr:expr) => {{
                    let sock_addr = <$ty>::from($addr);
                    match nix::sys::socket::sendmsg(
                        self.io.as_raw_fd(),
                        &[*slice],
                        &[],
                        MsgFlags::empty(),
                        Some(&sock_addr),
                    ) {
                        Ok(_send_bytes) => sent_packet += 1,
                        Err(e) if e == nix::errno::Errno::EINVAL => continue,
                        Err(_) if sent_packet > 0 => return Ok(sent_packet),
                        Err(e) if e == nix::errno::Errno::EAGAIN => {
                            return Err(io::Error::new(io::ErrorKind::WouldBlock, e));
                        }
                        Err(e) => {
                            tracing::error!("   Cause by: failing to sendmsg {e}");
                            return Err(e.into());
                        }
                    }
                }};
            }

            match send_hdr.dst {
                SocketAddr::V4(v4) => send_batch!(SockaddrIn, v4),
                SocketAddr::V6(v6) => send_batch!(SockaddrIn6, v6),
            }
        }
        Ok(sent_packet)
    }

    #[cfg(any(
        target_os = "android",
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd"
    ))]
    fn recvmsg(
        &self,
        bufs: &mut [std::io::IoSliceMut<'_>],
        recv_hdrs: &mut [DatagramHeader],
    ) -> io::Result<usize> {
        use nix::sys::socket::{MsgFlags, recvmmsg};

        use super::BATCH_SIZE;
        let mut msgs: Vec<_> = bufs
            .iter_mut()
            .map(|buf| [std::io::IoSliceMut::new(&mut buf[..])])
            .collect();

        let cmsg_buffer = cmsg_space!(libc::in_pktinfo, libc::in6_pktinfo, libc::c_int);
        let mut data = nix::sys::socket::MultiHeaders::<SockaddrStorage>::preallocate(
            BATCH_SIZE,
            Some(cmsg_buffer),
        );

        let res = match recvmmsg(
            self.io.as_raw_fd(),
            &mut data,
            &mut msgs,
            MsgFlags::MSG_DONTWAIT,
            None,
        ) {
            Ok(results) => results.collect::<Vec<_>>(),
            Err(e) => {
                if matches!(e, nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) {
                    return Err(io::Error::new(io::ErrorKind::WouldBlock, e));
                }
                return Err(e.into());
            }
        };

        let local_port = self.local_addr()?.port();
        let mut count = 0;

        for recv_msg in res {
            let src_addr = recv_msg.address.unwrap().to_socketaddr();
            let mut recv_hdr = DatagramHeader {
                src: src_addr,
                dst: recv_hdrs[count].dst,
                ttl: 0,
                ecn: None,
                seg_size: recv_msg.bytes as u16,
            };
            for cmsg in recv_msg.cmsgs().unwrap() {
                parse_cmsg(cmsg, &mut recv_hdr);
            }
            recv_hdr.dst.set_port(local_port);
            recv_hdrs[count] = recv_hdr;
            count += 1;
        }

        Ok(count)
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "watchos",
        target_os = "tvos"
    ))]
    fn recvmsg(
        &self,
        bufs: &mut [std::io::IoSliceMut<'_>],
        recv_hdrs: &mut [DatagramHeader],
    ) -> io::Result<usize> {
        use nix::sys::socket::{MsgFlags, recvmsg};
        let mut cmsg_space = cmsg_space!(libc::in_pktinfo, libc::in6_pktinfo, libc::c_int);
        let result = recvmsg::<SockaddrStorage>(
            self.io.as_raw_fd(),
            bufs,
            Some(&mut cmsg_space),
            MsgFlags::empty(),
        );

        match result {
            Ok(recv_msg) => {
                if let Ok(cmsgs) = recv_msg.cmsgs() {
                    for cmsg in cmsgs {
                        parse_cmsg(cmsg, &mut recv_hdrs[0]);
                    }
                }
                recv_hdrs[0].dst.set_port(self.local_addr()?.port());
                recv_hdrs[0].src = recv_msg.address.unwrap().to_socketaddr();
                recv_hdrs[0].seg_size = recv_msg.bytes as u16;
                Ok(1)
            }
            Err(e) => {
                if matches!(e, nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) {
                    // actually, it's not an error, just a signal to retry
                    return Err(io::Error::new(io::ErrorKind::WouldBlock, e));
                }
                Err(e.into())
            }
        }
    }
}

fn parse_cmsg(cmsg: ControlMessageOwned, hdr: &mut DatagramHeader) {
    match cmsg {
        ControlMessageOwned::Ipv4PacketInfo(pktinfo) => {
            let ip = IpAddr::V4(Ipv4Addr::from(pktinfo.ipi_addr.s_addr.to_ne_bytes()));
            hdr.dst.set_ip(ip);
        }
        ControlMessageOwned::Ipv6PacketInfo(pktinfo6) => {
            let ip = IpAddr::V6(Ipv6Addr::from(pktinfo6.ipi6_addr.s6_addr));
            hdr.dst.set_ip(ip);
        }
        _ => {}
    }
}

trait ToSocketAddr {
    fn to_socketaddr(&self) -> SocketAddr;
}

impl ToSocketAddr for SockaddrStorage {
    fn to_socketaddr(&self) -> SocketAddr {
        match self.family() {
            Some(nix::sys::socket::AddressFamily::Inet) => {
                let sockaddr_in = self.as_sockaddr_in().unwrap();
                let v4_addr = SocketAddrV4::new(sockaddr_in.ip(), sockaddr_in.port());
                SocketAddr::V4(v4_addr)
            }
            Some(nix::sys::socket::AddressFamily::Inet6) => {
                let sockaddr_in6 = self.as_sockaddr_in6().unwrap();
                let v6_addr = SocketAddrV6::new(
                    sockaddr_in6.ip(),
                    sockaddr_in6.port(),
                    sockaddr_in6.flowinfo(),
                    sockaddr_in6.scope_id(),
                );
                SocketAddr::V6(v6_addr)
            }
            _ => panic!("Unsupported address family"),
        }
    }
}
