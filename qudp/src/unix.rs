use std::{
    io::{self, IoSlice, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::fd::{AsFd, AsRawFd},
};

use nix::{
    cmsg_space,
    sys::socket::{
        ControlMessageOwned, MsgFlags, RecvMsg, SockaddrIn, SockaddrIn6, SockaddrLike,
        SockaddrStorage,
        sockopt::{self},
    },
};
use socket2::Domain;
use tracing::info;

use crate::{BATCH_SIZE, DEFAULT_TTL, Io, PacketHeader, UdpSocketController};

const OPTION_ON: bool = true;
const OPTION_OFF: bool = false;

impl Io for UdpSocketController {
    fn config<T: AsFd>(io: T, family: Domain) -> io::Result<()> {
        nix::sys::socket::setsockopt(&io, sockopt::RcvBuf, &(2 * 1024 * 1024))?;
        match family {
            Domain::IPV4 => {
                #[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "ios"))]
                {
                    nix::sys::socket::setsockopt(&io, sockopt::IpDontFrag, OPTION_ON);
                    nix::sys::socket::setsockopt(&io, sockopt::Ipv4RecvDstAddr, OPTION_ON);
                }

                nix::sys::socket::setsockopt(&io, sockopt::Ipv4PacketInfo, &OPTION_ON)?;
                nix::sys::socket::setsockopt(&io, sockopt::Ipv4Ttl, &DEFAULT_TTL)?;
            }
            Domain::IPV6 => {
                nix::sys::socket::setsockopt(&io, sockopt::Ipv6V6Only, &OPTION_OFF)?;
                nix::sys::socket::setsockopt(&io, sockopt::Ipv6RecvPacketInfo, &OPTION_ON)?;
                nix::sys::socket::setsockopt(&io, sockopt::Ipv6DontFrag, &OPTION_ON)?;
                nix::sys::socket::setsockopt(&io, sockopt::Ipv6Ttl, &DEFAULT_TTL)?;
            }
            _ => {
                todo!("support unix socket")
            }
        }
        Ok(())
    }

    #[cfg(any(
        target_os = "android",
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd"
    ))]
    fn sendmsg(&self, slices: &[IoSlice<'_>], send_hdr: &PacketHeader) -> io::Result<usize> {
        use nix::sys::socket::{ControlMessage, MsgFlags, SockaddrIn, SockaddrIn6};
        let mut sent_packet = 0;
        for batch in slices.chunks(BATCH_SIZE) {
            let batch_size = batch.len();
            let buffers: Vec<_> = batch
                .iter()
                .take(batch_size)
                .map(std::slice::from_ref)
                .collect();

            let (cmsgs, cmsg_buffer) = {
                let mut cmsgs = Vec::new();
                #[allow(unused_assignments)]
                let mut buffer = None;
                #[cfg(feature = "gso")]
                {
                    cmsgs.push(ControlMessage::UdpGsoSegments(&send_hdr.seg_size));
                    buffer = Some(cmsg_space!(libc::c_int));
                }
                (cmsgs, buffer)
            };

            macro_rules! send_batch {
                ($ty:ty, $addr:expr) => {{
                    let sock_addr = <$ty>::from($addr);
                    let addrs = vec![Some(sock_addr); batch_size];
                    let mut data =
                        nix::sys::socket::MultiHeaders::<$ty>::preallocate(batch_size, cmsg_buffer);
                    match nix::sys::socket::sendmmsg(
                        self.io.as_raw_fd(),
                        &mut data,
                        &buffers,
                        &addrs,
                        &cmsgs,
                        MsgFlags::empty(),
                    ) {
                        Ok(results) => sent_packet += results.into_iter().count(),
                        Err(e) => tracing::warn!("sendmsg error: {}", e),
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
        target_os = "macos",
        target_os = "ios",
        target_os = "watchos",
        target_os = "tvos"
    ))]
    fn sendmsg(&self, slices: &[IoSlice<'_>], send_hdr: &PacketHeader) -> io::Result<usize> {
        use nix::sys::socket::{ControlMessage, MsgFlags, SockaddrIn, SockaddrIn6};
        let mut sent_packet = 0;
        for slice in slices.iter() {
            let mut cmsgs: Vec<ControlMessage> = Vec::new();
            #[cfg(feature = "gso")]
            cmsgs.push(ControlMessage::UdpGsoSegments(&send_hdr.seg_size));

            macro_rules! send_batch {
                ($ty:ty, $addr:expr) => {{
                    let sock_addr = <$ty>::from($addr);
                    match nix::sys::socket::sendmsg(
                        self.io.as_raw_fd(),
                        &[*slice],
                        &cmsgs,
                        MsgFlags::empty(),
                        Some(&sock_addr),
                    ) {
                        Ok(_sent_bytes) => sent_packet += 1,
                        Err(e) => tracing::warn!("sendmsg error: {}", e),
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
        recv_hdrs: &mut [PacketHeader],
    ) -> io::Result<usize> {
        use nix::sys::socket::recvmmsg;
        let mut msgs = std::collections::LinkedList::new();
        msgs.extend(bufs.iter_mut().map(|buf| [IoSliceMut::new(&mut buf[..])]));

        let cmsg_buffer = cmsg_space!(libc::in_pktinfo, libc::in6_pktinfo, libc::c_int);
        let mut data = nix::sys::socket::MultiHeaders::<SockaddrStorage>::preallocate(
            BATCH_SIZE,
            Some(cmsg_buffer),
        );
        let res: Vec<RecvMsg<SockaddrStorage>> = recvmmsg(
            self.io.as_raw_fd(),
            &mut data,
            &mut msgs,
            MsgFlags::MSG_DONTWAIT,
            None,
        )?
        .collect();

        let mut count = 0;
        for recv_msg in res {
            let sockaddr = recv_msg.address.unwrap();
            let src_addr = sockaddr.to_socketaddr();
            let mut recv_hdr = PacketHeader {
                src: src_addr,
                dst: recv_hdrs[count].dst,
                ttl: 0,
                ecn: None,
                seg_size: recv_msg.bytes as u16,
            };

            let cmsgs = recv_msg.cmsgs().unwrap();
            for cmsg in cmsgs {
                parse_cmsg(cmsg, &mut recv_hdr);
            }
            recv_hdr.dst.set_port(self.local_addr()?.port());
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
        recv_hdrs: &mut [PacketHeader],
    ) -> io::Result<usize> {
        use nix::sys::socket::{SockaddrIn, SockaddrIn6, recvmsg};
        use tracing::warn;

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
                recv_hdrs[0].src = recv_msg.address.unwrap().to_socketaddr();
                recv_hdrs[0].seg_size = recv_msg.bytes as u16;
                Ok(1)
            }
            Err(e) => {
                warn!("recv error {:?}", e);
                let kind = if e == nix::errno::Errno::EINTR {
                    io::ErrorKind::WouldBlock
                } else {
                    io::ErrorKind::Other
                };
                Err(io::Error::new(kind, e))
            }
        }
    }
}

fn parse_cmsg(cmsg: ControlMessageOwned, hdr: &mut PacketHeader) {
    match cmsg {
        ControlMessageOwned::Ipv4PacketInfo(pktinfo) => {
            let ip = IpAddr::V4(Ipv4Addr::from(pktinfo.ipi_addr.s_addr.to_ne_bytes()));
            hdr.dst.set_ip(ip);
        }
        ControlMessageOwned::Ipv6PacketInfo(pktinfo6) => {
            let ip = IpAddr::V6(Ipv6Addr::from(pktinfo6.ipi6_addr.s6_addr));
            hdr.dst.set_ip(ip);
        }
        ControlMessageOwned::UdpGroSegments(segments) => {
            hdr.seg_size = segments as u16;
            info!("Received UDP GRO segment size: {}", segments);
        }
        _ => {
            info!("Unsupported control message: {:?}", cmsg);
        }
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

impl ToSocketAddr for SockaddrIn {
    fn to_socketaddr(&self) -> SocketAddr {
        let v4_addr = SocketAddrV4::new(self.ip(), self.port());
        SocketAddr::V4(v4_addr)
    }
}

impl ToSocketAddr for SockaddrIn6 {
    fn to_socketaddr(&self) -> SocketAddr {
        let v6_addr = SocketAddrV6::new(self.ip(), self.port(), self.flowinfo(), self.scope_id());
        SocketAddr::V6(v6_addr)
    }
}
