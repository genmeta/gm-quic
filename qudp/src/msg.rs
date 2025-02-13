use std::{
    io::IoSliceMut,
    mem::{self, MaybeUninit},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use socket2::SockAddr;

use crate::{
    cmsghdr::{decode, Cmsg, CmsgHdr, Iter, MsgHdr},
    unix::Gso,
    PacketHeader, UdpSocketController, BATCH_SIZE,
};

pub(crate) const CMSG_LEN: usize = 88;

#[cfg(target_os = "freebsd")]
type IpTosTy = libc::c_uchar;
#[cfg(not(target_os = "freebsd"))]
type IpTosTy = libc::c_int;

#[cfg(not(feature = "gso"))]
type HdrTy = libc::msghdr;
#[cfg(feature = "gso")]
type HdrTy = libc::mmsghdr;

#[macro_export]
macro_rules! msg_hdr {
    ($hdr:expr) => {{
        #[cfg(not(feature = "gso"))]
        {
            $hdr
        }
        #[cfg(feature = "gso")]
        {
            &mut $hdr.msg_hdr
        }
    }};
}

#[derive(Copy, Clone)]
#[repr(align(8))] // Conservative bound for align_of<libc::cmsghdr>
pub(crate) struct Aligned<T>(pub(crate) T);

pub struct Message {
    pub(super) hdrs: [HdrTy; BATCH_SIZE],
    names: [MaybeUninit<libc::sockaddr_storage>; BATCH_SIZE],
    ctrls: [Aligned<[u8; CMSG_LEN]>; BATCH_SIZE],
}

impl Default for Message {
    fn default() -> Self {
        Self {
            hdrs: unsafe { mem::zeroed::<[HdrTy; BATCH_SIZE]>() },
            names: [MaybeUninit::<libc::sockaddr_storage>::uninit(); BATCH_SIZE],
            ctrls: [Aligned([0u8; CMSG_LEN]); BATCH_SIZE],
        }
    }
}

impl Message {
    pub(super) fn prepare_sent(
        &mut self,
        pkt_hdr: &PacketHeader,
        dst: &SockAddr,
        gso_size: u16,
        msg_count: usize,
    ) {
        for (i, hdr) in self.hdrs.iter_mut().enumerate().take(msg_count) {
            let hdr = msg_hdr!(hdr);
            hdr.msg_name = dst.as_ptr() as *mut _;
            hdr.msg_namelen = dst.len();

            let ctrl = &mut self.ctrls[i];
            hdr.msg_control = ctrl.0.as_mut_ptr() as _;
            hdr.msg_controllen = CMSG_LEN as _;

            let mut cmsghdr = unsafe { CmsgHdr::new(hdr) };
            let ecn = pkt_hdr.ecn.unwrap_or(0) as libc::c_int;

            if pkt_hdr.dst.is_ipv4() {
                cmsghdr.append(libc::IPPROTO_IP, libc::IP_TOS, ecn as IpTosTy);
            } else {
                cmsghdr.append(libc::IPPROTO_IPV6, libc::IPV6_TCLASS, ecn);
            }

            if gso_size > 1 {
                UdpSocketController::set_segment_size(&mut cmsghdr, pkt_hdr.seg_size);
            }
            cmsghdr.finish();
        }
    }

    pub(super) fn prepare_recv(&mut self, bufs: &mut [IoSliceMut<'_>], msg_count: usize) {
        assert!(msg_count <= BATCH_SIZE);
        for (i, hdr) in self.hdrs.iter_mut().enumerate().take(msg_count) {
            let hdr = msg_hdr!(hdr);
            hdr.msg_name = self.names[i].as_mut_ptr() as _;
            hdr.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as _;

            let buf = &mut bufs[i];
            hdr.msg_iov = buf as *mut IoSliceMut as *mut libc::iovec;
            hdr.msg_iovlen = 1;

            let ctrl = &mut self.ctrls[i];
            hdr.msg_control = ctrl.0.as_mut_ptr() as _;
            hdr.msg_controllen = CMSG_LEN as _;
            hdr.msg_flags = 0;
        }
    }

    pub(super) fn decode_recv(
        &mut self,
        recv_hdrs: &mut [PacketHeader],
        msg_count: usize,
        port: u16,
    ) {
        assert!(msg_count <= BATCH_SIZE);
        for (i, hdr) in self.hdrs.iter_mut().enumerate().take(msg_count) {
            #[cfg(feature = "gso")]
            {
                recv_hdrs[i].seg_size = hdr.msg_len as u16;
            }
            let hdr = msg_hdr!(hdr);
            let name = unsafe { self.names[i].assume_init() };
            let cmsg_iter = unsafe { Iter::new(hdr) };

            let recv_hdr = &mut recv_hdrs[i];
            for cmsg in cmsg_iter {
                match (cmsg.cmsg_level, cmsg.cmsg_type) {
                    (libc::IPPROTO_IP, libc::IP_TOS) | (libc::IPPROTO_IP, libc::IP_RECVTOS) => unsafe {
                        recv_hdr.ecn = Some(decode::<u8, libc::cmsghdr>(cmsg));
                    },
                    (libc::IPPROTO_IPV6, libc::IPV6_TCLASS) => unsafe {
                        // Temporary hack around broken macos ABI. Remove once upstream fixes it.
                        // https://bugreport.apple.com/web/?problemID=48761855
                        #[allow(clippy::unnecessary_cast)] // cmsg.cmsg_len defined as size_t
                        if (cfg!(target_os = "macos") || cfg!(target_os = "ios"))
                            && cmsg.cmsg_len as usize
                                == libc::CMSG_LEN(mem::size_of::<u8>() as _) as usize
                        {
                            recv_hdr.ecn = Some(decode::<u8, libc::cmsghdr>(cmsg));
                        } else {
                            recv_hdr.ecn = Some(decode::<libc::c_int, libc::cmsghdr>(cmsg) as u8);
                        }
                    },
                    #[cfg(any(target_os = "linux", target_os = "android"))]
                    (libc::IPPROTO_IP, libc::IP_PKTINFO) => {
                        let pktinfo = unsafe { decode::<libc::in_pktinfo, libc::cmsghdr>(cmsg) };
                        let ip = IpAddr::V4(Ipv4Addr::from(pktinfo.ipi_addr.s_addr.to_ne_bytes()));
                        recv_hdr.dst.set_ip(ip);
                    }
                    #[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "ios",))]
                    (libc::IPPROTO_IP, libc::IP_RECVDSTADDR) => {
                        let in_addr = unsafe { decode::<libc::in_addr, libc::cmsghdr>(cmsg) };
                        recv_hdr
                            .dst
                            .set_ip(IpAddr::V4(Ipv4Addr::from(in_addr.s_addr.to_ne_bytes())));
                    }

                    (libc::IPPROTO_IP, libc::IP_TTL) => unsafe {
                        recv_hdr.ttl = decode::<u32, libc::cmsghdr>(cmsg) as u8;
                    },
                    (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
                        let pktinfo = unsafe { decode::<libc::in6_pktinfo, libc::cmsghdr>(cmsg) };
                        let ip = IpAddr::V6(Ipv6Addr::from(pktinfo.ipi6_addr.s6_addr));
                        recv_hdr.dst.set_ip(ip);
                    }
                    (libc::IPPROTO_IP, libc::IP_RECVTTL) => unsafe {
                        recv_hdr.ttl = decode::<u32, libc::cmsghdr>(cmsg) as u8;
                    },
                    _ => {
                        log::trace!(
                            "read unkown level {} cmsg {}",
                            cmsg.cmsg_level,
                            cmsg.cmsg_type
                        );
                    }
                }
            }

            recv_hdr.dst.set_port(port);
            recv_hdr.src = match libc::c_int::from(name.ss_family) {
                libc::AF_INET => {
                    let addr: &libc::sockaddr_in =
                        unsafe { &*(&name as *const _ as *const libc::sockaddr_in) };
                    SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes()),
                        u16::from_be(addr.sin_port),
                    ))
                }
                libc::AF_INET6 => {
                    let addr: &libc::sockaddr_in6 =
                        unsafe { &*(&name as *const _ as *const libc::sockaddr_in6) };
                    SocketAddr::V6(SocketAddrV6::new(
                        Ipv6Addr::from(addr.sin6_addr.s6_addr),
                        u16::from_be(addr.sin6_port),
                        addr.sin6_flowinfo,
                        addr.sin6_scope_id,
                    ))
                }
                _ => unreachable!(),
            };
        }
    }
}

impl MsgHdr for libc::msghdr {
    type ControlMessage = libc::cmsghdr;

    fn first_cmsg(&self) -> *mut Self::ControlMessage {
        unsafe { libc::CMSG_FIRSTHDR(self) }
    }

    fn next(&self, cmsg: &Self::ControlMessage) -> *mut Self::ControlMessage {
        unsafe { libc::CMSG_NXTHDR(self, cmsg) }
    }

    fn set_len(&mut self, len: usize) {
        self.msg_controllen = len as _;
        if len == 0 {
            self.msg_control = std::ptr::null_mut();
        }
    }

    fn capacity(&self) -> usize {
        self.msg_controllen as _
    }
}

impl Cmsg for libc::cmsghdr {
    fn cmsg_len(length: usize) -> usize {
        unsafe { libc::CMSG_LEN(length as _) as usize }
    }

    fn space(length: usize) -> usize {
        unsafe { libc::CMSG_SPACE(length as _) as usize }
    }

    fn data(&self) -> *mut libc::c_uchar {
        unsafe { libc::CMSG_DATA(self) }
    }

    fn set(&mut self, level: libc::c_int, ty: libc::c_int, len: usize) {
        self.cmsg_level = level as _;
        self.cmsg_type = ty as _;
        self.cmsg_len = len as _;
    }
}
