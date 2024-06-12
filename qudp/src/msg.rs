use std::{
    io::{IoSlice, IoSliceMut},
    mem::{self, MaybeUninit},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use crate::{Gso, RecvHeader, SendHeader, UdpSocketController};

pub(crate) const CMSG_LEN: usize = 88;

#[cfg(target_os = "freebsd")]
type IpTosTy = libc::c_uchar;
#[cfg(not(target_os = "freebsd"))]
type IpTosTy = libc::c_int;

use std::ptr;

#[derive(Copy, Clone)]
#[repr(align(8))] // Conservative bound for align_of<cmsghdr>

pub(crate) struct Aligned<T>(pub(crate) T);

pub(crate) struct Cmsg<'a> {
    hdr: &'a mut libc::msghdr,
    cmsg: Option<&'a mut libc::cmsghdr>,
    len: usize,
}

impl<'a> Cmsg<'a> {
    pub(crate) unsafe fn new(hdr: &'a mut libc::msghdr) -> Self {
        Self {
            cmsg: libc::CMSG_FIRSTHDR(hdr).as_mut(),
            hdr,
            len: 0,
        }
    }

    /// Append a control message to the buffer.
    ///
    /// # Panics
    /// - If insufficient buffer space remains.
    /// - If `T` has stricter alignment requirements than `cmsghdr`
    pub(crate) fn push<T: Copy + ?Sized>(&mut self, level: libc::c_int, ty: libc::c_int, value: T) {
        //  T 的对齐要求不比 libc::cmsghdr 的对齐要求更严格
        assert!(mem::align_of::<T>() <= mem::align_of::<libc::cmsghdr>());
        let space = unsafe { libc::CMSG_SPACE(mem::size_of_val(&value) as _) as usize };
        //  检查空间是否足够
        #[allow(clippy::unnecessary_cast)]
        if (self.hdr.msg_controllen as usize) < self.len + space {
            panic!(
                "control message buffer too small. Need {}, Availableve {}",
                space + self.len,
                self.hdr.msg_controllen
            );
        }
        let cmsg = self.cmsg.take().expect("no control buffer space remaining");
        cmsg.cmsg_level = level;
        cmsg.cmsg_type = ty;
        cmsg.cmsg_len = unsafe { libc::CMSG_LEN(mem::size_of_val(&value) as _) } as _;
        unsafe {
            ptr::write(libc::CMSG_DATA(cmsg) as *const T as *mut T, value);
        }
        self.len += space;
        self.cmsg = unsafe { libc::CMSG_NXTHDR(self.hdr, cmsg).as_mut() };
    }

    /// Finishes appending control messages to the buffer
    pub(crate) fn finish(&mut self) {
        self.hdr.msg_controllen = self.len as _;
    }
}

/// # Safety
///
/// `cmsg` must refer to a cmsg containing a payload of type `T`
pub(crate) unsafe fn decode<T: Copy>(cmsg: &libc::cmsghdr) -> T {
    assert!(mem::align_of::<T>() <= mem::align_of::<libc::cmsghdr>());
    ptr::read(libc::CMSG_DATA(cmsg) as *const T)
}

pub(crate) struct Iter<'a> {
    hdr: &'a libc::msghdr,
    cmsg: Option<&'a libc::cmsghdr>,
}

impl<'a> Iter<'a> {
    /// # Safety
    ///
    /// `hdr.msg_control` must point to memory outliving `'a` which can be soundly read for the
    /// lifetime of the constructed `Iter` and contains a buffer of cmsgs, i.e. is aligned for
    /// `cmsghdr`, is fully initialized, and has correct internal links.
    pub(crate) unsafe fn new(hdr: &'a libc::msghdr) -> Self {
        Self {
            hdr,
            cmsg: libc::CMSG_FIRSTHDR(hdr).as_ref(),
        }
    }
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a libc::cmsghdr;
    fn next(&mut self) -> Option<&'a libc::cmsghdr> {
        let current = self.cmsg.take()?;
        self.cmsg = unsafe { libc::CMSG_NXTHDR(self.hdr, current).as_ref() };
        Some(current)
    }
}

pub(crate) fn prepare_sent(
    bufs: &[IoSlice<'_>],
    send_hdr: &SendHeader,
    hdr: &mut libc::msghdr,
    ctrl: &mut Aligned<[u8; CMSG_LEN]>,
    with_gso: bool,
) {
    let dst_addr = socket2::SockAddr::from(send_hdr.dst);
    hdr.msg_name = dst_addr.as_ptr() as *mut _;
    hdr.msg_namelen = dst_addr.len();
    hdr.msg_iov = bufs.as_ptr() as *mut _;
    hdr.msg_iovlen = bufs.len() as _;

    hdr.msg_control = ctrl.0.as_mut_ptr() as _;
    hdr.msg_controllen = CMSG_LEN as _;
    let mut encoder = unsafe { Cmsg::new(hdr) };
    let ecn = send_hdr.ecn.map_or(0, |x| x as libc::c_int);

    // IPv4 or IPv4-Mapped IPv6
    let is_ipv4: bool = send_hdr.dst.is_ipv4()
        || matches!(send_hdr.dst.ip(),IpAddr::V6(addr) if addr.to_ipv4_mapped().is_some());

    if is_ipv4 {
        encoder.push(libc::IPPROTO_IP, libc::IP_TOS, ecn as IpTosTy);
    } else {
        encoder.push(libc::IPPROTO_IPV6, libc::IPV6_TCLASS, ecn);
    }

    if let Some(segment_size) = send_hdr.seg_size {
        if with_gso {
            UdpSocketController::set_segment_size(&mut encoder, segment_size);
        }
    }

    match send_hdr.src.ip() {
        IpAddr::V4(v4) => {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            {
                let pktinfo = libc::in_pktinfo {
                    ipi_ifindex: 0,
                    ipi_spec_dst: libc::in_addr {
                        s_addr: u32::from_ne_bytes(v4.octets()),
                    },
                    ipi_addr: libc::in_addr { s_addr: 0 },
                };
                encoder.push(libc::IPPROTO_IP, libc::IP_PKTINFO, pktinfo);
            }
            #[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "ios",))]
            {
                let addr = libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.octets()),
                };
                encoder.push(libc::IPPROTO_IP, libc::IP_RECVDSTADDR, addr);
            }
        }
        IpAddr::V6(v6) => {
            let pktinfo = libc::in6_pktinfo {
                ipi6_ifindex: 0,
                ipi6_addr: libc::in6_addr {
                    s6_addr: v6.octets(),
                },
            };
            encoder.push(libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, pktinfo);
        }
    }
    encoder.finish();
}

pub(crate) fn prepare_recv(
    buf: &mut IoSliceMut,
    name: &mut MaybeUninit<libc::sockaddr_storage>,
    ctrl: &mut Aligned<MaybeUninit<[u8; CMSG_LEN]>>,
    hdr: &mut libc::msghdr,
) {
    hdr.msg_name = name.as_mut_ptr() as _;
    hdr.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as _;
    hdr.msg_iov = buf as *mut IoSliceMut as *mut libc::iovec;
    hdr.msg_iovlen = 1;
    hdr.msg_control = ctrl.0.as_mut_ptr() as _;
    hdr.msg_controllen = CMSG_LEN as _;
    hdr.msg_flags = 0;
}

pub(crate) fn decode_recv(
    name: &MaybeUninit<libc::sockaddr_storage>,
    hdr: &libc::msghdr,
    len: usize,
    recv_hdr: &mut RecvHeader,
) {
    let name = unsafe { name.assume_init() };
    let cmsg_iter = unsafe { Iter::new(hdr) };
    recv_hdr.seg_size = len;
    for cmsg in cmsg_iter {
        match (cmsg.cmsg_level, cmsg.cmsg_type) {
            (libc::IPPROTO_IP, libc::IP_TOS) | (libc::IPPROTO_IP, libc::IP_RECVTOS) => unsafe {
                recv_hdr.ecn = Some(decode::<u8>(cmsg));
            },
            (libc::IPPROTO_IPV6, libc::IPV6_TCLASS) => unsafe {
                // Temporary hack around broken macos ABI. Remove once upstream fixes it.
                // https://bugreport.apple.com/web/?problemID=48761855
                #[allow(clippy::unnecessary_cast)] // cmsg.cmsg_len defined as size_t
                if (cfg!(target_os = "macos") || cfg!(target_os = "ios"))
                    && cmsg.cmsg_len as usize == libc::CMSG_LEN(mem::size_of::<u8>() as _) as usize
                {
                    recv_hdr.ecn = Some(decode::<u8>(cmsg));
                } else {
                    recv_hdr.ecn = Some(decode::<libc::c_int>(cmsg) as u8);
                }
            },
            #[cfg(any(target_os = "linux", target_os = "android"))]
            (libc::IPPROTO_IP, libc::IP_PKTINFO) => {
                let pktinfo = unsafe { decode::<libc::in_pktinfo>(cmsg) };
                let ip = IpAddr::V4(Ipv4Addr::from(pktinfo.ipi_addr.s_addr.to_ne_bytes()));
                recv_hdr.dst.set_ip(ip);
            }
            #[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "ios",))]
            (libc::IPPROTO_IP, libc::IP_RECVDSTADDR) => {
                let in_addr = unsafe { decode::<libc::in_addr>(cmsg) };
                recv_hdr
                    .dst
                    .set_ip(IpAddr::V4(Ipv4Addr::from(in_addr.s_addr.to_ne_bytes())));
            }
            (libc::IPPROTO_IP, libc::IP_TTL) => unsafe {
                recv_hdr.ttl = decode::<u32>(cmsg) as u8;
            },
            (libc::IPPROTO_IPV6, libc::IPV6_HOPLIMIT) => unsafe {
                recv_hdr.ttl = decode::<u32>(cmsg) as u8;
            },
            (libc::IPPROTO_IP, libc::IP_RECVTTL) => unsafe {
                recv_hdr.ttl = decode::<u32>(cmsg) as u8;
            },
            _ => {
                log::error!("read unkown cmsg {}", cmsg.cmsg_type);
            }
        }
    }

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
