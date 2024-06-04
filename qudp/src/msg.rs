use std::{
    io::IoSliceMut,
    mem::{self, MaybeUninit},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use crate::{
    cmsg::{self, Aligned, Encoder},
    unix::gso,
    RecvMeta, SendMeta,
};
const CMSG_LEN: usize = 88;

#[cfg(target_os = "freebsd")]
type IpTosTy = libc::c_uchar;
#[cfg(not(target_os = "freebsd"))]
type IpTosTy = libc::c_int;

pub(crate) fn prepare_sent(
    packet: &SendMeta,
    hdr: &mut libc::msghdr,
    iov: &mut libc::iovec,
    ctrl: &mut Aligned<[u8; CMSG_LEN]>,
) {
    iov.iov_base = packet.buf.as_ptr() as *const _ as *mut _;
    iov.iov_len = packet.buf.len();

    let dst_addr = socket2::SockAddr::from(packet.dest_addr);
    let name = dst_addr.as_ptr() as *mut libc::c_void;
    let namelen = dst_addr.len();
    hdr.msg_name = name as *mut _;
    hdr.msg_namelen = namelen;
    hdr.msg_iov = iov;
    hdr.msg_iovlen = 1;

    hdr.msg_control = ctrl.0.as_mut_ptr() as _;
    hdr.msg_controllen = CMSG_LEN as _;
    let mut encoder = unsafe { Encoder::new(hdr) };
    let ecn = packet.ecn.map_or(0, |x| x as libc::c_int);

    if packet.dest_addr.is_ipv4() {
        encoder.push(libc::IPPROTO_IP, libc::IP_TOS, ecn as IpTosTy);
    } else {
        encoder.push(libc::IPPROTO_IPV6, libc::IPV6_TCLASS, ecn);
    }

    if let Some(segment_size) = packet.segment_size {
        gso::set_segment_size(&mut encoder, segment_size as u16);
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
    meta: &mut RecvMeta,
) {
    let name = unsafe { name.assume_init() };
    let cmsg_iter = unsafe { cmsg::Iter::new(hdr) };
    meta.len = len;
    for cmsg in cmsg_iter {
        // todo: read ecn
        match (cmsg.cmsg_level, cmsg.cmsg_type) {
            (libc::IPPROTO_IP, libc::IP_TTL) => {
                meta.ttl = unsafe { cmsg::decode::<u32>(cmsg) } as u8;
            }
            (libc::IPPROTO_IPV6, libc::IPV6_HOPLIMIT) => {
                meta.ttl = unsafe { cmsg::decode::<u32>(cmsg) } as u8;
            }
            (libc::IPPROTO_IP, libc::IP_RECVTTL) => {
                meta.ttl = unsafe { cmsg::decode::<u32>(cmsg) } as u8;
            }
            _ => {
                println!("read unkown cmsg");
                todo!("other cmsg");
            }
        }
    }

    meta.src_addr = match libc::c_int::from(name.ss_family) {
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
