use std::{
    io::IoSliceMut,
    mem::{self, MaybeUninit},
    net::IpAddr,
};

use crate::{
    cmsg::{Aligned, Encoder},
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
    // todo: if return sendmsg EINVAL
    if packet.dest_addr.is_ipv4() {
        encoder.push(libc::IPPROTO_IP, libc::IP_TOS, ecn as IpTosTy);
    } else {
        encoder.push(libc::IPPROTO_IPV6, libc::IPV6_TCLASS, ecn);
    }

    if let Some(segment_size) = packet.segment_size {
        gso::set_segment_size(&mut encoder, segment_size as u16);
    }

    if let Some(ip) = &packet.src_ip {
        match ip {
            IpAddr::V4(v4) => {
                #[cfg(target_os = "linux")]
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
                #[cfg(any(target_os = "freebsd", target_os = "macos"))]
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
    _name: &MaybeUninit<libc::sockaddr_storage>,
    _hdr: &libc::msghdr,
    _len: usize,
) -> RecvMeta {
    todo!()
}
