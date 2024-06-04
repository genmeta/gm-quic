use crate::RecvMeta;
use crate::{
    cmsg::{self, CMSG_LEN},
    io,
    msg::prepare_sent,
    SendMeta,
};
use std::{io::IoSliceMut, mem::MaybeUninit};
use std::{mem, os::fd::AsRawFd};

const OPTION_ON: libc::c_int = 1;
const OPTION_OFF: libc::c_int = 0;
pub(super) const DEFAULT_TTL: libc::c_int = 64;

pub(super) fn config(io: &socket2::Socket) -> io::Result<()> {
    io.set_nonblocking(true)?;

    let addr = io.local_addr()?;
    let is_ipv4 = addr.family() == libc::AF_INET as libc::sa_family_t;
    if is_ipv4 || !io.only_v6()? {
        //  If enabled, the IP_TOS ancillary message is passed with
        //  incoming packets.  It contains a byte which specifies the
        //  Type of Service/Precedence field of the packet header.
        if let Err(err) = set_socket_option(io, libc::IPPROTO_IP, libc::IP_RECVTOS, OPTION_ON) {
            println!("setsockopt IP_RECVTOS failed: {}", err);
        }
    }

    if is_ipv4 {
        #[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "ios"))]
        {
            // IP_DONTFRAG  may	 be used to set	the Don't Fragment flag	on IP packets.
            set_socket_option(io, libc::IPPROTO_IP, libc::IP_DONTFRAG, OPTION_ON)?;
            // If the IP_RECVDSTADDR	option	is enabled on a	SOCK_DGRAM socket, the
            // recvmsg(2) call will return the destination IP address for a UDP	 datagram.
            set_socket_option(io, libc::IPPROTO_IP, libc::IP_RECVDSTADDR, OPTION_ON)?;
        }
        set_socket_option(io, libc::IPPROTO_IP, libc::IP_PKTINFO, OPTION_ON)?;
        set_socket_option(io, libc::IPPROTO_IP, libc::IP_TTL, DEFAULT_TTL)?;
        // todo: 测试兼容性
        // When this flag is set, pass a IP_TTL control message with
        // the time-to-live field of the received packet as a 32 bit
        // integer.  Not supported for SOCK_STREAM sockets.
        set_socket_option(io, libc::IPPROTO_IP, libc::IP_RECVTTL, OPTION_ON)?;
    }
    // Options standardized in RFC 3542
    else {
        //  If this flag is set to false (zero), then the socket can
        //  be used to send and receive packets to and from an IPv6
        //  address or an IPv4-mapped IPv6 address.
        set_socket_option(io, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, OPTION_OFF)?;
        // Set delivery of the IPV6_PKTINFO control message on incoming datagrams.
        set_socket_option(io, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, OPTION_ON)?;
        set_socket_option(io, libc::IPPROTO_IPV6, libc::IPV6_RECVTCLASS, OPTION_ON)?;
        set_socket_option(io, libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG, OPTION_ON)?;
        set_socket_option(io, libc::IPPROTO_IP, libc::IPV6_PKTINFO, OPTION_ON)?;
        // The received hop limit is returned as ancillary data by recvmsg()
        // only if the application has enabled the IPV6_RECVHOPLIMIT socket option
        set_socket_option(io, libc::IPPROTO_IP, libc::IPV6_RECVHOPLIMIT, OPTION_ON)?;
        set_socket_option(io, libc::IPPROTO_IP, libc::IP_RECVTTL, OPTION_ON)?;
        set_socket_option(io, libc::IPPROTO_IP, libc::IPV6_UNICAST_HOPS, DEFAULT_TTL)?;
    }

    Ok(())
}

pub(super) fn set_socket_option(
    socket: &impl AsRawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> Result<(), io::Error> {
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            &value as *const _ as _,
            mem::size_of_val(&value) as _,
        )
    };

    match result == 0 {
        true => Ok(()),
        false => Err(io::Error::last_os_error()),
    }
}

#[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "ios"))]
pub(super) fn send(io: socket2::SockRef<'_>, packets: &[SendMeta]) -> io::Result<usize> {
    let mut hdr: libc::msghdr = unsafe { mem::zeroed() };
    let mut iov: libc::iovec = unsafe { mem::zeroed() };
    let mut ctrl = cmsg::Aligned([0u8; CMSG_LEN]);
    let mut sent = 0;

    while sent < packets.len() {
        prepare_sent(&packets[sent], &mut hdr, &mut iov, &mut ctrl);
        let n = unsafe { libc::sendmsg(io.as_raw_fd(), &hdr, 0) };
        if n == -1 {
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::Interrupted => {
                    // Retry the transmission
                }
                io::ErrorKind::WouldBlock if sent != 0 => return Ok(sent),
                io::ErrorKind::WouldBlock => return Err(e),
                _ => {
                    // ingnore other errors
                    sent += 1;
                }
            }
        } else {
            sent += 1;
        }
    }
    Ok(sent)
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(super) fn recv(
    io: socket2::SockRef<'_>,
    buf: &mut IoSliceMut<'_>,
    meta: &mut RecvMeta,
) -> io::Result<usize> {
    use crate::msg::{decode_recv, prepare_recv};

    let mut name = MaybeUninit::<libc::sockaddr_storage>::uninit();
    let mut ctrl = cmsg::Aligned(MaybeUninit::<[u8; CMSG_LEN]>::uninit());
    let mut hdr = unsafe { mem::zeroed::<libc::msghdr>() };

    prepare_recv(buf, &mut name, &mut ctrl, &mut hdr);
    let n = loop {
        let n = unsafe { libc::recvmsg(io.as_raw_fd(), &mut hdr, 0) };
        if n == -1 {
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::Interrupted => {
                    continue;
                }
                _ => return Err(e),
            }
        }
        if hdr.msg_flags & libc::MSG_TRUNC != 0 {
            continue;
        }
        break n;
    };

    decode_recv(&name, &hdr, n as usize, meta);
    Ok(1)
}

#[cfg(not(target_os = "linux"))]
pub(crate) mod gso {
    use crate::cmsg;

    pub(crate) fn set_segment_size(_encoder: &mut cmsg::Encoder, _segment_size: u16) {
        panic!("Setting a segment size is not supported on current platform");
    }
}

#[cfg(target_os = "linux")]
pub(crate) mod gso {
    use crate::cmsg;

    pub(crate) fn set_segment_size(_encoder: &mut cmsg::Encoder, _segment_size: u16) {
        todo!("set gso on linux")
    }
}
