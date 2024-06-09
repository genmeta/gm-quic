use crate::msg::{decode_recv, prepare_recv, Aligned, Cmsg, CMSG_LEN};
use crate::{io, msg::prepare_sent, SendInfo};
use crate::{Gro, Gso, Io, RecvInfo, UdpSocketController};
use std::mem::MaybeUninit;
use std::{mem, os::fd::AsRawFd};

const OPTION_ON: libc::c_int = 1;
const OPTION_OFF: libc::c_int = 0;
pub(super) const DEFAULT_TTL: libc::c_int = 64;

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
pub(crate) const BATCH_SIZE: usize = 32;

#[cfg(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "macos",
    target_os = "ios",
))]
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
            if let Err(err) = self.set_socket_option(libc::IPPROTO_IP, libc::IP_RECVTOS, OPTION_ON)
            {
                log::error!("setsockopt IP_RECVTOS failed: {}", err);
            }
        }

        if is_ipv4 {
            #[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "ios"))]
            {
                // IP_DONTFRAG  may	 be used to set	the Don't Fragment flag	on IP packets.
                self.set_socket_option(libc::IPPROTO_IP, libc::IP_DONTFRAG, OPTION_ON)?;
                // If the IP_RECVDSTADDR	option	is enabled on a	SOCK_DGRAM socket, the
                // recvmsg(2) call will return the destination IP address for a UDP	 datagram.
                self.set_socket_option(libc::IPPROTO_IP, libc::IP_RECVDSTADDR, OPTION_ON)?;
            }
            self.set_socket_option(libc::IPPROTO_IP, libc::IP_PKTINFO, OPTION_ON)?;
            self.set_socket_option(libc::IPPROTO_IP, libc::IP_TTL, DEFAULT_TTL)?;
            // When this flag is set, pass a IP_TTL control message with
            // the time-to-live field of the received packet as a 32 bit
            // integer.  Not supported for SOCK_STREAM sockets.
            self.set_socket_option(libc::IPPROTO_IP, libc::IP_RECVTTL, OPTION_ON)?;
        }
        // Options standardized in RFC 3542
        else {
            //  If this flag is set to false (zero), then the socket can
            //  be used to send and receive packets to and from an IPv6
            //  address or an IPv4-mapped IPv6 address.
            self.set_socket_option(libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, OPTION_OFF)?;
            // Set delivery of the IPV6_PKTINFO control message on incoming datagrams.
            self.set_socket_option(libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, OPTION_ON)?;
            self.set_socket_option(libc::IPPROTO_IPV6, libc::IPV6_RECVTCLASS, OPTION_ON)?;
            self.set_socket_option(libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG, OPTION_ON)?;
            self.set_socket_option(libc::IPPROTO_IP, libc::IPV6_PKTINFO, OPTION_ON)?;
            // The received hop limit is returned as ancillary data by recvmsg()
            // only if the application has enabled the IPV6_RECVHOPLIMIT socket option
            self.set_socket_option(libc::IPPROTO_IP, libc::IPV6_RECVHOPLIMIT, OPTION_ON)?;
            self.set_socket_option(libc::IPPROTO_IP, libc::IP_RECVTTL, OPTION_ON)?;
            self.set_socket_option(libc::IPPROTO_IP, libc::IPV6_UNICAST_HOPS, DEFAULT_TTL)?;
        }

        Ok(())
    }

    fn set_socket_option(
        &self,
        level: libc::c_int,
        name: libc::c_int,
        value: libc::c_int,
    ) -> Result<(), io::Error> {
        let result = unsafe {
            libc::setsockopt(
                self.io.as_raw_fd(),
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

    fn sendmsg(
        &self,
        buf: &mut std::io::IoSliceMut<'_>,
        send_info: &SendInfo,
    ) -> io::Result<usize> {
        let io = socket2::SockRef::from(&self.io);

        let send = |send_buf: &std::io::IoSliceMut<'_>| {
            let mut hdr: libc::msghdr = unsafe { mem::zeroed() };
            let mut iov: libc::iovec = unsafe { mem::zeroed() };
            let mut ctrl = Aligned([0u8; CMSG_LEN]);
            prepare_sent(send_buf, send_info, &mut hdr, &mut iov, &mut ctrl);
            loop {
                let ret = to_result(unsafe { libc::sendmsg(io.as_raw_fd(), &hdr, 0) });

                match ret {
                    Ok(_) => return ret,
                    Err(e) => {
                        match e.kind() {
                            io::ErrorKind::Interrupted => {
                                // Retry
                            }
                            io::ErrorKind::WouldBlock => return Err(e),
                            _ => {
                                log::warn!("sendmsg failed: {}", e);
                                // ingnore other errors
                                return Ok(0);
                            }
                        }
                    }
                }
            }
        };

        // send without gso, split by segment size
        if send_info.segment_size.is_some() && self.max_gso_segments() == 1 {
            let mut offset = 0;
            let mut left = buf.len();
            let mut written = 0;

            while left > 0 {
                let pkt_len = std::cmp::min(left, send_info.segment_size.unwrap() as usize);
                let send_buf: std::io::IoSliceMut<'_> =
                    std::io::IoSliceMut::new(&mut buf[offset..(offset + pkt_len)]);
                match send(&send_buf) {
                    Ok(n) => {
                        written += n;
                    }
                    Err(e) => return Err(e),
                }
                offset += pkt_len;
                left -= pkt_len;
            }
            return Ok(written);
        }

        // send with gso
        send(buf)
    }

    #[cfg(target_os = "linux")]
    fn recvmsg(
        &self,
        bufs: &mut [std::io::IoSliceMut<'_>],
        recv_infos: &mut [RecvInfo],
    ) -> io::Result<usize> {
        let mut hdrs = unsafe { mem::zeroed::<[libc::mmsghdr; BATCH_SIZE]>() };
        let mut names = [MaybeUninit::<libc::sockaddr_storage>::uninit(); BATCH_SIZE];
        let mut cmsgs = [Aligned(MaybeUninit::<[u8; CMSG_LEN]>::uninit()); BATCH_SIZE];
        let max_msg_count = bufs.len().min(BATCH_SIZE);

        for i in 0..max_msg_count {
            prepare_recv(
                &mut bufs[i],
                &mut names[i],
                &mut cmsgs[i],
                &mut hdrs[i].msg_hdr,
            );
        }
        let msg_count = loop {
            let ret = unsafe {
                recvmmsg(
                    self.io.as_raw_fd(),
                    hdrs.as_mut_ptr(),
                    bufs.len().min(BATCH_SIZE) as _,
                )
            };
            match ret {
                Ok(ret) => break ret,
                Err(e) => {
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(e);
                }
            }
        };

        for i in 0..(msg_count as usize) {
            decode_recv(
                &names[i],
                &hdrs[i].msg_hdr,
                hdrs[i].msg_len as usize,
                recv_infos.get_mut(i).unwrap(),
            );
        }
        Ok(msg_count as usize)
    }

    #[cfg(not(target_os = "linux"))]
    fn recvmsg(
        &self,
        bufs: &mut [std::io::IoSliceMut<'_>],
        recv_infos: &mut [RecvInfo],
    ) -> io::Result<usize> {
        let mut hdr = unsafe { mem::zeroed::<libc::msghdr>() };
        let mut name = MaybeUninit::<libc::sockaddr_storage>::uninit();
        let mut cmsg = Aligned(MaybeUninit::<[u8; CMSG_LEN]>::uninit());
        prepare_recv(&mut bufs[0], &mut name, &mut cmsg, &mut hdr);

        let n = loop {
            let ret = to_result(unsafe { libc::recvmsg(self.io.as_raw_fd(), &mut hdr, 0) });
            match ret {
                Ok(ret) => {
                    if hdr.msg_flags & libc::MSG_CTRUNC != 0 {
                        continue;
                    }
                    break ret;
                }
                Err(e) => {
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(e);
                }
            }
        };
        decode_recv(&name, &hdr, n as usize, recv_infos.get_mut(0).unwrap());
        Ok(1)
    }
}

#[cfg(target_os = "linux")]
unsafe fn recvmmsg(
    sockfd: libc::c_int,
    msgvec: *mut libc::mmsghdr,
    vlen: libc::c_uint,
) -> io::Result<usize> {
    use std::ptr;

    let flags = 0;
    let timeout = ptr::null_mut::<libc::timespec>();

    let ret: io::Result<usize>;

    #[cfg(not(target_os = "freebsd"))]
    {
        ret = to_result(
            libc::syscall(libc::SYS_recvmmsg, sockfd, msgvec, vlen, flags, timeout) as isize,
        );
    }

    // libc on FreeBSD implements `recvmmsg` as a high-level abstraction over `recvmsg`,
    // thus `SYS_recvmmsg` constant and direct system call do not exist
    #[cfg(target_os = "freebsd")]
    {
        ret = to_result(libc::recvmmsg(sockfd, msgvec, vlen as usize, flags, timeout) as isize);
    }

    match ret {
        Ok(_) => return ret,
        Err(e) => match e.raw_os_error() {
            Some(libc::ENOSYS) => {
                let flags = 0;
                if vlen == 0 {
                    return Ok(0);
                }
                to_result(libc::recvmsg(sockfd, &mut (*msgvec).msg_hdr, flags) as isize)
            }
            _ => Err(e),
        },
    }
}

fn to_result(code: isize) -> io::Result<usize> {
    if code == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(code as usize)
    }
}

#[cfg(target_os = "linux")]
impl Gso for UdpSocketController {
    fn max_gso_segments(&self) -> usize {
        if let Some(gso) = self.gro_segments {
            return gso as usize;
        }
        match self.set_socket_option(libc::SOL_UDP, libc::UDP_SEGMENT, OPTION_ON) {
            Ok(()) => 64,
            Err(_) => 1,
        }
    }

    fn set_segment_size(encoder: &mut Cmsg, segment_size: usize) {
        encoder.push(libc::SOL_UDP, libc::UDP_SEGMENT, segment_size);
    }
}

#[cfg(target_os = "linux")]
impl Gro for UdpSocketController {
    fn gro_segments(&self) -> usize {
        if let Some(gro) = self.gro_segments {
            return gro as usize;
        }
        match self.set_socket_option(libc::SOL_UDP, libc::UDP_GRO, OPTION_ON) {
            Ok(()) => 64,
            Err(_) => 1,
        }
    }
}

#[cfg(not(target_os = "linux"))]
impl Gso for UdpSocketController {
    fn max_gso_segments(&self) -> usize {
        1
    }

    fn set_segment_size(_: &mut Cmsg, _: usize) {
        panic!("set_segment_size is not supported on this platform");
    }
}

#[cfg(not(target_os = "linux"))]
impl Gro for UdpSocketController {
    fn gro_segments(&self) -> usize {
        1
    }
}
