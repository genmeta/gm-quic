use std::{
    ffi::c_int,
    io, mem,
    net::{IpAddr, Ipv4Addr},
    os::windows::io::AsRawSocket,
    ptr,
};

use libc::c_uchar;
use windows_sys::Win32::Networking::WinSock;

use crate::{
    cmsghdr::{self, Cmsg, MsgHdr},
    Io, PacketHeader, UdpSocketController, DEFAULT_TTL,
};

const OPTION_ON: libc::c_int = 1;

impl MsgHdr for WinSock::WSAMSG {
    type ControlMessage = WinSock::CMSGHDR;

    fn first_cmsg(&self) -> *mut Self::ControlMessage {
        if self.Control.len as usize >= mem::size_of::<WinSock::CMSGHDR>() {
            self.Control.buf as *mut WinSock::CMSGHDR
        } else {
            ptr::null_mut::<WinSock::CMSGHDR>()
        }
    }

    fn next(&self, cmsg: &Self::ControlMessage) -> *mut Self::ControlMessage {
        let next =
            (cmsg as *const _ as usize + cmsghdr_align(cmsg.cmsg_len)) as *mut WinSock::CMSGHDR;
        let max = self.Control.buf as usize + self.Control.len as usize;
        if unsafe { next.offset(1) } as usize > max {
            ptr::null_mut()
        } else {
            next
        }
    }

    fn set_len(&mut self, len: usize) {
        self.Control.len = len as _;
    }

    fn capacity(&self) -> usize {
        self.Control.len as _
    }
}

impl Cmsg for WinSock::CMSGHDR {
    fn cmsg_len(length: usize) -> usize {
        cmsgdata_align(mem::size_of::<Self>()) + length
    }

    fn space(length: usize) -> usize {
        cmsgdata_align(mem::size_of::<Self>() + cmsghdr_align(length))
    }

    fn data(&self) -> *mut libc::c_uchar {
        (self as *const _ as usize + cmsgdata_align(mem::size_of::<Self>())) as *mut c_uchar
    }

    fn set(&mut self, level: libc::c_int, ty: libc::c_int, len: usize) {
        self.cmsg_level = level as _;
        self.cmsg_type = ty as _;
        self.cmsg_len = len as _;
    }
}

const fn cmsghdr_align(length: usize) -> usize {
    (length + mem::align_of::<WinSock::CMSGHDR>() - 1) & !(mem::align_of::<WinSock::CMSGHDR>() - 1)
}

fn cmsgdata_align(length: usize) -> usize {
    (length + mem::align_of::<usize>() - 1) & !(mem::align_of::<usize>() - 1)
}

const CMSG_LEN: usize = 128;
#[derive(Copy, Clone)]
#[repr(align(8))] // Conservative bound for align_of<WinSock::CMSGHDR>
pub(crate) struct Aligned<T>(pub(crate) T);

impl Io for UdpSocketController {
    fn config(&mut self) -> std::io::Result<()> {
        let io = socket2::SockRef::from(&self.io);
        io.set_nonblocking(true)?;

        let addr = io.local_addr()?;
        let is_ipv6 = addr.is_ipv6();

        let is_ipv4 = addr.is_ipv4();
        if is_ipv4 {
            self.setsockopt(WinSock::IPPROTO_IP, WinSock::IP_RECVTOS, OPTION_ON);
            self.setsockopt(WinSock::IPPROTO_IP, WinSock::IP_PKTINFO, OPTION_ON);
            self.setsockopt(WinSock::IPPROTO_IP, WinSock::IP_RECVTTL, OPTION_ON);
            self.setsockopt(WinSock::IPPROTO_IP, WinSock::IP_RECVDSTADDR, OPTION_ON);
            self.setsockopt(WinSock::IPPROTO_IP, WinSock::IP_TTL, DEFAULT_TTL);
        }

        if is_ipv6 {
            self.setsockopt(WinSock::IPPROTO_IPV6, WinSock::IPV6_HOPLIMIT, OPTION_ON);
            self.setsockopt(WinSock::IPPROTO_IPV6, WinSock::IPV6_RECVTCLASS, OPTION_ON);
            self.setsockopt(WinSock::IPPROTO_IPV6, WinSock::IPV6_PKTINFO, OPTION_ON);
        }
        Ok(())
    }

    fn sendmsg(
        &self,
        bufs: &[std::io::IoSlice<'_>],
        hdr: &crate::PacketHeader,
    ) -> std::io::Result<usize> {
        let mut ctrl_buf = Aligned([0; CMSG_LEN]);

        // FIXME: Ipv6 mapped address should be supported
        let dst = socket2::SockAddr::from(hdr.dst);
        let mut count = 0;

        for buf in bufs {
            let mut data = WinSock::WSABUF {
                buf: buf.as_ptr() as *mut _,
                len: buf.len() as _,
            };

            let ctrl = WinSock::WSABUF {
                buf: ctrl_buf.0.as_mut_ptr(),
                len: ctrl_buf.0.len() as _,
            };

            let mut wsa_msg = WinSock::WSAMSG {
                name: dst.as_ptr() as *mut _,
                namelen: dst.len(),
                lpBuffers: &mut data,
                Control: ctrl,
                dwBufferCount: 1,
                dwFlags: 0,
            };

            let mut cmsghdr = unsafe { cmsghdr::CmsgHdr::new(&mut wsa_msg) };

            let src = socket2::SockAddr::from(hdr.src);

            match src.family() {
                WinSock::AF_INET => {
                    let src_ip = unsafe { ptr::read(src.as_ptr() as *const WinSock::SOCKADDR_IN) };
                    let pktinfo = WinSock::IN_PKTINFO {
                        ipi_addr: src_ip.sin_addr,
                        ipi_ifindex: 0,
                    };
                    cmsghdr.append(WinSock::IPPROTO_IP, WinSock::IP_PKTINFO, pktinfo);
                }
                WinSock::AF_INET6 => {
                    let src_ip = unsafe { ptr::read(src.as_ptr() as *const WinSock::SOCKADDR_IN6) };
                    let pktinfo = WinSock::IN6_PKTINFO {
                        ipi6_addr: src_ip.sin6_addr,
                        ipi6_ifindex: unsafe { src_ip.Anonymous.sin6_scope_id },
                    };
                    cmsghdr.append(WinSock::IPPROTO_IPV6, WinSock::IPV6_PKTINFO, pktinfo);
                }
                _ => {
                    return Err(io::Error::from(io::ErrorKind::InvalidInput));
                }
            }

            let ecn = hdr.ecn.map_or(0, |x| x as c_int);
            // True for IPv4 or IPv4-Mapped IPv6
            let is_ipv4 = hdr.dst.is_ipv4()
                || matches!(hdr.dst.ip(), IpAddr::V6(addr) if addr.to_ipv4_mapped().is_some());
            if is_ipv4 {
                cmsghdr.append(WinSock::IPPROTO_IP, WinSock::IP_ECN, ecn);
            } else {
                cmsghdr.append(WinSock::IPPROTO_IPV6, WinSock::IPV6_ECN, ecn);
            }
            cmsghdr.finish();

            let mut len = 0;
            let ret = unsafe {
                WinSock::WSASendMsg(
                    self.io.as_raw_socket() as usize,
                    &wsa_msg,
                    0,
                    &mut len,
                    ptr::null_mut(),
                    None,
                )
            };

            if ret != 0 {
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::WouldBlock {
                    return Err(e);
                }
            }
            count += 1;
        }
        Ok(count as usize)
    }

    fn recvmsg(
        &self,
        bufs: &mut [std::io::IoSliceMut<'_>],
        hdr: &mut [crate::PacketHeader],
    ) -> std::io::Result<usize> {
        let wsa_recvmsg_ptr = WSARECVMSG_PTR.expect("valid function pointer for WSARecvMsg");

        let mut ctrl_buf = Aligned([0; CMSG_LEN]);
        let mut source: WinSock::SOCKADDR_INET = unsafe { mem::zeroed() };

        let ctrl = WinSock::WSABUF {
            buf: ctrl_buf.0.as_mut_ptr(),
            len: ctrl_buf.0.len() as _,
        };

        let mut wsa_msg = WinSock::WSAMSG {
            name: &mut source as *mut _ as *mut _,
            namelen: mem::size_of_val(&source) as _,
            lpBuffers: &mut WinSock::WSABUF {
                buf: bufs[0].as_mut_ptr(),
                len: bufs[0].len() as _,
            },
            Control: ctrl,
            dwBufferCount: 1,
            dwFlags: 0,
        };

        let mut len = 0;
        unsafe {
            let rc = (wsa_recvmsg_ptr)(
                self.io.as_raw_socket() as usize,
                &mut wsa_msg,
                &mut len,
                ptr::null_mut(),
                None,
            );
            if rc == -1 {
                return Err(io::Error::last_os_error());
            }
        }

        let addr = unsafe {
            let (_, addr) = socket2::SockAddr::try_init(|addr_storage, len| {
                *len = mem::size_of_val(&source) as _;
                ptr::copy_nonoverlapping(&source, addr_storage as _, 1);
                Ok(())
            })?;
            addr.as_socket()
        };

        let mut ecn_bits = 0;
        let mut dst_ip = None;
        let cmsg_iter = unsafe { cmsghdr::Iter::new(&wsa_msg) };
        for cmsg in cmsg_iter {
            // [header (len)][data][padding(len + sizeof(data))] -> [header][data][padding]
            match (cmsg.cmsg_level, cmsg.cmsg_type) {
                (WinSock::IPPROTO_IP, WinSock::IP_PKTINFO) => {
                    let pktinfo =
                        unsafe { cmsghdr::decode::<WinSock::IN_PKTINFO, WinSock::CMSGHDR>(cmsg) };
                    // Addr is stored in big endian format
                    let ip4 = Ipv4Addr::from(u32::from_be(unsafe { pktinfo.ipi_addr.S_un.S_addr }));
                    dst_ip = Some(ip4.into());
                }
                (WinSock::IPPROTO_IPV6, WinSock::IPV6_PKTINFO) => {
                    let pktinfo =
                        unsafe { cmsghdr::decode::<WinSock::IN6_PKTINFO, WinSock::CMSGHDR>(cmsg) };
                    // Addr is stored in big endian format
                    dst_ip = Some(IpAddr::from(unsafe { pktinfo.ipi6_addr.u.Byte }));
                }
                (WinSock::IPPROTO_IP, WinSock::IP_ECN) => {
                    // ECN is a C integer https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-ecn
                    ecn_bits = unsafe { cmsghdr::decode::<c_int, WinSock::CMSGHDR>(cmsg) };
                }
                (WinSock::IPPROTO_IPV6, WinSock::IPV6_ECN) => {
                    // ECN is a C integer https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-ecn
                    ecn_bits = unsafe { cmsghdr::decode::<c_int, WinSock::CMSGHDR>(cmsg) };
                }
                _ => {}
            }
        }
        let dst = if let Some(ip) = dst_ip {
            crate::SocketAddr::new(ip, self.local_addr().port())
        } else {
            self.local_addr()
        };
        hdr[0] = PacketHeader {
            src: addr.unwrap(),
            dst: dst,
            ttl: DEFAULT_TTL as u8,
            ecn: Some(ecn_bits as u8),
            seg_size: len as u16,
            gso: false,
        };

        Ok(1)
    }

    fn setsockopt(&self, level: libc::c_int, name: libc::c_int, value: libc::c_int) {
        unsafe {
            WinSock::setsockopt(
                self.io.as_raw_socket() as usize,
                level,
                name,
                &value as *const _ as _,
                mem::size_of_val(&value) as _,
            )
        };
    }

    fn set_ttl(&mut self, ttl: u8) -> io::Result<()> {
        if ttl == self.ttl {
            return Ok(());
        }
        self.setsockopt(WinSock::IPPROTO_IP, WinSock::IP_TTL, ttl as _);
        Ok(())
    }
}

static WSARECVMSG_PTR: std::sync::LazyLock<WinSock::LPFN_WSARECVMSG> =
    std::sync::LazyLock::new(|| {
        let s = unsafe { WinSock::socket(WinSock::AF_INET as _, WinSock::SOCK_DGRAM as _, 0) };
        if s == WinSock::INVALID_SOCKET {
            log::warn!(
                "failed to create socket for WSARecvMsg function pointer: {}",
                io::Error::last_os_error()
            );
            return None;
        }
        // Detect if OS expose WSARecvMsg API based on
        // https://github.com/Azure/mio-uds-windows/blob/a3c97df82018086add96d8821edb4aa85ec1b42b/src/stdnet/ext.rs#L601
        let guid = WinSock::WSAID_WSARECVMSG;
        let mut wsa_recvmsg_ptr = None;
        let mut len = 0;

        // Safety: Option handles the NULL pointer with a None value
        let ret = unsafe {
            WinSock::WSAIoctl(
                s as _,
                WinSock::SIO_GET_EXTENSION_FUNCTION_POINTER,
                &guid as *const _ as *const _,
                mem::size_of_val(&guid) as u32,
                &mut wsa_recvmsg_ptr as *mut _ as *mut _,
                mem::size_of_val(&wsa_recvmsg_ptr) as u32,
                &mut len,
                ptr::null_mut(),
                None,
            )
        };

        if ret == -1 {
            log::warn!(
                "failed to get WSARecvMsg function pointer: {}",
                io::Error::last_os_error()
            );
        } else if len as usize != mem::size_of::<WinSock::LPFN_WSARECVMSG>() {
            log::warn!(
                "WSARecvMsg function pointer size mismatch: expected {}, got {}",
                mem::size_of::<WinSock::LPFN_WSARECVMSG>(),
                len
            );
            wsa_recvmsg_ptr = None;
        }

        unsafe {
            WinSock::closesocket(s);
        }

        wsa_recvmsg_ptr
    });
