use std::{
    future::Future,
    io::{self, IoSlice, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::atomic::AtomicU16,
    task::{ready, Context, Poll},
};

use socket2::{Domain, Socket, Type};
use tokio::io::Interest;

const DEFAULT_TTL: libc::c_int = 64;

cfg_if::cfg_if! {
    if #[cfg(unix)]{
        #[path = "unix.rs"]
        mod uinx;
        mod msg;
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        pub const BATCH_SIZE: usize = 64;
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        pub const BATCH_SIZE: usize = 1;
    } else if #[cfg(windows)] {
        #[path = "windows.rs"]
        mod windows;
        pub const BATCH_SIZE: usize = 1;
    } else {
        compile_error!("Unsupported platform");
    }
}

mod cmsghdr;

#[derive(Clone, Copy, Debug)]
pub struct PacketHeader {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub ttl: u8,
    // Explicit congestion notification (ECN)
    pub ecn: Option<u8>,
    // packet segment size
    pub seg_size: u16,
    // use gso
    pub gso: bool,
}

impl Default for PacketHeader {
    fn default() -> Self {
        Self {
            src: SocketAddr::from(([0, 0, 0, 0], 0)),
            dst: SocketAddr::from(([0, 0, 0, 0], 0)),
            ttl: DEFAULT_TTL as u8,
            ecn: None,
            gso: false,
            seg_size: 0,
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct UdpSocketController {
    io: tokio::net::UdpSocket,
    // TOOD: unread?
    gso_size: AtomicU16,
    gro_size: AtomicU16,
}

impl UdpSocketController {
    pub fn new(addr: SocketAddr) -> io::Result<Self> {
        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };

        let socket = Socket::new(domain, Type::DGRAM, None)?;
        if let Err(e) = socket.bind(&addr.into()) {
            log::error!("Failed to bind socket: {}", e);
            return Err(io::Error::new(io::ErrorKind::AddrInUse, e));
        }

        let io = tokio::net::UdpSocket::from_std(socket.into())?;

        // TODO: 会报错
        // io.set_ttl(DEFAULT_TTL as u32)?;

        let socket = Self {
            io,
            gso_size: AtomicU16::new(1),
            gro_size: AtomicU16::new(1),
        };
        socket.config()?;
        Ok(socket)
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    pub fn poll_send(
        &self,
        bufs: &[IoSlice<'_>],
        hdr: &PacketHeader,
        cx: &mut Context,
    ) -> Poll<io::Result<usize>> {
        ready!(self.io.poll_send_ready(cx)?);
        let f = || self.sendmsg(bufs, hdr);
        let ret = self.io.try_io(Interest::WRITABLE, f);
        Poll::Ready(ret)
    }

    pub fn poll_recv(
        &self,
        bufs: &mut [IoSliceMut<'_>],
        hdrs: &mut [PacketHeader],
        cx: &mut Context,
    ) -> Poll<io::Result<usize>> {
        ready!(self.io.poll_recv_ready(cx)?);
        let f = || self.recvmsg(bufs, hdrs);
        let ret = self.io.try_io(Interest::READABLE, f);
        if matches!(&ret, Err(e) if e.kind() == io::ErrorKind::WouldBlock) {
            return Poll::Ready(Ok(0));
        }
        Poll::Ready(ret)
    }
}

trait Io {
    fn config(&self) -> io::Result<()>;

    fn sendmsg(&self, bufs: &[IoSlice<'_>], hdr: &PacketHeader) -> io::Result<usize>;

    fn recvmsg(&self, bufs: &mut [IoSliceMut<'_>], hdr: &mut [PacketHeader]) -> io::Result<usize>;

    fn setsockopt(&self, level: libc::c_int, name: libc::c_int, value: libc::c_int);
}

impl UdpSocketController {
    pub fn send<'a>(&'a self, iovecs: &'a [IoSlice<'a>], header: PacketHeader) -> Send<'a> {
        Send {
            usc: self,
            iovecs,
            header,
        }
    }

    pub fn receiver(&self) -> Receiver {
        Receiver {
            usc: self,
            iovecs: (0..BATCH_SIZE)
                .map(|_| [0u8; 1500].to_vec())
                .collect::<Vec<_>>(),
            headers: (0..BATCH_SIZE)
                .map(|_| PacketHeader::default())
                .collect::<Vec<_>>(),
        }
    }
}

pub struct Send<'a> {
    pub usc: &'a UdpSocketController,
    pub iovecs: &'a [IoSlice<'a>],
    pub header: PacketHeader,
}

impl Future for Send<'_> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.usc.poll_send(this.iovecs, &this.header, cx)
    }
}

pub struct Receiver<'u> {
    pub usc: &'u UdpSocketController,
    pub iovecs: Vec<Vec<u8>>,
    pub headers: Vec<PacketHeader>,
}

impl Receiver<'_> {
    #[inline]
    pub fn poll_recv(&mut self, cx: &mut Context) -> Poll<io::Result<usize>> {
        let mut bufs = self
            .iovecs
            .iter_mut()
            .map(|b| IoSliceMut::new(b))
            .collect::<Vec<_>>();

        self.usc.poll_recv(&mut bufs, &mut self.headers, cx)
    }

    #[inline]
    pub async fn recv(&mut self) -> io::Result<usize> {
        core::future::poll_fn(|cx| self.poll_recv(cx)).await
    }
}
