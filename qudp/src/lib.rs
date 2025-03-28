use std::{
    future::Future,
    io::{self, IoSlice, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll, ready},
};

use socket2::{Domain, Socket, Type};
use tokio::io::Interest;
const DEFAULT_TTL: libc::c_int = 64;
pub const BATCH_SIZE: usize = 64;
cfg_if::cfg_if! {
    if #[cfg(unix)]{
        #[path = "unix.rs"]
        mod unix;
    } else if #[cfg(windows)] {
        #[path = "windows.rs"]
        mod windows;
    } else {
        compile_error!("Unsupported platform");
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PacketHeader {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub ttl: u8,
    // Explicit congestion notification (ECN)
    pub ecn: Option<u8>,
    // packet segment size
    pub seg_size: u16,
}

impl PacketHeader {
    pub fn new(src: SocketAddr, dst: SocketAddr, ttl: u8, ecn: Option<u8>, seg_size: u16) -> Self {
        Self {
            src,
            dst,
            ttl,
            ecn,
            seg_size,
        }
    }
}
impl Default for PacketHeader {
    fn default() -> Self {
        Self {
            src: SocketAddr::from(([0, 0, 0, 0], 0)),
            dst: SocketAddr::from(([0, 0, 0, 0], 0)),
            ttl: DEFAULT_TTL as u8,
            ecn: None,
            seg_size: 0,
        }
    }
}

#[derive(Debug)]
pub struct UdpSocketController {
    io: tokio::net::UdpSocket,
}

impl UdpSocketController {
    pub fn bind(addr: SocketAddr) -> io::Result<Self> {
        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };

        let socket = Socket::new(domain, Type::DGRAM, None)?;
        socket.set_nonblocking(true)?;
        Self::config(&socket, addr)?;
        let io = tokio::net::UdpSocket::from_std(socket.into())?;
        let usc = Self { io };
        Ok(usc)
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    pub fn poll_send(
        &self,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
        hdr: &PacketHeader,
    ) -> Poll<io::Result<usize>> {
        let mut sent = 0;
        while sent < bufs.len() {
            ready!(self.io.poll_send_ready(cx)?);
            let current_bufs = &bufs[sent..];
            match self
                .io
                .try_io(Interest::WRITABLE, || self.sendmsg(current_bufs, hdr))
            {
                Ok(n) => sent += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
        Poll::Ready(Ok(sent))
    }

    pub fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        hdrs: &mut [PacketHeader],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_recv_ready(cx)?);
            let f = || self.recvmsg(bufs, hdrs);
            let ret = self.io.try_io(Interest::READABLE, f);
            if matches!(&ret, Err(e) if e.kind() == io::ErrorKind::WouldBlock) {
                continue;
            } else {
                return Poll::Ready(ret);
            }
        }
    }
}

pub trait Io {
    fn config(io: &socket2::Socket, addr: SocketAddr) -> io::Result<()>;

    fn sendmsg(&self, bufs: &[IoSlice<'_>], hdr: &PacketHeader) -> io::Result<usize>;

    fn recvmsg(&self, bufs: &mut [IoSliceMut<'_>], hdr: &mut [PacketHeader]) -> io::Result<usize>;
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
        this.usc.poll_send(cx, this.iovecs, &this.header)
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

        self.usc.poll_recv(cx, &mut bufs, &mut self.headers)
    }

    #[inline]
    pub async fn recv(&mut self) -> io::Result<usize> {
        core::future::poll_fn(|cx| self.poll_recv(cx)).await
    }
}
