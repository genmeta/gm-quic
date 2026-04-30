use std::{
    future::Future,
    io::{self, IoSlice, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::atomic::AtomicI32,
    task::{Context, Poll, ready},
};

use bytes::BytesMut;
use qbase::net::route::Line;
use socket2::{Domain, Socket, Type};
use tokio::io::Interest;
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

#[derive(Debug)]
pub struct UdpSocket {
    io: tokio::net::UdpSocket,
    ttl: AtomicI32,
}

impl UdpSocket {
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
        let usc = Self {
            io,
            ttl: AtomicI32::new(Line::DEFAULT_TTL as i32),
        };
        Ok(usc)
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    pub fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.io.poll_send_ready(cx)
    }

    pub fn poll_recv_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.io.poll_recv_ready(cx)
    }

    pub fn poll_send(
        &self,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
        line: &Line,
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.poll_send_ready(cx))?;
            self.set_ttl(line.ttl as i32)?;
            match self
                .io
                .try_io(Interest::WRITABLE, || self.sendmsg(bufs, line))
            {
                Ok(n) => return Poll::Ready(Ok(n)),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    pub fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        lines: &mut [Line],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.poll_recv_ready(cx)?);
            let f = || self.recvmsg(bufs, lines);
            let ret = self.io.try_io(Interest::READABLE, f);
            if matches!(&ret, Err(e) if e.kind() == io::ErrorKind::WouldBlock) {
                continue;
            } else {
                return Poll::Ready(ret);
            }
        }
    }

    #[allow(unreachable_code)]
    pub fn bind_device(&self, _device: &str) -> io::Result<()> {
        // #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        // android and linux support bind_device_by_index, which is called by codes below
        #[cfg(target_os = "fuchsia")]
        {
            let socket = socket2::SockRef::from(&self.io);
            return socket.bind_device(Some(_device.as_bytes()));
        }
        #[cfg(any(
            target_os = "ios",
            target_os = "visionos",
            target_os = "macos",
            target_os = "tvos",
            target_os = "watchos",
            target_os = "illumos",
            target_os = "solaris",
            target_os = "linux",
            target_os = "android",
        ))]
        {
            let socket = socket2::SockRef::from(&self.io);
            let index = nix::net::if_::if_nametoindex(_device)?;
            let index = std::num::NonZeroU32::new(index)
                .expect("Already checked by nix::net::if_::if_nametoindex");
            match self.io.local_addr()? {
                SocketAddr::V4(..) => socket.bind_device_by_index_v4(Some(index))?,
                SocketAddr::V6(..) => socket.bind_device_by_index_v6(Some(index))?,
            }
            return Ok(());
        }
        Ok(())
    }
}

pub trait Io {
    fn config(io: &socket2::Socket, addr: SocketAddr) -> io::Result<()>;

    fn sendmsg(&self, bufs: &[IoSlice<'_>], line: &Line) -> io::Result<usize>;

    fn recvmsg(&self, bufs: &mut [IoSliceMut<'_>], line: &mut [Line]) -> io::Result<usize>;

    fn set_ttl(&self, ttl: i32) -> io::Result<()>;
}

impl UdpSocket {
    pub fn send<'a>(&'a self, iovecs: &'a [IoSlice<'a>], line: Line) -> Send<'a> {
        Send {
            socket: self,
            iovecs,
            line,
        }
    }

    pub fn receiver(&self) -> Receiver<'_> {
        Receiver {
            socket: self,
            iovecs: (0..BATCH_SIZE)
                .map(|_| {
                    let mut buf = BytesMut::with_capacity(1500);
                    buf.resize(1500, 0);
                    buf
                })
                .collect::<Vec<_>>(),
            lines: (0..BATCH_SIZE).map(|_| Line::default()).collect::<Vec<_>>(),
        }
    }
}

pub struct Send<'a> {
    pub socket: &'a UdpSocket,
    pub iovecs: &'a [IoSlice<'a>],
    pub line: Line,
}

impl Future for Send<'_> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.socket.poll_send(cx, this.iovecs, &this.line)
    }
}

pub struct Receiver<'u> {
    pub socket: &'u UdpSocket,
    pub iovecs: Vec<BytesMut>,
    pub lines: Vec<Line>,
}

impl Receiver<'_> {
    #[inline]
    pub fn poll_recv(&mut self, cx: &mut Context) -> Poll<io::Result<usize>> {
        let mut bufs = self
            .iovecs
            .iter_mut()
            .map(|b| IoSliceMut::new(b))
            .collect::<Vec<_>>();

        self.socket.poll_recv(cx, &mut bufs, &mut self.lines)
    }

    #[inline]
    pub async fn recv(&mut self) -> io::Result<usize> {
        core::future::poll_fn(|cx| self.poll_recv(cx)).await
    }
}
