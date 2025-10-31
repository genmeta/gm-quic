use std::{
    collections::VecDeque,
    future::Future,
    io::{self, IoSlice, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex, atomic::AtomicI32},
    task::{Context, Poll, Wake, Waker, ready},
};

use bytes::BytesMut;
use socket2::{Domain, Socket, Type};
use tokio::io::Interest;
pub const DEFAULT_TTL: libc::c_int = 64;
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
pub struct DatagramHeader {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub ttl: u8,
    // Explicit congestion notification (ECN)
    pub ecn: Option<u8>,
    // packet segment size
    pub seg_size: u16,
}

impl DatagramHeader {
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

impl Default for DatagramHeader {
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
    read: Arc<Wakers>,
    write: Arc<Wakers>,
    ttl: AtomicI32,
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
        let usc = Self {
            io,
            read: Default::default(),
            write: Default::default(),
            ttl: AtomicI32::new(DEFAULT_TTL),
        };
        Ok(usc)
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    pub fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.write.register(cx.waker());
        self.io
            .poll_send_ready(&mut Context::from_waker(&self.write.clone().into()))
    }

    pub fn poll_recv_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.read.register(cx.waker());
        self.io
            .poll_recv_ready(&mut Context::from_waker(&self.read.clone().into()))
    }

    pub fn poll_send(
        &self,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
        hdr: &DatagramHeader,
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.poll_send_ready(cx))?;
            self.set_ttl(hdr.ttl as i32)?;
            match self
                .io
                .try_io(Interest::WRITABLE, || self.sendmsg(bufs, hdr))
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
        hdrs: &mut [DatagramHeader],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.poll_recv_ready(cx)?);
            let f = || self.recvmsg(bufs, hdrs);
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

#[derive(Default, Debug)]
struct Wakers(Mutex<VecDeque<Waker>>);

impl Wakers {
    fn register(&self, waker: &Waker) {
        self.0.lock().unwrap().push_back(waker.clone());
    }
}

impl Wake for Wakers {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        for waker in self.0.lock().unwrap().drain(..) {
            waker.wake_by_ref();
        }
    }
}

impl Drop for UdpSocketController {
    fn drop(&mut self) {
        self.read.wake_by_ref();
        self.write.wake_by_ref();
    }
}

pub trait Io {
    fn config(io: &socket2::Socket, addr: SocketAddr) -> io::Result<()>;

    fn sendmsg(&self, bufs: &[IoSlice<'_>], hdr: &DatagramHeader) -> io::Result<usize>;

    fn recvmsg(&self, bufs: &mut [IoSliceMut<'_>], hdr: &mut [DatagramHeader])
    -> io::Result<usize>;

    fn set_ttl(&self, ttl: i32) -> io::Result<()>;
}

impl UdpSocketController {
    pub fn send<'a>(&'a self, iovecs: &'a [IoSlice<'a>], header: DatagramHeader) -> Send<'a> {
        Send {
            usc: self,
            iovecs,
            header,
        }
    }

    pub fn receiver(&self) -> Receiver<'_> {
        Receiver {
            usc: self,
            iovecs: (0..BATCH_SIZE)
                .map(|_| {
                    let mut buf = BytesMut::with_capacity(1500);
                    buf.resize(1500, 0);
                    buf
                })
                .collect::<Vec<_>>(),
            headers: (0..BATCH_SIZE)
                .map(|_| DatagramHeader::default())
                .collect::<Vec<_>>(),
        }
    }
}

pub struct Send<'a> {
    pub usc: &'a UdpSocketController,
    pub iovecs: &'a [IoSlice<'a>],
    pub header: DatagramHeader,
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
    pub iovecs: Vec<BytesMut>,
    pub headers: Vec<DatagramHeader>,
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
