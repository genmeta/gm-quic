use std::{
    collections::VecDeque,
    future::Future,
    io::{self, IoSlice, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
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
const BUFFER_CAPACITY: usize = 5;

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

// [`OffloadStatus`] is an enumeration that represents the status of offload features
#[derive(PartialEq, Eq, Debug, Default)]
#[allow(dead_code)]
enum OffloadStatus {
    #[default]
    Unknown,
    Unsupported,
    Supported(u16),
}

#[derive(Debug)]
#[allow(dead_code)]
struct UdpSocketController {
    io: tokio::net::UdpSocket,
    ttl: u8,
    gso_size: OffloadStatus,
    gro_size: OffloadStatus,
    bufs: VecDeque<(Vec<u8>, PacketHeader)>,
}

impl UdpSocketController {
    fn new(addr: SocketAddr) -> io::Result<Self> {
        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };

        let socket = Socket::new(domain, Type::DGRAM, None).expect("Failed to create socket");
        if let Err(e) = socket.bind(&addr.into()) {
            log::error!("Failed to bind socket: {}", e);
            return Err(io::Error::new(io::ErrorKind::AddrInUse, e));
        }

        let io =
            tokio::net::UdpSocket::from_std(socket.into()).expect("Failed to create tokio socket");

        let mut socket = Self {
            ttl: DEFAULT_TTL as u8,
            io,
            gso_size: OffloadStatus::Unknown,
            gro_size: OffloadStatus::Unknown,
            bufs: VecDeque::with_capacity(BUFFER_CAPACITY),
        };
        socket.config().expect("Failed to config socket");
        Ok(socket)
    }

    fn local_addr(&self) -> SocketAddr {
        self.io.local_addr().expect("Failed to get local address")
    }

    fn poll_send(
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
    fn config(&mut self) -> io::Result<()>;

    fn sendmsg(&self, bufs: &[IoSlice<'_>], hdr: &PacketHeader) -> io::Result<usize>;

    fn recvmsg(&self, bufs: &mut [IoSliceMut<'_>], hdr: &mut [PacketHeader]) -> io::Result<usize>;

    fn setsockopt(&self, level: libc::c_int, name: libc::c_int, value: libc::c_int);

    fn set_ttl(&mut self, ttl: u8) -> io::Result<()>;
}

#[derive(Debug, Clone)]
pub struct ArcUsc(Arc<Mutex<Result<UdpSocketController, io::Error>>>);

impl ArcUsc {
    pub fn new(addr: SocketAddr) -> io::Result<Self> {
        UdpSocketController::new(addr).map(|io| Self(Arc::new(Mutex::new(Ok(io)))))
    }

    pub fn close(&self, error: io::Error) {
        let mut guard = self.0.lock().unwrap();
        *guard = Err(error);
    }

    pub fn poll_send(
        &self,
        bufs: &[IoSlice<'_>],
        hdr: &PacketHeader,
        cx: &mut Context,
    ) -> Poll<io::Result<usize>> {
        let mut guard = self.0.lock().unwrap();
        let controller = guard
            .as_mut()
            .map_err(|e| io::Error::new(e.kind(), e.to_string()))?;
        controller.poll_send(bufs, hdr, cx).map_err(|e| {
            let e_clone = io::Error::new(e.kind(), e.to_string());
            *guard = Err(e);
            e_clone
        })
    }

    pub fn poll_recv(
        &self,
        bufs: &mut [IoSliceMut<'_>],
        hdrs: &mut [PacketHeader],
        cx: &mut Context,
    ) -> Poll<io::Result<usize>> {
        let mut guard = self.0.lock().unwrap();
        let controller = guard
            .as_mut()
            .map_err(|e| io::Error::new(e.kind(), e.to_string()))?;
        controller.poll_recv(bufs, hdrs, cx).map_err(|e| {
            let e_clone = io::Error::new(e.kind(), e.to_string());
            *guard = Err(e);
            e_clone
        })
    }

    fn map_lock<T>(&self, f: impl FnOnce(&mut UdpSocketController) -> T) -> io::Result<T> {
        let mut guard = self.0.lock().unwrap();
        guard
            .as_mut()
            .map_err(|e| io::Error::new(e.kind(), e.to_string()))
            .map(f)
    }
    pub fn ttl(&self) -> io::Result<u8> {
        self.map_lock(|controller| controller.ttl)
    }

    pub fn set_ttl(&self, ttl: u8) -> io::Result<()> {
        self.map_lock(|controller| controller.set_ttl(ttl))?
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.map_lock(|controller| controller.local_addr())
    }

    // Send synchronously, usc saves a small amount of data packets,and USC sends internal asynchronous tasks
    pub fn sync_send(&self, packet: Vec<u8>, hdr: &PacketHeader) -> io::Result<()> {
        self.map_lock(|controller| {
            if controller.bufs.len() >= BUFFER_CAPACITY {
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "buffer full"));
            }
            controller.bufs.push_back((packet, *hdr));
            if controller.bufs.len() == 1 {
                let arc_usc = self.clone();
                tokio::spawn(SyncSend(arc_usc));
            }

            Ok(())
        })?
    }

    pub fn send<'a>(&'a self, iovecs: &'a [IoSlice<'a>], header: PacketHeader) -> Send<'a> {
        Send {
            usc: self.clone(),
            iovecs,
            header,
        }
    }

    pub fn receiver(&self) -> Receiver {
        Receiver {
            usc: self.clone(),
            iovecs: (0..BATCH_SIZE)
                .map(|_| [0u8; 1500].to_vec())
                .collect::<Vec<_>>(),
            headers: (0..BATCH_SIZE)
                .map(|_| PacketHeader::default())
                .collect::<Vec<_>>(),
        }
    }
}

impl Drop for ArcUsc {
    fn drop(&mut self) {
        // current usc + usc in task
        if Arc::strong_count(&self.0) == 2 {
            let mut guard = self.0.lock().unwrap();
            if guard.is_ok() {
                *guard = Err(io::Error::new(io::ErrorKind::Other, "usc shutdown"));
            }
        }
    }
}

#[derive(Clone)]
struct SyncSend(ArcUsc);

impl Future for SyncSend {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut guard = self.0 .0.lock().unwrap();
        let controller = guard
            .as_mut()
            .map_err(|e| io::Error::new(e.kind(), e.to_string()))?;
        let Some((packet, header)) = controller.bufs.pop_front() else {
            return Poll::Ready(Ok(()));
        };
        ready!(controller.poll_send(&[IoSlice::new(&packet)], &header, cx)?);
        Poll::Ready(Ok(()))
    }
}

pub struct Send<'a> {
    pub usc: ArcUsc,
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

pub struct Receiver {
    pub usc: ArcUsc,
    pub iovecs: Vec<Vec<u8>>,
    pub headers: Vec<PacketHeader>,
}

impl Receiver {
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
