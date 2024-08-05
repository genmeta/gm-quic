use std::{
    collections::VecDeque,
    future::Future,
    io::{self, IoSlice, IoSliceMut},
    net::SocketAddr,
    sync::{Arc, Mutex},
    task::{ready, Context, Poll},
};

use msg::Encoder;
use socket2::{Domain, Socket, Type};
use tokio::io::Interest;
use unix::DEFAULT_TTL;
mod msg;
pub mod unix;

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
pub const BATCH_SIZE: usize = 64;

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub const BATCH_SIZE: usize = 1;

const BUFFER_CAPACITY: usize = 5;

#[derive(Clone, Copy, Debug)]
pub struct PacketHeader {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub ttl: u8,
    pub ecn: Option<u8>,
    pub seg_size: u16,
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

#[derive(PartialEq, Eq, Debug, Default)]
enum OffloadStatus {
    #[default]
    Unknown,
    Unsupported,
    Supported(u16),
}

#[derive(Debug)]
struct UdpSocketController {
    io: tokio::net::UdpSocket,
    ttl: u8,
    gso_size: OffloadStatus,
    gro_size: OffloadStatus,
    bufs: VecDeque<(Vec<u8>, PacketHeader)>,
}

impl UdpSocketController {
    fn new(addr: SocketAddr) -> Self {
        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };

        let socket = Socket::new(domain, Type::DGRAM, None).expect("Failed to create socket");
        socket.bind(&addr.into()).expect("Failed to bind socket");

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
        socket
    }

    fn local_addr(&self) -> SocketAddr {
        self.io.local_addr().expect("Failed to get local address")
    }

    fn set_ttl(&mut self, ttl: u8) -> io::Result<()> {
        if self.ttl == ttl {
            return Ok(());
        }

        if self.local_addr().is_ipv4() {
            self.setsockopt(libc::IPPROTO_IP, libc::IP_TTL, ttl as i32);
        } else {
            self.setsockopt(libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS, ttl as i32);
        }
        self.ttl = ttl;
        Ok(())
    }
}

trait Io {
    fn config(&mut self) -> io::Result<()>;

    fn sendmsg(&self, bufs: &[IoSlice<'_>], hdr: &PacketHeader) -> io::Result<usize>;

    fn recvmsg(&self, bufs: &mut [IoSliceMut<'_>], hdr: &mut [PacketHeader]) -> io::Result<usize>;

    fn setsockopt(&self, level: libc::c_int, name: libc::c_int, value: libc::c_int);
}

trait Gso: Io {
    fn max_gso_segments(&self) -> usize;

    fn set_segment_size(encoder: &mut Encoder, segment_size: u16);
}

trait Gro: Io {
    fn max_gro_segments(&self) -> usize;
}

#[derive(Debug, Clone)]
pub struct ArcUsc(Arc<Mutex<UdpSocketController>>);

impl ArcUsc {
    pub fn new(addr: SocketAddr) -> Self {
        Self(Arc::new(Mutex::new(UdpSocketController::new(addr))))
    }

    pub fn poll_send(
        &self,
        bufs: &[IoSlice<'_>],
        hdr: &PacketHeader,
        cx: &mut Context,
    ) -> Poll<io::Result<usize>> {
        let controller = self.0.lock().unwrap();
        ready!(controller.io.poll_send_ready(cx))?;
        let ret = controller
            .io
            .try_io(Interest::WRITABLE, || controller.sendmsg(bufs, hdr));

        Poll::Ready(ret)
    }

    pub fn poll_recv(
        &self,
        bufs: &mut [IoSliceMut<'_>],
        hdrs: &mut [PacketHeader],
        cx: &mut Context,
    ) -> Poll<io::Result<usize>> {
        let controller = self.0.lock().unwrap();
        ready!(controller.io.poll_recv_ready(cx))?;
        let ret = controller
            .io
            .try_io(Interest::READABLE, || controller.recvmsg(bufs, hdrs));
        Poll::Ready(ret)
    }

    pub fn ttl(&self) -> u8 {
        self.0.lock().unwrap().ttl
    }

    pub fn set_ttl(&self, ttl: u8) -> io::Result<()> {
        self.0.lock().unwrap().set_ttl(ttl)
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.0.lock().unwrap().local_addr()
    }

    //Send synchronously, usc saves a small amount of data packets,and USC sends internal asynchronous tasks
    pub fn sync_send(&self, packet: Vec<u8>, hdr: PacketHeader) -> io::Result<()> {
        let mut guard = self.0.lock().unwrap();
        if guard.bufs.len() >= BUFFER_CAPACITY {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "buffer full"));
        }
        guard.bufs.push_back((packet, hdr));
        if guard.bufs.len() == 1 {
            tokio::spawn({
                let usc = self.clone();
                async move {
                    let send_guard = SendGuard(usc);
                    while (send_guard.clone().await).is_ok() {}
                }
            });
        }
        Ok(())
    }

    pub fn sender<'a>(&self, iovecs: &'a [IoSlice<'a>], hdr: PacketHeader) -> Sender<'a> {
        Sender {
            usc: self.clone(),
            iovecs,
            hdr,
        }
    }
}

pub struct Sender<'a> {
    pub usc: ArcUsc,
    pub iovecs: &'a [IoSlice<'a>],
    pub hdr: PacketHeader,
}

impl<'a> Future for Sender<'a> {
    type Output = io::Result<usize>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let usc = self.usc.0.lock().unwrap();
        ready!(usc.io.poll_send_ready(cx))?;
        let ret = usc
            .io
            .try_io(Interest::WRITABLE, || usc.sendmsg(self.iovecs, &self.hdr));

        Poll::Ready(ret)
    }
}

#[derive(Clone)]
pub struct SendGuard(ArcUsc);

impl Future for SendGuard {
    type Output = io::Result<usize>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut usc = self.0 .0.lock().unwrap();
        if let Some((pkt, hdr)) = usc.bufs.pop_front() {
            ready!(usc.io.poll_send_ready(cx))?;
            let ret = usc.io.try_io(Interest::WRITABLE, || {
                usc.sendmsg(&[IoSlice::new(&pkt)], &hdr)
            })?;

            Poll::Ready(Ok(ret))
        } else {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "buffer empty",
            )))
        }
    }
}
