use msg::Cmsg;
use socket2::{Domain, Socket, Type};
use std::io::IoSlice;
use std::io::IoSliceMut;
use std::sync::Arc;
use std::sync::Mutex;
use std::task::ready;
use std::task::Poll;
use std::{io, net::SocketAddr, task::Context};
use tokio::io::Interest;
use unix::DEFAULT_TTL;
mod msg;
mod unix;

#[derive(Clone)]
pub struct SendHeader {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub ttl: u8,
    pub ecn: Option<u8>,
    // gso segment size
    pub seg_size: Option<u16>,
}

impl Default for SendHeader {
    fn default() -> Self {
        Self {
            src: SocketAddr::from(([0, 0, 0, 0], 0)),
            dst: SocketAddr::from(([0, 0, 0, 0], 0)),
            ttl: DEFAULT_TTL as u8,
            ecn: None,
            seg_size: None,
        }
    }
}
#[derive(Clone, Debug)]
pub struct RecvHeader {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub ttl: u8,
    pub seg_size: usize,
    pub ecn: Option<u8>,
}

impl Default for RecvHeader {
    fn default() -> Self {
        Self {
            // empty address
            src: SocketAddr::from(([0, 0, 0, 0], 0)),
            dst: SocketAddr::from(([0, 0, 0, 0], 0)),
            ttl: DEFAULT_TTL as u8,
            seg_size: 0,
            ecn: None,
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
        };
        socket.config().expect("Failed to config socket");
        socket
    }

    fn loacl_address(&self) -> SocketAddr {
        self.io.local_addr().expect("Failed to get local address")
    }

    fn set_ttl(&mut self, ttl: u8) -> io::Result<()> {
        if self.ttl == ttl {
            return Ok(());
        }

        if self.loacl_address().is_ipv4() {
            self.set_socket_option(libc::IPPROTO_IP, libc::IP_TTL, ttl as i32)?;
        } else {
            self.set_socket_option(libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS, ttl as i32)?;
        }
        self.ttl = ttl;
        Ok(())
    }
}

trait Io {
    fn config(&mut self) -> io::Result<()>;

    fn sendmsg(&self, bufs: &mut [IoSlice<'_>], hdr: &SendHeader) -> io::Result<usize>;

    fn recvmsg(&self, bufs: &mut [IoSliceMut<'_>], hdr: &mut [RecvHeader]) -> io::Result<usize>;

    fn set_socket_option(
        &self,
        level: libc::c_int,
        name: libc::c_int,
        value: libc::c_int,
    ) -> Result<(), io::Error>;
}

trait Gso: Io {
    fn max_gso_segments(&self) -> usize;

    fn set_segment_size(encoder: &mut Cmsg, segment_size: u16);
}

trait Gro: Io {
    fn max_gro_segments(&self) -> usize;
}

#[derive(Debug, Clone)]
pub struct ArcController(Arc<Mutex<UdpSocketController>>);

impl ArcController {
    pub fn new(addr: SocketAddr) -> Self {
        Self(Arc::new(Mutex::new(UdpSocketController::new(addr))))
    }

    pub fn poll_send(
        &self,
        bufs: &mut [IoSlice<'_>],
        hdr: &SendHeader,
        cx: &mut Context,
    ) -> Poll<io::Result<usize>> {
        let contorler = self.0.lock().unwrap();
        ready!(contorler.io.poll_send_ready(cx))?;
        let ret = contorler
            .io
            .try_io(Interest::WRITABLE, || contorler.sendmsg(bufs, hdr));

        Poll::Ready(ret)
    }

    pub fn poll_recv(
        &self,
        bufs: &mut [IoSliceMut<'_>],
        hdrs: &mut [RecvHeader],
        cx: &mut Context,
    ) -> Poll<io::Result<usize>> {
        loop {
            let contorler = self.0.lock().unwrap();
            ready!(contorler.io.poll_recv_ready(cx))?;
            if let Ok(res) = contorler
                .io
                .try_io(Interest::READABLE, || contorler.recvmsg(bufs, hdrs))
            {
                return Poll::Ready(Ok(res));
            }
        }
    }

    pub fn ttl(&self) -> u8 {
        self.0.lock().unwrap().ttl
    }

    pub fn set_ttl(&self, ttl: u8) -> io::Result<()> {
        self.0.lock().unwrap().set_ttl(ttl)
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.0.lock().unwrap().loacl_address()
    }
}
