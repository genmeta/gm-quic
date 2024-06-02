use msg::Cmsg;
use socket2::{Domain, Socket, Type};
use std::sync::Arc;
use std::sync::Mutex;
use std::task::ready;
use std::task::Poll;
use std::{io, net::SocketAddr, task::Context};
use tokio::io::Interest;
use unix::DEFAULT_TTL;
mod msg;
mod unix;

pub struct SendInfo {
    pub to: SocketAddr,
    pub from: SocketAddr,
    pub ttl: u8,
    pub ecn: Option<u8>,
    // gso segment size
    pub segment_size: Option<u16>,
}

pub struct RecvInfo {
    pub from: SocketAddr,
    pub to: SocketAddr,
    pub ttl: u8,
    pub len: usize,
    pub ecn: Option<u8>,
}

pub struct Sender(Arc<Mutex<UdpSocketController>>);

impl Sender {
    pub fn poll_send(
        &self,
        bufs: &mut std::io::IoSliceMut<'_>,
        send_info: &SendInfo,
        cx: &mut Context,
    ) -> Poll<io::Result<usize>> {
        loop {
            let contorler = self.0.lock().unwrap();
            match contorler.io.poll_send_ready(cx) {
                Poll::Ready(_) => {
                    if let Ok(res) = contorler
                        .io
                        .try_io(Interest::WRITABLE, || contorler.sendmsg(bufs, send_info))
                    {
                        return Poll::Ready(Ok(res));
                    }
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

pub struct Receiver(Arc<Mutex<UdpSocketController>>);

impl Receiver {
    pub fn poll_recv(
        &self,
        bufs: &mut [std::io::IoSliceMut<'_>],
        recv_infos: &mut [RecvInfo],
        cx: &mut Context,
    ) -> Poll<io::Result<usize>> {
        loop {
            let contorler = self.0.lock().unwrap();
            ready!(contorler.io.poll_recv_ready(cx))?;
            if let Ok(res) = contorler
                .io
                .try_io(Interest::READABLE, || contorler.recvmsg(bufs, recv_infos))
            {
                return Poll::Ready(Ok(res));
            }
        }
    }
}

pub struct UdpSocketController {
    pub io: tokio::net::UdpSocket,
    pub ttl: u8,
    pub max_gso_size: Option<u16>,
    pub gro_segments: Option<u16>,
}

impl UdpSocketController {
    pub fn new(addr: SocketAddr) -> Self {
        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };

        let socket = Socket::new(domain, Type::DGRAM, None).expect("Failed to create socket");
        socket.bind(&addr.into()).expect("Failed to bind socket");

        let io =
            tokio::net::UdpSocket::from_std(socket.into()).expect("Failed to create tokio socket");

        let socket = Self {
            ttl: DEFAULT_TTL as u8,
            io,
            max_gso_size: None,
            gro_segments: None,
        };
        socket.config().expect("Failed to config socket");
        socket
    }

    pub fn loacl_address(&self) -> SocketAddr {
        self.io.local_addr().expect("Failed to get local address")
    }

    pub fn loacl_port(&self) -> u16 {
        self.loacl_address().port()
    }

    pub fn set_ttl(&mut self, ttl: u8) -> io::Result<()> {
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

    pub fn split(self) -> (Sender, Receiver) {
        let arc = Arc::new(Mutex::new(self));
        (Sender(arc.clone()), Receiver(arc))
    }
}

// todo: 换个名字
trait Io {
    fn config(&self) -> io::Result<()>;

    fn sendmsg(&self, buf: &mut std::io::IoSliceMut<'_>, send_info: &SendInfo)
        -> io::Result<usize>;

    fn recvmsg(
        &self,
        bufs: &mut [std::io::IoSliceMut<'_>],
        recv_infos: &mut [RecvInfo],
    ) -> io::Result<usize>;

    fn set_socket_option(
        &self,
        level: libc::c_int,
        name: libc::c_int,
        value: libc::c_int,
    ) -> Result<(), io::Error>;
}

trait Gso {
    fn max_gso_segments(&self) -> usize;

    fn set_segment_size(encoder: &mut Cmsg, segment_size: usize);
}

pub trait Gro {
    fn gro_segments(&self) -> usize;
}
