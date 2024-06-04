use bytes::Bytes;
use socket2::{Domain, Socket, Type};
use std::task::ready;
use std::task::Poll;
use std::{io, net::SocketAddr, task::Context};
use tokio::io::Interest;
use unix::config;
use unix::recv;
use unix::send;
use unix::set_socket_option;
use unix::DEFAULT_TTL;

mod cmsg;
mod msg;
mod unix;

pub struct SendMeta {
    pub dest_addr: SocketAddr,
    pub ttl: u8,
    pub buf: Bytes,
    pub ecn: Option<u8>,
    // The segment size if this transmission contains multiple datagrams.
    // This is `None` if the transmit only contains a single datagram
    pub segment_size: Option<usize>,
}

pub struct RecvMeta {
    pub src_addr: SocketAddr,
    pub ttl: u8,
    pub len: usize,
}

pub struct UdpSocketController {
    pub io: tokio::net::UdpSocket,
    pub ttl: u8,
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
        config(&socket).expect("Failed to config socket");
        let io =
            tokio::net::UdpSocket::from_std(socket.into()).expect("Failed to create tokio socket");

        Self {
            ttl: DEFAULT_TTL as u8,
            io,
        }
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
            set_socket_option(&self.io, libc::IPPROTO_IP, libc::IP_TTL, ttl as i32)?;
        } else {
            set_socket_option(
                &self.io,
                libc::IPPROTO_IPV6,
                libc::IPV6_UNICAST_HOPS,
                ttl as i32,
            )?;
        }
        self.ttl = ttl;
        Ok(())
    }

    pub fn poll_send(
        &mut self,
        cx: &mut Context,
        packets: &[SendMeta],
        ttl: u8,
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_send_ready(cx))?;
            self.set_ttl(ttl).expect("set ttl error");
            if let Ok(res) = self.io.try_io(Interest::WRITABLE, || {
                send(socket2::SockRef::from(&self.io), packets)
            }) {
                return Poll::Ready(Ok(res));
            }
        }
    }

    pub fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            if let Ok(res) = self.io.try_io(Interest::READABLE, || {
                recv(socket2::SockRef::from(&self.io), &mut bufs[0], &mut meta[0])
            }) {
                return Poll::Ready(Ok(res));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
