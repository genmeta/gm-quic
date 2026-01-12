use std::{
    io::{self},
    net::SocketAddr,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::BytesMut;
use qbase::net::{addr::BindUri, route::SocketEndpointAddr};
use qinterface::{QuicIO, logical::QuicInterface};

use crate::{Link, iface::TraversalQuicInterface};

pub mod client;
mod msg;
pub mod protocol;
pub mod server;
pub mod tx;

pub trait StunIO: Send + Sync {
    fn local_addr(&self) -> io::Result<SocketAddr>;

    fn poll_stun_send(
        &self,
        cx: &mut std::task::Context<'_>,
        packet: BytesMut,
        link: Link,
    ) -> Poll<io::Result<usize>>;

    fn poll_stun_recv(&self, cx: &mut std::task::Context<'_>)
    -> Poll<io::Result<(BytesMut, Link)>>;

    fn stun_bind_uri(&self) -> BindUri;

    fn poll_endpoint_addr(&self, cx: &mut Context) -> Poll<io::Result<SocketEndpointAddr>> {
        _ = cx;
        Poll::Ready(Err(io::Error::other("not implemented endpoint_addr")))
    }

    fn poll_nat_type(&self, cx: &mut Context) -> Poll<io::Result<u8>> {
        _ = cx;
        Poll::Ready(Err(io::Error::other("not implemented nat_type")))
    }

    fn stun_protocol(&self) -> io::Result<Arc<protocol::StunProtocol>> {
        Err(io::Error::other("not implemented stun_protocol"))
    }
}

impl StunIO for QuicInterface {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.real_addr().and_then(|addr| match addr {
            qbase::net::addr::RealAddr::Internet(inet) => Ok(inet),
            _ => Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "not an internet address",
            )),
        })
    }

    fn poll_stun_send(
        &self,
        cx: &mut std::task::Context<'_>,
        packet: BytesMut,
        link: Link,
    ) -> Poll<io::Result<usize>> {
        self.borrow(|io| {
            if let Some(stun_io) = io.as_any().downcast_ref::<TraversalQuicInterface>() {
                stun_io.poll_stun_send(cx, packet, link)
            } else {
                Poll::Ready(Err(io::Error::other("Not a TraversalQuicInterface")))
            }
        })
        .unwrap_or_else(|e| Poll::Ready(Err(e)))
    }

    fn poll_stun_recv(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<(BytesMut, Link)>> {
        self.borrow(|io| {
            if let Some(stun_io) = io.as_any().downcast_ref::<TraversalQuicInterface>() {
                stun_io.poll_stun_recv(cx)
            } else {
                Poll::Ready(Err(io::Error::other("Not a TraversalQuicInterface")))
            }
        })
        .unwrap_or_else(|e| Poll::Ready(Err(e)))
    }

    fn stun_bind_uri(&self) -> BindUri {
        self.bind_uri()
    }

    fn poll_endpoint_addr(&self, cx: &mut Context) -> Poll<io::Result<SocketEndpointAddr>> {
        self.borrow(|io| {
            if let Some(stun_io) = io.as_any().downcast_ref::<TraversalQuicInterface>() {
                stun_io.poll_endpoint_addr(cx)
            } else {
                Poll::Ready(Err(io::Error::other("Not a TraversalQuicInterface")))
            }
        })
        .unwrap_or_else(|e| Poll::Ready(Err(e)))
    }

    fn poll_nat_type(&self, cx: &mut Context) -> Poll<io::Result<u8>> {
        self.borrow(|io| {
            if let Some(stun_io) = io.as_any().downcast_ref::<TraversalQuicInterface>() {
                stun_io.poll_nat_type(cx)
            } else {
                Poll::Ready(Err(io::Error::other("Not a TraversalQuicInterface")))
            }
        })
        .unwrap_or_else(|e| Poll::Ready(Err(e)))
    }

    fn stun_protocol(&self) -> io::Result<Arc<protocol::StunProtocol>> {
        self.borrow(|io| {
            if let Some(stun_io) = io.as_any().downcast_ref::<TraversalQuicInterface>() {
                stun_io.stun_protocol()
            } else {
                Err(io::Error::other("Not a TraversalQuicInterface"))
            }
        })
        .unwrap_or_else(Err)
    }
}
