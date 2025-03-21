// handy（qudp）是可选的
pub mod handy;
pub mod queue;
pub mod router;
pub mod util;

use std::{
    io,
    net::SocketAddr,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::BytesMut;
use qbase::net::route::{Link, Pathway};

pub trait QuicInterface: Send + Sync {
    fn reversed_bytes(&self, on: Pathway) -> io::Result<usize>;

    fn local_addr(&self) -> io::Result<SocketAddr>;

    fn max_segment_size(&self) -> io::Result<usize>;

    fn max_segments(&self) -> io::Result<usize>;

    fn poll_send(
        &self,
        cx: &mut Context,
        ptks: &[io::IoSlice],
        way: Pathway,
        dst: SocketAddr,
    ) -> Poll<io::Result<usize>>;

    fn poll_recv(&self, cx: &mut Context) -> Poll<io::Result<(BytesMut, Pathway, Link)>>;
}

impl<Qi: ?Sized + QuicInterface> QuicInterface for Arc<Qi> {
    #[inline]
    fn reversed_bytes(&self, on: Pathway) -> io::Result<usize> {
        self.as_ref().reversed_bytes(on)
    }

    #[inline]
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.as_ref().local_addr()
    }

    #[inline]
    fn max_segment_size(&self) -> io::Result<usize> {
        self.as_ref().max_segment_size()
    }

    #[inline]
    fn max_segments(&self) -> io::Result<usize> {
        self.as_ref().max_segments()
    }

    #[inline]
    fn poll_send(
        &self,
        cx: &mut Context,
        ptks: &[io::IoSlice],
        way: Pathway,
        dst: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        self.as_ref().poll_send(cx, ptks, way, dst)
    }

    #[inline]
    fn poll_recv(&self, cx: &mut Context) -> Poll<io::Result<(BytesMut, Pathway, Link)>> {
        self.as_ref().poll_recv(cx)
    }
}
