// handy（qudp）是可选的
pub mod handy;
pub mod path;
pub mod queue;
pub mod router;
pub mod util;

use std::{
    io,
    net::SocketAddr,
    task::{Context, Poll},
};

use bytes::BytesMut;
use path::{Link, Pathway};

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
