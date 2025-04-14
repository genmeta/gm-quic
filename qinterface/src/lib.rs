// handy（qudp）是可选的
pub mod factory;
pub mod handy;
pub mod packet;
pub mod queue;
pub mod router;
pub mod util;

use std::{
    io,
    net::SocketAddr,
    task::{Context, Poll},
};

use bytes::BytesMut;
use qbase::net::route::PacketHeader;

pub trait QuicInterface: Send + Sync {
    fn local_addr(&self) -> io::Result<SocketAddr>;

    fn max_segment_size(&self) -> usize;

    fn max_segments(&self) -> usize;

    fn poll_send(
        &self,
        cx: &mut Context,
        pkts: &[io::IoSlice],
        hdr: PacketHeader,
    ) -> Poll<io::Result<usize>>;

    fn poll_recv(
        &self,
        cx: &mut Context,
        pkts: &mut Vec<BytesMut>,
        hdrs: &mut [PacketHeader],
    ) -> Poll<io::Result<usize>>;
}
