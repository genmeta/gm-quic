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

use qbase::net::route::PacketHeader;

pub trait QuicInterface: Send + Sync {
    fn local_addr(&self) -> io::Result<SocketAddr>;

    fn max_segment_size(&self) -> usize;

    fn max_segments(&self) -> usize;

    fn poll_send(
        &self,
        cx: &mut Context,
        ptks: &[io::IoSlice],
        hdr: PacketHeader,
    ) -> Poll<io::Result<usize>>;

    fn poll_recv(
        &self,
        cx: &mut Context,
        pkts: &mut [io::IoSliceMut],
        hdrs: &mut [PacketHeader],
    ) -> Poll<io::Result<usize>>;
}
