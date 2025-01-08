pub mod conn;
// handy（qudp）是可选的
#[cfg(feature = "qudp")]
pub mod handy;
pub mod path;
pub mod router;

use std::{
    io,
    net::SocketAddr,
    task::{Context, Poll},
};

use bytes::BytesMut;
use path::Pathway;

pub struct SendCapability {
    // 一个数据报最大多大
    pub max_segment_size: u16,
    // 一个数据报的前多少字节应该保留
    pub reversed_size: u16,
    // 指示对GSO的支持
    pub max_segments: u16,
}

pub trait QuicInterface: Send + Sync {
    fn send_capability(&self, on: Pathway) -> io::Result<SendCapability>;

    fn poll_send(
        &self,
        cx: &mut Context,
        ptks: &[io::IoSlice],
        way: Pathway,
        dst: SocketAddr,
    ) -> Poll<io::Result<usize>>;

    fn poll_recv(&self, cx: &mut Context) -> Poll<io::Result<(BytesMut, Pathway)>>;
}
