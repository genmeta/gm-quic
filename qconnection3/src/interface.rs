// handy（qudp）是可选的
#[cfg(feature = "handy_quic_interface")]
pub mod handy;

use std::{
    io, net,
    task::{Context, Poll},
};

use crate::path;

pub struct SendCapability {
    // 一个数据报最大多大
    pub segment_size: u16,
    // 一个数据报的前多少字节应该保留
    pub reversed_size: u16,
    // 指示对GSO的支持
    pub segments: u16,
}

pub trait QuicInterface {
    fn send_capability(&self, on: path::Pathway) -> io::Result<SendCapability>;

    fn poll_send(
        &self,
        cx: &mut Context,
        ptks: &[io::IoSlice],
        way: path::Pathway,
        dst: net::SocketAddr,
    ) -> Poll<io::Result<usize>>;

    fn poll_recv(&self, cx: &mut Context) -> Poll<io::Result<(bytes::BytesMut, path::Pathway)>>;
}
