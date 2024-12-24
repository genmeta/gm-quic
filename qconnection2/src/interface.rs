use std::{
    io, net,
    task::{Context, Poll},
};

use super::path;

pub trait QuicInteraface: Send + Sync {
    fn poll_send(
        &self,
        cx: &mut Context,
        pkt: &[u8],
        way: path::Pathway,
        dst: net::SocketAddr,
    ) -> Poll<io::Result<()>>;

    fn new_packet(&self, way: path::Pathway) -> bytes::BytesMut;

    fn poll_recv(&self, cx: &mut Context) -> Poll<io::Result<(bytes::BytesMut, path::Pathway)>>;
}
