pub mod data;
pub mod handshake;
pub mod initial;
mod util;

use std::future::Future;

pub use data::{ClosingOneRttScope, DataSpace};
pub use handshake::{ClosingHandshakeScope, HandshakeSpace};
pub use initial::InitialSpace;
use qbase::{
    frame::{Frame, FrameReader},
    packet::{decrypt::decrypt_packet, header::GetType, DataPacket},
};
use tokio::sync::Notify;

pub trait RecvPacket {
    fn has_rcvd_ccf(&self, packet: DataPacket) -> bool;

    fn decrypt_and_parse(
        key: &dyn rustls::quic::PacketKey,
        pn: u64,
        mut packet: DataPacket,
        body_offset: usize,
    ) -> bool {
        decrypt_packet(key, pn, packet.bytes.as_mut(), body_offset).unwrap();
        let body = packet.bytes.split_off(body_offset);
        FrameReader::new(body.freeze(), packet.header.get_type())
            .filter_map(|frame| frame.ok())
            .any(|(f, _)| matches!(f, Frame::Close(_)))
    }
}

async fn any<F, T>(fut: F, notify: &Notify) -> Option<T>
where
    F: Future<Output = Option<T>>,
{
    tokio::select! {
        _ = notify.notified() => None,
        v = fut => v,
    }
}

pub type RcvdBundle<H> = (
    (H, bytes::BytesMut, usize),
    crate::path::Pathway,
    crate::usc::ArcUsc,
);
