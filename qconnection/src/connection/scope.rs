pub mod data;
pub mod handshake;
pub mod initial;

pub use data::{ClosingOneRttScope, DataScope};
pub use handshake::{ClosingHandshakeScope, HandshakeScope};
pub use initial::InitialScope;
use qbase::{
    frame::{Frame, FrameReader},
    packet::{decrypt::decrypt_packet, header::GetType, DataPacket},
};

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
            .map(|(f, _)| matches!(f, Frame::Close(_)))
            .fold(false, |sum, v| sum || v)
    }
}
