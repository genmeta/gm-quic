use qbase::packet::{header::long, DataHeader, Packet};

use super::Pathway;
use crate::{
    space::{HandshakePacket, InitialPacket, OneRttPacket, ZeroRttPacket},
    util::bound_queue::BoundQueue,
};

pub struct PacketEntry {
    pub initial: BoundQueue<(InitialPacket, Pathway)>,
    pub handshake: BoundQueue<(HandshakePacket, Pathway)>,
    pub zero_rtt: BoundQueue<(ZeroRttPacket, Pathway)>,
    pub one_rtt: BoundQueue<(OneRttPacket, Pathway)>,
    // pub retry:
}

impl Default for PacketEntry {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketEntry {
    pub fn new() -> Self {
        Self {
            initial: BoundQueue::new(16),
            handshake: BoundQueue::new(16),
            zero_rtt: BoundQueue::new(16),
            one_rtt: BoundQueue::new(16),
        }
    }

    pub async fn deliver(&self, packet: Packet, pathway: Pathway) -> bool {
        match packet {
            Packet::Data(packet) => match packet.header {
                DataHeader::Long(long::DataHeader::Initial(header)) => {
                    let packet = (header, packet.bytes, packet.offset);
                    self.initial.send((packet, pathway)).await.is_ok()
                }
                DataHeader::Long(long::DataHeader::Handshake(header)) => {
                    let packet = (header, packet.bytes, packet.offset);
                    self.handshake.send((packet, pathway)).await.is_ok()
                }
                DataHeader::Long(long::DataHeader::ZeroRtt(header)) => {
                    let packet = (header, packet.bytes, packet.offset);
                    self.zero_rtt.send((packet, pathway)).await.is_ok()
                }
                DataHeader::Short(header) => {
                    let packet = (header, packet.bytes, packet.offset);
                    self.one_rtt.send((packet, pathway)).await.is_ok()
                }
            },
            Packet::VN(_vn) => true,
            Packet::Retry(_retry) => true,
        }
    }
}
