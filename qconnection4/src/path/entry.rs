use qbase::{
    packet::{header::long, DataHeader, Packet},
    util::bound_deque::BoundQueue,
};

use super::Pathway;
use crate::space::{
    data::{OneRttPacket, ZeroRttPacket},
    handshake::HandshakePacket,
    initial::InitialPacket,
};

pub struct RcvdPacketBuffer {
    initial: BoundQueue<(InitialPacket, Pathway)>,
    handshake: BoundQueue<(HandshakePacket, Pathway)>,
    zero_rtt: BoundQueue<(ZeroRttPacket, Pathway)>,
    one_rtt: BoundQueue<(OneRttPacket, Pathway)>,
    // pub retry:
}

impl Default for RcvdPacketBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl RcvdPacketBuffer {
    pub fn new() -> Self {
        Self {
            initial: BoundQueue::new(16),
            handshake: BoundQueue::new(16),
            zero_rtt: BoundQueue::new(16),
            one_rtt: BoundQueue::new(16),
        }
    }

    pub fn initial(&self) -> &BoundQueue<(InitialPacket, Pathway)> {
        &self.initial
    }

    pub fn handshake(&self) -> &BoundQueue<(HandshakePacket, Pathway)> {
        &self.handshake
    }

    pub fn zero_rtt(&self) -> &BoundQueue<(ZeroRttPacket, Pathway)> {
        &self.zero_rtt
    }

    pub fn one_rtt(&self) -> &BoundQueue<(OneRttPacket, Pathway)> {
        &self.one_rtt
    }

    pub fn close(&self) {
        self.initial.close();
        self.handshake.close();
        // zero_rtt has already closed?
        self.zero_rtt.close();
        self.one_rtt.close();
    }

    pub async fn deliver(&self, packet: Packet, pathway: Pathway) {
        match packet {
            Packet::Data(packet) => match packet.header {
                DataHeader::Long(long::DataHeader::Initial(header)) => {
                    let packet = (header, packet.bytes, packet.offset);
                    _ = self.initial.send((packet, pathway)).await;
                }
                DataHeader::Long(long::DataHeader::Handshake(header)) => {
                    let packet = (header, packet.bytes, packet.offset);
                    _ = self.handshake.send((packet, pathway)).await;
                }
                DataHeader::Long(long::DataHeader::ZeroRtt(header)) => {
                    let packet = (header, packet.bytes, packet.offset);
                    _ = self.zero_rtt.send((packet, pathway)).await;
                }
                DataHeader::Short(header) => {
                    let packet = (header, packet.bytes, packet.offset);
                    _ = self.one_rtt.send((packet, pathway)).await;
                }
            },
            Packet::VN(_vn) => {}
            Packet::Retry(_retry) => {}
        }
    }
}
