use qbase::{
    packet::{
        DataHeader, Packet,
        header::{long, short},
    },
    util::BoundQueue,
};

use crate::{packet::CipherPacket, route::Way};

type PacketQueue<P> = BoundQueue<(CipherPacket<P>, Way)>;

// 需要一个四元组，pathway + src + dst
pub struct RcvdPacketQueue {
    initial: PacketQueue<long::InitialHeader>,
    handshake: PacketQueue<long::HandshakeHeader>,
    zero_rtt: PacketQueue<long::ZeroRttHeader>,
    one_rtt: PacketQueue<short::OneRttHeader>,
    // pub retry:
}

impl Default for RcvdPacketQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl RcvdPacketQueue {
    pub fn new() -> Self {
        Self {
            initial: BoundQueue::new(8),
            handshake: BoundQueue::new(8),
            zero_rtt: BoundQueue::new(8),
            one_rtt: BoundQueue::new(128),
        }
    }

    pub fn initial(&self) -> &PacketQueue<long::InitialHeader> {
        &self.initial
    }

    pub fn handshake(&self) -> &PacketQueue<long::HandshakeHeader> {
        &self.handshake
    }

    pub fn zero_rtt(&self) -> &PacketQueue<long::ZeroRttHeader> {
        &self.zero_rtt
    }

    pub fn one_rtt(&self) -> &PacketQueue<short::OneRttHeader> {
        &self.one_rtt
    }

    pub fn close_all(&self) {
        self.initial.close();
        self.handshake.close();
        self.zero_rtt.close();
        self.one_rtt.close();
    }

    pub async fn deliver(&self, packet: Packet, way: Way) {
        match packet {
            Packet::Data(packet) => match packet.header {
                DataHeader::Long(long::DataHeader::Initial(header)) => {
                    let packet = CipherPacket::new(header, packet.bytes, packet.offset);
                    _ = self.initial.send((packet, way)).await;
                }
                DataHeader::Long(long::DataHeader::Handshake(header)) => {
                    let packet = CipherPacket::new(header, packet.bytes, packet.offset);
                    _ = self.handshake.send((packet, way)).await;
                }
                DataHeader::Long(long::DataHeader::ZeroRtt(header)) => {
                    let packet = CipherPacket::new(header, packet.bytes, packet.offset);
                    _ = self.zero_rtt.send((packet, way)).await;
                }
                DataHeader::Short(header) => {
                    let packet = CipherPacket::new(header, packet.bytes, packet.offset);
                    _ = self.one_rtt.send((packet, way)).await;
                }
            },
            Packet::VN(_vn) => {}
            Packet::Retry(_retry) => {}
        }
    }
}
