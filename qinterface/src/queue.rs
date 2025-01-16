use qbase::{
    packet::{
        header::{long, short},
        DataHeader, Packet,
    },
    util::bound_deque::BoundQueue,
};

use crate::path::{Pathway, Socket};

pub type InitialPacket = (long::InitialHeader, bytes::BytesMut, usize);
pub type HandshakePacket = (long::HandshakeHeader, bytes::BytesMut, usize);
pub type ZeroRttPacket = (long::ZeroRttHeader, bytes::BytesMut, usize);
pub type OneRttPacket = (short::OneRttHeader, bytes::BytesMut, usize);

// 需要一个四元组，pathway + src + dst
pub struct RcvdPacketQueue {
    initial: BoundQueue<(InitialPacket, Pathway, Socket)>,
    handshake: BoundQueue<(HandshakePacket, Pathway, Socket)>,
    zero_rtt: BoundQueue<(ZeroRttPacket, Pathway, Socket)>,
    one_rtt: BoundQueue<(OneRttPacket, Pathway, Socket)>,
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
            initial: BoundQueue::new(16),
            handshake: BoundQueue::new(16),
            zero_rtt: BoundQueue::new(16),
            one_rtt: BoundQueue::new(16),
        }
    }

    pub fn initial(&self) -> &BoundQueue<(InitialPacket, Pathway, Socket)> {
        &self.initial
    }

    pub fn handshake(&self) -> &BoundQueue<(HandshakePacket, Pathway, Socket)> {
        &self.handshake
    }

    pub fn zero_rtt(&self) -> &BoundQueue<(ZeroRttPacket, Pathway, Socket)> {
        &self.zero_rtt
    }

    pub fn one_rtt(&self) -> &BoundQueue<(OneRttPacket, Pathway, Socket)> {
        &self.one_rtt
    }

    pub fn close_all(&self) {
        self.initial.close();
        self.handshake.close();
        self.zero_rtt.close();
        self.one_rtt.close();
    }

    pub async fn deliver(&self, packet: Packet, pathway: Pathway, local: Socket) {
        match packet {
            Packet::Data(packet) => match packet.header {
                DataHeader::Long(long::DataHeader::Initial(header)) => {
                    let packet = (header, packet.bytes, packet.offset);
                    _ = self.initial.send((packet, pathway, local)).await;
                }
                DataHeader::Long(long::DataHeader::Handshake(header)) => {
                    let packet = (header, packet.bytes, packet.offset);
                    _ = self.handshake.send((packet, pathway, local)).await;
                }
                DataHeader::Long(long::DataHeader::ZeroRtt(header)) => {
                    let packet = (header, packet.bytes, packet.offset);
                    _ = self.zero_rtt.send((packet, pathway, local)).await;
                }
                DataHeader::Short(header) => {
                    let packet = (header, packet.bytes, packet.offset);
                    _ = self.one_rtt.send((packet, pathway, local)).await;
                }
            },
            Packet::VN(_vn) => {}
            Packet::Retry(_retry) => {}
        }
    }
}
