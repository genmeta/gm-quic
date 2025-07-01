use qbase::{
    net::{
        addr::BindAddr,
        route::{Link, Pathway},
    },
    packet::{
        DataHeader, Packet,
        header::{long, short},
    },
    util::BoundQueue,
};

use crate::packet::CipherPacket;

type PacketQueue<P> = BoundQueue<(BindAddr, CipherPacket<P>, Pathway, Link)>;

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
            initial: BoundQueue::new(16),
            handshake: BoundQueue::new(16),
            zero_rtt: BoundQueue::new(16),
            one_rtt: BoundQueue::new(16),
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

    pub async fn deliver(&self, bind_addr: BindAddr, packet: Packet, pathway: Pathway, link: Link) {
        match packet {
            Packet::Data(packet) => match packet.header {
                DataHeader::Long(long::DataHeader::Initial(header)) => {
                    // tracing::warn!("deliver initial packet from {}", link.dst());
                    let packet = CipherPacket::new(header, packet.bytes, packet.offset);
                    _ = self.initial.send((bind_addr, packet, pathway, link)).await;
                }
                DataHeader::Long(long::DataHeader::Handshake(header)) => {
                    // tracing::warn!("deliver handshake packet from {}", link.dst());
                    let packet = CipherPacket::new(header, packet.bytes, packet.offset);
                    _ = self
                        .handshake
                        .send((bind_addr, packet, pathway, link))
                        .await;
                }
                DataHeader::Long(long::DataHeader::ZeroRtt(header)) => {
                    // tracing::warn!("deliver 0rtt packet from {}", link.dst());
                    let packet = CipherPacket::new(header, packet.bytes, packet.offset);
                    _ = self.zero_rtt.send((bind_addr, packet, pathway, link)).await;
                }
                DataHeader::Short(header) => {
                    // tracing::warn!("deliver 1rtt packet from {}", link.dst());
                    let packet = CipherPacket::new(header, packet.bytes, packet.offset);
                    _ = self.one_rtt.send((bind_addr, packet, pathway, link)).await;
                }
            },
            Packet::VN(_vn) => {}
            Packet::Retry(_retry) => {}
        }
    }
}
