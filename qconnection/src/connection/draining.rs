use qbase::{
    cid::ConnectionId,
    packet::{HandshakePacket, InitialPacket, OneRttPacket, ZeroRttPacket},
};

use super::ArcLocalCids;

/// Connection in draining state, entered from the raw state or closing state.
/// It just ignores all packets, and waits for dismissing.
/// Dont forget to remove the connection from the global router.
#[derive(Debug)]
pub struct DrainingConnection {
    origin_cid: ConnectionId,
    local_cids: ArcLocalCids,
}

impl DrainingConnection {
    // TODO: 应该是由RawConnection或者ClosingConnection Into而来
    //       为其实现From trait为宜，等RawConnection/ClosingConnection实现好
    pub fn new(origin_cid: ConnectionId, local_cids: ArcLocalCids) -> Self {
        Self {
            origin_cid,
            local_cids,
        }
    }

    /// Just ignore the packet, with a warning log
    pub fn recv_initial_pkt(&self, _pkt: InitialPacket) {
        println!("WARN: Receive a initial packet in the draining state, ignore it");
    }

    /// Just ignore the packet, with a warning log
    pub fn recv_0rtt_pkt(&self, _pkt: ZeroRttPacket) {
        println!("WARN: Receive a 0-rtt packet in the draining state, ignore it");
    }

    /// Just ignore the packet, with a warning log
    pub fn recv_handshake_pkt(&self, _pkt: HandshakePacket) {
        println!("WARN: Receive a handshake packet in the draining state, ignore it");
    }

    /// Just ignore the packet, with a warning log
    pub fn recv_1rtt_pkt(&self, _pkt: OneRttPacket) {
        println!("WARN: Receive a 1-rtt packet in the draining state, ignore it");
    }

    /// Return the original connection ID, which is used to remove item in the global router
    pub fn origin_cid(&self) -> &ConnectionId {
        &self.origin_cid
    }

    /// Return the local connection IDs, which are used to remove item in the global router
    pub fn local_cids(&self) -> &ArcLocalCids {
        &self.local_cids
    }
}
