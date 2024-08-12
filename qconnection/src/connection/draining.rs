use qbase::packet::{header::GetType, DataPacket};

use super::ArcLocalCids;

/// Connection in draining state, entered from the raw state or closing state.
/// It just ignores all packets, and waits for dismissing.
/// Dont forget to remove the connection from the global router.
#[derive(Debug)]
pub struct DrainingConnection(ArcLocalCids);

impl DrainingConnection {
    // TODO: 应该是由RawConnection或者ClosingConnection Into而来
    // 为其实现From trait为宜，等RawConnection/ClosingConnection实现好
    pub fn new(local_cids: ArcLocalCids) -> Self {
        Self(local_cids)
    }

    /// Just ignore the packet, with a warning log
    pub fn recv_packet(&self, packet: DataPacket) {
        println!(
            "WARN: Receive a {:?} packet in the draining state, ignore it",
            packet.header.get_type()
        );
    }

    /// Return the local connection IDs, which are used to remove item in the global router
    pub fn local_cids(&self) -> &ArcLocalCids {
        &self.0
    }
}
