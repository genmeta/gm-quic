use qbase::{
    error::Error,
    packet::{header::GetType, DataPacket},
};

use super::ArcLocalCids;

/// Connection in draining state, entered from the raw state or closing state.
/// It just ignores all packets, and waits for dismissing.
/// Dont forget to remove the connection from the global router.
#[derive(Debug)]
pub struct DrainingConnection {
    /// Local connection IDs, which are used to remove item in the global router
    pub local_cids: ArcLocalCids,
    /// The error that causes the connection to close
    pub error: Error,
}

impl DrainingConnection {
    /// Create a new draining connection
    pub fn new(local_cids: ArcLocalCids, error: Error) -> Self {
        Self { local_cids, error }
    }
}

impl DrainingConnection {
    /// Just ignore the packet, with a warning log
    pub fn recv_packet(&self, packet: DataPacket) {
        log::warn!(
            "Receive a {:?} packet in the draining state, ignore it",
            packet.get_type()
        );
    }
}
