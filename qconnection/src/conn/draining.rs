use qbase::{
    cid::ConnectionId,
    error::Error,
    packet::{header::GetType, DataPacket, Packet},
};

/// Connection in draining state, entered from the raw state or closing state.
/// It just ignores all packets, and waits for dismissing.
/// Dont forget to remove the connection from the global router.
#[derive(Debug)]
pub struct DrainingConnection {
    /// Local connection IDs, which are used to remove item in the global router
    local_cids: Vec<ConnectionId>,
    /// The error that causes the connection to close
    error: Error,
}

impl DrainingConnection {
    /// Create a new draining connection
    pub fn new(local_cids: Vec<ConnectionId>, error: Error) -> Self {
        Self { local_cids, error }
    }

    /// Return the [`Error`] that causes the connection to drain.
    pub fn error(&self) -> &Error {
        &self.error
    }

    /// Return the local connection IDs.
    ///
    /// Used to remove item in the global router
    pub fn local_cids(&self) -> &[ConnectionId] {
        &self.local_cids
    }

    pub const fn packet_entry(
        &self,
    ) -> impl Fn(Packet, crate::path::Pathway, crate::usc::ArcUsc) + Send + Sync + 'static {
        // ignore all rcvd packets
        |_, _, _| {}
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
