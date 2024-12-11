use std::{net::SocketAddr, sync::LazyLock};

use dashmap::DashMap;
use qbase::{
    cid::{ConnectionId, GenUniqueCid},
    error::Error,
    frame::{NewConnectionIdFrame, ReceiveFrame, RetireConnectionIdFrame, SendFrame},
    packet::{header::GetDcid, long, DataHeader, DataPacket},
};

use crate::{conn::PacketEntry, path::Pathway, usc::ArcUsc};

/// Global Router for managing connections.
static ROUTER: LazyLock<DashMap<ConnectionId, [PacketEntry; 4]>> = LazyLock::new(DashMap::new);
static INITIAL_ROUTER: LazyLock<DashMap<Signpost, [PacketEntry; 4]>> = LazyLock::new(DashMap::new);

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Signpost {
    cid: ConnectionId,
    peer_addr: Option<SocketAddr>,
}

impl Signpost {
    pub fn init_with(cid: ConnectionId, peer_addr: Option<SocketAddr>) -> Self {
        Self { cid, peer_addr }
    }

    pub fn with_cid_only(cid: ConnectionId) -> Self {
        Self::init_with(cid, None)
    }

    pub fn with_no_cid(peer_addr: SocketAddr) -> Self {
        Self::init_with(ConnectionId::default(), Some(peer_addr))
    }
}

impl From<ConnectionId> for Signpost {
    fn from(cid: ConnectionId) -> Self {
        Self::with_cid_only(cid)
    }
}

impl From<SocketAddr> for Signpost {
    fn from(peer_addr: SocketAddr) -> Self {
        Self::with_no_cid(peer_addr)
    }
}

/// A interface to control the global router, which used to route packets to the corresponding connection.
pub struct Router;

impl Router {
    /// Try to route the packet to the corresponding connection.
    ///
    /// The argument `packet` is the packet to be routed, `pathway` and `usc` is where the packet
    /// comes from,you can read the [`Pathway`] and [`ArcUsc`]'s documents for more information.
    ///
    /// If the connection does not exist, the packet will be returned with out any modification.
    pub fn try_to_route_packet_from(
        packet: DataPacket,
        pathway: Pathway,
        usc: &ArcUsc,
    ) -> Result<(), DataPacket> {
        let dcid = packet.header.get_dcid();
        let Some(entries) = ROUTER.get(dcid) else {
            return Err(packet);
        };
        let index = match packet.header {
            DataHeader::Long(long::DataHeader::Initial(_)) => 0,
            DataHeader::Long(long::DataHeader::ZeroRtt(_)) => 1,
            DataHeader::Long(long::DataHeader::Handshake(_)) => 2,
            DataHeader::Short(_) => 3,
        };
        _ = entries[index].unbounded_send((packet, pathway, usc.clone()));
        Ok(())
    }

    /// Register a new connection to the global router.
    ///
    /// Return a [`RouterRegistry`], a wrapper around the connection's local CIDs. it can be used to
    /// generate a new unique CID and add a router entry to the global router.
    pub fn registry<ISSUED>(
        scid: ConnectionId,
        issued_cids: ISSUED,
        packet_entries: [PacketEntry; 4],
    ) -> RouterRegistry<ISSUED>
    where
        ISSUED: SendFrame<NewConnectionIdFrame>,
    {
        ROUTER.insert(scid, packet_entries.clone());
        RouterRegistry {
            issued_cids,
            packet_entries,
        }
    }

    /// Return a [`RevokeRouter`], a wrapper around the local CIDs of the connection.
    ///
    /// It can be used to remove the router entry from the global router when a CID is revoked, read
    /// the [`RevokeRouter`] for more information.
    pub fn revoke<T>(local_cids: T) -> RevokeRouter<T> {
        RevokeRouter { local_cids }
    }

    /// Remove the router entry from the global router directly.
    ///
    /// This is used when the connection is closed, all the remaining router entries of the
    /// connection should be removed.
    pub fn remove(cid: &ConnectionId) {
        ROUTER.remove(cid);
    }
}

#[derive(Debug, Clone)]
pub struct RouterRegistry<ISSUED> {
    issued_cids: ISSUED,
    packet_entries: [PacketEntry; 4],
}

impl<T> SendFrame<NewConnectionIdFrame> for RouterRegistry<T>
where
    T: SendFrame<NewConnectionIdFrame>,
{
    fn send_frame<I: IntoIterator<Item = NewConnectionIdFrame>>(&self, iter: I) {
        self.issued_cids.send_frame(iter);
    }
}

impl<T> GenUniqueCid for RouterRegistry<T> {
    fn gen_unique_cid(&self) -> ConnectionId {
        std::iter::from_fn(|| Some(ConnectionId::random_gen_with_mark(8, 0x80, 0x7F)))
            .find(|cid| {
                let entry = ROUTER.entry(*cid);
                if matches!(entry, dashmap::Entry::Vacant(_)) {
                    entry.or_insert(self.packet_entries.clone());
                    true
                } else {
                    false
                }
            })
            .unwrap()
    }
}

/// A wrapper around the local CIDs of the connection, used to remove the router entry from the
/// global router.
///
/// The way this structure works is receiving the [`RetireConnectionIdFrame`], and then passed it to
/// the wrapped struct. The wrapped struct should return whether the CID is revoked as [`Option`].
/// If the CID revoked, its router entry will be removed from the global router.
#[derive(Clone)]
pub struct RevokeRouter<T> {
    local_cids: T,
}

impl<T> ReceiveFrame<RetireConnectionIdFrame> for RevokeRouter<T>
where
    T: ReceiveFrame<RetireConnectionIdFrame, Output = Option<ConnectionId>>,
{
    type Output = ();

    fn recv_frame(&self, frame: &RetireConnectionIdFrame) -> Result<Self::Output, Error> {
        if let Some(cid) = self.local_cids.recv_frame(frame)? {
            ROUTER.remove(&cid);
        }
        Ok(())
    }
}
