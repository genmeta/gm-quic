use std::sync::{Arc, LazyLock, RwLock};

use dashmap::DashMap;
use qbase::{
    cid::{ConnectionId, GenUniqueCid},
    error::Error,
    frame::{NewConnectionIdFrame, ReceiveFrame, RetireConnectionIdFrame, SendFrame},
    packet::{header::GetDcid, Packet},
};

use crate::{path::Pathway, usc::ArcUsc};

type PacketEntry = Box<dyn Fn(Packet, Pathway, ArcUsc) + Send + Sync + 'static>;

type ArcPacketEntry = Arc<RwLock<PacketEntry>>;

static ROUTER: LazyLock<DashMap<ConnectionId, ArcPacketEntry>> = LazyLock::new(DashMap::new);

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
        packet: Packet,
        pathway: Pathway,
        usc: &ArcUsc,
    ) -> Result<(), Packet> {
        let dcid = match &packet {
            Packet::VN(hdr) => hdr.get_dcid(),
            Packet::Retry(hdr) => hdr.get_dcid(),
            Packet::Data(pkt) => pkt.header.get_dcid(),
        };
        let Some(entry) = ROUTER.get(dcid) else {
            return Err(packet);
        };
        entry.read().unwrap()(packet, pathway, usc.clone());
        Ok(())
    }

    /// Register a new connection to the global router.
    ///
    /// Return a [`RouterRegistry`], a wrapper around the connection's local CIDs. it can be used to
    /// generate a new unique CID and add a router entry to the global router.
    pub fn registry<ISSUED>(
        scid: ConnectionId,
        issued_cids: ISSUED,
        packet_entry: ArcPacketEntry,
    ) -> RouterRegistry<ISSUED>
    where
        ISSUED: SendFrame<NewConnectionIdFrame>,
    {
        ROUTER.insert(scid, packet_entry.clone());
        RouterRegistry {
            issued_cids,
            packet_entry,
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

#[derive(Clone)]
pub struct RouterRegistry<ISSUED> {
    issued_cids: ISSUED,
    packet_entry: ArcPacketEntry,
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
                    entry.or_insert(self.packet_entry.clone());
                    true
                } else {
                    false
                }
            })
            .unwrap()
    }
}

impl<T> RouterRegistry<T> {
    /// Update the packet entry of the connection.
    ///
    /// This is used when the connection enter the closing state, the packet entry should be updated.
    pub fn update_packet_entry(&self, packet_entry: PacketEntry) {
        *self.packet_entry.write().unwrap() = packet_entry;
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
