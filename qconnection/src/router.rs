use std::sync::{Arc, LazyLock};

use dashmap::DashMap;
use deref_derive::Deref;
use qbase::{
    cid::{ConnectionId, UniqueCid},
    frame::NewConnectionIdFrame,
    packet::{header::GetDcid, long, DataHeader, DataPacket},
};
use qudp::ArcUsc;

use crate::{connection::PacketEntry, path::Pathway};

/// Global Router for managing connections.
pub static ROUTER: LazyLock<ArcRouter> = LazyLock::new(|| ArcRouter(Arc::new(DashMap::new())));

#[derive(Clone, Debug, Deref)]
pub struct ArcRouter(Arc<DashMap<ConnectionId, [PacketEntry; 4]>>);

impl UniqueCid for ArcRouter {
    fn is_unique_cid(&self, cid: &ConnectionId) -> bool {
        self.0.get(cid).is_none()
    }
}

impl ArcRouter {
    pub fn recv_packet_via_pathway(
        &self,
        packet: DataPacket,
        pathway: Pathway,
        usc: &ArcUsc,
    ) -> bool {
        let dcid = packet.header.get_dcid();
        self.0
            .get(&dcid)
            .map(|packet_entries| {
                let index = match packet.header {
                    DataHeader::Long(long::DataHeader::Initial(_)) => 0,
                    DataHeader::Long(long::DataHeader::ZeroRtt(_)) => 1,
                    DataHeader::Long(long::DataHeader::Handshake(_)) => 2,
                    DataHeader::Short(_) => 3,
                };
                _ = packet_entries[index].unbounded_send((packet, pathway, usc.clone()));
                true
            })
            .unwrap_or(false)
    }

    pub fn registry<ISSUED>(
        &self,
        issued_cids: ISSUED,
        packet_entries: [PacketEntry; 4],
    ) -> RouterRegistry<ISSUED>
    where
        ISSUED: Extend<NewConnectionIdFrame>,
    {
        RouterRegistry {
            router: self.clone(),
            issued_cids,
            packet_entries,
        }
    }

    pub fn add_conn(&self, cid: ConnectionId, packet_entries: [PacketEntry; 4]) {
        self.0.insert(cid, packet_entries);
    }

    pub fn remove_conn(&self, cid: ConnectionId) {
        self.0.remove(&cid);
    }
}

#[derive(Debug, Clone)]
pub struct RouterRegistry<ISSUED> {
    router: ArcRouter,
    issued_cids: ISSUED,
    packet_entries: [PacketEntry; 4],
}

impl<T> Extend<NewConnectionIdFrame> for RouterRegistry<T>
where
    T: Extend<NewConnectionIdFrame>,
{
    fn extend<I: IntoIterator<Item = NewConnectionIdFrame>>(&mut self, iter: I) {
        self.issued_cids.extend(iter.into_iter().inspect(|frame| {
            self.router.insert(frame.id, self.packet_entries.clone());
        }))
    }
}

impl<T> UniqueCid for RouterRegistry<T> {
    fn is_unique_cid(&self, cid: &ConnectionId) -> bool {
        self.router.is_unique_cid(cid)
    }
}
