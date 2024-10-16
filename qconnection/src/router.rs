use std::sync::LazyLock;

use dashmap::DashMap;
use qbase::{
    cid::{ConnectionId, GenUniqueCid},
    error::Error,
    frame::{NewConnectionIdFrame, ReceiveFrame, RetireConnectionIdFrame, SendFrame},
    packet::{header::GetDcid, long, DataHeader, DataPacket},
};
use qudp::ArcUsc;

use crate::{connection::PacketEntry, path::pathway::Pathway};

/// Global Router for managing connections.
static ROUTER: LazyLock<DashMap<ConnectionId, [PacketEntry; 4]>> = LazyLock::new(DashMap::new);

#[derive(Clone, Debug)]
pub struct Router;

impl Router {
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

    pub fn revoke<T>(local_cids: T) -> RevokeRouter<T> {
        RevokeRouter { local_cids }
    }

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
