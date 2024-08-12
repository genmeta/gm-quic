use std::sync::{Arc, LazyLock};

use dashmap::DashMap;
use deref_derive::Deref;
use qbase::{
    cid::{ConnectionId, UniqueCid},
    error::Error,
    frame::{NewConnectionIdFrame, ReceiveFrame, RetireConnectionIdFrame},
    packet::{
        header::GetDcid,
        long::{self},
        DataHeader, DataPacket, RetryHeader,
    },
};
use qudp::ArcUsc;

use crate::{
    connection::{PacketEntry, RetryEntry},
    path::Pathway,
};

/// Global Router for managing connections.
pub static ROUTER: LazyLock<ArcRouter> = LazyLock::new(|| ArcRouter(Arc::new(DashMap::new())));

#[derive(Clone, Debug, Deref)]
pub struct ArcRouter(Arc<DashMap<ConnectionId, ([PacketEntry; 4], RetryEntry)>>);

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
            .get(dcid)
            .map(|packet_entries| {
                let index = match packet.header {
                    DataHeader::Long(long::DataHeader::Initial(_)) => 0,
                    DataHeader::Long(long::DataHeader::ZeroRtt(_)) => 1,
                    DataHeader::Long(long::DataHeader::Handshake(_)) => 2,
                    DataHeader::Short(_) => 3,
                };
                _ = packet_entries.0[index].unbounded_send((packet, pathway, usc.clone()));
                true
            })
            .unwrap_or(false)
    }

    pub fn recv_retry_packet(&self, packet: RetryHeader) -> bool {
        let dcid = packet.get_dcid();
        self.0
            .get(dcid)
            .map(|packet_entries| {
                _ = packet_entries.1.unbounded_send(packet);
                true
            })
            .unwrap_or(false)
    }

    pub fn registry<ISSUED>(
        &self,
        issued_cids: ISSUED,
        packet_entries: [PacketEntry; 4],
        retry_entry: RetryEntry,
    ) -> RouterRegistry<ISSUED>
    where
        ISSUED: Extend<NewConnectionIdFrame>,
    {
        RouterRegistry {
            router: self.clone(),
            issued_cids,
            packet_entries,
            retry_entry,
        }
    }

    pub fn revoke<T>(&self, local_cids: T) -> RevokeRouter<T> {
        RevokeRouter {
            router: self.clone(),
            local_cids,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RouterRegistry<ISSUED> {
    router: ArcRouter,
    issued_cids: ISSUED,
    packet_entries: [PacketEntry; 4],
    retry_entry: RetryEntry,
}

impl<T> Extend<NewConnectionIdFrame> for RouterRegistry<T>
where
    T: Extend<NewConnectionIdFrame>,
{
    fn extend<I: IntoIterator<Item = NewConnectionIdFrame>>(&mut self, iter: I) {
        self.issued_cids.extend(iter.into_iter().inspect(|frame| {
            self.router.insert(
                frame.id,
                (self.packet_entries.clone(), self.retry_entry.clone()),
            );
        }))
    }
}

impl<T> UniqueCid for RouterRegistry<T> {
    fn is_unique_cid(&self, cid: &ConnectionId) -> bool {
        self.router.is_unique_cid(cid)
    }
}

#[derive(Debug, Clone)]
pub struct RevokeRouter<T> {
    router: ArcRouter,
    local_cids: T,
}

impl<T> ReceiveFrame<RetireConnectionIdFrame> for RevokeRouter<T>
where
    T: ReceiveFrame<RetireConnectionIdFrame, Output = Option<ConnectionId>>,
{
    type Output = ();

    fn recv_frame(&mut self, frame: &RetireConnectionIdFrame) -> Result<Self::Output, Error> {
        if let Some(cid) = self.local_cids.recv_frame(frame)? {
            self.router.remove(&cid);
        }
        Ok(())
    }
}
