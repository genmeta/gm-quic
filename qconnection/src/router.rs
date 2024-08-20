use std::sync::{Arc, LazyLock};

use dashmap::DashMap;
use deref_derive::Deref;
use qbase::{
    cid::{ConnectionId, UniqueCid},
    error::Error,
    frame::{NewConnectionIdFrame, ReceiveFrame, RetireConnectionIdFrame},
    packet::{header::GetDcid, long, DataHeader, DataPacket, RetryHeader},
};
use qudp::ArcUsc;

use crate::{
    connection::{PacketEntry, TokenRegistry},
    path::Pathway,
};

/// Global Router for managing connections.
pub static ROUTER: LazyLock<ArcRouter> = LazyLock::new(|| ArcRouter(Arc::new(DashMap::new())));

#[derive(Clone, Deref, Debug)]
pub struct ArcRouter(Arc<DashMap<ConnectionId, ([PacketEntry; 4], TokenRegistry)>>);

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
            .map(|item| {
                let index = match packet.header {
                    DataHeader::Long(long::DataHeader::Initial(_)) => 0,
                    DataHeader::Long(long::DataHeader::ZeroRtt(_)) => 1,
                    DataHeader::Long(long::DataHeader::Handshake(_)) => 2,
                    DataHeader::Short(_) => 3,
                };
                _ = item.0[index].unbounded_send((packet, pathway, usc.clone()));
                // TODO: 从全局维护的 connection 中获取对应的 connection
                // 获取 pathway 对应的 path, 并更新最后接收时间
                // path.update_recv_time();
                true
            })
            .unwrap_or(false)
    }

    pub fn recv_retry_packet(&self, packet: RetryHeader) -> bool {
        let dcid = packet.get_dcid();
        self.0
            .get_mut(dcid)
            .map(|mut item| {
                item.1.receive_retry_packet(packet.token.clone());
                true
            })
            .unwrap_or(false)
    }

    pub fn registry<ISSUED>(
        &self,
        token_registry: TokenRegistry,
        issued_cids: ISSUED,
        packet_entries: [PacketEntry; 4],
    ) -> RouterRegistry<ISSUED>
    where
        ISSUED: Extend<NewConnectionIdFrame>,
    {
        RouterRegistry {
            router: self.clone(),
            issued_cids,
            token_registry,
            packet_entries,
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
    token_registry: TokenRegistry,
    packet_entries: [PacketEntry; 4],
}

impl<T> Extend<NewConnectionIdFrame> for RouterRegistry<T>
where
    T: Extend<NewConnectionIdFrame>,
{
    fn extend<I: IntoIterator<Item = NewConnectionIdFrame>>(&mut self, iter: I) {
        self.issued_cids.extend(iter.into_iter().inspect(|frame| {
            self.router.insert(
                frame.id,
                (self.packet_entries.clone(), self.token_registry.clone()),
            );
        }))
    }
}

impl<T> UniqueCid for RouterRegistry<T> {
    fn is_unique_cid(&self, cid: &ConnectionId) -> bool {
        self.router.is_unique_cid(cid)
    }
}

#[derive(Clone)]
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
