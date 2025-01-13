use std::{io, net::SocketAddr, sync::Arc};

use dashmap::DashMap;
use deref_derive::{Deref, DerefMut};
use qbase::frame::{
    ConnectionCloseFrame, NewConnectionIdFrame, RetireConnectionIdFrame, SendFrame,
};
use tokio::task::AbortHandle;

use crate::{
    buffer::RcvdPacketBuffer,
    closing::ClosingInterface,
    path::Pathway,
    router::{QuicProto, RouterRegistry},
    SendCapability,
};

#[derive(Deref, DerefMut)]
pub struct PathGuard<P> {
    #[deref]
    path: Arc<P>,
    task: AbortHandle,
}

impl<P> PathGuard<P> {
    pub fn new(path: Arc<P>, task: AbortHandle) -> Self {
        Self { path, task }
    }
}

impl<P> Drop for PathGuard<P> {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub struct ConnInterface<P> {
    router_iface: Arc<QuicProto>,
    rcvd_pkts_buf: Arc<RcvdPacketBuffer>,
    paths: DashMap<Pathway, PathGuard<P>>,
}

impl<P> ConnInterface<P> {
    pub fn new(router_iface: Arc<QuicProto>) -> Self {
        Self {
            router_iface,
            rcvd_pkts_buf: Arc::new(Default::default()),
            paths: DashMap::new(),
        }
    }

    pub fn router_if(&self) -> &Arc<QuicProto> {
        &self.router_iface
    }

    pub fn received_packets_buffer(&self) -> &Arc<RcvdPacketBuffer> {
        &self.rcvd_pkts_buf
    }

    pub fn send_capability(&self, on: Pathway) -> io::Result<SendCapability> {
        self.router_iface.send_capability(on)
    }

    pub fn paths(&self) -> &DashMap<Pathway, PathGuard<P>> {
        &self.paths
    }

    pub async fn send_packets(
        &self,
        pkts: &[io::IoSlice<'_>],
        way: Pathway,
        dst: SocketAddr,
    ) -> io::Result<()> {
        self.router_iface.send_packets(pkts, way, dst).await
    }
}

pub type ArcLocalCids<ISSUED> = qbase::cid::local_cid2::ArcLocalCids<RouterRegistry<ISSUED>>;
pub type ArcRemoteCids<RETIRED> = qbase::cid::ArcRemoteCids<RETIRED>;

pub type CidRegistry<ISSUED, RETIRED> =
    qbase::cid::Registry<ArcLocalCids<ISSUED>, ArcRemoteCids<RETIRED>>;

impl<P> ConnInterface<P> {
    pub fn close<ISSUED, RETIRED>(
        &self,
        connection_close_frame: ConnectionCloseFrame,
        cid_registry: &CidRegistry<ISSUED, RETIRED>,
    ) -> ClosingInterface
    where
        ISSUED: SendFrame<NewConnectionIdFrame> + Send + Sync + 'static,
        RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
    {
        ClosingInterface::new(
            self.router_iface.clone(),
            self.rcvd_pkts_buf.clone(),
            cid_registry.local.initial_scid(),
            cid_registry.remote.latest_dcid(),
            connection_close_frame,
        )
    }
}
