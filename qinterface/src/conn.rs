use std::{
    io,
    net::SocketAddr,
    sync::{atomic::AtomicUsize, Arc, Mutex},
    time::Instant,
};

use dashmap::DashMap;
use futures::channel::mpsc;
use qbase::{
    cid::RegisterCid,
    frame::{ConnectionCloseFrame, NewConnectionIdFrame, RetireConnectionIdFrame, SendFrame},
    packet::Packet,
    util::bound_deque::{BoundQueue, Receiver},
};

use crate::{
    closing::ClosingInterface,
    path::Pathway,
    router::{QuicProto, RouterRegistry},
    SendCapability,
};

pub struct ConnInterface {
    router_iface: Arc<QuicProto>,
    probed_path_tx: mpsc::UnboundedSender<Pathway>,
    paths: DashMap<Pathway, BoundQueue<Packet>>,
}

impl ConnInterface {
    pub fn new(
        router_iface: Arc<QuicProto>,
        probed_path_tx: mpsc::UnboundedSender<Pathway>,
    ) -> Self {
        Self {
            router_iface,
            probed_path_tx,
            paths: DashMap::new(),
        }
    }

    pub fn router_if(&self) -> &Arc<QuicProto> {
        &self.router_iface
    }

    pub fn send_capability(&self, on: Pathway) -> io::Result<SendCapability> {
        self.router_iface.send_capability(on)
    }

    pub async fn send_packets(
        &self,
        pkts: &[io::IoSlice<'_>],
        way: Pathway,
        dst: SocketAddr,
    ) -> io::Result<()> {
        self.router_iface.send_packets(pkts, way, dst).await
    }

    pub async fn recv_from(&self, packet: Packet, pathway: Pathway) {
        let queue = self.paths.entry(pathway).or_insert_with(|| {
            _ = self.probed_path_tx.unbounded_send(pathway);
            BoundQueue::new(16)
        });
        _ = queue.send(packet).await;
    }

    pub fn register(&self, pathway: Pathway) -> Receiver<Packet> {
        let entry = self.paths.entry(pathway);
        entry.or_insert_with(|| BoundQueue::new(16)).receiver()
    }

    pub fn unregister(&self, pathway: &Pathway) {
        let (_pathway, queue) = self.paths.remove(pathway).unwrap();
        queue.close();
    }
}

pub type ArcLocalCids<ISSUED> = qbase::cid::local_cid2::ArcLocalCids<RouterRegistry<ISSUED>>;
pub type ArcRemoteCids<RETIRED> = qbase::cid::ArcRemoteCids<RETIRED>;

pub type CidRegistry<ISSUED, RETIRED> =
    qbase::cid::Registry<ArcLocalCids<ISSUED>, ArcRemoteCids<RETIRED>>;

impl ConnInterface {
    pub fn disable_probing(&self) {
        self.probed_path_tx.close_channel();
    }

    pub fn close<ISSUED, RETIRED>(
        &self,
        connection_close_frame: ConnectionCloseFrame,
        cid_registry: &CidRegistry<ISSUED, RETIRED>,
    ) -> ClosingInterface
    where
        ISSUED: SendFrame<NewConnectionIdFrame> + Send + Sync + 'static,
        RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
    {
        self.disable_probing();
        ClosingInterface::new(
            self.router_iface.clone(),
            Mutex::new(Instant::now()),
            AtomicUsize::new(0),
            cid_registry.local.initial_scid(),
            cid_registry.remote.latest_dcid(),
            connection_close_frame,
        )
    }
}
