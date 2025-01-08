use std::{io, net::SocketAddr, sync::Arc};

use dashmap::DashMap;
use futures::channel::mpsc;
use qbase::packet::Packet;

use crate::{
    interface::SendCapability,
    path::Pathway,
    util::bound_queue::{BoundQueue, Receiver},
};

pub struct ConnInterface {
    router_iface: Arc<super::QuicProto>,
    probed_pathway_tx: mpsc::UnboundedSender<Pathway>,
    queues: DashMap<Pathway, BoundQueue<Packet>>,
}

impl ConnInterface {
    pub fn new(
        router_iface: Arc<super::QuicProto>,
        probed_pathway_tx: mpsc::UnboundedSender<Pathway>,
    ) -> Self {
        Self {
            router_iface,
            probed_pathway_tx,
            queues: DashMap::new(),
        }
    }

    pub fn router_if(&self) -> &Arc<super::QuicProto> {
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

    pub async fn deliver(&self, pathway: Pathway, packet: Packet) {
        let queue = self.queues.entry(pathway).or_insert_with(|| {
            _ = self.probed_pathway_tx.unbounded_send(pathway);
            BoundQueue::new(16)
        });
        _ = queue.send(packet).await;
    }

    pub fn register(&self, pathway: Pathway) -> Receiver<Packet> {
        let entry = self.queues.entry(pathway);
        entry.or_insert_with(|| BoundQueue::new(16)).receiver()
    }

    pub fn unregister(&self, pathway: &Pathway) {
        let (_pathway, queue) = self.queues.remove(pathway).unwrap();
        queue.close();
    }

    pub fn disable_probing(&self) {
        self.probed_pathway_tx.close_channel();
    }
}
