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
        router_if: Arc<super::QuicProto>,
        probed_pathway_tx: mpsc::UnboundedSender<Pathway>,
    ) -> Self {
        Self {
            router_iface: router_if,
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

    pub async fn deliver(&self, way: Pathway, pkt: Packet) {
        let queue = self.queues.entry(way).or_insert_with(|| {
            _ = self.probed_pathway_tx.unbounded_send(way);
            BoundQueue::new(16)
        });
        _ = queue.send(pkt);
    }

    pub fn register(&self, way: Pathway) -> Receiver<Packet> {
        let entry = self.queues.entry(way);
        // 不该发生冲突
        debug_assert!(matches!(entry, dashmap::Entry::Vacant(..)));
        entry.or_insert_with(|| BoundQueue::new(16)).receiver()
    }

    pub fn unregister(&self, way: &Pathway) {
        let (_way, queue) = self.queues.remove(way).unwrap();
        queue.close();
    }
}
