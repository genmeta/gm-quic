use std::{io, net, sync::Arc};

use dashmap::DashMap;
use futures::channel::mpsc;
use qbase::packet::Packet;

use crate::{interface, path, util::bound_queue};

pub struct ConnInterface {
    router_iface: Arc<super::QuicProto>,
    probed_pathway_tx: mpsc::UnboundedSender<path::Pathway>,
    queues: DashMap<path::Pathway, bound_queue::BoundQueue<Packet>>,
}

impl ConnInterface {
    pub fn new(
        router_if: Arc<super::QuicProto>,
        probed_pathway_tx: mpsc::UnboundedSender<path::Pathway>,
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

    pub fn send_capability(&self, on: path::Pathway) -> io::Result<interface::SendCapability> {
        self.router_iface.send_capability(on)
    }

    pub async fn send_packets(
        &self,
        pkt: &[io::IoSlice<'_>],
        way: path::Pathway,
        dst: net::SocketAddr,
    ) -> io::Result<()> {
        self.router_iface.send_packets(pkt, way, dst).await
    }

    pub async fn deliver(&self, way: path::Pathway, pkt: Packet) {
        let queue = self.queues.entry(way).or_insert_with(|| {
            _ = self.probed_pathway_tx.unbounded_send(way);
            bound_queue::BoundQueue::new(16)
        });
        queue.send(pkt);
    }

    pub fn register(&self, way: path::Pathway) -> bound_queue::Receiver<Packet> {
        let entry = self.queues.entry(way);
        // 不该发生冲突
        debug_assert!(matches!(entry, dashmap::Entry::Vacant(..)));
        entry
            .or_insert_with(|| bound_queue::BoundQueue::new(16))
            .receiver()
    }

    pub fn unregister(&self, way: path::Pathway) {
        let (_way, queue) = self.queues.remove(&way).unwrap();
        queue.close();
    }
}
