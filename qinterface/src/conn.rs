use std::{io, net::SocketAddr, sync::Arc};

use dashmap::DashMap;
use qbase::{
    packet::Packet,
    util::bound_deque::{BoundQueue, Receiver},
};
use tokio::{sync::mpsc, task::AbortHandle};

use crate::{path::Pathway, router::QuicProto, SendCapability};

pub struct PathProber {
    // tokio的channel不能close，futures的可以close但它的实现是是链表
    pathway_entry: mpsc::UnboundedSender<Pathway>,
    probed_task: AbortHandle,
}

impl Drop for PathProber {
    fn drop(&mut self) {
        self.disable_probing();
    }
}

impl PathProber {
    pub fn new<P>(path_creator: Box<dyn Fn(Pathway) + Send>) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let probed_task = tokio::spawn(async move {
            while let Some(pathway) = rx.recv().await {
                path_creator(pathway);
            }
        });
        Self {
            pathway_entry: tx,
            probed_task: probed_task.abort_handle(),
        }
    }

    fn on_probed(&self, pathway: Pathway) {
        _ = self.pathway_entry.send(pathway);
    }

    pub fn disable_probing(&self) {
        self.probed_task.abort();
    }
}

pub struct ConnInterface {
    router_iface: Arc<QuicProto>,
    path_prober: PathProber,
    queues: DashMap<Pathway, BoundQueue<Packet>>,
}

impl ConnInterface {
    pub fn new(router_iface: Arc<QuicProto>, path_prober: PathProber) -> Self {
        Self {
            router_iface,
            path_prober,
            queues: DashMap::new(),
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
        let queue = self.queues.entry(pathway).or_insert_with(|| {
            self.path_prober.on_probed(pathway);
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
        self.path_prober.disable_probing();
    }
}
