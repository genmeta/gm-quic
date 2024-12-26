use std::{convert::Infallible, io, net, sync::Arc};

use dashmap::DashMap;
use qbase::{packet::Packet, util::ArcAsyncDeque};

use crate::{path, util::subscribe};

// packet_subscriber(paths <- create_entry <- components(data_space) <- cid_registry) <- router_revoke/registry <- paths, cycle on paths, fk
// packet_subscriber = ConnInterface(distinguish with Paths)
// how to discovery new path passively?
// when receive a packet from new way, deliver the packway
pub struct ConnInterface {
    router_if: Arc<super::QuicProto>,
    new_pathway: Box<dyn subscribe::Subscribe<path::Pathway, Error = Infallible> + Send + Sync>,
    deques: DashMap<net::SocketAddr, ArcAsyncDeque<Packet>>,
}

impl ConnInterface {
    pub fn new(
        router_if: Arc<super::QuicProto>,
        new_path: Box<dyn subscribe::Subscribe<path::Pathway, Error = Infallible> + Send + Sync>,
    ) -> Self {
        Self {
            router_if,
            new_pathway: new_path,
            deques: DashMap::new(),
        }
    }

    pub fn router_if(&self) -> &Arc<super::QuicProto> {
        &self.router_if
    }

    pub fn new_packet(&self, way: path::Pathway) -> Option<bytes::BytesMut> {
        self.router_if.new_packet(way)
    }

    pub async fn send_packet(
        &self,
        pkt: &[u8],
        way: path::Pathway,
        dst: net::SocketAddr,
    ) -> io::Result<()> {
        self.router_if.send_packet(pkt, way, dst).await
    }
}

impl subscribe::Publish<path::Pathway> for Arc<ConnInterface> {
    type Resource = Packet;

    type Subscription = ArcAsyncDeque<Self::Resource>;

    fn subscribe(&self, pathway: path::Pathway) -> Self::Subscription {
        self.deques.entry(pathway.src()).or_default().clone()
    }

    fn unsubscribe(&self, pathway: &path::Pathway) {
        if let Some((_bind, deque)) = self.deques.remove(&pathway.src()) {
            deque.close();
        }
    }
}

impl subscribe::Subscribe<(path::Pathway, Packet)> for ConnInterface {
    type Error = Infallible;

    fn deliver(&self, (pathway, pkt): (path::Pathway, Packet)) -> Result<(), Self::Error> {
        let deque = self.deques.entry(pathway.src()).or_insert_with(|| {
            // Passive path discovery
            _ = self.new_pathway.deliver(pathway);
            ArcAsyncDeque::new()
        });
        deque.push_back(pkt);
        Ok(())
    }
}
