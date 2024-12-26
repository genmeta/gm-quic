use std::{convert::Infallible, sync::Arc};

use qbase::packet::Packet;

use super::closed;
use crate::{conn, path, router, util::subscribe};

#[derive(Clone)]
pub struct Connection {
    router_if: Arc<router::QuicProto>,
    cid_registry: conn::CidRegistry,
}

impl Connection {
    pub fn new(router_if: Arc<router::QuicProto>, cid_registry: conn::CidRegistry) -> Self {
        use futures::StreamExt;
        use subscribe::{Publish, Subscribe};

        let local_cids = cid_registry.local.active_cids();
        let streams = local_cids.into_iter().map(|local_cid| {
            // resubscribe to redirect packets to the draining connection interface
            router_if.unsubscribe(&local_cid.into());
            router_if.resources_viewer(local_cid.into())
        });
        let mut packets = futures::stream::select_all(streams);

        let conn = Self {
            cid_registry,
            router_if,
        };

        let conn_if = conn.clone();
        tokio::spawn(async move {
            while let Some(bundle) = packets.next().await {
                _ = conn_if.deliver(bundle);
            }
        });

        conn
    }

    pub fn enter_closed(self) -> closed::Connection {
        closed::Connection::new(&self.router_if, &self.cid_registry)
    }
}

impl subscribe::Subscribe<(path::Pathway, Packet)> for Connection {
    type Error = Infallible;

    fn deliver(&self, (way, pkt): (path::Pathway, Packet)) -> Result<(), Self::Error> {
        _ = (way, pkt);
        Ok(())
    }
}
