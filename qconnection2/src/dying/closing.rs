use std::{
    convert::Infallible,
    ops::DerefMut,
    sync::{Arc, Mutex},
};

use qbase::packet::{self, Packet};

use super::{closed, draining};
use crate::{
    conn, path, router,
    space::{data, handshake},
    util::subscribe,
};

#[derive(Clone)]
pub struct Spaces {
    // ccf packets from initial is trustless, so we don't need to store it
    pub(crate) handshake: handshake::ClosingSpace,
    pub(crate) data: data::ClosingSpace,
}

#[doc(alias = "ConnInterface")]
#[derive(Clone)]
pub struct Connection {
    router_if: Arc<router::QuicProto>,
    cid_registry: conn::CidRegistry,
    spaces: Spaces,
    statistics: Arc<Mutex<Statistics>>,
}

struct Statistics {
    last_recv_time: tokio::time::Instant,
    new_rcvd_packets: u32,
}

impl Connection {
    pub fn new(
        router_if: Arc<router::QuicProto>,
        cid_registry: conn::CidRegistry,
        spaces: Spaces,
    ) -> Self {
        use futures::StreamExt;
        use subscribe::{Publish, Subscribe};

        let local_cids = cid_registry.local.active_cids();
        let streams = local_cids.into_iter().map(|local_cid| {
            // resubscribe to redirect packets to the closing connection interface
            router_if.unsubscribe(&local_cid.into());
            router_if.resources_viewer(local_cid.into())
        });
        let mut packets = futures::stream::select_all(streams);

        let statistics = Arc::new(Mutex::new(Statistics {
            last_recv_time: tokio::time::Instant::now(),
            new_rcvd_packets: 0,
        }));

        let conn = Self {
            router_if,
            cid_registry,
            spaces,
            statistics,
        };

        let conn_if = conn.clone();
        tokio::spawn(async move {
            while let Some(bundle) = packets.next().await {
                _ = conn_if.deliver(bundle);
            }
        });

        conn
    }

    pub fn enter_draining(self) -> draining::Connection {
        draining::Connection::new(self.router_if, self.cid_registry)
    }

    pub fn enter_closed(self) -> closed::Connection {
        closed::Connection::new(&self.router_if, &self.cid_registry)
    }
}

impl subscribe::Subscribe<(path::Pathway, Packet)> for Connection {
    type Error = Infallible;

    fn deliver(&self, (way, pkt): (path::Pathway, Packet)) -> Result<(), Self::Error> {
        let mut statistics_guard = self.statistics.lock().unwrap();
        let statistics = statistics_guard.deref_mut();
        let last_recv_time =
            core::mem::replace(&mut statistics.last_recv_time, tokio::time::Instant::now());
        statistics.new_rcvd_packets += 1;

        if statistics.new_rcvd_packets % 3 == 0
            || last_recv_time.elapsed() > tokio::time::Duration::from_secs(1)
        {
            let handshake_packet = self.spaces.handshake.ccf_packet();
            let one_rtt_packet = self.spaces.data.ccf_packet();
            let router_if = self.router_if.clone();
            tokio::spawn(async move {
                use bytes::BufMut;
                let f = |pkt: &bytes::Bytes| !pkt.is_empty();
                for non_empty_packet in [handshake_packet, one_rtt_packet].into_iter().filter(f) {
                    let Some(mut buf) = router_if.new_packet(way) else {
                        return;
                    };
                    buf.put(non_empty_packet);
                    if (router_if.send_packet(&buf, way, way.dst()).await).is_err() {
                        break;
                    }
                }
            });
        }

        // decrease the critical time
        drop(statistics_guard);

        if let Packet::Data(data_packet) = pkt {
            match data_packet.header {
                packet::DataHeader::Long(packet::long::DataHeader::Handshake(hdr)) => {
                    let pkt = (hdr, data_packet.bytes, data_packet.offset);
                    self.spaces.handshake.deliver(pkt)?
                }
                packet::DataHeader::Short(hdr) => {
                    let pkt = (hdr, data_packet.bytes, data_packet.offset);
                    self.spaces.data.deliver(pkt)?
                }
                _ => {}
            }
        }

        Ok(())
    }
}
