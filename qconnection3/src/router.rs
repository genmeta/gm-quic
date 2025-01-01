use core::net;
use std::{convert::Infallible, io, net::SocketAddr, sync::Arc};

use dashmap::DashMap;
use qbase::{
    cid::{ConnectionId, GenUniqueCid},
    frame::{NewConnectionIdFrame, ReceiveFrame, RetireConnectionIdFrame, SendFrame},
    packet::{self, header::GetDcid, Packet},
    util::ArcAsyncDeque,
};
use tokio::task;

use super::{interface, path};

mod conn_if;
mod signpost;
pub use conn_if::ConnInterface;
pub use signpost::Signpost;

#[doc(alias = "RouterInterface")]
#[derive(Default)]
pub struct QuicProto {
    interfaces: DashMap<SocketAddr, Arc<dyn interface::QuicInteraface>>,
    entries: DashMap<Signpost, ArcAsyncDeque<(path::Pathway, Packet)>>,
    listener: Option<QuicListener>,
}

impl QuicProto {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_with_listener(listener: QuicListener) -> Self {
        Self {
            interfaces: DashMap::new(),
            entries: DashMap::new(),
            listener: Some(listener),
        }
    }

    pub fn add_interface(
        self: &Arc<Self>,
        local: SocketAddr,
        qi: Arc<dyn interface::QuicInteraface>,
    ) -> task::JoinHandle<io::Result<Infallible>> {
        struct Guard {
            addr: SocketAddr,
            map: DashMap<SocketAddr, Arc<dyn interface::QuicInteraface>>,
        }

        impl Drop for Guard {
            fn drop(&mut self) {
                self.map.remove(&self.addr);
            }
        }

        let this = self.clone();
        tokio::spawn(async move {
            this.interfaces.insert(local, qi.clone());
            let _guard = Guard {
                addr: local,
                map: this.interfaces.clone(),
            };
            let mut rcvd_pkts = Vec::with_capacity(3);
            loop {
                // way: peer -> local
                let (datagram, way) = core::future::poll_fn(|cx| qi.poll_recv(cx)).await?;
                let datagram_size = datagram.len();
                // todo: parse packets with any length of dcid
                rcvd_pkts.extend(qbase::packet::PacketReader::new(datagram, 8).flatten());

                // rfc9000 14.1
                // A server MUST discard an Initial packet that is carried in a UDP datagram with a payload that is smaller than
                // the smallest allowed maximum datagram size of 1200 bytes. A server MAY also immediately close the
                // connection by sending a CONNECTION_CLOSE frame with an error code of PROTOCOL_VIOLATION; see
                // Section 10.2.3.
                let is_initial_packet = |pkt: &Packet| matches!(pkt, Packet::Data(packet) if matches!(packet.header, packet::DataHeader::Long(packet::long::DataHeader::Initial(..))));
                let contain_initial_packet = rcvd_pkts.iter().any(is_initial_packet);

                for pkt in rcvd_pkts.drain(..) {
                    let dcid = match &pkt {
                        Packet::VN(vn) => vn.get_dcid(),
                        Packet::Retry(retry) => retry.get_dcid(),
                        Packet::Data(data_packet) => data_packet.get_dcid(),
                    };
                    let signpost = if dcid.len() != 0 {
                        Signpost::from(*dcid)
                    } else {
                        use path::Endpoint::*;
                        let (Direct { addr } | Relay { agent: addr, .. }) = way.local;
                        Signpost::from(addr)
                    };

                    if let Some(queue) = this.entries.get(&signpost) {
                        queue.push_back((way, pkt));
                        continue;
                    }
                    if let Some(listener) = this.listener.as_ref() {
                        if contain_initial_packet && datagram_size < 1200 {
                            continue;
                        }
                        _ = listener.deliver((this.clone(), way, pkt));
                    }
                }
            }
        })
    }

    pub(crate) fn new_packet(&self, way: path::Pathway) -> Option<bytes::BytesMut> {
        Some(self.interfaces.get(&way.src())?.new_packet(way))
    }

    pub(crate) async fn send_packet(
        &self,
        pkt: &[u8],
        way: path::Pathway,
        dst: net::SocketAddr,
    ) -> io::Result<()> {
        let qi = self
            .interfaces
            .get(&way.src())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no interface"))?
            .clone();
        core::future::poll_fn(|cx| qi.poll_send(cx, pkt, way, dst)).await
    }

    fn del_entry(&self, key: &Signpost) {
        if let Some((_signpost, deque)) = self.entries.remove(key) {
            deque.close();
        }
    }
}

#[derive(Clone)]
pub struct RouterRegistry<ISSUED> {
    proto: Arc<QuicProto>,
    conn_if: Arc<ConnInterface>,
    local_cids: ISSUED,
}

impl QuicProto {
    pub fn registry<ISSUED>(
        self: &Arc<Self>,
        conn_if: Arc<ConnInterface>,
        scid: ConnectionId,
        local_cids: ISSUED,
    ) -> RouterRegistry<ISSUED> {
        let registry = RouterRegistry {
            proto: self.clone(),
            conn_if,
            local_cids,
        };
        registry.launch_pipeline(scid.into());
        registry
    }
}

impl<T> SendFrame<NewConnectionIdFrame> for RouterRegistry<T>
where
    T: SendFrame<NewConnectionIdFrame>,
{
    fn send_frame<I: IntoIterator<Item = NewConnectionIdFrame>>(&self, iter: I) {
        self.local_cids.send_frame(iter);
    }
}

impl<T> GenUniqueCid for RouterRegistry<T>
where
    T: Send + Sync + 'static,
{
    fn gen_unique_cid(&self) -> ConnectionId {
        // generate a unique cid
        let unique_cid =
            std::iter::from_fn(|| Some(ConnectionId::random_gen_with_mark(8, 0x80, 0x7F)))
                .find(|cid| {
                    let signpost = signpost::Signpost::from(*cid);
                    let entry = self.proto.entries.entry(signpost);

                    if matches!(entry, dashmap::Entry::Occupied(..)) {
                        return false;
                    }

                    // same as `self.proto.subscribe(&signpost)`
                    entry.insert(ArcAsyncDeque::new());
                    true
                })
                .unwrap();

        self.launch_pipeline(unique_cid.into());

        unique_cid
    }
}

impl<ISSUED> RouterRegistry<ISSUED> {
    fn launch_pipeline(&self, signpost: signpost::Signpost) {
        // spawn a task to deliver packets
        use futures::StreamExt;
        use subscribe::{Publish, Subscribe};
        let conn_if = self.conn_if.clone();
        let mut packets = self.proto.resources_viewer(signpost);
        tokio::spawn(async move {
            while let Some((way, pkt)) = packets.next().await {
                _ = conn_if.deliver((way, pkt))
            }
        });
    }
}

impl<T> ReceiveFrame<RetireConnectionIdFrame> for RouterRegistry<T>
where
    T: ReceiveFrame<RetireConnectionIdFrame, Output = Option<ConnectionId>>,
{
    type Output = ();

    fn recv_frame(
        &self,
        frame: &RetireConnectionIdFrame,
    ) -> Result<Self::Output, qbase::error::Error> {
        if let Some(cid) = self.local_cids.recv_frame(frame)? {
            self.proto.del_entry(&signpost::Signpost::from(cid));
        }
        Ok(())
    }
}
