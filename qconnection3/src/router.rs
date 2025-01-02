use core::net;
use std::{convert::Infallible, io, net::SocketAddr, sync::Arc};

use dashmap::DashMap;
use qbase::{
    cid::{ConnectionId, GenUniqueCid},
    frame::{NewConnectionIdFrame, ReceiveFrame, RetireConnectionIdFrame, SendFrame},
    packet::{self, header::GetDcid, Packet},
};
use tokio::task;

use super::{interface, path};
use crate::util::bound_queue;

mod conn_iface;
mod signpost;
pub use conn_iface::ConnInterface;
pub use signpost::Signpost;

pub type QuicListener = Arc<dyn Fn((Arc<QuicProto>, path::Pathway, Packet)) + Send + Sync>;

#[doc(alias = "RouterInterface")]
#[derive(Default)]
pub struct QuicProto {
    interfaces: DashMap<SocketAddr, Arc<dyn interface::QuicInterface>>,
    entries: DashMap<Signpost, bound_queue::BoundQueue<(path::Pathway, Packet)>>,
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
        qiface: Arc<dyn interface::QuicInterface>,
    ) -> task::JoinHandle<io::Result<Infallible>> {
        struct Guard {
            addr: SocketAddr,
            iface: Arc<QuicProto>,
        }

        impl Drop for Guard {
            fn drop(&mut self) {
                self.iface.interfaces.remove(&self.addr);
            }
        }

        let this = self.clone();
        tokio::spawn(async move {
            this.interfaces.insert(local, qiface.clone());
            let _guard = Guard {
                addr: local,
                iface: this.clone(),
            };
            let mut rcvd_pkts = Vec::with_capacity(3);
            loop {
                // way: peer -> local
                let (datagram, way) = core::future::poll_fn(|cx| qiface.poll_recv(cx)).await?;
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
                        queue.send((way, pkt)).await;
                        continue;
                    }
                    if let Some(listener) = this.listener.as_ref() {
                        if contain_initial_packet && datagram_size < 1200 {
                            continue;
                        }
                        _ = (listener)((this.clone(), way, pkt));
                    }
                }
            }
        })
    }

    pub(crate) fn send_capability(
        &self,
        on: path::Pathway,
    ) -> io::Result<interface::SendCapability> {
        self.interfaces
            .get(&on.src())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no interface"))?
            .value()
            .send_capability(on)
    }

    pub(crate) async fn send_packets(
        &self,
        mut pkts: &[io::IoSlice<'_>],
        way: path::Pathway,
        dst: net::SocketAddr,
    ) -> io::Result<()> {
        let qiface = self
            .interfaces
            .get(&way.src())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no interface"))?
            .clone();
        while !pkts.is_empty() {
            let sent = core::future::poll_fn(|cx| qiface.poll_send(cx, pkts, way, dst)).await?;
            pkts = &pkts[sent..];
        }
        Ok(())
    }

    pub(crate) fn register(
        &self,
        signpost: Signpost,
    ) -> bound_queue::Receiver<(path::Pathway, Packet)> {
        // size?
        self.entries
            .entry(signpost)
            .or_insert_with(|| bound_queue::BoundQueue::new(16))
            .receiver()
    }

    pub(crate) fn unregister(&self, signpost: &Signpost) {
        self.entries.remove(signpost);
    }

    pub(crate) fn registry<ISSUED>(
        self: &Arc<Self>,
        conn_iface: Arc<ConnInterface>,
        scid: ConnectionId,
        local_cids: ISSUED,
    ) -> RouterRegistry<ISSUED> {
        let registry = RouterRegistry {
            router_iface: self.clone(),
            conn_iface,
            local_cids,
        };
        registry.launch_receiving_pipeline(scid.into());
        registry
    }
}

impl GenUniqueCid for QuicProto {
    /// Once this is called, the return connection ID must be used.
    fn gen_unique_cid(&self) -> ConnectionId {
        core::iter::from_fn(|| Some(ConnectionId::random_gen_with_mark(8, 0x80, 0x7F)))
            .find(|cid| {
                let signpost = Signpost::from(*cid);
                let entry = self.entries.entry(signpost);

                if matches!(entry, dashmap::Entry::Occupied(..)) {
                    return false;
                }

                entry.insert(bound_queue::BoundQueue::new(16));
                true
            })
            .unwrap()
    }
}

#[derive(Clone)]
pub struct RouterRegistry<ISSUED> {
    router_iface: Arc<QuicProto>,
    conn_iface: Arc<ConnInterface>,
    local_cids: ISSUED,
}

impl<ISSUED> RouterRegistry<ISSUED> {
    fn launch_receiving_pipeline(&self, signpost: signpost::Signpost) {
        use futures::StreamExt;
        let mut pkts = self.router_iface.register(signpost);
        let conn_iface = self.conn_iface.clone();
        tokio::spawn(async move {
            while let Some((way, pkt)) = pkts.next().await {
                conn_iface.deliver(way, pkt);
            }
        });
    }
}

impl<T> GenUniqueCid for RouterRegistry<T>
where
    T: Send + Sync + 'static,
{
    fn gen_unique_cid(&self) -> ConnectionId {
        let unique_cid = self.router_iface.gen_unique_cid();
        self.launch_receiving_pipeline(unique_cid.into());
        unique_cid
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
            self.router_iface.unregister(&signpost::Signpost::from(cid));
        }
        Ok(())
    }
}
