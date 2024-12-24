use core::net;
use std::{
    convert::Infallible,
    io,
    sync::Arc,
    task::{Context, Poll},
};

use dashmap::DashMap;
use qbase::{
    cid, frame,
    packet::{self, header::GetDcid, Packet},
    util::ArcAsyncDeque,
};
use tokio::task;

use super::{
    interface, path,
    util::{publish, subscribe},
};

mod signpost;
pub use signpost::Signpost;

pub type QuicListener = Box<
    dyn subscribe::Subscribe<(Arc<QuicProto>, path::Pathway, Packet), Error = Infallible>
        + Send
        + Sync,
>;

#[doc(alias = "RouterInterface")]
pub struct QuicProto {
    interfaces: DashMap<net::SocketAddr, Arc<dyn interface::QuicInteraface>>,
    entries: DashMap<Signpost, ArcAsyncDeque<(path::Pathway, Packet)>>,
    listener: Option<QuicListener>,
}

impl QuicProto {
    pub fn new(listener: impl Into<Option<QuicListener>>) -> Self {
        Self {
            interfaces: DashMap::new(),
            entries: DashMap::new(),
            listener: listener.into(),
        }
    }

    pub fn add_interface(
        self: &Arc<Self>,
        local: net::SocketAddr,
        qi: Arc<dyn interface::QuicInteraface>,
    ) -> task::JoinHandle<io::Result<Infallible>> {
        struct Guard {
            addr: net::SocketAddr,
            map: DashMap<net::SocketAddr, Arc<dyn interface::QuicInteraface>>,
        }

        impl Drop for Guard {
            fn drop(&mut self) {
                self.map.remove(&self.addr);
            }
        }

        let this = self.clone();
        tokio::spawn(async move {
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

    pub(crate) async fn send(
        &self,
        pkt: &[u8],
        way: path::Pathway,
        dst: net::SocketAddr,
    ) -> io::Result<()> {
        let no_if = || io::Error::new(io::ErrorKind::NotConnected, "no interface");
        let qi = self.interfaces.get(&way.src()).ok_or_else(no_if)?.clone();
        core::future::poll_fn(|cx| qi.poll_send(cx, pkt, way, dst)).await
    }

    fn del_entry(&self, key: &Signpost) {
        if let Some((_signpost, deque)) = self.entries.remove(key) {
            deque.close();
        }
    }
}

impl publish::Publish<Signpost> for QuicProto {
    type Resource = (path::Pathway, Packet);

    fn subscribe(&self, key: &Signpost) {
        self.entries.insert(*key, ArcAsyncDeque::new());
    }

    fn poll_acquire(&self, cx: &mut Context, key: &Signpost) -> Poll<Option<Self::Resource>> {
        let Some(deque) = self.entries.get(key) else {
            return Poll::Ready(None);
        };
        deque.poll_pop(cx)
    }

    fn unsubscribe(&self, key: &Signpost) {
        self.del_entry(key);
    }
}

#[derive(Clone)]
pub struct RouterRegistry<ISSUED> {
    proto: Arc<QuicProto>,
    conn_if: Arc<path::ConnInterface>,
    local_cids: ISSUED,
}

impl QuicProto {
    pub fn registry<ISSUED>(
        self: &Arc<Self>,
        conn_if: Arc<path::ConnInterface>,
        local_cids: ISSUED,
    ) -> RouterRegistry<ISSUED> {
        RouterRegistry {
            proto: self.clone(),
            conn_if,
            local_cids,
        }
    }
}

impl<T> frame::SendFrame<frame::NewConnectionIdFrame> for RouterRegistry<T>
where
    T: frame::SendFrame<frame::NewConnectionIdFrame>,
{
    fn send_frame<I: IntoIterator<Item = frame::NewConnectionIdFrame>>(&self, iter: I) {
        self.local_cids.send_frame(iter);
    }
}

impl<T> cid::GenUniqueCid for RouterRegistry<T>
where
    T: Send + Sync + 'static,
{
    fn gen_unique_cid(&self) -> cid::ConnectionId {
        core::iter::from_fn(|| Some(cid::ConnectionId::random_gen_with_mark(8, 0x80, 0x7F)))
            .find(|cid| {
                use futures::StreamExt;
                use publish::Publish;
                use subscribe::Subscribe;

                let signpost = signpost::Signpost::from(*cid);
                let entry = self.proto.entries.entry(signpost);
                if !matches!(entry, dashmap::Entry::Vacant(_)) {
                    return false;
                }

                let conn_if = self.conn_if.clone();
                let mut packets = self.proto.subscription(signpost);
                tokio::spawn(async move {
                    while let Some((way, pkt)) = packets.next().await {
                        _ = conn_if.deliver((way, pkt))
                    }
                });

                true
            })
            .unwrap()
    }
}

impl<T> frame::ReceiveFrame<frame::RetireConnectionIdFrame> for RouterRegistry<T>
where
    T: frame::ReceiveFrame<frame::RetireConnectionIdFrame, Output = Option<cid::ConnectionId>>,
{
    type Output = ();

    fn recv_frame(
        &self,
        frame: &frame::RetireConnectionIdFrame,
    ) -> Result<Self::Output, qbase::error::Error> {
        if let Some(cid) = self.local_cids.recv_frame(frame)? {
            self.proto.del_entry(&signpost::Signpost::from(cid));
        }
        Ok(())
    }
}
