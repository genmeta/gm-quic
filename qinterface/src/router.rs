use std::{convert::Infallible, fmt, io, net::SocketAddr, sync::Arc};

use dashmap::DashMap;
use qbase::{
    cid::{ConnectionId, GenUniqueCid, RetireCid},
    error::Error,
    frame::{NewConnectionIdFrame, ReceiveFrame, RetireConnectionIdFrame, SendFrame},
    packet::{self, header::GetDcid, Packet, PacketReader},
};
use tokio::task::{AbortHandle, JoinHandle};

use crate::{
    path::{Endpoint, Pathway, Socket},
    queue::RcvdPacketQueue,
    util::Channel,
    QuicInterface,
};

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub struct Signpost {
    cid: ConnectionId,
    peer: Option<SocketAddr>,
}

impl From<ConnectionId> for Signpost {
    fn from(value: ConnectionId) -> Self {
        Self {
            cid: value,
            peer: None,
        }
    }
}

impl From<SocketAddr> for Signpost {
    fn from(value: SocketAddr) -> Self {
        Self {
            cid: ConnectionId::default(),
            peer: Some(value),
        }
    }
}

struct InterfaceContext {
    inner: Arc<dyn QuicInterface>,
    task: AbortHandle,
}

impl Drop for InterfaceContext {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[doc(alias = "RouterInterface")]
#[derive(Default)]
pub struct QuicProto {
    interfaces: DashMap<SocketAddr, InterfaceContext>,
    // 叫 "路由表" 这样的名字
    connections: DashMap<Signpost, Arc<RcvdPacketQueue>>,
    // unrouted packets : ...<(packet, pathway, SocketAddr)>
    unrouted_packets: Channel<(Packet, Pathway, Socket)>,
}

impl fmt::Debug for QuicProto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuicProto")
            .field("interfaces", &"...")
            .field("connections", &"...")
            .field("listner", &"...")
            .finish()
    }
}

impl QuicProto {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_interface(
        self: &Arc<Self>,
        local_address: SocketAddr,
        interface: Arc<dyn QuicInterface>,
    ) -> JoinHandle<io::Result<Infallible>> {
        let entry = self
            .interfaces
            .entry(local_address)
            .and_modify(|ctx| ctx.task.abort());

        let this = self.clone();
        let recv_task = tokio::spawn(async move {
            let mut rcvd_pkts = Vec::with_capacity(3);
            loop {
                // way: local -> peer
                let (datagram, pathway, socket) = core::future::poll_fn(|cx| {
                    let interface = this.interfaces.get(&local_address).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "interface already be removed")
                    })?;
                    interface.inner.poll_recv(cx)
                })
                .await?;
                let datagram_size = datagram.len();
                // todo: parse packets with any length of dcid
                rcvd_pkts.extend(PacketReader::new(datagram, 8).flatten());

                // rfc9000 14.1
                // A server MUST discard an Initial packet that is carried in a UDP datagram with a payload that is smaller than
                // the smallest allowed maximum datagram size of 1200 bytes. A server MAY also immediately close the
                // connection by sending a CONNECTION_CLOSE frame with an error code of PROTOCOL_VIOLATION; see
                // Section 10.2.3.
                let is_initial_packet = |pkt: &Packet| matches!(pkt, Packet::Data(packet) if matches!(packet.header, packet::DataHeader::Long(packet::long::DataHeader::Initial(..))));

                for packet in rcvd_pkts
                    .drain(..)
                    .filter(|pkt| !(is_initial_packet(pkt) && datagram_size < 1200))
                {
                    this.deliver(packet, pathway, socket).await;
                }
            }
        });
        entry.insert(InterfaceContext {
            inner: interface,
            task: recv_task.abort_handle(),
        });
        recv_task
    }

    pub fn get_interface(&self, local_address: SocketAddr) -> io::Result<Arc<dyn QuicInterface>> {
        self.interfaces
            .get(&local_address)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "interface does not exist"))
            .map(|ctx| ctx.inner.clone())
    }

    pub fn del_interface(&self, local_address: SocketAddr) {
        self.interfaces.remove(&local_address);
    }

    pub async fn deliver(self: &Arc<Self>, packet: Packet, pathway: Pathway, socket: Socket) {
        let dcid = match &packet {
            Packet::VN(vn) => vn.get_dcid(),
            Packet::Retry(retry) => retry.get_dcid(),
            Packet::Data(data_packet) => data_packet.get_dcid(),
        };
        let signpost = if dcid.len() != 0 {
            Signpost::from(*dcid)
        } else {
            use Endpoint::*;
            let (Direct { addr } | Relay { agent: addr, .. }) = pathway.local();
            Signpost::from(addr)
        };

        if let Some(conn_iface) = self.connections.get(&signpost) {
            _ = conn_iface.deliver(packet, pathway, socket).await;
            return;
        }
        _ = self.unrouted_packets.send((packet, pathway, socket));
    }

    pub fn try_recv_unrouted_packet(&self) -> Option<(Packet, Pathway, Socket)> {
        self.unrouted_packets.try_recv().ok()
    }

    pub async fn recv_unrouted_packet(&self) -> (Packet, Pathway, Socket) {
        // channel will never be closed
        self.unrouted_packets.recv().await.unwrap()
    }

    // for origin_dcid
    pub fn add_router_entry(&self, signpost: Signpost, queue: Arc<RcvdPacketQueue>) {
        self.connections.insert(signpost, queue);
    }

    pub fn del_router_entry(&self, signpost: &Signpost) {
        self.connections.remove(signpost);
    }

    pub fn registry<ISSUED>(
        self: &Arc<Self>,
        rcvd_pkts_buf: Arc<RcvdPacketQueue>,
        issued_cids: ISSUED,
    ) -> RouterRegistry<ISSUED> {
        RouterRegistry {
            router_iface: self.clone(),
            rcvd_pkts_buf,
            issued_cids,
        }
    }
}

#[derive(Clone)]
pub struct RouterRegistry<ISSUED> {
    router_iface: Arc<QuicProto>,
    rcvd_pkts_buf: Arc<RcvdPacketQueue>,
    issued_cids: ISSUED,
}

impl<T> GenUniqueCid for RouterRegistry<T>
where
    T: Send + Sync + 'static,
{
    fn gen_unique_cid(&self) -> ConnectionId {
        core::iter::from_fn(|| Some(ConnectionId::random_gen_with_mark(8, 0x80, 0x7F)))
            .find(|cid| {
                let signpost = Signpost::from(*cid);
                let entry = self.router_iface.connections.entry(signpost);

                if matches!(entry, dashmap::Entry::Occupied(..)) {
                    return false;
                }

                entry.insert(self.rcvd_pkts_buf.clone());
                true
            })
            .unwrap()
    }
}

impl<T> RetireCid for RouterRegistry<T>
where
    T: Send + Sync + 'static,
{
    fn retire_cid(&self, cid: ConnectionId) {
        self.router_iface.del_router_entry(&Signpost::from(cid));
    }
}

impl<T> SendFrame<NewConnectionIdFrame> for RouterRegistry<T>
where
    T: SendFrame<NewConnectionIdFrame>,
{
    fn send_frame<I: IntoIterator<Item = NewConnectionIdFrame>>(&self, iter: I) {
        self.issued_cids.send_frame(iter);
    }
}

impl<T> ReceiveFrame<RetireConnectionIdFrame> for RouterRegistry<T>
where
    T: ReceiveFrame<RetireConnectionIdFrame, Output = ()>,
{
    type Output = ();

    fn recv_frame(&self, frame: &RetireConnectionIdFrame) -> Result<Self::Output, Error> {
        self.issued_cids.recv_frame(frame)
    }
}
