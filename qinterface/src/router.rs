use std::{fmt, io, net::SocketAddr, sync::Arc};

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
    util::{Channel, TryRecvError},
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

    /// Add a new interface for quic connections to send and receive packets.
    ///
    /// ### Listen
    ///
    /// A task will be spawned to poll the interface to receive packets(by calling [`QuicInterface::poll_recv`]).
    ///
    /// When a packet is received, it will be delivered to the corresponding connection if it exists.
    ///
    /// Otherwise, it will be stored in the unrouted packets queue, you can get it by calling [`Self::recv_unrouted_packet`],
    /// or [`Self::try_recv_unrouted_packet`] to check if there is a packet in the queue.
    /// For quic server, they can accept connections by handling unrouted packets.
    ///
    /// If you want to dismiss all unrouted packets, you can call [`Self::dismiss_unrouted_packets`].
    ///
    /// ### Note
    ///
    /// If you add an interface with the same local address, the old interface will be replaced, and the exist receive task
    /// on interface(if exist) will be aborted.
    ///
    /// Though the interface is replaced, the connections that are using the old interface will not be affected.
    pub fn add_interface(
        self: &Arc<Self>,
        local_addr: SocketAddr,
        interface: Arc<dyn QuicInterface>,
    ) -> JoinHandle<io::Error> {
        let entry = self
            .interfaces
            .entry(local_addr)
            .and_modify(|ctx| ctx.task.abort());

        let this = self.clone();
        let recv_task = tokio::spawn(async move {
            let mut rcvd_pkts = Vec::with_capacity(3);
            loop {
                // way: local -> peer
                let recv = core::future::poll_fn(|cx| {
                    let interface = this.interfaces.get(&local_addr).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "interface already be removed")
                    })?;
                    interface.inner.poll_recv(cx)
                });
                let (datagram, pathway, socket) = match recv.await {
                    Ok(t) => t,
                    Err(e) => return e,
                };
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

    pub fn get_interface(&self, local_addr: SocketAddr) -> io::Result<Arc<dyn QuicInterface>> {
        self.interfaces
            .get(&local_addr)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "interface does not exist"))
            .map(|ctx| ctx.inner.clone())
    }

    /// Remove the interface by the local address.
    ///
    /// If the interface exist, it will be removed, and the receive task on the interface will be aborted.
    pub fn del_interface(&self, local_addr: SocketAddr) {
        self.interfaces.remove(&local_addr);
    }

    /// Remove the interface by the local address if the condition is [`true`].
    ///
    /// Its better to use this method to remove the interface than [`Self::del_interface`].
    pub fn del_interface_if<P>(&self, local_addr: SocketAddr, f: P) -> bool
    where
        P: for<'a> FnOnce(&'a Arc<dyn QuicInterface>, &'a AbortHandle) -> bool,
    {
        if let dashmap::Entry::Occupied(entry) = self.interfaces.entry(local_addr) {
            if f(&entry.get().inner, &entry.get().task) {
                entry.remove();
                return true;
            }
        }
        false
    }

    pub async fn deliver(self: &Arc<Self>, packet: Packet, pathway: Pathway, socket: Socket) {
        let dcid = match &packet {
            Packet::VN(vn) => vn.get_dcid(),
            Packet::Retry(retry) => retry.get_dcid(),
            Packet::Data(data_packet) => data_packet.get_dcid(),
        };
        let signpost = if !dcid.is_empty() {
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

    /// Dismiss all unrouted packets.
    ///
    /// This is useful for a quic client that dont need to handle unrouted packets.
    ///
    /// Once this is called, [`Self::try_recv_unrouted_packet`] will always return [`TryRecvError::Closed`],
    /// and [`Self::recv_unrouted_packet`] will return None.
    ///
    /// **Once this operation is called it cannot be undone**
    pub fn dismiss_unrouted_packets(&self) {
        self.unrouted_packets.close();
    }

    pub fn try_recv_unrouted_packet(&self) -> Result<(Packet, Pathway, Socket), TryRecvError> {
        self.unrouted_packets.try_recv()
    }

    pub async fn recv_unrouted_packet(&self) -> Option<(Packet, Pathway, Socket)> {
        self.unrouted_packets.recv().await
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
