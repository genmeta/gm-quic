use std::{fmt, io, net::SocketAddr, sync::Arc};

use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use qbase::{
    cid::{ConnectionId, GenUniqueCid, RetireCid},
    error::Error,
    frame::{NewConnectionIdFrame, ReceiveFrame, RetireConnectionIdFrame, SendFrame},
    net::{
        PacketHeader,
        route::{EndpointAddr, Link, Pathway},
    },
    packet::{self, Packet, PacketReader, header::GetDcid},
};
use tokio::task::{AbortHandle, JoinHandle};

use crate::{QuicInterface, queue::RcvdPacketQueue, util::Channel};

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
    router_table: DashMap<Signpost, Arc<RcvdPacketQueue>>,
    unrouted_packets: Channel<(Packet, Pathway, Link)>,
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
    /// to check if there is a packet in the queue.
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
    ) -> JoinHandle<io::Result<()>> {
        let entry = self
            .interfaces
            .entry(local_addr)
            .and_modify(|ctx| ctx.task.abort());

        let this = self.clone();
        let recv_task = tokio::spawn(async move {
            let mut rcvd_pkts = Vec::with_capacity(3);

            let mut recv_bufs: Vec<BytesMut> = vec![];
            let mut recv_hdrs: Vec<PacketHeader> = vec![];

            loop {
                // way: local -> peer
                let receive = core::future::poll_fn(|cx| {
                    let interface = this.interfaces.get(&local_addr).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "interface already be removed")
                    })?;
                    let max_segments = interface.inner.max_segments();
                    let max_segment_size = interface.inner.max_segment_size();
                    recv_bufs.resize_with(max_segments, || {
                        Bytes::from_owner(vec![0u8; max_segment_size]).into()
                    });
                    recv_hdrs.resize_with(max_segments, PacketHeader::empty);
                    interface
                        .inner
                        .poll_recv(cx, &mut recv_bufs, &mut recv_hdrs)
                });

                for (datagram, header) in receive
                    .await
                    .map(|rcvd| recv_bufs.drain(..rcvd).zip(recv_hdrs.drain(..rcvd)))?
                    .map(|(mut seg, hdr)| (seg.split_to(seg.len().min(hdr.seg_size() as _)), hdr))
                {
                    let datagram_size = datagram.len();
                    // todo: parse packets with any length of dcid, but this doesn't seem to matter because the DCID of the perr is chosen by ourselves
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
                        this.deliver(packet, header.pathway(), header.link()).await;
                    }
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

    async fn try_deliver(
        &self,
        packet: Packet,
        pathway: Pathway,
        link: Link,
    ) -> Result<(), (Packet, Pathway, Link)> {
        let dcid = match &packet {
            Packet::VN(vn) => vn.dcid(),
            Packet::Retry(retry) => retry.dcid(),
            Packet::Data(data_packet) => data_packet.dcid(),
        };
        let signpost = if !dcid.is_empty() {
            Signpost::from(*dcid)
        } else {
            use EndpointAddr::*;
            let (Direct { addr } | Agent { agent: addr, .. }) = pathway.local();
            Signpost::from(addr)
        };

        if let Some(rcvd_pkt_q) = self.router_table.get(&signpost).map(|queue| queue.clone()) {
            _ = rcvd_pkt_q.deliver(packet, pathway, link).await;
            return Ok(());
        }
        Err((packet, pathway, link))
    }

    pub async fn deliver(&self, packet: Packet, pathway: Pathway, link: Link) {
        if let Err(received) = self.try_deliver(packet, pathway, link).await {
            _ = self.unrouted_packets.send(received);
        }
    }

    /// Dismiss all unrouted packets.
    ///
    /// This is useful for a quic client that dont need to handle unrouted packets.
    ///
    /// Once this is called, [`Self::recv_unrouted_packet`] always will return None.
    ///
    /// **Once this operation is called it cannot be undone**
    pub fn dismiss_unrouted_packets(&self) {
        self.unrouted_packets.close();
    }

    pub async fn recv_unrouted_packet(&self) -> Option<(Packet, Pathway, Link)> {
        loop {
            let (packet, pathway, link) = self.unrouted_packets.recv().await?;
            match self.try_deliver(packet, pathway, link).await {
                Ok(()) => continue,
                Err((packet, pathway, link)) => return Some((packet, pathway, link)),
            }
        }
    }

    // for origin_dcid
    pub fn add_router_entry(&self, signpost: Signpost, queue: Arc<RcvdPacketQueue>) {
        self.router_table.insert(signpost, queue);
    }

    pub fn del_router_entry(&self, signpost: &Signpost) {
        self.router_table.remove(signpost);
    }

    pub fn registry<T>(
        self: &Arc<Self>,
        rcvd_pkts_buf: Arc<RcvdPacketQueue>,
        issued_cids: T,
    ) -> RouterRegistry<T> {
        RouterRegistry {
            router_iface: self.clone(),
            rcvd_pkts_buf,
            issued_cids,
        }
    }
}

#[derive(Clone)]
pub struct RouterRegistry<TX> {
    router_iface: Arc<QuicProto>,
    rcvd_pkts_buf: Arc<RcvdPacketQueue>,
    issued_cids: TX,
}

impl<T> GenUniqueCid for RouterRegistry<T>
where
    T: Send + Sync + 'static,
{
    fn gen_unique_cid(&self) -> ConnectionId {
        core::iter::from_fn(|| Some(ConnectionId::random_gen_with_mark(8, 0x80, 0x7F)))
            .find(|cid| {
                let signpost = Signpost::from(*cid);
                let entry = self.router_iface.router_table.entry(signpost);

                if matches!(entry, dashmap::Entry::Occupied(..)) {
                    return false;
                }

                entry.insert(self.rcvd_pkts_buf.clone());
                true
            })
            .unwrap()
    }
}

impl<TX> RetireCid for RouterRegistry<TX>
where
    TX: Send + Sync + 'static,
{
    fn retire_cid(&self, cid: ConnectionId) {
        self.router_iface.del_router_entry(&Signpost::from(cid));
    }
}

impl<TX> SendFrame<NewConnectionIdFrame> for RouterRegistry<TX>
where
    TX: SendFrame<NewConnectionIdFrame>,
{
    fn send_frame<I: IntoIterator<Item = NewConnectionIdFrame>>(&self, iter: I) {
        self.issued_cids.send_frame(iter);
    }
}

impl<RX> ReceiveFrame<RetireConnectionIdFrame> for RouterRegistry<RX>
where
    RX: ReceiveFrame<RetireConnectionIdFrame, Output = ()>,
{
    type Output = ();

    fn recv_frame(&self, frame: &RetireConnectionIdFrame) -> Result<Self::Output, Error> {
        self.issued_cids.recv_frame(frame)
    }
}
