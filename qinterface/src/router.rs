use std::{convert::Infallible, fmt, io, net::SocketAddr, sync::Arc};

use dashmap::DashMap;
use qbase::{
    cid::{ConnectionId, GenUniqueCid, RetireCid},
    error::Error,
    frame::{NewConnectionIdFrame, ReceiveFrame, RetireConnectionIdFrame, SendFrame},
    packet::{self, header::GetDcid, Packet, PacketReader},
};
use tokio::task::JoinHandle;

use crate::{
    buffer::RcvdPacketBuffer,
    path::{Endpoint, Pathway},
    QuicInterface, SendCapability,
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

pub type QuicListener = Box<dyn Fn(Arc<QuicProto>, Packet, Pathway) + Send + Sync>;

#[doc(alias = "RouterInterface")]
#[derive(Default)]
pub struct QuicProto {
    interfaces: DashMap<SocketAddr, Arc<dyn QuicInterface>>,
    connections: DashMap<Signpost, Arc<RcvdPacketBuffer>>,
    listner: Option<QuicListener>,
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

    pub fn with_listener(listner: QuicListener) -> Self {
        Self {
            listner: Some(listner),
            ..Default::default()
        }
    }

    pub fn add_interface(
        self: &Arc<Self>,
        local_address: SocketAddr,
        interface: Arc<dyn QuicInterface>,
    ) -> JoinHandle<io::Result<Infallible>> {
        struct InterfaceGuard {
            addr: SocketAddr,
            proto: Arc<QuicProto>,
        }

        impl Drop for InterfaceGuard {
            fn drop(&mut self) {
                self.proto.interfaces.remove(&self.addr);
            }
        }

        let this = self.clone();
        tokio::spawn(async move {
            this.interfaces.insert(local_address, interface.clone());
            let _guard = InterfaceGuard {
                addr: local_address,
                proto: this.clone(),
            };
            let mut rcvd_pkts = Vec::with_capacity(3);
            loop {
                // way: local -> peer
                let (datagram, pathway) =
                    core::future::poll_fn(|cx| interface.poll_recv(cx)).await?;
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
                    this.route_packet(packet, pathway).await;
                }
            }
        })
    }

    pub async fn route_packet(self: &Arc<Self>, packet: Packet, pathway: Pathway) {
        let dcid = match &packet {
            Packet::VN(vn) => vn.get_dcid(),
            Packet::Retry(retry) => retry.get_dcid(),
            Packet::Data(data_packet) => data_packet.get_dcid(),
        };
        let signpost = if dcid.len() != 0 {
            Signpost::from(*dcid)
        } else {
            use Endpoint::*;
            let (Direct { addr } | Relay { agent: addr, .. }) = pathway.local;
            Signpost::from(addr)
        };

        if let Some(conn_iface) = self.connections.get(&signpost) {
            _ = conn_iface.recv_from(packet, pathway).await;
            return;
        }
        if let Some(listener) = self.listner.as_ref() {
            (listener)(self.clone(), packet, pathway);
        }
    }

    pub fn send_capability(&self, on: Pathway) -> io::Result<SendCapability> {
        self.interfaces
            .get(&on.src())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no interface"))?
            .value()
            .send_capability(on)
    }

    pub async fn send_packets(
        &self,
        mut pkts: &[io::IoSlice<'_>],
        way: Pathway,
        dst: SocketAddr,
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

    // for origin_dcid
    pub fn register(&self, signpost: Signpost, buffer: Arc<RcvdPacketBuffer>) {
        self.connections.insert(signpost, buffer);
    }

    pub fn unregister(&self, signpost: &Signpost) {
        self.connections.remove(signpost);
    }

    pub fn registry<ISSUED>(
        self: &Arc<Self>,
        rcvd_pkts_buf: Arc<RcvdPacketBuffer>,
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
    rcvd_pkts_buf: Arc<RcvdPacketBuffer>,
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
        self.router_iface.unregister(&Signpost::from(cid));
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
