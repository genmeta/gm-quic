use std::{
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, OnceLock},
};

use dashmap::DashMap;
use futures::{Sink, SinkExt, Stream, StreamExt, lock::Mutex, never::Never};
use qbase::{
    cid::{ConnectionId, GenUniqueCid, RetireCid},
    error::Error,
    frame::{NewConnectionIdFrame, ReceiveFrame, RetireConnectionIdFrame, SendFrame},
    net::{
        address::{BindAddr, RealAddr},
        route::{Link, Pathway},
    },
    packet::{GetDcid, Packet},
};

use crate::queue::RcvdPacketQueue;

pub type Received = (BindAddr, Packet, Pathway, Link);

type UnroutedPacketSink = Pin<Box<dyn Sink<Received, Error = Never> + Send + Sync>>;

pub struct Router {
    table: DashMap<Signpost, Arc<RcvdPacketQueue>>,
    unrouted: Mutex<UnroutedPacketSink>,
}

impl Router {
    pub fn global() -> &'static Arc<Self> {
        static GLOBAL_ROUTER: OnceLock<Arc<Router>> = OnceLock::new();
        GLOBAL_ROUTER.get_or_init(|| {
            Arc::new(Router {
                table: DashMap::new(),
                unrouted: Mutex::new(Box::pin(futures::sink::drain())),
            })
        })
    }

    // for origin_dcid
    pub fn insert(&self, signpost: Signpost, queue: Arc<RcvdPacketQueue>) {
        self.table.insert(signpost, queue);
    }

    pub fn remove(&self, signpost: &Signpost) {
        self.table.remove(signpost);
    }

    pub async fn try_deliver(
        &self,
        (bind_addr, packet, pathway, link): Received,
    ) -> Result<(), Received> {
        let dcid = match &packet {
            Packet::VN(vn) => vn.dcid(),
            Packet::Retry(retry) => retry.dcid(),
            Packet::Data(data_packet) => data_packet.dcid(),
        };
        let signpost = if !dcid.is_empty() {
            Signpost::from(*dcid)
        } else {
            match *pathway.local() {
                RealAddr::Inet(socket_addr) => Signpost::from(socket_addr),
                _ => {
                    tracing::warn!(
                        "receive a packet with empty dcid, and failed to fallback to zero length cid"
                    );
                    return Err((bind_addr, packet, pathway, link));
                }
            }
        };

        if let Some(rcvd_pkt_q) = self.table.get(&signpost).map(|queue| queue.clone()) {
            _ = rcvd_pkt_q.deliver(bind_addr, packet, pathway, link).await;
            return Ok(());
        }
        Err((bind_addr, packet, pathway, link))
    }

    pub async fn deliver(&self, received: Received) {
        if let Err(received) = self.try_deliver(received).await {
            let mut unrouted = self.unrouted.lock().await;
            _ = unrouted.send(received).await;
            _ = unrouted.flush().await;
        }
    }

    pub async fn deliver_all(&self, mut stream: impl Stream<Item = Received> + Unpin) {
        while let Some(received) = stream.next().await {
            self.deliver(received).await;
        }
    }

    pub async fn register_unrouted_sink<S>(&self, handler: S)
    where
        S: Sink<Received, Error = Never> + Send + Sync + 'static,
    {
        *self.unrouted.lock().await = Box::pin(handler);
    }

    pub fn registry<T>(
        self: &Arc<Self>,
        rcvd_pkts_buf: Arc<RcvdPacketQueue>,
        issued_cids: T,
    ) -> RouterRegistry<T> {
        RouterRegistry {
            router: self.clone(),
            rcvd_pkts_buf,
            issued_cids,
        }
    }
}

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

#[derive(Clone)]
pub struct RouterRegistry<TX> {
    router: Arc<Router>,
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
                let entry = self.router.table.entry(signpost);

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
        self.router.remove(&Signpost::from(cid));
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
