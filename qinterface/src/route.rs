use std::{
    net::SocketAddr,
    sync::{Arc, Mutex, OnceLock, Weak},
};

use dashmap::DashMap;
pub use qbase::packet::Packet;
use qbase::{
    cid::{ConnectionId, GenUniqueCid, RetireCid},
    error::Error,
    frame::{NewConnectionIdFrame, ReceiveFrame, RetireConnectionIdFrame, SendFrame},
    net::{
        addr::{BindAddr, RealAddr},
        route::{Link, Pathway},
    },
    packet::GetDcid,
};

use crate::queue::RcvdPacketQueue;
pub type Way = (BindAddr, Pathway, Link);

type ConnectlessPacketHandler = Box<dyn FnMut(Packet, Way) + Send>;

pub struct Router {
    table: DashMap<Signpost, Arc<RcvdPacketQueue>>,
    on_unrouted: Mutex<ConnectlessPacketHandler>,
}

impl Router {
    pub fn global() -> &'static Arc<Self> {
        static GLOBAL_ROUTER: OnceLock<Arc<Router>> = OnceLock::new();
        GLOBAL_ROUTER.get_or_init(|| {
            Arc::new(Router {
                table: DashMap::new(),
                on_unrouted: Mutex::new(Box::new(|_, _| {})),
            })
        })
    }

    // for origin_dcid
    pub fn insert(
        self: &Arc<Self>,
        signpost: Signpost,
        queue: Arc<RcvdPacketQueue>,
    ) -> RouterEntry {
        self.table.insert(signpost, queue.clone());
        RouterEntry {
            signpost,
            queue: Arc::downgrade(&queue),
            router: self.clone(),
        }
    }

    pub fn remove(&self, signpost: &Signpost) {
        self.table.remove(signpost);
    }

    fn find_entry(&self, packet: &Packet, link: &Link) -> Option<Arc<RcvdPacketQueue>> {
        let dcid = match packet {
            Packet::VN(vn) => vn.dcid(),
            Packet::Retry(retry) => retry.dcid(),
            Packet::Data(data_packet) => data_packet.dcid(),
        };

        if !dcid.is_empty() {
            let signpost = Signpost::from(*dcid);
            self.table.get(&signpost).map(|queue| queue.clone())
        } else {
            match link.dst() {
                RealAddr::Internet(socket_addr) => {
                    let signpost = Signpost::from(socket_addr);
                    self.table.get(&signpost).map(|queue| queue.clone())
                }
                _ => None,
            }
        }
    }

    pub async fn deliver(&self, packet: Packet, way: Way) {
        let rcvd_pkt_q = match self.find_entry(&packet, &way.2) {
            Some(rcvd_pkt_q) => rcvd_pkt_q,
            None => {
                // For packets that cannot be routed, this likely indicates a new connection.
                // In some cases, multiple threads (e.g., A and B) may be waiting for the lock,
                // and both would cause the server to create separate new connections.
                let mut on_unrouted = self.on_unrouted.lock().unwrap();
                // Therefore, we retry routing here to allow thread B to route its packet
                // to the connection created by thread A, instead of creating another new connection.
                match self.find_entry(&packet, &way.2) {
                    Some(rcvd_pkt_q) => rcvd_pkt_q,
                    None => {
                        (on_unrouted)(packet.clone(), way.clone());
                        return;
                    }
                }
            }
        };
        rcvd_pkt_q.deliver(packet, way).await;
    }

    pub fn on_connectless_packets<H>(&self, handler: H)
    where
        H: FnMut(Packet, Way) + Send + 'static,
    {
        *self.on_unrouted.lock().unwrap() = Box::new(handler);
    }

    pub fn registry_on_issuing_scid<T>(
        self: &Arc<Self>,
        rcvd_pkts_q: Arc<RcvdPacketQueue>,
        issued_cids: T,
    ) -> RouterRegistry<T> {
        RouterRegistry {
            router: self.clone(),
            rcvd_pkts_q,
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
#[must_use = "When RouterEntry dropped, this will remove the entry from the router table"]
pub struct RouterEntry {
    signpost: Signpost,
    queue: Weak<RcvdPacketQueue>,
    router: Arc<Router>,
}

impl RouterEntry {
    pub fn signpost(&self) -> Signpost {
        self.signpost
    }

    pub fn remove(&self) {
        self.router
            .table
            .remove_if(&self.signpost, |_, exist_queue| {
                Weak::ptr_eq(&Arc::downgrade(exist_queue), &self.queue)
            });
    }
}

impl Drop for RouterEntry {
    fn drop(&mut self) {
        self.remove();
    }
}

#[derive(Clone)]
pub struct RouterRegistry<TX> {
    router: Arc<Router>,
    rcvd_pkts_q: Arc<RcvdPacketQueue>,
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

                entry.insert(self.rcvd_pkts_q.clone());
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
