use std::{
    net::SocketAddr,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll},
};

use dashmap::DashMap;
use qbase::util::ArcAsyncDeque;
use qinterface::logical::{QuicInterface, WeakQuicInterface, component::Component};
use tokio::sync::SetOnce;
use tracing::debug;

use super::msg::{self, Packet, Request, Response, TransactionId};
use crate::Link;

type ResponseRouter = Arc<DashMap<TransactionId, Arc<SetOnce<(Response, SocketAddr)>>>>;

#[derive(Default, Debug, Clone)]
pub struct StunRouter {
    request_router: ArcAsyncDeque<(Request, TransactionId, SocketAddr)>,
    response_router: ResponseRouter,
}

impl StunRouter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn deliver_stun_packet(&self, txid: TransactionId, packet: Packet, link: Link) {
        match packet {
            msg::Packet::Request(request) => {
                self.request_router.push_back((request, txid, link.dst()));
            }
            msg::Packet::Response(response) => {
                if let Some((_id, recv_resp)) = self.response_router.remove(&txid) {
                    let _ = recv_resp.set((response, link.dst()));
                } else {
                    debug!(
                        target: "stun",
                        ?txid, %link, from =% link.dst(),
                        "Unknown request transaction id",
                    );
                }
            }
        }
    }

    pub async fn receive_request(&self) -> Option<(Request, TransactionId, SocketAddr)> {
        self.request_router.pop().await
    }

    pub fn clear(&self) {
        // TODO: self.request_router.clear();
        self.response_router.clear();
    }

    pub(super) fn register(
        &self,
        transaction_id: TransactionId,
        future: Arc<SetOnce<(Response, SocketAddr)>>,
    ) {
        self.response_router.insert(transaction_id, future);
    }

    pub(super) fn remove(&self, transaction_id: &TransactionId) {
        let _ = self.response_router.remove(transaction_id);
    }
}

// #[derive(Default, Debug, Clone)]
// pub struct StunRouters<IO: RefInterface> {
//     // agent -> router
//     routers: DashMap<SocketAddr, StunRouter>,
//     ref_iface: IO,
// }

// impl<IO: RefInterface> StunRouters<IO> {
//     pub fn new(ref_iface: IO, routers: impl IntoIterator<Item = (SocketAddr, StunRouter)>) -> Self {
//         Self {
//             ref_iface,
//             routers: routers.into_iter().collect(),
//         }
//     }

//     pub fn ref_iface(&self) -> &IO {
//         &self.ref_iface
//     }

//     pub fn router(&self, agent_addr: SocketAddr) -> StunRouter {
//         self.routers.entry(agent_addr).or_default().clone()
//     }
// }

#[derive(Debug)]
struct StunRouterComponentInner {
    router: StunRouter,
    ref_iface: WeakQuicInterface,
}

#[derive(Debug)]
pub struct StunRouterComponent {
    inner: Mutex<StunRouterComponentInner>,
}

impl StunRouterComponent {
    pub fn new(ref_iface: WeakQuicInterface) -> Self {
        Self {
            inner: Mutex::new(StunRouterComponentInner {
                router: StunRouter::new(),
                ref_iface,
            }),
        }
    }

    fn lock_inner(&self) -> MutexGuard<'_, StunRouterComponentInner> {
        self.inner.lock().expect("StunRouter lock poisoned")
    }

    pub fn ref_iface(&self) -> WeakQuicInterface {
        self.lock_inner().ref_iface.clone()
    }

    pub fn router(&self) -> StunRouter {
        self.lock_inner().router.clone()
    }
}

impl Component for StunRouterComponent {
    fn reinit(&self, quic_iface: &QuicInterface) {
        let mut inner = self.lock_inner();
        if inner.ref_iface.same_io(&quic_iface.downgrade()) {
            return;
        }
        *inner = StunRouterComponentInner {
            router: StunRouter::new(),
            ref_iface: quic_iface.downgrade(),
        };
    }

    fn poll_shutdown(&self, _cx: &mut Context<'_>) -> Poll<()> {
        Poll::Ready(())
    }
}
