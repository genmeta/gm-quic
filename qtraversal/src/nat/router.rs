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

type RequestPacket = (TransactionId, Request, SocketAddr);

type ResponseRouter = Arc<DashMap<TransactionId, Arc<SetOnce<(Response, SocketAddr)>>>>;

#[derive(Debug, Clone)]
pub struct StunRouter {
    request_router: ArcAsyncDeque<(Request, TransactionId, SocketAddr)>,
    response_router: ResponseRouter,
}

impl StunRouter {
    pub fn new() -> Self {
        Self {
            request_router: ArcAsyncDeque::new(),
            response_router: ResponseRouter::default(),
        }
    }

    pub fn deliver_stun_packet(&self, txid: TransactionId, packet: Packet, link: Link) {
        match packet {
            msg::Packet::Request(request) => {
                self.request_router.push_back((request, txid, link.src()));
            }
            msg::Packet::Response(response) => {
                if let Some((_id, recv_resp)) = self.response_router.remove(&txid) {
                    let _ = recv_resp.set((response, link.src()));
                } else {
                    debug!(
                        target: "stun",
                        ?txid, %link, from =% link.src(),
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

// pub fn resume(&self)
//     where
//         IO: Interface,
//     {
//         warn!(target: "stun", local_addr=?self.local_addr(), "Resuming stun protocol");
//         self.response_router.clear();
//     }

//     pub async fn send_stun_packet(
//         &self,
//         packet: Packet,
//         txid: TransactionId,
//         dst: &SocketAddr,
//     ) -> std::io::Result<()>
//     where
//         IO: Interface,
//     {
//         let mut buf = BytesMut::zeroed(128);
//         let (mut stun_hdr, mut stun_body) = buf.split_at_mut(StunHeader::encoding_size());

//         // put stun header
//         stun_hdr.put_stun_header(&StunHeader::new(0));

//         // put stun body
//         let origin = stun_body.remaining_mut();
//         stun_body.put_packet(&txid, &packet);
//         let consumed = origin - stun_body.remaining_mut();
//         buf.truncate(StunHeader::encoding_size() + consumed);

//         let bufs = &[io::IoSlice::new(&buf)];

//         // assemble packet header
//         let link = Link::new(self.iface.real_addr()?, RealAddr::Internet(*dst));
//         let pathway = link.into();

//         let hdr = qbase::net::route::PacketHeader::new(pathway, link, 64, None, 0);

//         self.iface.sendmmsg(bufs, hdr).await
//     }

//     pub fn local_addr(&self) -> io::Result<SocketAddr>
//     where
//         IO: Interface,
//     {
//         let real_addr = self.iface.real_addr()?;
//         real_addr.try_into().map_err(io::Error::other)
//     }

//     pub fn bind_uri(&self) -> BindUri
//     where
//         IO: Interface,
//     {
//         self.iface.bind_uri()
//     }

#[derive(Debug)]
pub struct StunRouterComponent {
    stun_protocol: Mutex<(StunRouter, WeakQuicInterface)>,
}

impl StunRouterComponent {
    pub fn new(weak_iface: WeakQuicInterface) -> Self {
        Self {
            stun_protocol: Mutex::new((StunRouter::new(), weak_iface)),
        }
    }

    fn lock_protocol(&self) -> MutexGuard<'_, (StunRouter, WeakQuicInterface)> {
        self.stun_protocol
            .lock()
            .expect("StunProtocol lock poisoned")
    }

    pub fn router(&self) -> StunRouter {
        self.lock_protocol().0.clone()
    }

    pub fn iface(&self) -> WeakQuicInterface {
        self.lock_protocol().1.clone()
    }
}

impl Component for StunRouterComponent {
    fn reinit(&self, quic_iface: &QuicInterface) {
        let mut protocol = self.lock_protocol();
        if protocol.1.same_io(&quic_iface.downgrade()) {
            return;
        }
        *protocol = (StunRouter::new(), quic_iface.downgrade());
    }

    fn poll_shutdown(&self, _cx: &mut Context<'_>) -> Poll<()> {
        Poll::Ready(())
    }
}
