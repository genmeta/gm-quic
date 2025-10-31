use std::{
    future::poll_fn,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, ready},
};

use bytes::{BufMut, BytesMut};
use dashmap::DashMap;
use qbase::{
    net::{addr::BindUri, route::Link},
    util::ArcAsyncDeque,
};
use tokio_util::task::AbortOnDropHandle;
use tracing::{debug, warn};

use super::{
    StunIO,
    msg::{self, Packet, Request, Response, TransactionId, WritePacket, be_packet},
};
use crate::{future::Future, packet::StunHeader};

type ResponseRouter = Arc<DashMap<TransactionId, Arc<Future<(Response, SocketAddr)>>>>;

pub struct StunProtocol {
    iface: Arc<dyn StunIO>,
    bind_uri: BindUri,
    task: Mutex<Option<AbortOnDropHandle<()>>>,
    request_router: ArcAsyncDeque<(Request, TransactionId, SocketAddr)>,
    response_router: ResponseRouter,
}

impl std::fmt::Debug for StunProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StunProtocol")
            .field("iface", &"...")
            .field("router", &self.response_router)
            .finish()
    }
}

impl StunProtocol {
    pub fn new(iface: Arc<dyn StunIO>) -> Self {
        let request_router = ArcAsyncDeque::new();
        let response_router = ResponseRouter::default();
        let bind_uri = iface.stun_bind_uri();
        let recv_task = tokio::spawn({
            let request_router = request_router.clone();
            let response_router = response_router.clone();
            let iface = iface.clone();
            async move {
                while let Ok(()) = poll_fn(|cx| {
                    let (packet, link) = match ready!(iface.poll_stun_recv(cx)) {
                        Ok(ret) => ret,
                        Err(e) => return Poll::Ready(Err(e)),
                    };
                    if let Ok((_remain, (txid, payload))) = be_packet(&packet) {
                        match payload {
                            msg::Packet::Request(request) => {
                                request_router.push_back((request, txid, link.src()));
                            }
                            msg::Packet::Response(response) => {
                                if let Some((_id, recv_resp)) = response_router.remove(&txid) {
                                    let _ = recv_resp.assign((response, link.src()));
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
                    Poll::Ready(Ok(()))
                })
                .await
                {}
            }
        });

        Self {
            iface,
            task: Mutex::new(Some(AbortOnDropHandle::new(recv_task))),
            request_router,
            response_router,
            bind_uri,
        }
    }

    /// 关闭 StunProtocol 的后台任务
    pub fn poll_close(&self, cx: &mut Context) -> Poll<()> {
        let mut guard = self.task.lock().unwrap();
        if let Some(task) = guard.as_mut() {
            task.abort();
            _ = ready!(Pin::new(task).poll(cx));
            *guard = None;
        }
        self.request_router.close();
        Poll::Ready(())
    }

    pub fn resume(&self) {
        warn!(target: "stun", local_addr=?self.local_addr(), "Resuming stun protocol");
        self.response_router.clear();
    }

    pub async fn send_stun_packet(
        &self,
        packet: Packet,
        txid: TransactionId,
        dst: &SocketAddr,
    ) -> std::io::Result<usize> {
        let mut buf = vec![0u8; 128];
        let (mut _stun_hdr, mut stun_body) = buf.split_at_mut(StunHeader::encoding_size());
        let origin = stun_body.remaining_mut();
        stun_body.put_packet(&txid, &packet);
        let consume = origin - stun_body.remaining_mut();
        buf.truncate(StunHeader::encoding_size() + consume);

        let link = Link::new(self.iface.local_addr()?, *dst);
        poll_fn(|cx| {
            self.iface
                .poll_stun_send(cx, BytesMut::from(buf.as_slice()), link)
        })
        .await
    }

    pub async fn receive_request(&self) -> Option<(Request, TransactionId, SocketAddr)> {
        self.request_router.pop().await
    }

    pub fn rigister(
        &self,
        transaction_id: TransactionId,
        future: Arc<Future<(Response, SocketAddr)>>,
    ) {
        self.response_router.insert(transaction_id, future);
    }

    pub fn remove(&self, transaction_id: &TransactionId) {
        let _ = self.response_router.remove(transaction_id);
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.iface.local_addr()
    }

    pub fn bind_uri(&self) -> BindUri {
        self.bind_uri.clone()
    }
}
