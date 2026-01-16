use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use qinterface::RefInterface;
use tokio::{sync::SetOnce, time::timeout};

use super::{
    msg::{Packet, Request, Response, TransactionId},
    router::StunRouter,
};
use crate::nat::iface::StunIO;

#[derive(Clone)]
pub struct Transaction<IO> {
    stun_router: StunRouter,
    ref_iface: IO,
    transaction_id: TransactionId,
    pending_response: Arc<SetOnce<(Response, SocketAddr)>>,
    retry_times: u8,
    timeout: Duration,
}

impl<IO: RefInterface> Transaction<IO> {
    pub fn begin(
        ref_iface: IO,
        stun_router: StunRouter,
        retry_times: u8,
        timeout: Duration,
    ) -> Self {
        let pending_response = Arc::new(SetOnce::new());
        let transaction_id = TransactionId::random();
        stun_router.register(transaction_id, pending_response.clone());
        Self {
            stun_router,
            ref_iface,
            transaction_id,
            pending_response,
            retry_times,
            timeout,
        }
    }
    pub async fn send_request(
        &self,
        request: Request,
        dst: SocketAddr,
    ) -> io::Result<Option<Response>> {
        let mut retry_times = self.retry_times;
        while retry_times > 0 {
            match timeout(self.timeout, self.do_tick(dst, request.clone())).await {
                Ok(result) => return result.map(Some),
                Err(_error) => retry_times -= 1,
            }
        }
        Ok(None)
    }

    async fn do_tick(&self, dst: SocketAddr, request: Request) -> io::Result<Response> {
        self.ref_iface
            .iface()
            .send_stun_packet(Packet::Request(request), self.transaction_id, dst)
            .await?;
        let (response, _src) = self.pending_response.wait().await.clone();
        Ok(response)
    }
}

impl<IO> Drop for Transaction<IO> {
    fn drop(&mut self) {
        self.stun_router.remove(&self.transaction_id);
    }
}
