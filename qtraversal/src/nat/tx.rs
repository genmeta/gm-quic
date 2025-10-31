use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use tokio::time::timeout;

use super::{
    msg::{Packet, Request, Response, TransactionId},
    protocol::StunProtocol,
};
use crate::future;

#[derive(Clone)]
pub struct Transaction {
    stun_protocol: Arc<StunProtocol>,
    transaction_id: TransactionId,
    pending_response: Arc<future::Future<(Response, SocketAddr)>>,
    retry_times: u8,
    timeout: Duration,
}

impl Transaction {
    pub fn begin(stun_protocol: Arc<StunProtocol>, retry_times: u8, timeout: Duration) -> Self {
        let pending_response = Arc::new(future::Future::new());
        let transaction_id = TransactionId::random();
        stun_protocol.rigister(transaction_id, pending_response.clone());
        Self {
            stun_protocol,
            transaction_id,
            pending_response,
            retry_times,
            timeout,
        }
    }

    pub async fn send_request(
        &self,
        request: Request,
        dst: &SocketAddr,
    ) -> io::Result<Option<Response>> {
        let mut retry_times = self.retry_times;
        while retry_times > 0 {
            match timeout(self.timeout, self.do_tick(dst, request.clone())).await {
                Ok(result) => return result.map(Some),
                Err(_) => retry_times -= 1,
            }
        }
        Ok(None)
    }

    async fn do_tick(&self, dst: &SocketAddr, request: Request) -> io::Result<Response> {
        self.stun_protocol
            .send_stun_packet(Packet::Request(request), self.transaction_id, dst)
            .await?;
        let (response, _src) = self.pending_response.get().await.clone();
        Ok(response)
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        self.stun_protocol.remove(&self.transaction_id);
    }
}
