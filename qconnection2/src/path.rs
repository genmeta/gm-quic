mod aa;
mod alive;
pub mod burst;
pub mod entry;
mod paths;
mod util;

use core::net;
use std::{io, sync::Arc};

pub use aa::*;
pub use alive::*;
pub use paths::*;
use qbase::frame::{PathChallengeFrame, PathResponseFrame, ReceiveFrame};
pub use util::*;

use crate::router;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Endpoint {
    Direct {
        addr: net::SocketAddr,
    },
    Relay {
        agent: net::SocketAddr,
        inner: net::SocketAddr,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pathway {
    pub local: Endpoint,
    pub remote: Endpoint,
}

impl Pathway {
    pub fn flip(self) -> Self {
        Self {
            local: self.remote,
            remote: self.local,
        }
    }

    pub fn src(&self) -> net::SocketAddr {
        match self.local {
            Endpoint::Direct { addr } => addr,
            Endpoint::Relay { agent, .. } => agent,
        }
    }

    pub fn dst(&self) -> net::SocketAddr {
        match self.remote {
            Endpoint::Direct { addr } => addr,
            Endpoint::Relay { agent, .. } => agent,
        }
    }
}

pub struct Path {
    way: Pathway,
    cc: qcongestion::ArcCC,
    anti_amplifier: aa::AntiAmplifier,
    last_recv_time: alive::LastReceiveTime,
    challenge_sndbuf: util::SendBuffer<PathChallengeFrame>,
    response_sndbuf: util::SendBuffer<PathResponseFrame>,
    response_rcvbuf: util::RecvBuffer<PathResponseFrame>,

    conn_if: Arc<router::ConnInterface>,
}

impl Path {
    pub fn cc(&self) -> &qcongestion::ArcCC {
        &self.cc
    }

    pub fn on_rcvd(&self, amount: usize) {
        self.anti_amplifier.on_rcvd(amount);
        self.last_recv_time.update();
    }

    pub fn grant_anti_amplifier(&self) {
        self.anti_amplifier.grant();
    }

    pub fn new_packet(&self) -> Option<bytes::BytesMut> {
        self.conn_if.new_packet(self.way)
    }

    pub async fn send_packet(&self, pkt: &[u8], dst: net::SocketAddr) -> io::Result<()> {
        self.conn_if.send_packet(pkt, self.way, dst).await
    }

    pub fn begin_validation<F>(self: &Arc<Self>, on_failed: F) -> tokio::task::JoinHandle<()>
    where
        F: FnOnce() + Send + 'static,
    {
        let this = self.clone();
        tokio::spawn(async move {
            let challenge = PathChallengeFrame::random();
            for _ in 0..3 {
                use qcongestion::CongestionControl;
                let pto = this.cc.pto_time(qbase::Epoch::Data);
                this.challenge_sndbuf.write(challenge);
                match tokio::time::timeout(pto, this.response_rcvbuf.receive()).await {
                    Ok(Some(response)) if *response == *challenge => {
                        this.anti_amplifier.grant();
                        return;
                    }
                    // 外部发生变化，导致路径验证任务作废
                    Ok(None) => return,
                    // 超时或者收到不对的response，按"停-等协议"，继续再发一次Challenge，最多3次
                    _ => continue,
                }
            }
            this.anti_amplifier.abort();
            (on_failed)();
        })
    }

    pub fn begin_tick(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let this = self.clone();
        tokio::spawn(async move {
            use qcongestion::CongestionControl;
            loop {
                tokio::time::sleep(tokio::time::Duration::from_micros(10)).await;
                this.cc.do_tick();
            }
        })
    }
}

impl Drop for Path {
    fn drop(&mut self) {
        self.response_rcvbuf.dismiss();
    }
}

impl ReceiveFrame<PathChallengeFrame> for Path {
    type Output = ();

    fn recv_frame(&self, frame: &PathChallengeFrame) -> Result<Self::Output, qbase::error::Error> {
        self.challenge_sndbuf.write(*frame);
        Ok(())
    }
}

impl ReceiveFrame<PathResponseFrame> for Path {
    type Output = ();

    fn recv_frame(&self, frame: &PathResponseFrame) -> Result<Self::Output, qbase::error::Error> {
        self.response_rcvbuf.write(*frame);
        Ok(())
    }
}
