use std::{
    io::{self},
    net::SocketAddr,
    ops::Deref,
    sync::{Arc, Mutex},
};

mod aa;
pub mod burst;
pub mod entry;
mod paths;
pub use aa::*;
pub use paths::*;

mod util;
use qbase::{
    error::Error,
    frame::{PathChallengeFrame, PathResponseFrame, ReceiveFrame},
};
use qcongestion::ArcCC;
use tokio::time::Instant;
pub use util::*;

use crate::{interface::SendCapability, router::ConnInterface};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Endpoint {
    Direct {
        addr: SocketAddr,
    },
    Relay {
        agent: SocketAddr,
        inner: SocketAddr,
    },
}

impl Deref for Endpoint {
    type Target = SocketAddr;

    fn deref(&self) -> &Self::Target {
        match self {
            Endpoint::Direct { addr } => addr,
            Endpoint::Relay { inner, .. } => inner,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pathway {
    pub local: Endpoint,
    pub remote: Endpoint,
}

impl Pathway {
    pub fn new(local: Endpoint, remote: Endpoint) -> Self {
        Self { local, remote }
    }

    pub fn flip(self) -> Self {
        Self {
            local: self.remote,
            remote: self.local,
        }
    }

    pub fn src(&self) -> SocketAddr {
        match self.local {
            Endpoint::Direct { addr } => addr,
            Endpoint::Relay { agent, .. } => agent,
        }
    }

    pub fn dst(&self) -> SocketAddr {
        match self.remote {
            Endpoint::Direct { addr } => addr,
            Endpoint::Relay { agent, .. } => agent,
        }
    }
}

pub struct Path {
    way: Pathway,
    cc: ArcCC,
    anti_amplifier: AntiAmplifier,
    last_recv_time: Mutex<Instant>,
    challenge_sndbuf: SendBuffer<PathChallengeFrame>,
    response_sndbuf: SendBuffer<PathResponseFrame>,
    response_rcvbuf: RecvBuffer<PathResponseFrame>,

    conn_iface: Arc<ConnInterface>,
}

impl Path {
    pub fn new(way: Pathway, cc: ArcCC, conn_iface: Arc<ConnInterface>) -> Self {
        Self {
            way,
            cc,
            conn_iface,
            anti_amplifier: Default::default(),
            last_recv_time: Instant::now().into(),
            challenge_sndbuf: Default::default(),
            response_sndbuf: Default::default(),
            response_rcvbuf: Default::default(),
        }
    }

    pub async fn validate(&self) -> bool {
        let challenge = PathChallengeFrame::random();
        for _ in 0..3 {
            use qcongestion::CongestionControl;
            let pto = self.cc.pto_time(qbase::Epoch::Data);
            self.challenge_sndbuf.write(challenge);
            match tokio::time::timeout(pto, self.response_rcvbuf.receive()).await {
                Ok(Some(response)) if *response == *challenge => {
                    self.anti_amplifier.grant();
                    return true;
                }
                // 外部发生变化，导致路径验证任务作废
                Ok(None) => return false,
                // 超时或者收到不对的response，按"停-等协议"，继续再发一次Challenge，最多3次
                _ => continue,
            }
        }
        false
    }

    pub fn cc(&self) -> &ArcCC {
        &self.cc
    }

    pub fn on_rcvd(&self, amount: usize) {
        self.anti_amplifier.on_rcvd(amount);
        *self.last_recv_time.lock().unwrap() = Instant::now();
    }

    pub fn grant_anti_amplifier(&self) {
        self.anti_amplifier.grant();
    }

    pub fn send_capability(&self) -> io::Result<SendCapability> {
        self.conn_iface.send_capability(self.way)
    }

    pub async fn send_packets(&self, pkts: &[io::IoSlice<'_>], dst: SocketAddr) -> io::Result<()> {
        self.conn_iface.send_packets(pkts, self.way, dst).await
    }
}

impl Drop for Path {
    fn drop(&mut self) {
        self.response_rcvbuf.dismiss();
    }
}

impl ReceiveFrame<PathChallengeFrame> for Path {
    type Output = ();

    fn recv_frame(&self, frame: &PathChallengeFrame) -> Result<Self::Output, Error> {
        self.challenge_sndbuf.write(*frame);
        Ok(())
    }
}

impl ReceiveFrame<PathResponseFrame> for Path {
    type Output = ();

    fn recv_frame(&self, frame: &PathResponseFrame) -> Result<Self::Output, Error> {
        self.response_rcvbuf.write(*frame);
        Ok(())
    }
}
