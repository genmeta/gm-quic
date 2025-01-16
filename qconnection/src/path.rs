use std::{
    io::{self},
    net::SocketAddr,
    sync::Mutex,
};

use qbase::{
    error::Error,
    frame::{PathChallengeFrame, PathResponseFrame, ReceiveFrame},
};
use qcongestion::{ArcCC, CongestionControl};
use qinterface::{path::Pathway, SendCapability};
use tokio::{sync::Notify, time::Instant};

mod aa;
pub mod ticker;
mod util;
pub use aa::*;
pub use util::*;
pub mod burst;
pub mod idle;

use crate::ArcConnInterface;

#[derive(Debug, Clone, Copy)]
pub struct PathKind {
    is_initial: bool,
    is_probed: bool,
}

impl PathKind {
    pub fn new(is_initial: bool, is_probed: bool) -> Self {
        Self {
            is_initial,
            is_probed,
        }
    }

    pub fn is_initial(&self) -> bool {
        self.is_initial
    }

    pub fn is_probed(&self) -> bool {
        self.is_probed
    }
}

pub struct Path {
    pathway: Pathway,
    cc: ArcCC,
    kind: PathKind,
    anti_amplifier: AntiAmplifier,
    last_recv_time: Mutex<Instant>,
    challenge_sndbuf: SendBuffer<PathChallengeFrame>,
    response_sndbuf: SendBuffer<PathResponseFrame>,
    response_rcvbuf: RecvBuffer<PathResponseFrame>,

    conn_iface: ArcConnInterface,
    send_notify: Notify,
}

impl Path {
    pub fn new(way: Pathway, cc: ArcCC, kind: PathKind, conn_iface: ArcConnInterface) -> Self {
        Self {
            pathway: way,
            cc,
            kind,
            conn_iface,
            anti_amplifier: Default::default(),
            last_recv_time: Instant::now().into(),
            challenge_sndbuf: Default::default(),
            response_sndbuf: Default::default(),
            response_rcvbuf: Default::default(),
            send_notify: Notify::new(),
        }
    }

    pub async fn validate(&self) -> bool {
        let challenge = PathChallengeFrame::random();
        for _ in 0..3 {
            let pto = self.cc.pto_time(qbase::Epoch::Data);
            self.challenge_sndbuf.write(challenge);
            self.send_notify.notify_waiters();
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
        self.conn_iface.send_capability(self.pathway)
    }

    pub async fn send_packets(&self, pkts: &[io::IoSlice<'_>], dst: SocketAddr) -> io::Result<()> {
        self.conn_iface.send_packets(pkts, self.pathway, dst).await
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
