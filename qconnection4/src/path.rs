use std::{
    io::{self},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use dashmap::DashMap;
use qbase::{
    error::Error,
    frame::{PathChallengeFrame, PathResponseFrame, ReceiveFrame},
    Epoch,
};
use qcongestion::{ArcCC, CongestionControl};
use qinterface::{conn::ConnInterface, path::Pathway, SendCapability};
use tokio::{task::AbortHandle, time::Instant};

mod aa;
pub use aa::*;
pub mod burst;
mod util;
pub use util::*;

pub struct Path {
    pathway: Pathway,
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
            pathway: way,
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

pub struct PathGuard {
    path: Arc<Path>,
    task: AbortHandle,
}

impl PathGuard {
    pub fn new(path: Arc<Path>, task: AbortHandle) -> Self {
        Self { path, task }
    }
}

impl Drop for PathGuard {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Clone)]
pub struct ArcPaths {
    paths: Arc<DashMap<Pathway, PathGuard>>,
    ticker: AbortHandle,
}

impl Default for ArcPaths {
    fn default() -> Self {
        Self::new()
    }
}

impl ArcPaths {
    pub fn new() -> Self {
        let paths: Arc<DashMap<Pathway, PathGuard>> = Arc::new(DashMap::new());
        let ticker = tokio::spawn({
            let arc_paths = paths.clone();
            async move {
                loop {
                    tokio::time::sleep(Duration::from_micros(10)).await;
                    for path_guard in arc_paths.iter() {
                        path_guard.path.cc.do_tick();
                    }
                }
            }
        })
        .abort_handle();
        Self { paths, ticker }
    }

    pub fn get(&self, pathway: &Pathway) -> Option<Arc<Path>> {
        self.paths.get(pathway).map(|guard| guard.path.clone())
    }

    pub fn entry(&self, pathway: Pathway) -> dashmap::Entry<'_, Pathway, PathGuard> {
        self.paths.entry(pathway)
    }

    pub fn del(&self, pathway: &Pathway) {
        self.paths.remove(pathway);
    }

    pub fn exist_paths(&self) -> usize {
        self.paths.len()
    }

    pub fn max_pto_duration(&self) -> Option<Duration> {
        self.paths
            .iter()
            .map(|guard| guard.path.cc.pto_time(Epoch::Data))
            .max()
    }

    pub fn clear(&self) {
        self.ticker.abort();
        self.paths.clear();
    }
}
