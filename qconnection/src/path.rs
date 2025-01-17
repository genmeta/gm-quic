use std::{
    io,
    ops::Deref,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

use qbase::{
    error::Error,
    frame::{PathChallengeFrame, PathResponseFrame, ReceiveFrame},
};
use qcongestion::{ArcCC, CongestionControl};
use qinterface::{
    path::{Pathway, Socket},
    router::QuicProto,
    QuicInterface,
};
use tokio::{sync::Notify, time::Instant};

mod aa;
mod paths;
pub mod ticker;
mod util;
pub use aa::*;
pub use paths::*;
pub use util::*;
pub mod burst;
pub mod idle;

pub struct Path {
    interface: Arc<dyn QuicInterface>,
    validated: AtomicBool,
    socket: Socket,
    pathway: Pathway,
    cc: ArcCC,
    anti_amplifier: AntiAmplifier,
    last_recv_time: Mutex<Instant>,
    challenge_sndbuf: SendBuffer<PathChallengeFrame>,
    response_sndbuf: SendBuffer<PathResponseFrame>,
    response_rcvbuf: RecvBuffer<PathResponseFrame>,
    sendable: Notify,
}

impl Path {
    pub fn new(proto: &QuicProto, socket: Socket, pathway: Pathway, cc: ArcCC) -> Option<Self> {
        let interface = proto.get_interface(socket.src()).ok()?;
        Some(Self {
            interface,
            socket,
            pathway,
            cc,
            validated: AtomicBool::new(false),
            anti_amplifier: Default::default(),
            last_recv_time: Instant::now().into(),
            challenge_sndbuf: Default::default(),
            response_sndbuf: Default::default(),
            response_rcvbuf: Default::default(),
            sendable: Notify::new(),
        })
    }

    pub fn skip_validation(&self) {
        self.validated.store(true, Ordering::Release);
    }

    pub async fn validate(&self) -> bool {
        let challenge = PathChallengeFrame::random();
        for _ in 0..3 {
            let pto = self.cc.pto_time(qbase::Epoch::Data);
            self.challenge_sndbuf.write(challenge);
            self.sendable.notify_waiters();
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

    pub fn interface(&self) -> &dyn QuicInterface {
        self.interface.deref()
    }

    pub fn on_rcvd(&self, amount: usize) {
        self.anti_amplifier.on_rcvd(amount);
        *self.last_recv_time.lock().unwrap() = Instant::now();
    }

    pub fn grant_anti_amplifier(&self) {
        self.anti_amplifier.grant();
    }

    pub async fn send_packets(&self, mut pkts: &[io::IoSlice<'_>]) -> io::Result<()> {
        while !pkts.is_empty() {
            let sent = core::future::poll_fn(|cx| {
                self.interface
                    .poll_send(cx, pkts, self.pathway, self.socket.dst())
            })
            .await?;
            pkts = &pkts[sent..];
        }
        Ok(())
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
