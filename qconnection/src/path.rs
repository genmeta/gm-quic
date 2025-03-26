use std::{
    io,
    ops::Deref,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use qbase::{
    Epoch,
    error::Error,
    frame::{PathChallengeFrame, PathResponseFrame, ReceiveFrame},
    net::{
        route::{Link, Pathway},
        tx::ArcSendWaker,
    },
    packet::PacketContains,
};
use qcongestion::{ArcCC, Transport};
use qinterface::{QuicInterface, router::QuicProto};
use tokio::task::AbortHandle;

mod aa;
mod paths;
mod util;
pub use aa::*;
pub use paths::*;
pub use util::*;
pub mod burst;
pub mod idle;

pub struct Path {
    interface: Arc<dyn QuicInterface>,
    validated: AtomicBool,
    link: Link,
    pathway: Pathway,
    cc: (ArcCC, AbortHandle),
    anti_amplifier: AntiAmplifier,
    last_active_time: Mutex<Instant>,
    challenge_sndbuf: SendBuffer<PathChallengeFrame>,
    response_sndbuf: SendBuffer<PathResponseFrame>,
    response_rcvbuf: RecvBuffer<PathResponseFrame>,
    tx_waker: ArcSendWaker,
}

impl Path {
    pub fn new(
        proto: &QuicProto,
        link: Link,
        pathway: Pathway,
        cc: ArcCC,
        tx_waker: ArcSendWaker,
    ) -> io::Result<Self> {
        let interface = proto.get_interface(link.src())?;
        let handle = cc.launch();
        Ok(Self {
            interface,
            link,
            pathway,
            cc: (cc, handle),
            validated: AtomicBool::new(false),
            anti_amplifier: AntiAmplifier::new(tx_waker.clone()),
            last_active_time: Instant::now().into(),
            challenge_sndbuf: SendBuffer::new(tx_waker.clone()),
            response_sndbuf: SendBuffer::new(tx_waker.clone()),
            response_rcvbuf: Default::default(),
            tx_waker,
        })
    }

    pub fn skip_validation(&self) {
        self.validated.store(true, Ordering::Release);
    }

    pub async fn validate(&self) -> bool {
        let challenge = PathChallengeFrame::random();
        for _ in 0..3 {
            let pto = self.cc().get_pto(qbase::Epoch::Data);
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
        &self.cc.0
    }

    pub fn interface(&self) -> &dyn QuicInterface {
        self.interface.deref()
    }

    pub fn tx_waker(&self) -> &ArcSendWaker {
        &self.tx_waker
    }

    pub fn on_packet_rcvd(
        &self,
        epoch: Epoch,
        pn: u64,
        size: usize,
        packet_contains: PacketContains,
    ) {
        self.anti_amplifier.on_rcvd(size);
        if packet_contains == PacketContains::EffectivePayload {
            *self.last_active_time.lock().unwrap() = Instant::now();
        }
        let is_ack_elicition = packet_contains != PacketContains::NonAckEliciting;
        self.cc().on_pkt_rcvd(epoch, pn, is_ack_elicition);
    }

    pub fn grant_anti_amplification(&self) {
        self.anti_amplifier.grant();
        self.cc().grant_anti_amplification();
    }

    pub async fn send_packets(&self, mut segments: &[io::IoSlice<'_>]) -> io::Result<()> {
        while !segments.is_empty() {
            let sent = core::future::poll_fn(|cx| {
                self.interface
                    .poll_send(cx, segments, self.pathway, self.link.dst())
            })
            .await?;
            segments = &segments[sent..];
        }
        Ok(())
    }
}

impl Drop for Path {
    fn drop(&mut self) {
        self.response_rcvbuf.dismiss();
        self.cc.1.abort();
    }
}

impl ReceiveFrame<PathChallengeFrame> for Path {
    type Output = ();

    fn recv_frame(&self, frame: &PathChallengeFrame) -> Result<Self::Output, Error> {
        self.response_sndbuf.write((*frame).into());
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
