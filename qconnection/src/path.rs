use std::{
    io,
    ops::Deref,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
};

use qbase::{
    Epoch,
    error::Error,
    frame::{PathChallengeFrame, PathResponseFrame, ReceiveFrame},
    net::{
        PacketHeader,
        route::{Link, Pathway},
        tx::ArcSendWaker,
    },
    packet::PacketContains,
};
use qcongestion::{Algorithm, ArcCC, Feedback, HandshakeStatus, MSS, PathStatus, Transport};
use qinterface::{QuicInterface, router::QuicProto};
use tokio::{
    task::AbortHandle,
    time::{Duration, Instant},
};

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
    pmtu: Arc<AtomicU16>,
    status: PathStatus,
}

impl Path {
    pub fn new(
        proto: &QuicProto,
        link: Link,
        pathway: Pathway,
        max_ack_delay: Duration,
        feedbacks: [Arc<dyn Feedback>; 3],
        handshake_status: Arc<HandshakeStatus>,
    ) -> io::Result<Self> {
        let interface = proto.get_interface(link.src())?;
        let pmtu = Arc::new(AtomicU16::new(MSS as u16));
        let path_status = PathStatus::new(handshake_status, pmtu.clone());
        let tx_waker = ArcSendWaker::new();

        let cc = ArcCC::new(
            Algorithm::NewReno,
            max_ack_delay,
            feedbacks,
            path_status.clone(),
            tx_waker.clone(),
        );
        let handle = cc.launch();
        Ok(Self {
            interface,
            link,
            pathway,
            cc: (cc, handle),
            validated: AtomicBool::new(false),
            anti_amplifier: AntiAmplifier::new(tx_waker.clone()),
            last_active_time: tokio::time::Instant::now().into(),
            challenge_sndbuf: SendBuffer::new(tx_waker.clone()),
            response_sndbuf: SendBuffer::new(tx_waker.clone()),
            response_rcvbuf: Default::default(),
            tx_waker,
            pmtu,
            status: path_status,
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
        if size > 0 {
            self.status.release_anti_amplification_limit();
        }
        if packet_contains == PacketContains::EffectivePayload {
            *self.last_active_time.lock().unwrap() = tokio::time::Instant::now();
        }
        self.cc()
            .on_pkt_rcvd(epoch, pn, packet_contains.ack_eliciting());
    }

    pub fn grant_anti_amplification(&self) {
        self.anti_amplifier.grant();
        self.cc().grant_anti_amplification();
    }

    pub fn mtu(&self) -> u16 {
        self.pmtu.load(Ordering::Acquire)
    }

    pub async fn send_packets(&self, mut segments: &[io::IoSlice<'_>]) -> io::Result<()> {
        self.anti_amplifier
            .on_sent(segments.iter().map(|s| s.len()).sum());
        if self.anti_amplifier.balance().is_err() {
            self.status.enter_anti_amplification_limit();
        }
        while !segments.is_empty() {
            let hdr = PacketHeader::new(self.pathway, self.link, 64, None, self.mtu() as _);
            let sent =
                core::future::poll_fn(|cx| self.interface.poll_send(cx, segments, hdr)).await?;
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
