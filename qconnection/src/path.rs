use std::{
    io,
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
        addr::BindAddr,
        route::{Link, PacketHeader, Pathway},
        tx::ArcSendWaker,
    },
    packet::PacketContains,
    param::ParameterId,
};
use qcongestion::{Algorithm, ArcCC, Feedback, HandshakeStatus, MSS, PathStatus, Transport};
use qevent::{quic::connectivity::PathAssigned, telemetry::Instrument};
use qinterface::{QuicIO, ifaces::borrowed::QuicInterface};
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

use crate::Components;
pub mod burst;
pub mod idle;

pub struct Path {
    interface: Arc<QuicInterface>,
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

impl Components {
    pub fn get_or_try_create_path(
        &self,
        bind_addr: BindAddr,
        link: Link,
        pathway: Pathway,
        is_probed: bool,
    ) -> io::Result<Arc<Path>> {
        let try_create = || {
            let interface = self
                .interfaces
                .get(&bind_addr)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "interface not found"))?;
            let max_ack_delay = self
                .parameters
                .lock_guard()?
                .get_local(ParameterId::MaxAckDelay)
                .expect("unreachable: default value will be got if the value unset");

            let do_validate = !self.conn_state.try_entry_attempted(self, link)?;
            qevent::event!(PathAssigned {
                path_id: pathway.to_string(),
                path_local: link.src(),
                path_remote: link.dst(),
            });

            let path = Arc::new(Path::new(
                interface,
                link,
                pathway,
                max_ack_delay,
                [
                    self.spaces.initial().clone(),
                    self.spaces.handshake().clone(),
                    self.spaces.data().clone(),
                ],
                self.quic_handshake.status(),
            )?);

            if !is_probed {
                path.grant_anti_amplification();
            }

            let burst = path.new_burst(self);
            let idle_timeout = path.idle_timeout(self.parameters.clone(), self.paths.clone());

            let task = {
                let path = path.clone();
                let defer_idle_timeout = self.defer_idle_timeout;
                async move {
                    let validate = async {
                        if do_validate {
                            path.validate().await
                        } else {
                            path.skip_validation();
                            true
                        }
                    };
                    let reason: String = tokio::select! {
                        false = validate => "failed to validate".into(),
                        true = idle_timeout => "idle timeout".into(),
                        Err(e) = burst.launch() => format!("failed to send packets: {:?}", e),
                        _ = path.defer_idle_timeout(defer_idle_timeout) => "failed to defer idle timeout".into(),
                    };
                    Err(reason)
                }
            };

            let task =
                Instrument::instrument(task, qevent::span!(@current, path=pathway.to_string()))
                    .instrument_in_current();

            tracing::info!(%pathway, %link, is_probed, do_validate, "add new path:");
            Ok((path, task))
        };
        self.paths.get_or_try_create_with(pathway, try_create)
    }
}

impl Path {
    pub fn new(
        interface: Arc<QuicInterface>,
        link: Link,
        pathway: Pathway,
        max_ack_delay: Duration,
        feedbacks: [Arc<dyn Feedback>; 3],
        handshake_status: Arc<HandshakeStatus>,
    ) -> io::Result<Self> {
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
        *self.last_active_time.lock().unwrap() = tokio::time::Instant::now();
        self.cc()
            .on_pkt_rcvd(epoch, pn, packet_contains.ack_eliciting());
    }

    pub fn last_active_time(&self) -> Instant {
        *self.last_active_time.lock().unwrap()
    }

    pub fn grant_anti_amplification(&self) {
        self.anti_amplifier.grant();
        self.cc().grant_anti_amplification();
    }

    pub fn mtu(&self) -> u16 {
        self.pmtu.load(Ordering::Acquire)
    }

    pub async fn send_packets(&self, bufs: &[io::IoSlice<'_>]) -> io::Result<()> {
        self.anti_amplifier
            .on_sent(bufs.iter().map(|s| s.len()).sum());
        if self.anti_amplifier.balance().is_err() {
            self.status.enter_anti_amplification_limit();
        }
        let hdr = PacketHeader::new(self.pathway, self.link, 64, None, self.mtu() as _);
        let iface: &dyn QuicIO = self.interface.as_ref();
        iface.sendmmsg(bufs, hdr).await
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
