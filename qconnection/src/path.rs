use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
};

use derive_more::From;
use qbase::{
    Epoch,
    error::Error,
    frame::{PathChallengeFrame, PathResponseFrame, ReceiveFrame},
    net::{
        addr::BindUri,
        route::{Link, PacketHeader, Pathway},
        tx::ArcSendWaker,
    },
    packet::PacketContains,
    param::ParameterId,
    time::{ArcDeferIdleTimer, MaxIdleTimer},
};
use qcongestion::{Algorithm, ArcCC, Feedback, HandshakeStatus, MSS, PathStatus, Transport};
use qevent::{quic::connectivity::PathAssigned, telemetry::Instrument};
use qinterface::{QuicIO, iface::QuicInterface};
use thiserror::Error;
use tokio::{task::AbortHandle, time::Duration};

mod aa;
mod paths;
mod util;
mod validate;
pub use aa::*;
pub use paths::*;
pub use util::*;

use crate::{ArcDcidCell, Components};
pub mod burst;

pub struct Path {
    interface: Arc<QuicInterface>,
    validated: AtomicBool,
    link: Link,
    pathway: Pathway,
    cc: (ArcCC, AbortHandle),
    dcid_cell: ArcDcidCell,
    anti_amplifier: AntiAmplifier,
    defer_idle_timer: ArcDeferIdleTimer,
    challenge_sndbuf: SendBuffer<PathChallengeFrame>,
    response_sndbuf: SendBuffer<PathResponseFrame>,
    response_rcvbuf: RecvBuffer<PathResponseFrame>,
    tx_waker: ArcSendWaker,
    pmtu: Arc<AtomicU16>,
    status: PathStatus,
}

#[derive(Debug, From, Error)]
pub enum CreatePathFailure {
    #[error("Network interface not found for bind URI: {0}")]
    NoInterface(BindUri),
    #[error("Connection is closed: {0}")]
    ConnectionClosed(Error),
}

#[derive(Debug, From, Error)]
pub enum PathDeactivated {
    #[error("Path validation failed: {0}")]
    ValidationFailed(validate::ValidateFailure),
    #[error("Path hasn't received any packets since {0:?}")]
    IdleTimeout(tokio::time::Instant),
    #[error("Failed to send packets on path: {0}")]
    SendError(io::Error),
    #[error("Manually removed by application")]
    ApplicationRemoved,
}

impl Components {
    pub fn get_or_try_create_path(
        &self,
        bind_uri: BindUri,
        link: Link,
        pathway: Pathway,
        is_probed: bool,
    ) -> Result<Arc<Path>, CreatePathFailure> {
        let try_create = || {
            let interface = self
                .interfaces
                .get(bind_uri.clone())
                .ok_or(CreatePathFailure::NoInterface(bind_uri))?;
            let dcid_cell = self.cid_registry.remote.apply_dcid();
            let max_ack_delay = self
                .parameters
                .lock_guard()?
                .get_local(ParameterId::MaxAckDelay)
                .expect("unreachable: default value will be got if the value unset");

            let is_initial_path = self.conn_state.try_entry_attempted(self, link)?;
            qevent::event!(PathAssigned {
                path_id: pathway.to_string(),
                path_local: link.src(),
                path_remote: link.dst(),
            });

            let path = Arc::new(Path::new(
                interface,
                link,
                pathway,
                dcid_cell,
                max_ack_delay,
                self.parameters.max_idle_timer(),
                self.defer_idle_timer.clone(),
                [
                    self.spaces.initial().clone(),
                    self.spaces.handshake().clone(),
                    self.spaces.data().clone(),
                ],
                self.quic_handshake.status(),
            ));

            let burst = path.new_burst(self);
            let validate = {
                let paths = self.paths.clone();
                let data_space = self.spaces.data().clone();
                move |path: Arc<Path>| async move {
                    if !is_probed {
                        path.grant_anti_amplification();
                    }
                    data_space.tls_fin().await;

                    match paths.handshake_path() {
                        Some(handshake_path) if Arc::ptr_eq(&handshake_path, &path) => {
                            path.validated();
                            Ok(())
                        }
                        _ => path.validate().await,
                    }
                }
            };

            let task = {
                let path = path.clone();
                async move {
                    Err(tokio::select! {
                        biased;
                        Err(e) = validate(path.clone()) => PathDeactivated::from(e),
                        Err(e) = burst.launch() => PathDeactivated::from(e),
                    })
                }
            };

            let task =
                Instrument::instrument(task, qevent::span!(@current, path=pathway.to_string()))
                    .instrument_in_current();

            tracing::info!(%pathway, %link, is_probed, is_initial_path, "add new path:");
            Ok((path, task))
        };
        self.paths.get_or_try_create_with(pathway, try_create)
    }
}

impl Path {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        interface: Arc<QuicInterface>,
        link: Link,
        pathway: Pathway,
        dcid_cell: ArcDcidCell,
        max_ack_delay: Duration,
        max_idle_timer: MaxIdleTimer,
        defer_idle_timer: ArcDeferIdleTimer,
        feedbacks: [Arc<dyn Feedback>; 3],
        handshake_status: Arc<HandshakeStatus>,
    ) -> Self {
        let pmtu = Arc::new(AtomicU16::new(MSS as u16));
        let path_status = PathStatus::new(handshake_status, pmtu.clone());
        let tx_waker = ArcSendWaker::new();

        let cc = ArcCC::new(
            Algorithm::NewReno,
            max_ack_delay,
            max_idle_timer,
            feedbacks,
            path_status.clone(),
            tx_waker.clone(),
        );
        let handle = cc.launch();
        Self {
            interface,
            link,
            pathway,
            cc: (cc, handle),
            dcid_cell,
            validated: AtomicBool::new(false),
            anti_amplifier: AntiAmplifier::new(tx_waker.clone()),
            defer_idle_timer,
            challenge_sndbuf: SendBuffer::new(tx_waker.clone()),
            response_sndbuf: SendBuffer::new(tx_waker.clone()),
            response_rcvbuf: Default::default(),
            tx_waker,
            pmtu,
            status: path_status,
        }
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
        if packet_contains.ack_eliciting() {
            self.defer_idle_timer.renew_on_effective_communicated();
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
