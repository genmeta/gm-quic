use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
};

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
    time::{ArcDeferIdleTimer, ArcMaxIdleTimer, MaxIdleTimer},
};
use qcongestion::{Algorithm, ArcCC, Feedback, HandshakeStatus, MSS, PathStatus, Transport};
use qevent::{quic::connectivity::PathAssigned, telemetry::Instrument};
use qinterface::{QuicIoExt, iface::QuicInterface};
use tokio::time::Duration;

mod aa;
mod burst;
mod drive;
pub mod error;
pub mod paths;
pub mod util;
mod validate;
pub use aa::*;
pub use burst::PacketSpace;
pub use error::*;
pub use paths::*;
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument as _;
pub use util::*;

use crate::{ArcDcidCell, Components, path::burst::BurstError};
// pub mod burst;

pub struct Path {
    interface: QuicInterface,
    validated: AtomicBool,
    link: Link,
    pathway: Pathway,
    cc: ArcCC,
    dcid_cell: ArcDcidCell,
    anti_amplifier: AntiAmplifier,
    max_idle_timer: ArcMaxIdleTimer,
    heartbeat: ArcHeartbeat,
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
        bind_uri: BindUri,
        link: Link,
        pathway: Pathway,
        is_probed: bool,
    ) -> Result<Arc<Path>, CreatePathFailure> {
        let try_create = || {
            let interface = self
                .interfaces
                .get(&bind_uri)
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
                    Arc::new(
                        self.spaces
                            .initial()
                            .tracker(self.crypto_streams[Epoch::Initial].clone()),
                    ),
                    Arc::new(
                        self.spaces
                            .handshake()
                            .tracker(self.crypto_streams[Epoch::Handshake].clone()),
                    ),
                    Arc::new(self.spaces.data().tracker(
                        self.crypto_streams[Epoch::Data].clone(),
                        self.data_streams.clone(),
                        self.reliable_frames.clone(),
                    )),
                ],
                self.quic_handshake.status(),
            ));

            let validate = {
                let path = path.clone();
                let paths = self.paths.clone();
                let tls_handshake = self.tls_handshake.clone();
                let conn_state = self.conn_state.clone();
                async move {
                    if !is_probed {
                        path.grant_anti_amplification();
                    }
                    if !tls_handshake.finished().await {
                        return Ok(());
                    }

                    match paths.handshake_path() {
                        Some(handshake_path) if Arc::ptr_eq(&handshake_path, &path) => {
                            path.validated();
                            Ok(())
                        }
                        _ => {
                            if !conn_state.handshaked().await {
                                return Ok(());
                            }
                            path.validate().await
                        }
                    }
                }
            };

            let drive = {
                let path = path.clone();
                let tls_handshake = self.tls_handshake.clone();
                async move { path.drive(tls_handshake).await }
            };

            let burst = {
                let path = path.clone();
                let mut packages = self.packages();
                let burst = path.new_burst(self);
                async move {
                    loop {
                        let mut buffers = vec![];
                        match burst.burst(&mut packages, &mut buffers).await {
                            Ok(segments) => path.send_packets(&segments).await?,
                            Err(BurstError::Signals(s)) => path.tx_waker.wait_for(s).await,
                            Err(BurstError::PathDeactived) => return io::Result::Ok(()),
                        }
                    }
                }
            };

            let task = async move {
                Err(tokio::select! {
                    Ok(Err(e)) = AbortOnDropHandle::new(tokio::spawn(validate.instrument_in_current().in_current_span())) => PathDeactivated::from(e),
                    Ok(Err(e)) = AbortOnDropHandle::new(tokio::spawn(drive.instrument_in_current().in_current_span())) => e,
                    Ok(Err(e)) = AbortOnDropHandle::new(tokio::spawn(burst.instrument_in_current().in_current_span())) => PathDeactivated::from(e),
                })
            };

            let task =
                Instrument::instrument(task, qevent::span!(@current, path=pathway.to_string()))
                    .in_current_span();

            tracing::info!(%pathway, %link, is_probed, is_initial_path, "Add new path");

            Ok((path, task))
        };
        self.paths.get_or_try_create_with(pathway, try_create)
    }
}

impl Path {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        interface: QuicInterface,
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
            feedbacks,
            path_status.clone(),
            tx_waker.clone(),
        );
        Self {
            interface,
            link,
            pathway,
            cc,
            dcid_cell,
            validated: AtomicBool::new(false),
            anti_amplifier: AntiAmplifier::new(tx_waker.clone()),
            max_idle_timer: ArcMaxIdleTimer::from(max_idle_timer),
            heartbeat: ArcHeartbeat::new(defer_idle_timer, Duration::from_secs(1)),
            challenge_sndbuf: SendBuffer::new(tx_waker.clone()),
            response_sndbuf: SendBuffer::new(tx_waker.clone()),
            response_rcvbuf: Default::default(),
            tx_waker,
            pmtu,
            status: path_status,
        }
    }

    pub fn cc(&self) -> &ArcCC {
        &self.cc
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
            self.heartbeat.renew_on_effective_communicated();
        }
        if epoch == Epoch::Data {
            self.max_idle_timer.renew_on_received_1rtt();
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
        self.interface.sendmmsg(bufs, hdr).await
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
