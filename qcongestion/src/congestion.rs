use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use qbase::{
    Epoch,
    frame::AckFrame,
    net::tx::{ArcSendWaker, Signals},
};
use qlog::{quic::recovery::PacketLostTrigger, telemetry::Instrument};
use tokio::task::AbortHandle;
use tracing::Instrument as _;

use crate::{
    Algorithm, Feedback, HandshakeStatus, MSS,
    algorithm::{Control, new_reno::NewReno},
    pacing::{self, Pacer},
    packets::{PacketSpace, SentPacket},
    rtt::{ArcRtt, INITIAL_RTT},
    status::PathStatus,
};

const INIT_CWND: usize = 10 * MSS;
const PACKET_THRESHOLD: usize = 3;

/// Imple RFC 9002 Appendix A. Loss Recovery
/// See [Appendix A](https://datatracker.ietf.org/doc/html/rfc9002#name-loss-recovery-pseudocode)
pub struct CongestionController {
    algorithm: Box<dyn Control>,
    // The Round-Trip Time (RTT) estimator.
    rtt: ArcRtt,
    loss_detection_timer: Option<Instant>,
    // The number of times a PTO has been sent without receiving an acknowledgment.
    // Use to pto backoff
    pto_count: u32,
    max_ack_delay: Duration,
    packet_spaces: [PacketSpace; Epoch::count()],
    // pacer is used to control the burst rate
    pacer: pacing::Pacer,
    // The waker to notify when the controller is ready to send.
    pending_burst: Option<usize>,
    // epoch packet trackers
    trackers: [Arc<dyn Feedback>; 3],
    need_send_ack_eliciting_packets: [usize; Epoch::count()],
    path_status: PathStatus,
    tx_waker: ArcSendWaker,
}

impl CongestionController {
    /// A.4. Initialization
    fn init(
        algorithm: Algorithm,
        max_ack_delay: Duration,
        trackers: [Arc<dyn Feedback>; 3],
        handshake_status: Arc<HandshakeStatus>,
        tx_waker: ArcSendWaker,
    ) -> Self {
        let algorithm: Box<dyn Control> = match algorithm {
            Algorithm::Bbr => todo!("implement BBR"),
            Algorithm::NewReno => Box::new(NewReno::new()),
        };

        let now = Instant::now();
        CongestionController {
            algorithm,
            rtt: ArcRtt::new(),
            loss_detection_timer: None,
            pto_count: 0,
            max_ack_delay,
            packet_spaces: [
                PacketSpace::with_epoch(Epoch::Initial, max_ack_delay),
                PacketSpace::with_epoch(Epoch::Handshake, max_ack_delay),
                PacketSpace::with_epoch(Epoch::Data, max_ack_delay),
            ],
            pacer: Pacer::new(INITIAL_RTT, INIT_CWND, MSS, now, None),
            pending_burst: None,
            trackers,
            need_send_ack_eliciting_packets: [0; Epoch::count()],
            path_status: PathStatus::new(handshake_status),
            tx_waker,
        }
    }

    /// A.5. On Sending a Packet
    /// OnPacketSent(packet_number, pn_space, ack_eliciting,
    ///              in_flight, sent_bytes):
    ///   sent_packets[pn_space][packet_number].packet_number =
    ///                                            packet_number
    ///   sent_packets[pn_space][packet_number].time_sent = now()
    ///   sent_packets[pn_space][packet_number].ack_eliciting =
    ///                                            ack_eliciting
    ///   sent_packets[pn_space][packet_number].in_flight = in_flight
    ///   sent_packets[pn_space][packet_number].sent_bytes = sent_bytes
    ///   if (in_flight):
    ///     if (ack_eliciting):
    ///       time_of_last_ack_eliciting_packet[pn_space] = now()
    ///     OnPacketSentCC(sent_bytes)
    ///     SetLossDetectionTimer()
    pub fn on_packet_sent(
        &mut self,
        packet_number: u64,
        epoch: Epoch,
        ack_eliciting: bool,
        in_flight: bool,
        sent_bytes: usize,
    ) {
        let now = tokio::time::Instant::now().into_std();
        let sent = SentPacket::new(packet_number, now, ack_eliciting, in_flight, sent_bytes);
        if in_flight {
            if ack_eliciting {
                self.packet_spaces[epoch].time_of_last_ack_eliciting_packet = Some(now);
                self.need_send_ack_eliciting_packets[epoch] =
                    self.need_send_ack_eliciting_packets[epoch].saturating_sub(1);
            }
            self.algorithm.on_packet_sent_cc(&sent);
            self.set_loss_detection_timer();
        }
        self.packet_spaces[epoch].sent_packets.push_back(sent);
        self.pacer.on_sent(sent_bytes);
    }

    /// A.6. On Receiving a Datagram
    /// OnDatagramReceived(datagram):
    ///   // If this datagram unblocks the server, arm the
    ///   // PTO timer to avoid deadlock.
    ///   if (server was at anti-amplification limit):
    ///     SetLossDetectionTimer()
    ///     if loss_detection_timer.timeout < now():
    ///       // Execute PTO if it would have expired
    ///       // while the amplification limit applied.
    ///       OnLossDetectionTimeout()
    pub fn on_datagram_rcvd(&mut self) {
        // If this datagram unblocks the server, arm the PTO timer to avoid deadlock.
        if self.path_status.is_at_anti_amplification_limit() {
            let now = tokio::time::Instant::now().into_std();
            self.set_loss_detection_timer();
            if self.loss_detection_timer.is_some_and(|t| t < now) {
                // Execute PTO if it would have expired while the amplification limit applied.
                self.on_loss_detection_timeout();
            }
        }
    }

    /// A.7. On Receiving an Acknowledgment
    /// OnAckReceived(ack, pn_space):
    ///   if (largest_acked_packet[pn_space] == infinite):
    ///     largest_acked_packet[pn_space] = ack.largest_acked
    ///   else:
    ///     largest_acked_packet[pn_space] =
    ///         max(largest_acked_packet[pn_space], ack.largest_acked)
    ///
    ///   // DetectAndRemoveAckedPackets finds packets that are newly
    ///   // acknowledged and removes them from sent_packets.
    ///   newly_acked_packets =
    ///       DetectAndRemoveAckedPackets(ack, pn_space)
    ///   // Nothing to do if there are no newly acked packets.
    ///   if (newly_acked_packets.empty()):
    ///     return
    ///
    ///   // Update the RTT if the largest acknowledged is newly acked
    ///   // and at least one ack-eliciting was newly acked.
    ///   if (newly_acked_packets.largest().packet_number ==
    ///           ack.largest_acked &&
    ///       IncludesAckEliciting(newly_acked_packets)):
    ///     latest_rtt =
    ///       now() - newly_acked_packets.largest().time_sent
    ///     UpdateRtt(ack.ack_delay)
    ///
    ///   // Process ECN information if present.
    ///   if (ACK frame contains ECN information):
    ///       ProcessECN(ack, pn_space)
    ///
    ///   lost_packets = DetectAndRemoveLostPackets(pn_space)
    ///   if (!lost_packets.empty()):
    ///     OnPacketsLost(lost_packets)
    ///   OnPacketsAcked(newly_acked_packets)
    ///
    ///   // Reset pto_count unless the client is unsure if
    ///   // the server has validated the client's address.
    ///   if (PeerCompletedAddressValidation()):
    ///     pto_count = 0
    ///   SetLossDetectionTimer()
    pub fn on_ack_rcvd(&mut self, epoch: Epoch, ack_frame: &AckFrame, now: Instant) {
        self.packet_spaces[epoch].update_largest_acked_packet(ack_frame.largest());

        match self.packet_spaces[epoch].on_ack_rcvd(ack_frame, &mut self.algorithm) {
            None => return,
            Some(newly_acked_packets) => {
                let (largest_pn, largest_time_sent) = newly_acked_packets.largest;
                if largest_pn == ack_frame.largest() && newly_acked_packets.include_ack_eliciting {
                    self.rtt.update(
                        now - largest_time_sent,
                        Duration::from_micros(ack_frame.delay()),
                        self.path_status.is_handshake_confirmed(),
                    );
                }
                // Process ECN information if present.
                if ack_frame.ecn().is_some() {
                    self.process_ecn(ack_frame, &largest_time_sent, epoch)
                }
            }
        }

        self.trackers[epoch].may_loss(
            PacketLostTrigger::TimeThreshold,
            &mut self.packet_spaces[epoch].detect_lost_packets(
                self.rtt.loss_delay(),
                PACKET_THRESHOLD,
                &mut self.algorithm,
            ),
        );

        if self.peer_completed_address_validation() {
            self.pto_count = 0;
        }
        self.set_loss_detection_timer();
    }

    /// A.8. Setting the Loss Detection Timer
    /// SetLossDetectionTimer():
    ///   earliest_loss_time, _ = GetLossTimeAndSpace()
    ///   if (earliest_loss_time != 0):
    ///     // Time threshold loss detection.
    ///     loss_detection_timer.update(earliest_loss_time)
    ///     return
    ///
    ///   if (server is at anti-amplification limit):
    ///     // The server's timer is not set if nothing can be sent.
    ///     loss_detection_timer.cancel()
    ///     return
    ///
    ///   if (no ack-eliciting packets in flight &&
    ///       PeerCompletedAddressValidation()):
    ///     // There is nothing to detect lost, so no timer is set.
    ///     // However, the client needs to arm the timer if the
    ///     // server might be blocked by the anti-amplification limit.
    ///     loss_detection_timer.cancel()
    ///     return
    ///
    ///   timeout, _ = GetPtoTimeAndSpace()
    ///   loss_detection_timer.update(timeout)
    fn set_loss_detection_timer(&mut self) {
        if let Some((earliest_loss_time, _)) = self.get_loss_time_and_epoch() {
            self.loss_detection_timer = Some(earliest_loss_time);
            return;
        }

        if self.path_status.is_at_anti_amplification_limit() {
            self.loss_detection_timer = None;
            return;
        }

        if self.no_ack_eliciting_in_flight() && self.peer_completed_address_validation() {
            self.loss_detection_timer = None;
            return;
        }

        if let Some((timeout, _)) = self.get_pto_time_and_epoch() {
            self.loss_detection_timer = Some(timeout);
        }
    }

    // A.9. On Timeout
    /// OnLossDetectionTimeout():
    ///   earliest_loss_time, pn_space = GetLossTimeAndSpace()
    ///   if (earliest_loss_time != 0):
    ///     // Time threshold loss Detection
    ///     lost_packets = DetectAndRemoveLostPackets(pn_space)
    ///     assert(!lost_packets.empty())
    ///     OnPacketsLost(lost_packets)
    ///     SetLossDetectionTimer()
    ///     return
    ///
    ///   if (no ack-eliciting packets in flight):
    ///     assert(!PeerCompletedAddressValidation())
    ///     // Client sends an anti-deadlock packet: Initial is padded
    ///     // to earn more anti-amplification credit,
    ///     // a Handshake packet proves address ownership.
    ///     if (has Handshake keys):
    ///       SendOneAckElicitingHandshakePacket()
    ///     else:
    ///       SendOneAckElicitingPaddedInitialPacket()
    ///   else:
    ///     // PTO. Send new data if available, else retransmit old data.
    ///     // If neither is available, send a single PING frame.
    ///     _, pn_space = GetPtoTimeAndSpace()
    ///     SendOneOrTwoAckElicitingPackets(pn_space)
    ///
    ///   pto_count++
    ///   SetLossDetectionTimer()
    fn on_loss_detection_timeout(&mut self) {
        if let Some((_, epoch)) = self.get_loss_time_and_epoch() {
            self.trackers[epoch].may_loss(
                PacketLostTrigger::TimeThreshold,
                &mut self.packet_spaces[epoch].detect_lost_packets(
                    self.rtt.loss_delay(),
                    PACKET_THRESHOLD,
                    &mut self.algorithm,
                ),
            );
            self.set_loss_detection_timer();
            return;
        }

        if self.no_ack_eliciting_in_flight() {
            assert!(!self.peer_completed_address_validation());
            if self.path_status.has_handshake_key() {
                // Send an anti-deadlock packet: Initial is padded
                // to earn more anti-amplification credit,
                // a Handshake packet proves address ownership.
                self.send_ack_eliciting_packet(Epoch::Handshake, 1);
            } else {
                self.send_ack_eliciting_packet(Epoch::Initial, 1);
            }
        } else {
            // PTO. Send new data if available, else retransmit old data.
            // If neither is available, send a single PING frame.
            if let Some((_, epoch)) = self.get_pto_time_and_epoch() {
                self.send_ack_eliciting_packet(epoch, 1);
            }
        }

        self.pto_count += 1;
        self.set_loss_detection_timer();
    }

    /// GetLossTimeAndSpace():
    ///   time = loss_time[Initial]
    ///   space = Initial
    ///   for pn_space in [ Handshake, ApplicationData ]:
    ///     if (time == 0 || loss_time[pn_space] < time):
    ///       time = loss_time[pn_space];
    ///       space = pn_space
    ///   return time, space
    fn get_loss_time_and_epoch(&self) -> Option<(Instant, Epoch)> {
        self.packet_spaces
            .iter()
            .zip(Epoch::iter())
            .filter(|(space, _)| space.loss_time.is_some())
            .map(|(space, epoch)| (space.loss_time.unwrap(), *epoch))
            .min_by_key(|(loss_time, _)| *loss_time)
    }

    // GetPtoTimeAndSpace():
    //   duration = (smoothed_rtt + max(4 * rttvar, kGranularity))
    //       * (2 ^ pto_count)
    //   // Anti-deadlock PTO starts from the current time
    //   if (no ack-eliciting packets in flight):
    //     assert(!PeerCompletedAddressValidation())
    //     if (has handshake keys):
    //       return (now() + duration), Handshake
    //     else:
    //       return (now() + duration), Initial
    //   pto_timeout = infinite
    //   pto_space = Initial
    //   for space in [ Initial, Handshake, ApplicationData ]:
    //     if (no ack-eliciting packets in flight in space):
    //         continue;
    //     if (space == ApplicationData):
    //       // Skip Application Data until handshake confirmed.
    //       if (handshake is not confirmed):
    //         return pto_timeout, pto_space
    //       // Include max_ack_delay and backoff for Application Data.
    //       duration += max_ack_delay * (2 ^ pto_count)
    //
    //     t = time_of_last_ack_eliciting_packet[space] + duration
    //     if (t < pto_timeout):
    //       pto_timeout = t
    //       pto_space = space
    //   return pto_timeout, pto_space
    fn get_pto_time_and_epoch(&self) -> Option<(Instant, Epoch)> {
        let mut duration = self.rtt.base_pto(self.pto_count);
        let now = tokio::time::Instant::now().into_std();
        if self.no_ack_eliciting_in_flight() {
            assert!(!self.peer_completed_address_validation());
            if self.path_status.has_handshake_key() {
                return Some((now + duration, Epoch::Handshake));
            } else {
                return Some((now + duration, Epoch::Initial));
            }
        }

        let mut pto_time = None;
        for &epoch in Epoch::iter() {
            if self.packet_spaces[epoch].no_ack_eliciting_in_flight() {
                continue;
            }
            if epoch == Epoch::Data {
                // An endpoint MUST NOT set its PTO timer for the Application Data
                // packet number epoch until the handshake is confirmed
                if !self.path_status.is_handshake_confirmed() {
                    return pto_time;
                }
                duration += self.max_ack_delay * (1 << self.pto_count);
            }
            let t = self.packet_spaces[epoch]
                .time_of_last_ack_eliciting_packet
                .unwrap()
                + duration;
            if pto_time.is_none_or(|(timeout, _)| t < timeout) {
                pto_time = Some((t, epoch));
            }
        }
        pto_time
    }

    fn no_ack_eliciting_in_flight(&self) -> bool {
        Epoch::iter().all(|epoch| self.packet_spaces[*epoch].no_ack_eliciting_in_flight())
    }

    /// PeerCompletedAddressValidation():
    ///   // Assume clients validate the server's address implicitly.
    ///   if (endpoint is server):
    ///     return true
    ///   // Servers complete address validation when a
    ///   // protected packet is received.
    ///   return has received Handshake ACK ||
    ///        handshake confirmed
    fn peer_completed_address_validation(&self) -> bool {
        self.path_status.is_server()
            || self.path_status.has_received_handshake_ack()
            || self.path_status.is_handshake_confirmed()
    }

    fn process_ecn(&mut self, ack: &AckFrame, sent_time: &Instant, epoch: Epoch) {
        self.algorithm.process_ecn(ack, sent_time, epoch);
    }

    fn send_ack_eliciting_packet(&mut self, epoch: Epoch, count: usize) {
        self.tx_waker.wake_by(Signals::PING);
        self.need_send_ack_eliciting_packets[epoch] += count;
    }

    #[inline]
    fn need_ack(&self) -> bool {
        Epoch::iter().any(|&epoch| self.packet_spaces[epoch].rcvd_packets.need_ack().is_some())
    }

    #[inline]
    fn send_quota(&mut self) -> usize {
        let now = tokio::time::Instant::now().into_std();
        self.pacer.schedule(
            self.rtt.smoothed_rtt(),
            self.algorithm.congestion_window(),
            MSS,
            now,
            self.algorithm.pacing_rate(),
        )
    }

    //OnPacketNumberSpaceDiscarded(pn_space):
    //   assert(pn_space != ApplicationData)
    //   RemoveFromBytesInFlight(sent_packets[pn_space])
    //   sent_packets[pn_space].clear()
    //   // Reset the loss detection and PTO timer
    //   time_of_last_ack_eliciting_packet[pn_space] = 0
    //   loss_time[pn_space] = 0
    //   pto_count = 0
    //   SetLossDetectionTimer()
    fn discard_epoch(&mut self, epoch: Epoch) {
        assert!(epoch != Epoch::Data);
        self.packet_spaces[epoch].discard(&mut self.algorithm);
        self.loss_detection_timer = None;
        self.pto_count = 0;
        self.set_loss_detection_timer();
    }

    fn get_pto(&self, epoch: Epoch) -> Duration {
        let mut pto_time = self.rtt.base_pto(self.pto_count);
        if epoch == Epoch::Data {
            pto_time += self.max_ack_delay * (1 << self.pto_count);
        }
        pto_time
    }
}

#[derive(Clone)]
pub struct ArcCC(Arc<Mutex<CongestionController>>);

impl ArcCC {
    pub fn new(
        algorithm: Algorithm,
        max_ack_delay: Duration,
        trackers: [Arc<dyn Feedback>; 3],
        handshake_status: Arc<HandshakeStatus>,
        tx_waker: ArcSendWaker,
    ) -> Self {
        ArcCC(Arc::new(Mutex::new(CongestionController::init(
            algorithm,
            max_ack_delay,
            trackers,
            handshake_status,
            tx_waker,
        ))))
    }
}

impl super::Transport for ArcCC {
    fn launch(&self) -> AbortHandle {
        let cc = self.clone();
        tokio::spawn(
            async move {
                let mut interval = tokio::time::interval(Duration::from_millis(10));
                loop {
                    interval.tick().await;
                    let now = Instant::now();
                    let mut guard = cc.0.lock().unwrap();
                    if guard.loss_detection_timer.is_some_and(|t| t <= now) {
                        guard.on_loss_detection_timeout();
                    }
                    if let Some(expect_quota) = guard.pending_burst {
                        if guard.send_quota() >= expect_quota {
                            guard.pending_burst = None;
                            guard.tx_waker.wake_by(Signals::CONGESTION);
                        }
                    }
                    if guard.need_ack() {
                        guard.tx_waker.wake_by(Signals::TRANSPORT);
                    }
                }
            }
            .instrument_in_current()
            .in_current_span(),
        )
        .abort_handle()
    }

    fn send_quota(&self, expect_quota: usize) -> Result<usize, Signals> {
        let mut guard = self.0.lock().unwrap();
        let send_quota = guard.send_quota();
        if send_quota >= expect_quota {
            Ok(send_quota)
        } else {
            guard.pending_burst = Some(expect_quota);
            Err(Signals::CONGESTION)
        }
    }

    fn retransmit_and_expire_time(&self, epoch: Epoch) -> (Duration, Duration) {
        let guard = self.0.lock().unwrap();
        (
            // 尽量让路径先发起重传
            guard.rtt.loss_delay() + guard.rtt.rttvar(),
            guard.get_pto(epoch),
        )
    }

    fn need_ack(&self, epoch: Epoch) -> Option<(u64, Instant)> {
        let guard = self.0.lock().unwrap();
        guard.packet_spaces[epoch].rcvd_packets.need_ack()
    }

    fn on_pkt_sent(
        &self,
        epoch: Epoch,
        pn: u64,
        is_ack_eliciting: bool,
        sent_bytes: usize,
        in_flight: bool,
        ack: Option<u64>,
    ) {
        let mut guard = self.0.lock().unwrap();
        guard.on_packet_sent(pn, epoch, is_ack_eliciting, in_flight, sent_bytes);

        if let Some(largest_acked) = ack {
            guard.packet_spaces[epoch]
                .rcvd_packets
                .on_ack_sent(pn, largest_acked);
        }
        // See [Section 17.2.2.1](https://www.rfc-editor.org/rfc/rfc9000#name-abandoning-initial-packets)
        if epoch == Epoch::Handshake && !guard.path_status.is_server() {
            guard.discard_epoch(Epoch::Initial);
        }
    }

    fn on_ack_rcvd(&self, epoch: Epoch, ack_frame: &AckFrame) {
        let mut guard = self.0.lock().unwrap();
        let now = Instant::now();
        guard.on_ack_rcvd(epoch, ack_frame, now);

        // See [Section 17.2.2.1](https://www.rfc-editor.org/rfc/rfc9000#name-abandoning-initial-packets)
        if epoch == Epoch::Handshake && guard.path_status.is_server() {
            guard.discard_epoch(Epoch::Initial);
        }
    }

    fn on_pkt_rcvd(&self, epoch: Epoch, pn: u64, is_ack_eliciting: bool) {
        if !is_ack_eliciting {
            return;
        }
        let mut guard = self.0.lock().unwrap();
        guard.packet_spaces[epoch].rcvd_packets.on_pkt_rcvd(pn);
        guard.on_datagram_rcvd();
    }

    fn get_pto(&self, epoch: Epoch) -> Duration {
        let guard = self.0.lock().unwrap();
        guard.get_pto(epoch)
    }

    fn discard_epoch(&self, epoch: Epoch) {
        let mut guard = self.0.lock().unwrap();
        guard.discard_epoch(epoch);
    }

    fn need_send_ack_eliciting(&self, epoch: Epoch) -> usize {
        let guard = self.0.lock().unwrap();
        guard.need_send_ack_eliciting_packets[epoch]
    }

    fn grant_anti_amplification(&self) {
        let guard = self.0.lock().unwrap();
        guard.path_status.release_anti_amplification_limit();
    }
}

#[cfg(test)]
mod tests {}
