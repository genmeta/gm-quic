use std::{
    sync::{Arc, Mutex},
    task::Waker,
    time::{Duration, Instant},
};

use qbase::{
    Epoch,
    frame::{AckFrame, EcnCounts},
    net::route::Pathway,
};
use qlog::quic::recovery::PacketLostTrigger;

use crate::{
    Algorithm, Feedback, MSS, MiniHeap, ObserveHandshake, TrackPackets,
    algorithm::{Control, new_reno::NewReno},
    new_reno::NewReno,
    pacing::{self, Pacer},
    packets::{PacketSpace, SentPacket},
    rtt::{ArcRtt, INITIAL_RTT},
    status::ConnectionStatus,
};

const K_GRANULARITY: Duration = Duration::from_millis(1);
const K_PACKET_THRESHOLD: usize = 3;
const K_TIME_THRESHOLD: f32 = 1.125f32;

/// Imple RFC 9002 Appendix A. Loss Recovery
/// See [Appendix A](https://datatracker.ietf.org/doc/html/rfc9002#name-loss-recovery-pseudocode)
pub struct CongestionController {
    pathway: Pathway,
    algorithm: Box<dyn Control + Send>,
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
    // The time the last packet was sent.
    last_sent_time: Instant,
    // The waker to notify when the controller is ready to send.
    pending_burst: Option<(Waker, usize)>,
    // epoch packet trackers
    trackers: [Arc<dyn Feedback>; 3],
    conn_status: Arc<ConnectionStatus>,
}

impl CongestionController {
    /// A.4. Initialization
    fn init(
        pathway: Pathway,
        algorithm: Algorithm,
        max_ack_delay: Duration,
        trackers: [Arc<dyn Feedback>; 3],
        conn_status: Arc<ConnectionStatus>,
    ) -> Self {
        let algorithm: Box<dyn Control> = match algorithm {
            Algorithm::Bbr => Box::new(bbr::Bbr::new()),
            Algorithm::NewReno => Box::new(NewReno::new()),
        };

        let now = Instant::now();
        CongestionController {
            pathway,
            erased,
            algorithm,
            rtt: ArcRtt::new(),
            loss_detection_timer: None,
            pto_count: 0,
            max_ack_delay,
            packet_spaces: [
                PacketSpace::with_epoch(Epoch::Initial),
                PacketSpace::with_epoch(Epoch::Handshake),
                PacketSpace::with_epoch(Epoch::Data),
            ],
            pacer: Pacer::new(INITIAL_RTT, INITIAL_CWND, MSS, now, None),
            last_sent_time: now,
            pending_burst: None,
            trackers,
            conn_status,
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
        let mut sent = SentPacket::new(packet_number, now, ack_eliciting, in_flight, sent_bytes);
        if in_flight {
            if ack_eliciting {
                self.packet_spaces[epoch].time_of_last_ack_eliciting_packet = Some(now);
            }
            self.algorithm.on_sent(&mut sent, sent_bytes);
            self.set_loss_detection_timer();
        }
        self.packet_spaces[epoch].sent_packets.push_back(sent);
        self.pacer.on_sent(sent_bytes as u64);
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
        if self.conn_status.is_at_anti_amplification_limit() {
            let now = tokio::time::Instant::now().into_std();
            self.set_loss_detection_timer();
            if self.loss_detection_timer.map_or(false, |t| t < now) {
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

        match self.packet_spaces[epoch].on_ack_rcvd(ack_frame, &self.algorithm) {
            None => return,
            Some(newly_acked_packets) => {
                let (largest_pn, largest_time_sent) = newly_acked_packets.largest;
                if largest_pn == ack_frame.largest() && newly_acked_packets.include_ack_eliciting {
                    self.rtt.update(
                        now - largest_time_sent,
                        Duration::from_micros(ack_frame.delay()),
                        self.conn_status.is_handshake_confirmed(),
                    );
                }
            }
        }

        // Process ECN information if present.
        if let Some(ecn) = ack_frame.ecn() {
            self.process_ecn(epoch, ecn)
        }

        self.trackers[epoch].may_loss(
            PacketLostTrigger::TimeThreshold,
            &mut self.packet_spaces[epoch]
                .detect_lost_packets(self.rtt.loss_delay(), K_PACKET_THRESHOLD),
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

        if self.conn_status.is_at_anti_amplification_limit() {
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
                &mut self.packet_spaces[epoch]
                    .detect_lost_packets(self.rtt.loss_delay(), K_PACKET_THRESHOLD),
            );
            self.set_loss_detection_timer();
            return;
        }

        if self.no_ack_eliciting_in_flight() {
            assert!(!self.peer_completed_address_validation());
            if self.conn_status.has_handshake_key() {
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

    /// GetPtoTimeAndSpace():
    ///   duration = (smoothed_rtt + max(4 * rttvar, kGranularity))
    ///       * (2 ^ pto_count)
    ///   // Anti-deadlock PTO starts from the current time
    ///   if (no ack-eliciting packets in flight):
    ///     assert(!PeerCompletedAddressValidation())
    ///     if (has handshake keys):
    ///       return (now() + duration), Handshake
    ///     else:
    ///       return (now() + duration), Initial
    ///   pto_timeout = infinite
    ///   pto_space = Initial
    ///   for space in [ Initial, Handshake, ApplicationData ]:
    ///     if (no ack-eliciting packets in flight in space):
    ///         continue;
    ///     if (space == ApplicationData):
    ///       // Skip Application Data until handshake confirmed.
    ///       if (handshake is not confirmed):
    ///         return pto_timeout, pto_space
    ///       // Include max_ack_delay and backoff for Application Data.
    ///       duration += max_ack_delay * (2 ^ pto_count)
    ///
    ///     t = time_of_last_ack_eliciting_packet[space] + duration
    ///     if (t < pto_timeout):
    ///       pto_timeout = t
    ///       pto_space = space
    ///   return pto_timeout, pto_space
    fn get_pto_time_and_epoch(&self) -> Option<(Instant, Epoch)> {
        let mut duration = self.rtt.base_pto(self.pto_count);
        let now = tokio::time::Instant::now().into_std();
        if self.no_ack_eliciting_in_flight() {
            assert!(!self.peer_completed_address_validation());
            if self.conn_status.has_handshake_key() {
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
                if !self.conn_status.is_handshake_confirmed() {
                    return pto_time;
                }
                duration += self.max_ack_delay * (1 << self.pto_count);
            }
            let t = self.packet_spaces[epoch]
                .time_of_last_ack_eliciting_packet
                .unwrap()
                + duration;
            if pto_time.map_or(true, |(timeout, _)| t < timeout) {
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
        self.conn_status.is_server()
            || self.conn_status.has_received_handshake_ack()
            || self.conn_status.is_handshake_confirmed()
    }

    fn process_ecn(&mut self, _: Epoch, _: EcnCounts) {
        todo!()
    }

    fn send_ack_eliciting_packet(&self, _epoch: Epoch, _count: usize) {
        todo!()
    }

    #[inline]
    fn requires_ack(&self, now: Instant) -> bool {
        todo!()
    }

    #[inline]
    fn send_quota(&mut self, now: Instant) -> usize {
        self.pacer.schedule(
            self.rtt.smoothed_rtt(),
            self.algorithm.cwnd(),
            MSS,
            now,
            self.algorithm.pacing_rate(),
        )
    }
}

#[derive(Clone)]
pub struct ArcCC(Arc<Mutex<CongestionController>>);

impl ArcCC {
    pub fn new(
        pathway: Pathway,
        algorithm: Algorithm,
        max_ack_delay: Duration,
        trackers: [Arc<dyn Feedback>; 3],
        conn_status: Arc<ConnectionStatus>,
    ) -> Self {
        ArcCC(Arc::new(Mutex::new(CongestionController::init(
            pathway,
            erased,
            algorithm,
            max_ack_delay,
            trackers,
            conn_status,
        ))))
    }
}

/*
impl super::CongestionControl for ArcCC {
    fn launch_with_waker(&self, tx_waker: ArcSendWaker) -> AbortHandle {
        let cc = self.clone();
        tokio::spawn(
            async move {
                let mut interval = tokio::time::interval(Duration::from_millis(10));
                loop {
                    interval.tick().await;
                    let now = Instant::now();
                    let mut guard = cc.0.lock().unwrap();
                    if guard.loss_detection_timer.is_timeout(now) {
                        guard.on_loss_detection_timeout(now);
                    }
                    if let Some(&(.., expect_quota)) = guard.pending_burst.as_ref() {
                        if guard.send_quota(now) >= expect_quota {
                            guard.pending_burst.take().unwrap().0.wake();
                        }
                    }
                    if guard.requires_ack(now) {
                        tx_waker.wake_by(Signals::TRANSPORT);
                    }
                }
            }
            .instrument_in_current()
            .in_current_span(),
        )
        .abort_handle()
    }

    fn poll_send(&self, cx: &mut Context<'_>, expect_quota: usize) -> Poll<usize> {
        let mut guard = self.0.lock().unwrap();
        let now = Instant::now();
        let send_quota = guard.send_quota(now);
        if send_quota >= expect_quota {
            return Poll::Ready(send_quota);
        }
        guard.pending_burst = Some((cx.waker().clone(), expect_quota));
        Poll::Pending
    }

    fn need_ack(&self, epoch: Epoch) -> Option<(u64, Instant)> {
        let guard = self.0.lock().unwrap();
        guard.rcvd_records[epoch].requires_ack(guard.max_ack_delay, Instant::now())
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
        let now = Instant::now();
        guard.on_packet_sent(pn, epoch, is_ack_eliciting, in_flight, sent_bytes, now);

        guard.last_sent_time = now;
        if let Some(largest_acked) = ack {
            let record = &guard.rcvd_records[epoch];
            // send ack for the first time
            if record.last_ack_sent.is_none() {
                let begin = record.rcvd_queue.front().map(|&(pn, _)| pn).unwrap_or(0);
                guard.erased[epoch].update(&guard.pathway, begin);
            }
            guard.rcvd_records[epoch].on_ack_sent(pn, largest_acked);
        }
    }

    fn on_ack_rcvd(&self, epoch: Epoch, ack_frame: &AckFrame) {
        let mut guard = self.0.lock().unwrap();
        let now = Instant::now();
        guard.on_ack_rcvd(epoch, ack_frame, now);
    }

    fn on_pkt_rcvd(&self, epoch: Epoch, pn: u64, is_ack_eliciting: bool) {
        if !is_ack_eliciting {
            return;
        }
        let mut guard = self.0.lock().unwrap();
        guard.rcvd_records[epoch].on_pkt_rcvd(pn);
        let now = Instant::now();
        guard.on_datagram_rcvd(now);
    }

    fn get_pto(&self, epoch: Epoch) -> Duration {
        self.0.lock().unwrap().current_pto(epoch)
    }

    fn stop(&self) {
        let guard = self.0.lock().unwrap();
        for epoch in &[Epoch::Initial, Epoch::Handshake, Epoch::Data] {
            // mark all inflights as lost
            let loss_pns = guard.sent_packets[*epoch]
                .iter()
                .filter(|&pkt| (!pkt.is_acked))
                .map(|pkt| pkt.pn);
            guard.trackers[*epoch]
                .may_loss(PacketLostTrigger::PtoExpired, &mut loss_pns.into_iter());
            // remove from paths erased
            guard.erased[*epoch].remove(&guard.pathway);
        }
    }
}

#[cfg(test)]
mod tests {
    use qbase::varint::VarInt;
    use qrecovery::reliable::ArcReliableFrameDeque;

    use super::*;

    #[test]
    fn test_on_packet_sent_multiple_packets() {
        let mut congestion = create_congestion_controller_for_test();
        let now = Instant::now();
        for i in 1..=5 {
            congestion.on_packet_sent(i, Epoch::Initial, true, true, 1000, now);
        }
        assert_eq!(congestion.sent_packets[Epoch::Initial].len(), 5);
        for (i, sent) in congestion.sent_packets[Epoch::Initial].iter().enumerate() {
            assert_eq!(sent.pn, i as u64 + 1);
            assert_eq!(sent.size, 1000);
            assert_eq!(sent.time_sent, now);
        }
    }

    #[test]
    fn test_on_packet_sent_different_epochs() {
        let mut congestion = create_congestion_controller_for_test();
        let now = Instant::now();
        congestion.on_packet_sent(1, Epoch::Initial, true, true, 1000, now);
        congestion.on_packet_sent(2, Epoch::Handshake, true, true, 1000, now);
        congestion.on_packet_sent(3, Epoch::Data, true, true, 1000, now);
        assert_eq!(congestion.sent_packets[Epoch::Initial].len(), 1);
        assert_eq!(congestion.sent_packets[Epoch::Handshake].len(), 1);
        assert_eq!(congestion.sent_packets[Epoch::Data].len(), 1);
        for epoch in &[Epoch::Initial, Epoch::Handshake, Epoch::Data] {
            let sent = &congestion.sent_packets[*epoch][0];
            assert_eq!(sent.pn, *epoch as u64 + 1);
            assert_eq!(sent.size, 1000);
            assert_eq!(sent.time_sent, now);
        }
    }

    #[test]
    fn test_detect_may_loss_packets() {
        let mut congestion = create_congestion_controller_for_test();
        let now = Instant::now();
        let epoch = Epoch::Initial;
        for i in 1..=5 {
            congestion.on_packet_sent(i, epoch, true, true, 1000, now);
        }
        // ack 5，检测出 1,2 因为乱序丢包
        congestion.largest_acked_packet[epoch] = Some(5);
        congestion.sent_packets[epoch][4].is_acked = true;
        let lost_packets = congestion.may_loss_packets(epoch, now);
        assert_eq!(lost_packets.len(), 2);
        for (i, &lost) in lost_packets.iter().enumerate() {
            assert_eq!(lost, i as u64 + 1);
        }
        assert_eq!(congestion.sent_packets[epoch].len(), 5);
        // loss delay =  333*1.25
        let loss_packets = congestion.may_loss_packets(epoch, now + Duration::from_millis(417));
        // 3,4 因为超时丢包
        assert_eq!(loss_packets.len(), 2);
        for (i, &lost) in loss_packets.iter().enumerate() {
            assert_eq!(lost, i as u64 + 3);
        }
    }

    #[test]
    fn test_remove_loss_packets() {
        let mut congestion = create_congestion_controller_for_test();
        let now = Instant::now();
        let epoch = Epoch::Initial;
        for i in 1..=5 {
            congestion.on_packet_sent(i, epoch, true, true, 1000, now);
        }
        congestion.largest_acked_packet[epoch] = Some(5);
        congestion.sent_packets[epoch][4].is_acked = true;
        // mark 1,2 may loss
        congestion.may_loss_packets(epoch, now);
        assert_eq!(congestion.sent_packets[epoch].len(), 5);
        let pto = congestion.current_pto(epoch);
        let new_time = now + pto + Duration::from_millis(100);
        // 超过了 PTO 还未收到
        congestion.remove_loss_packets(epoch, new_time);
        // 3,4,5
        assert_eq!(congestion.sent_packets[epoch].len(), 3);

        for i in 6..=10 {
            congestion.on_packet_sent(i, epoch, true, true, 1000, new_time);
        }

        // ack 6 ~ 10
        let ack_frame = AckFrame::new(
            VarInt::from_u32(10),
            VarInt::from_u32(100),
            VarInt::from_u32(4),
            Vec::new(),
            None,
        );
        congestion.on_ack_rcvd(epoch, &ack_frame, new_time);
        // 3,4 loss remove 6 ~ 10 ack remove
        congestion.may_loss_packets(epoch, new_time);
        assert_eq!(congestion.sent_packets[epoch].len(), 0);
    }

    #[test]
    fn test_on_ack_received() {
        let now = Instant::now();
        let mut congestion_controller = create_congestion_controller_for_test();

        // 发送 1 ~ 5
        for i in 1..=5 {
            congestion_controller.on_packet_sent(
                i,
                Epoch::Initial,
                true, // ack_eliciting
                true, // in_flight
                1000, // sent_bytes
                now,
            );
        }
        // ack 1 ~ 3
        let ack_frame = AckFrame::new(
            VarInt::from_u32(3),
            VarInt::from_u32(100),
            VarInt::from_u32(2),
            Vec::new(),
            None,
        );
        congestion_controller.on_ack_rcvd(Epoch::Initial, &ack_frame, now);
        // 验证前三个数据包已被移除，剩下的数据包还在
        assert_eq!(congestion_controller.sent_packets[Epoch::Initial].len(), 2);
        for (i, sent) in congestion_controller.sent_packets[Epoch::Initial]
            .iter()
            .enumerate()
        {
            assert_eq!(sent.pn, i as u64 + 4);
        }

        // 发送 8 ~ 13
        for i in 8..=13 {
            congestion_controller.on_packet_sent(
                i,
                Epoch::Initial,
                true, // ack_eliciting
                true, // in_flight
                1000, // sent_bytes
                now,
            );
        }

        // sent 为 4,5,8,9,10,11,12,13
        // ack 9
        // lost 4
        // 剩余 4(loss),5,8,9(ack),10,11,12,13
        let ack_frame = AckFrame::new(
            VarInt::from_u32(9),
            VarInt::from_u32(100),
            VarInt::from_u32(0),
            Vec::new(),
            None,
        );

        congestion_controller.on_ack_rcvd(Epoch::Initial, &ack_frame, now);
        assert_eq!(congestion_controller.sent_packets[Epoch::Initial].len(), 8);
    }

    #[test]
    fn test_ack_record() {
        let max_ack_delay = Duration::from_millis(100);
        let mut ack_reocrd = RcvdRecords::new(Epoch::Initial);
        ack_reocrd.on_pkt_rcvd(1);
        assert!(
            ack_reocrd
                .requires_ack(max_ack_delay, Instant::now())
                .is_some()
        );

        ack_reocrd.on_pkt_rcvd(1);
        assert_eq!(ack_reocrd.rcvd_queue.len(), 1);

        ack_reocrd.on_ack_sent(1, 1);

        assert!(
            ack_reocrd
                .requires_ack(max_ack_delay, Instant::now())
                .is_none()
        );

        ack_reocrd.on_pkt_rcvd(3);
        assert_eq!(
            ack_reocrd
                .rcvd_queue
                .iter()
                .map(|&(pn, _)| pn)
                .collect::<Vec<_>>(),
            vec![1, 3]
        );

        ack_reocrd.on_pkt_rcvd(0);
        assert_eq!(
            ack_reocrd
                .rcvd_queue
                .iter()
                .map(|&(pn, _)| pn)
                .collect::<Vec<_>>(),
            vec![0, 1, 3]
        );
        assert_eq!(
            ack_reocrd
                .requires_ack(max_ack_delay, Instant::now())
                .unwrap()
                .0,
            3
        );

        ack_reocrd.on_pkt_rcvd(5);
        ack_reocrd.on_pkt_rcvd(7);
        assert_eq!(
            ack_reocrd
                .rcvd_queue
                .iter()
                .map(|&(pn, _)| pn)
                .collect::<Vec<_>>(),
            vec![0, 1, 3, 5, 7]
        );
        assert_eq!(
            ack_reocrd
                .requires_ack(max_ack_delay, Instant::now())
                .unwrap()
                .0,
            7
        );

        // pn 2 ack 0,1,3,5,7
        ack_reocrd.on_ack_sent(2, 7);
        ack_reocrd.on_pkt_rcvd(9);
        assert_eq!(
            ack_reocrd
                .rcvd_queue
                .iter()
                .map(|&(pn, _)| pn)
                .collect::<Vec<_>>(),
            vec![0, 1, 3, 5, 7, 9]
        );

        // recv pn 2 ack, retire pn <= 7 - 3
        ack_reocrd.should_drain(2);
        assert_eq!(
            ack_reocrd
                .rcvd_queue
                .iter()
                .map(|&(pn, _)| pn)
                .collect::<Vec<_>>(),
            vec![5, 7, 9]
        );

        ack_reocrd.on_ack_sent(3, 9);
        ack_reocrd.on_pkt_rcvd(8);
        ack_reocrd.on_pkt_rcvd(11);
        assert_eq!(
            ack_reocrd
                .rcvd_queue
                .iter()
                .map(|&(pn, _)| pn)
                .collect::<Vec<_>>(),
            vec![5, 7, 8, 9, 11]
        );
        // recv pn 3 ack, retire pn <= 9 - 3

        ack_reocrd.should_drain(3);
        assert_eq!(
            ack_reocrd
                .rcvd_queue
                .iter()
                .map(|&(pn, _)| pn)
                .collect::<Vec<_>>(),
            vec![7, 8, 9, 11]
        );
    }

    #[test]
    fn test_ack_record_reversed() {
        let max_ack_delay = Duration::from_millis(100);
        let mut ack_reocrd = RcvdRecords::new(Epoch::Initial);

        ack_reocrd.on_pkt_rcvd(10);
        ack_reocrd.on_pkt_rcvd(9);
        ack_reocrd.on_pkt_rcvd(8);

        assert_eq!(
            ack_reocrd
                .requires_ack(max_ack_delay, Instant::now())
                .unwrap()
                .0,
            10
        );
        ack_reocrd.on_ack_sent(1, 10);

        ack_reocrd.on_pkt_rcvd(7);
        ack_reocrd.on_pkt_rcvd(6);
        ack_reocrd.on_pkt_rcvd(5);
        assert_eq!(
            ack_reocrd
                .requires_ack(max_ack_delay, Instant::now())
                .unwrap()
                .0,
            10
        );
        ack_reocrd.on_ack_sent(2, 10);
        assert_eq!(ack_reocrd.requires_ack(max_ack_delay, Instant::now()), None);

        // ack 1, retire pn <= 10 - 3
        ack_reocrd.should_drain(1);
        assert_eq!(ack_reocrd.requires_ack(max_ack_delay, Instant::now()), None);
        assert_eq!(
            ack_reocrd
                .rcvd_queue
                .iter()
                .map(|&(pn, _)| pn)
                .collect::<Vec<_>>(),
            vec![8, 9, 10]
        );

        // 4 属于迟到的包，可能被对面判定为丢包
        ack_reocrd.on_pkt_rcvd(4);

        // ack 2，对面可能判定 4 为丢包，retire pn <= 10 - 3
        ack_reocrd.should_drain(2);

        assert_eq!(
            ack_reocrd
                .requires_ack(max_ack_delay, Instant::now())
                .unwrap()
                .0,
            10
        );
        assert_eq!(
            ack_reocrd
                .rcvd_queue
                .iter()
                .map(|&(pn, _)| pn)
                .collect::<Vec<_>>(),
            vec![8, 9, 10]
        );
    }
    struct Mock;
    impl TrackPackets for Mock {
        fn may_loss(&self, _: PacketLostTrigger, _: &mut dyn Iterator<Item = u64>) {}
        fn drain_to(&self, _: u64) {}
    }

    fn create_congestion_controller_for_test() -> CongestionController {
        let output = ArcReliableFrameDeque::with_capacity_and_wakers(10, Default::default());
        let pathway = Pathway::new(
            "127.0.0.1:12345".parse().unwrap(),
            "127.0.0.1:54321".parse().unwrap(),
        );
        CongestionController::init(
            pathway,
            Algorithm::Bbr,
            Duration::from_millis(100),
            [Arc::new(Mock), Arc::new(Mock), Arc::new(Mock)],
            Box::new(Handshake::new(qbase::sid::Role::Client, output)),
        )
    }
}
*/
