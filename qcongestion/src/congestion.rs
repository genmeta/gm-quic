use std::{
    cmp::Ordering,
    collections::VecDeque,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use qbase::{
    Epoch,
    frame::{AckFrame, EcnCounts, HandshakeDoneFrame, SendFrame},
    handshake::Handshake,
    sid::Role,
};
use qlog::{quic::recovery::PacketLostTrigger, telemetry::Instrument};
use tokio::{sync::Notify, task::AbortHandle};
use tracing::Instrument as _;

// todo: remove this in future
impl<T> ObserveHandshake for Handshake<T>
where
    T: SendFrame<HandshakeDoneFrame> + Clone + Send + Sync,
{
    fn role(&self) -> qbase::sid::Role {
        Handshake::role(self)
    }

    fn is_handshake_done(&self) -> bool {
        Handshake::is_handshake_done(self)
    }

    fn is_getting_keys(&self) -> bool {
        Handshake::is_getting_keys(self)
    }
}

use crate::{
    ObserveHandshake, TrackPackets,
    bbr::{self, INITIAL_CWND},
    new_reno::NewReno,
    pacing::{self, Pacer},
    rtt::{ArcRtt, INITIAL_RTT},
};

const K_GRANULARITY: Duration = Duration::from_millis(1);
const K_PACKET_THRESHOLD: usize = 3;

///  default datagram size in bytes.
pub const MSS: usize = 1200;

/// The [`CongestionAlgorithm`] enum represents different congestion control algorithms that can be used.
pub enum CongestionAlgorithm {
    Bbr,
    NewReno,
}

/// Imple RFC 9002 Appendix A. Loss Recovery
/// See [Appendix A](https://datatracker.ietf.org/doc/html/rfc9002#name-loss-recovery-pseudocode)
pub struct CongestionController {
    algorithm: Box<dyn Algorithm + Send>,
    // The Round-Trip Time (RTT) estimator.
    rtt: ArcRtt,
    loss_timer: LossDetectionTimer,
    // The number of times a PTO has been sent without receiving an acknowledgment.
    // Use to pto backoff
    pto_count: u32,
    max_ack_delay: Duration,
    // The time the most recent ack-eliciting packet was sent.
    time_of_last_ack_eliciting_packet: [Option<Instant>; Epoch::count()],
    // The largest packet number acknowledged in the packet number space so far.
    largest_acked_packet: [Option<u64>; Epoch::count()],
    // The time at which the next packet in that packet number space can be
    // considered lost based on exceeding the reordering window in time.
    loss_time: [Option<Instant>; Epoch::count()],
    // record sent packets, remove it when receive ack.
    sent_packets: [VecDeque<SentPkt>; Epoch::count()],
    // pacer is used to control the burst rate
    pacer: pacing::Pacer,
    // The time the last packet was sent.
    last_sent_time: Instant,
    // Records of received packets for each epoch.
    rcvd_records: [RcvdRecords; Epoch::count()],
    // The waker to notify when the controller is ready to send.
    pending_burst: Option<(Waker, usize)>,
    // Space packet trackers
    trackers: [Arc<dyn TrackPackets>; 3],
    // Handshake state
    handshake: Box<dyn ObserveHandshake>,
}

impl CongestionController {
    // A.4. Initialization
    fn new(
        algorithm: CongestionAlgorithm,
        max_ack_delay: Duration,
        trackers: [Arc<dyn TrackPackets>; 3],
        handshake: Box<dyn ObserveHandshake>,
    ) -> Self {
        let algorithm: Box<dyn Algorithm> = match algorithm {
            CongestionAlgorithm::Bbr => Box::new(bbr::Bbr::new()),
            CongestionAlgorithm::NewReno => Box::new(NewReno::new()),
        };

        let now = Instant::now();
        CongestionController {
            algorithm,
            rtt: ArcRtt::new(),
            loss_timer: LossDetectionTimer::default(),
            max_ack_delay,
            pto_count: 0,
            time_of_last_ack_eliciting_packet: [None, None, None],
            largest_acked_packet: [None, None, None],
            loss_time: [None, None, None],
            sent_packets: [VecDeque::new(), VecDeque::new(), VecDeque::new()],
            rcvd_records: [
                RcvdRecords::new(Epoch::Initial),
                RcvdRecords::new(Epoch::Handshake),
                RcvdRecords::new(Epoch::Data),
            ],
            pacer: Pacer::new(INITIAL_RTT, INITIAL_CWND, MSS, now, None),
            last_sent_time: now,
            pending_burst: None,
            trackers,
            handshake,
        }
    }

    // A.5. On Sending a Packet
    pub fn on_packet_sent(
        &mut self,
        pn: u64,
        space: Epoch,
        ack_eliciting: bool,
        in_flight: bool,
        sent_bytes: usize,
        now: Instant,
    ) {
        let mut sent = SentPkt::new(pn, sent_bytes, now);
        if in_flight {
            if ack_eliciting {
                self.time_of_last_ack_eliciting_packet[space] = Some(now);
            }
            self.algorithm.on_sent(&mut sent, sent_bytes, now);
            self.set_loss_timer();
        }

        // Ensure that the packet number is greater than the last sent packet number for the given epoch.
        if let Some(last_pn) = self.sent_packets[space].back() {
            assert!(pn > last_pn.pn);
        }

        if ack_eliciting {
            self.sent_packets[space].push_back(sent);
        }
        self.pacer.on_sent(sent_bytes as u64);
    }

    // A.6. On Receiving a Datagram
    pub fn on_datagram_rcvd(&mut self, now: Instant) {
        // If this datagram unblocks the server, arm the PTO timer to avoid deadlock.
        self.set_loss_timer();
        if self.loss_timer.is_timeout(now) {
            // Execute PTO if it had expired while the amplification limit applied.
            self.on_loss_timeout(now);
        }
    }

    // A.7. On Receiving an Acknowledgment
    pub fn on_ack_rcvd(&mut self, space: Epoch, ack_frame: &AckFrame, now: Instant) {
        let largest_acked: u64 = ack_frame.largest();

        self.largest_acked_packet[space] =
            Some(largest_acked.max(self.largest_acked_packet[space].unwrap_or(0)));

        let (newly_acked_packets, latest_rtt) = self.get_newly_acked_packets(space, ack_frame);
        if newly_acked_packets.is_empty() {
            return;
        }

        let ack_delay = Duration::from_micros(ack_frame.delay());
        if let Some(latest_rtt) = latest_rtt {
            let is_handshake_confirmed = self.handshake.is_handshake_done();
            self.rtt
                .update(latest_rtt, ack_delay, is_handshake_confirmed);
        }

        // Process ECN information if present.
        if let Some(ecn) = ack_frame.ecn() {
            self.process_ecn(space, ecn)
        }

        let lost_packets = self.remove_loss_packets(space, now);
        if !lost_packets.is_empty() {
            self.on_packets_lost(
                PacketLostTrigger::ReorderingThreshold,
                lost_packets.into_iter(),
                space,
            );
        }
        self.algorithm.on_ack(newly_acked_packets, now);

        if self.server_completed_address_validation() {
            self.pto_count = 0;
        }
        self.set_loss_timer();
    }

    pub fn get_newly_acked_packets(
        &mut self,
        epoch: Epoch,
        ack_frame: &AckFrame,
    ) -> (VecDeque<AckedPkt>, Option<Duration>) {
        let mut newly_acked_packets: VecDeque<AckedPkt> = VecDeque::new();
        let largest_acked: u64 = ack_frame.largest();
        let mut latest_rtt = None;
        for range in ack_frame.iter() {
            for pn in range {
                let acked: Option<AckedPkt> = self.sent_packets[epoch]
                    .binary_search_by_key(&pn, |p| p.pn)
                    .ok()
                    .map(|idx| {
                        self.rcvd_records[epoch].ack(pn, &self.trackers);
                        self.sent_packets[epoch][idx].is_acked = true;
                        self.sent_packets[epoch][idx].clone().into()
                    });
                if let Some(ack) = acked {
                    // largest is newly ackd, update latest_rtt
                    if pn == largest_acked {
                        latest_rtt = Some(ack.rtt);
                    }
                    newly_acked_packets.push_back(ack);
                }
            }
        }
        self.slide_sent_packets(epoch);
        (newly_acked_packets, latest_rtt)
    }

    // A.8. Setting the Loss Detection Timer
    fn on_packets_lost(
        &mut self,
        trigger: PacketLostTrigger,
        packets: impl Iterator<Item = SentPkt>,
        epoch: Epoch,
    ) {
        let now = Instant::now();

        self.trackers[epoch].may_loss(
            trigger,
            &mut packets
                .inspect(|lost| self.algorithm.on_congestion_event(lost, now))
                .map(|lost| lost.pn),
        );
    }

    // A.8. Setting the Loss Detection Timer
    fn set_loss_timer(&mut self) {
        let (earliest_loss_time, _) = self.get_loss_time_and_space();
        if let Some(earliest_loss_time) = earliest_loss_time {
            self.loss_timer.update(earliest_loss_time);
            return;
        }

        if self.no_ack_eliciting_in_flight() && self.server_completed_address_validation() {
            self.loss_timer.cancel();
            return;
        }

        if let Some((pto_time, _)) = self.get_pto_timeout() {
            self.loss_timer.update(pto_time);
        }
    }

    // A.9. On Timeout
    fn on_loss_timeout(&mut self, now: Instant) {
        let (earliest_loss_time, space) = self.get_loss_time_and_space();
        // lost timeout
        if earliest_loss_time.is_some() {
            let loss_packet = self.remove_loss_packets(space, now);
            assert!(!loss_packet.is_empty());
            self.on_packets_lost(
                PacketLostTrigger::TimeThreshold,
                loss_packet.into_iter(),
                space,
            );
            self.set_loss_timer();
            return;
        }

        // probe timeout
        let pto_epoch =
            if self.no_ack_eliciting_in_flight() && !self.server_completed_address_validation() {
                // Client sends an anti-deadlock packet: Initial is padded
                // to earn more anti-amplification credit,
                // a Handshake packet proves address ownership.
                if self.handshake.is_getting_keys() {
                    Epoch::Handshake
                } else {
                    Epoch::Initial
                }
            } else if let Some((_, epoch)) = self.get_pto_timeout() {
                epoch
            } else {
                self.set_loss_timer();
                return;
            };

        self.pto_count += 1;
        // Retransmit frames from the oldest sent packet. However,
        // these packets are not actually declared lost, so have no effect on
        // congestion control, we just retransmit the data they carry.
        let retransmit = self.sent_packets[pto_epoch]
            .iter()
            .take(self.pto_count as usize);

        self.trackers[pto_epoch].may_loss(
            PacketLostTrigger::PtoExpired,
            &mut retransmit.map(|lost| lost.pn),
        );

        self.set_loss_timer();
    }

    fn get_loss_time_and_space(&self) -> (Option<Instant>, Epoch) {
        let mut time = self.loss_time[Epoch::Initial];
        let mut space = Epoch::Initial;
        for &epoch in Epoch::iter() {
            if let Some(loss) = self.loss_time[epoch] {
                if time.is_none() || loss < time.unwrap() {
                    time = Some(loss);
                    space = epoch;
                }
            }
        }
        (time, space)
    }

    fn get_pto_time(&self, epoch: Epoch) -> Duration {
        let smoothed_rtt = self.rtt.smoothed_rtt();
        let rttvar = self.rtt.rttvar();
        let mut duration = smoothed_rtt + std::cmp::max(K_GRANULARITY, rttvar * 4);
        // 握手已完成, 则应该考虑 max_ack_delay
        if epoch == Epoch::Data && self.handshake.is_handshake_done() {
            duration += self.max_ack_delay
        }
        duration * 2_u32.pow(self.pto_count)
    }

    fn get_pto_timeout(&self) -> Option<(Instant, Epoch)> {
        let mut duration = self.get_pto_time(Epoch::Initial);
        if self.no_ack_eliciting_in_flight() {
            return Some((Instant::now() + duration, Epoch::Initial));
        }

        let mut pto_time = None;
        for &space in Epoch::iter() {
            if self.sent_packets[space].is_empty() {
                continue;
            }
            if space == Epoch::Data {
                // An endpoint MUST NOT set its PTO timer for the Application Data
                // packet number space until the handshake is confirmed
                if !self.handshake.is_handshake_done() {
                    return pto_time;
                }
                duration += self.max_ack_delay * 2_u32.pow(self.pto_count);
            }
            let new_time = self.time_of_last_ack_eliciting_packet[space].unwrap() + duration;
            if pto_time.is_none() || new_time < pto_time.unwrap().0 {
                pto_time = Some((new_time, space));
            }
        }
        pto_time
    }

    fn remove_loss_packets(&mut self, space: Epoch, now: Instant) -> Vec<SentPkt> {
        assert!(self.largest_acked_packet[space].is_some());
        let largest_acked = self.largest_acked_packet[space].unwrap();
        self.loss_time[space] = None;

        let loss_delay = self.rtt.loss_delay();
        let lost_send_time = now.checked_sub(loss_delay).unwrap();

        let mut loss_packets = Vec::new();
        let mut loss_pn = Vec::new();

        let mut largest_ack_index = 0;
        while largest_ack_index != self.sent_packets[space].len()
            && self.sent_packets[space][largest_ack_index].pn < largest_acked
        {
            largest_ack_index += 1;
        }

        let mut i = 0;
        while i != self.sent_packets[space].len() && self.sent_packets[space][i].pn < largest_acked
        {
            if self.sent_packets[space][i].is_acked {
                i += 1;
                continue;
            }
            // 距离 largest ack index 相差超过 threshold 即为丢包
            if self.sent_packets[space][i].time_sent <= lost_send_time
                || largest_ack_index - i >= K_PACKET_THRESHOLD
            {
                if let Some(loss) = self.sent_packets[space].remove(i) {
                    let pn = loss.pn;
                    loss_pn.push(pn);
                    loss_packets.push(loss);
                    largest_ack_index -= 1;
                }
            } else {
                let loss_time = self.sent_packets[space][i].time_sent + loss_delay;
                self.loss_time[space] = match self.loss_time[space] {
                    Some(lt) => Some(lt.min(loss_time)),
                    None => Some(loss_time),
                };
                i += 1;
            }
        }

        self.slide_sent_packets(space);
        loss_packets
    }

    fn slide_sent_packets(&mut self, space: Epoch) {
        while self.sent_packets[space]
            .front()
            .is_some_and(|sent| sent.is_acked)
        {
            self.sent_packets[space].pop_front();
        }
    }

    fn no_ack_eliciting_in_flight(&self) -> bool {
        Epoch::iter().all(|space| self.sent_packets[*space].is_empty())
    }

    fn server_completed_address_validation(&mut self) -> bool {
        self.handshake.role() == Role::Server || self.handshake.is_handshake_done()
    }

    fn process_ecn(&mut self, _: Epoch, _: EcnCounts) {
        todo!()
    }

    #[inline]
    fn requires_ack(&self) -> bool {
        self.rcvd_records
            .iter()
            .any(|record| record.requires_ack(self.max_ack_delay).is_some())
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

/// Shared congestion controller
#[derive(Clone)]
pub struct ArcCC(Arc<Mutex<CongestionController>>);

impl ArcCC {
    pub fn new(
        algorithm: CongestionAlgorithm,
        max_ack_delay: Duration,
        trackers: [Arc<dyn TrackPackets>; 3],
        handshake: Box<dyn ObserveHandshake>,
    ) -> Self {
        ArcCC(Arc::new(Mutex::new(CongestionController::new(
            algorithm,
            max_ack_delay,
            trackers,
            handshake,
        ))))
    }
}

impl super::CongestionControl for ArcCC {
    fn launch(&self, notify: Arc<Notify>) -> AbortHandle {
        let cc = self.clone();
        tokio::spawn(
            async move {
                let mut interval = tokio::time::interval(Duration::from_millis(10));
                loop {
                    interval.tick().await;
                    let now = Instant::now();
                    let mut guard = cc.0.lock().unwrap();
                    if guard.loss_timer.is_timeout(now) {
                        guard.on_loss_timeout(now);
                    }
                    if let Some(&(.., expect_quota)) = guard.pending_burst.as_ref() {
                        if guard.send_quota(now) >= expect_quota {
                            guard.pending_burst.take().unwrap().0.wake();
                        }
                    }
                    if guard.requires_ack() {
                        notify.notify_waiters();
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

    fn need_ack(&self, space: Epoch) -> Option<(u64, Instant)> {
        let guard = self.0.lock().unwrap();
        guard.rcvd_records[space].requires_ack(guard.max_ack_delay)
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
            guard.rcvd_records[epoch].on_ack_sent(pn, largest_acked);
        }
    }

    fn on_ack(&self, space: Epoch, ack_frame: &AckFrame) {
        let mut guard = self.0.lock().unwrap();
        let now = Instant::now();
        guard.on_ack_rcvd(space, ack_frame, now);
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

    fn pto_time(&self, epoch: Epoch) -> Duration {
        self.0.lock().unwrap().get_pto_time(epoch)
    }
}

/// The [`RcvdRecords`] struct is used to maintain records of received packets for each epoch.
/// It tracks acknowledged packets and determines when an ACK frame should be sent.
/// It also retires packets that have been acknowledged by an ACK frame that has already sent and which has been confirmed by the peer.
#[derive(Debug)]
struct RcvdRecords {
    epoch: Epoch,
    ack_immedietly: bool,
    last_ack_sent: Option<(u64, u64)>,
    rcvd_queue: VecDeque<(u64, Instant)>,
}

impl RcvdRecords {
    fn new(epoch: Epoch) -> Self {
        Self {
            epoch,
            ack_immedietly: false,
            last_ack_sent: None,
            rcvd_queue: VecDeque::new(),
        }
    }

    fn on_pkt_rcvd(&mut self, pn: u64) {
        // An endpoint MUST acknowledge all ack-eliciting Initial and Handshake packets immediately
        if self.epoch == Epoch::Initial || self.epoch == Epoch::Handshake {
            self.ack_immedietly = true;
        }
        // See [Section 13.2.1](https://www.rfc-editor.org/rfc/rfc9000.html#name-sending-ack-frames)
        // An endpoint SHOULD generate and send an ACK frame without delay when it receives an ack-eliciting packet either:
        // 1. When the received packet has a packet number less than another ack-eliciting packet that has been received
        // 2. when the packet has a packet number larger than the highest-numbered ack-eliciting packet that has been
        // received and there are missing packets between that packet and this packet.
        if let Some(&(largest_pn, _)) = self.rcvd_queue.back() {
            self.ack_immedietly = pn < largest_pn || pn.saturating_sub(largest_pn) > 1;

            let idx = self.rcvd_queue.partition_point(|&(x, _)| x < pn);
            match self.rcvd_queue.get(idx) {
                Some(&(n, _)) if n != pn => self.rcvd_queue.insert(idx, (pn, Instant::now())),
                None => {
                    self.rcvd_queue.push_back((pn, Instant::now()));
                }
                _ => (),
            }
        } else {
            self.rcvd_queue.push_back((pn, Instant::now()));
        }
    }

    /// Checks whether an ACK frame needs to be sent.
    /// Returns [`Some`] if it's time to send an ACK based on the maximum delay.
    fn requires_ack(&self, max_delay: Duration) -> Option<(u64, Instant)> {
        let largest_pn = self.rcvd_queue.back().map(|&(pn, time)| (pn, time));
        if self.ack_immedietly {
            return largest_pn;
        }

        let largest_ack_sent = self.last_ack_sent.map(|x| x.1).unwrap_or(0);
        let now = Instant::now();
        for (pn, rec_time) in self.rcvd_queue.iter() {
            if now - *rec_time >= max_delay && pn > &largest_ack_sent {
                return largest_pn;
            }
        }
        None
    }

    /// Called when an ACK is sent.
    /// Updates the last ACK sent information and resets the `need_ack` flag.
    fn on_ack_sent(&mut self, pn: u64, largest_acked: u64) {
        self.last_ack_sent = Some((pn, largest_acked));
        self.ack_immedietly = false;
    }

    /// Processes an acknowledged (ACK) packet.
    /// If the ACKed packet number matches the last sent ACK number, retires all acknowledged packets.
    fn ack(&mut self, ack: u64, trackers: &[Arc<dyn TrackPackets>; 3]) {
        let largest_acked = match self.last_ack_sent {
            Some((pn, ref largest_acked)) if ack == pn => largest_acked,
            _ => return,
        };

        let begin = self.rcvd_queue.front().map(|&(pn, _)| pn).unwrap_or(0);
        let mut retire = begin..=*largest_acked;
        trackers[self.epoch].rotate(&mut retire);
        self.rcvd_queue.retain(|&(pn, _)| pn > *largest_acked);
    }
}

#[derive(Clone, Debug)]
pub struct AckedPkt {
    pub pn: u64,
    pub time_sent: Instant,
    pub size: usize,
    pub rtt: Duration,
    pub delivered: usize,
    pub delivered_time: Instant,
    pub first_sent_time: Instant,
    pub is_app_limited: bool,
}

impl From<SentPkt> for AckedPkt {
    fn from(sent: SentPkt) -> Self {
        let now = Instant::now();
        AckedPkt {
            pn: sent.pn,
            time_sent: sent.time_sent,
            size: sent.size,
            rtt: now - sent.time_sent,
            delivered: sent.delivered,
            delivered_time: sent.delivered_time,
            first_sent_time: sent.first_sent_time,
            is_app_limited: sent.is_app_limited,
        }
    }
}

#[derive(Eq, Clone, Debug)]
pub struct SentPkt {
    pub pn: u64,
    pub time_sent: Instant,
    pub size: usize,
    pub delivered: usize,
    pub delivered_time: Instant,
    pub first_sent_time: Instant,
    pub is_app_limited: bool,
    pub tx_in_flight: usize,
    pub lost: u64,
    pub is_acked: bool,
}

impl Default for SentPkt {
    fn default() -> Self {
        SentPkt {
            pn: 0,
            time_sent: Instant::now(),
            size: 0,
            delivered: 0,
            delivered_time: Instant::now(),
            first_sent_time: Instant::now(),
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            is_acked: false,
        }
    }
}

impl SentPkt {
    fn new(pn: u64, size: usize, now: Instant) -> Self {
        SentPkt {
            pn,
            time_sent: now,
            size,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            is_acked: false,
        }
    }
}

impl PartialOrd for SentPkt {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for SentPkt {
    fn eq(&self, other: &Self) -> bool {
        self.pn == other.pn
    }
}

impl Ord for SentPkt {
    fn cmp(&self, other: &Self) -> Ordering {
        self.pn.cmp(&other.pn)
    }
}

pub trait Algorithm: Send {
    fn on_sent(&mut self, sent: &mut SentPkt, sent_bytes: usize, now: Instant);

    fn on_ack(&mut self, packet: VecDeque<AckedPkt>, now: Instant);

    fn on_congestion_event(&mut self, lost: &SentPkt, now: Instant);

    fn cwnd(&self) -> u64;

    fn pacing_rate(&self) -> Option<u64>;
}

#[derive(Default)]
struct LossDetectionTimer {
    timeout: Option<Instant>,
}

impl LossDetectionTimer {
    fn update(&mut self, now: Instant) {
        self.timeout = Some(now);
    }

    fn cancel(&mut self) {
        self.timeout = None;
    }

    fn is_timeout(&self, now: Instant) -> bool {
        self.timeout.map(|t| now > t).unwrap_or(false)
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
    fn test_detect_and_remove_lost_packets() {
        let mut congestion = create_congestion_controller_for_test();
        let now = Instant::now();
        let space = Epoch::Initial;
        for i in 1..=5 {
            congestion.on_packet_sent(i, space, true, true, 1000, now);
        }
        // ack 5，检测出 1,2 因为乱序丢包
        congestion.largest_acked_packet[space] = Some(5);
        congestion.sent_packets[space][4].is_acked = true;
        congestion.sent_packets[space].pop_back();
        let lost_packets = congestion.remove_loss_packets(space, now);
        assert_eq!(lost_packets.len(), 2);
        for (i, lost) in lost_packets.iter().enumerate() {
            assert_eq!(lost.pn, i as u64 + 1);
        }
        assert_eq!(congestion.sent_packets[space].len(), 2);
        // loss delay =  333*1.25
        let loss_packets = congestion.remove_loss_packets(space, now + Duration::from_millis(417));
        // 3,4 因为超时丢包
        assert_eq!(loss_packets.len(), 2);
        for (i, lost) in loss_packets.iter().enumerate() {
            assert_eq!(lost.pn, i as u64 + 3);
        }
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
        // 剩余 5,8,9(ack),10,11,12,13
        let ack_frame = AckFrame::new(
            VarInt::from_u32(9),
            VarInt::from_u32(100),
            VarInt::from_u32(0),
            Vec::new(),
            None,
        );

        congestion_controller.on_ack_rcvd(Epoch::Initial, &ack_frame, now);
        assert_eq!(congestion_controller.sent_packets[Epoch::Initial].len(), 7);
        for (i, sent) in congestion_controller.sent_packets[Epoch::Initial]
            .iter()
            .enumerate()
        {
            match i {
                0 => assert_eq!(sent.pn, 5),
                _ => assert_eq!(sent.pn, (i + 7) as u64),
            }
            assert_eq!(sent.is_acked, sent.pn == 9);
        }
    }

    #[test]
    fn test_ack_record() {
        let max_ack_delay = Duration::from_millis(100);
        let mut ack_reocrd = RcvdRecords::new(Epoch::Initial);
        ack_reocrd.on_pkt_rcvd(1);
        assert!(ack_reocrd.requires_ack(max_ack_delay).is_some());

        ack_reocrd.on_pkt_rcvd(1);
        assert_eq!(ack_reocrd.rcvd_queue.len(), 1);

        ack_reocrd.on_ack_sent(1, 1);

        assert!(ack_reocrd.requires_ack(max_ack_delay).is_none());

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
        assert_eq!(ack_reocrd.requires_ack(max_ack_delay).unwrap().0, 3);

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
        assert_eq!(ack_reocrd.requires_ack(max_ack_delay).unwrap().0, 7);

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

        // recv pn 2 ack, retire 0,1,3,5,7
        ack_reocrd.ack(2, &[Arc::new(Mock), Arc::new(Mock), Arc::new(Mock)]);
        assert_eq!(
            ack_reocrd
                .rcvd_queue
                .iter()
                .map(|&(pn, _)| pn)
                .collect::<Vec<_>>(),
            vec![9]
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
            vec![8, 9, 11]
        );
        // recv pn 3 ack, retire 8,9

        ack_reocrd.ack(3, &[Arc::new(Mock), Arc::new(Mock), Arc::new(Mock)]);
        assert_eq!(
            ack_reocrd
                .rcvd_queue
                .iter()
                .map(|&(pn, _)| pn)
                .collect::<Vec<_>>(),
            vec![11]
        );
    }

    #[test]
    fn test_ack_record_reversed() {
        let max_ack_delay = Duration::from_millis(100);
        let mut ack_reocrd = RcvdRecords::new(Epoch::Initial);

        ack_reocrd.on_pkt_rcvd(10);
        ack_reocrd.on_pkt_rcvd(9);
        ack_reocrd.on_pkt_rcvd(8);

        assert_eq!(ack_reocrd.requires_ack(max_ack_delay).unwrap().0, 10);
        ack_reocrd.on_ack_sent(1, 10);

        ack_reocrd.on_pkt_rcvd(7);
        ack_reocrd.on_pkt_rcvd(6);
        ack_reocrd.on_pkt_rcvd(5);
        assert_eq!(ack_reocrd.requires_ack(max_ack_delay).unwrap().0, 10);
        ack_reocrd.on_ack_sent(2, 10);
        assert_eq!(ack_reocrd.requires_ack(max_ack_delay), None);

        // ingnore ack 1
        ack_reocrd.ack(1, &[Arc::new(Mock), Arc::new(Mock), Arc::new(Mock)]);
        assert_eq!(ack_reocrd.requires_ack(max_ack_delay), None);
        assert_eq!(
            ack_reocrd
                .rcvd_queue
                .iter()
                .map(|&(pn, _)| pn)
                .collect::<Vec<_>>(),
            vec![5, 6, 7, 8, 9, 10]
        );

        // 4 属于迟到的包，可能被对面判定为丢包
        ack_reocrd.on_pkt_rcvd(4);

        // ack 2，对面可能判定 4 为丢包，我放也应该 retir 4
        ack_reocrd.ack(2, &[Arc::new(Mock), Arc::new(Mock), Arc::new(Mock)]);

        assert_eq!(ack_reocrd.requires_ack(max_ack_delay), None);
        assert!(ack_reocrd.rcvd_queue.is_empty());
    }
    struct Mock;
    impl TrackPackets for Mock {
        fn may_loss(&self, _: PacketLostTrigger, _: &mut dyn Iterator<Item = u64>) {}
        fn rotate(&self, _: &mut dyn Iterator<Item = u64>) {}
    }

    fn create_congestion_controller_for_test() -> CongestionController {
        let output = ArcReliableFrameDeque::with_capacity(10);
        CongestionController::new(
            CongestionAlgorithm::Bbr,
            Duration::from_millis(100),
            [Arc::new(Mock), Arc::new(Mock), Arc::new(Mock)],
            Box::new(Handshake::new(qbase::sid::Role::Client, output)),
        )
    }
}
