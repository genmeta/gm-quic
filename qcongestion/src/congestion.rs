use std::{
    cmp::Ordering,
    collections::VecDeque,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use qbase::frame::{AckFrame, EcnCounts};
use qrecovery::space::Epoch;

use crate::{
    bbr::{self, INITIAL_CWND},
    new_reno::NewReno,
    pacing::{self, Pacer},
    rtt::{ArcRtt, INITIAL_RTT},
};

const K_GRANULARITY: Duration = Duration::from_millis(1);
const K_PACKET_THRESHOLD: usize = 3;
const MAX_SENT_DELAY: Duration = Duration::from_millis(30);

//  default datagram size in bytes.
pub const MSS: usize = 1200;

pub enum CongestionAlgorithm {
    Bbr,
    NewReno,
}

// imple RFC 9002 Appendix A. Loss Recovery
pub struct CongestionController {
    // congestion controlle algorithm: bbr or cubic
    algorithm: Box<dyn Algorithm + Send>,
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
    // record recv packts, remove it when ack frame be ackd;
    largest_ack_eliciting_packet: [Option<Recved>; Epoch::count()],
    // pacer is used to control the burst rate
    pacer: pacing::Pacer,
    last_sent_time: Instant,

    loss_pns: Option<(Epoch, Vec<u64>)>,
    newly_ack_pns: Option<(Epoch, Vec<u64>)>,
    pto_space: Option<Epoch>,
    // waker
    loss_waker: Option<Waker>,
    ack_waker: Option<Waker>,
    pto_waker: Option<Waker>,

    is_anti_amplification_limit: bool,
    has_handshake_keys: bool,
    is_handshake_done: bool,
}

impl CongestionController {
    // A.4. Initialization
    fn new(algorithm: CongestionAlgorithm, max_ack_delay: Duration) -> Self {
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
            largest_ack_eliciting_packet: [None, None, None],
            pacer: Pacer::new(INITIAL_RTT, INITIAL_CWND, MSS, now, None),
            last_sent_time: now,
            loss_pns: None,
            newly_ack_pns: None,
            pto_space: None,
            loss_waker: None,
            ack_waker: None,
            pto_waker: None,
            is_anti_amplification_limit: false,
            has_handshake_keys: false,
            is_handshake_done: false,
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
        let mut sent = SentPkt::new(pn, ack_eliciting, in_flight, sent_bytes, now);
        if in_flight {
            if ack_eliciting {
                self.time_of_last_ack_eliciting_packet[space] = Some(now);
            }
            self.algorithm.on_sent(&mut sent, sent_bytes, now);
            self.set_loss_timer();
        }

        // 为了使用二分查找 ack packet，sent_packets 的序号必须是严格升序
        if let Some(last_pn) = self.sent_packets[space].back() {
            assert!(pn > last_pn.pn);
        }
        self.sent_packets[space].push_back(sent);
        self.pacer.on_sent(sent_bytes as u64);
    }

    // A.6. On Receiving a Datagram
    // todo: on_revd_datagram
    pub fn on_datagram_rcvd(&mut self, now: Instant) {
        // If this datagram unblocks the server, arm the PTO timer to avoid deadlock.
        if self.is_anti_amplification_limit {
            self.set_loss_timer();
            if self.loss_timer.is_timeout(now) {
                // Execute PTO if it would have expired while the amplification limit applied.
                self.on_loss_timeout(now);
            }
        }
    }

    // A.7. On Receiving an Acknowledgment
    pub fn on_ack_rcvd(&mut self, space: Epoch, ack_frame: &AckFrame, now: Instant) {
        let largest_acked: u64 = ack_frame.largest.into();

        self.largest_acked_packet[space] =
            Some(largest_acked.max(self.largest_acked_packet[space].unwrap_or(0)));

        let (newly_acked_packets, latest_rtt) = self.get_newly_acked_packets(space, ack_frame);
        if newly_acked_packets.is_empty() {
            return;
        }

        // notify space
        if let Some(waker) = self.ack_waker.take() {
            waker.wake();
        }

        let ack_delay = Duration::from_millis(ack_frame.delay.into());
        if let Some(latest_rtt) = latest_rtt {
            self.rtt.update(latest_rtt, ack_delay);
        }

        // Process ECN information if present.
        if let Some(ecn) = ack_frame.ecn {
            self.process_ecn(space, ecn)
        }

        let lost_packets = self.remove_loss_packets(space, now);
        if !lost_packets.is_empty() {
            self.on_packets_lost(lost_packets, space);
        }
        self.algorithm.on_ack(newly_acked_packets, now);

        if self.server_completed_address_validation() {
            self.pto_count = 0;
        }
        self.set_loss_timer();
    }

    pub fn get_newly_acked_packets(
        &mut self,
        space: Epoch,
        ack_frame: &AckFrame,
    ) -> (VecDeque<AckedPkt>, Option<Duration>) {
        let mut newly_acked_packets: VecDeque<AckedPkt> = VecDeque::new();
        let mut newly_acked_pns = Vec::new();
        let largest_acked: u64 = ack_frame.largest.into();
        let mut latest_rtt = None;
        for range in ack_frame.iter() {
            for pn in range {
                let acked: Option<AckedPkt> = self.sent_packets[space]
                    .binary_search_by_key(&pn, |p| p.pn)
                    .ok()
                    // 检测ack的包，标记为 is_acked,不能直接remove
                    .map(|idx| {
                        self.sent_packets[space][idx].is_acked = true;
                        self.sent_packets[space][idx].clone().into()
                    });
                if let Some(ack) = acked {
                    // largest is newly ackd, update latest_rtt
                    if pn == largest_acked {
                        latest_rtt = Some(ack.rtt);
                    }
                    newly_acked_packets.push_back(ack);
                    newly_acked_pns.push(pn);
                }
            }
        }
        self.slide_sent_packets(space);
        if !newly_acked_pns.is_empty() {
            self.newly_ack_pns = Some((space, newly_acked_pns));
        }

        (newly_acked_packets, latest_rtt)
    }

    // A.8. Setting the Loss Detection Timer
    fn on_packets_lost(&mut self, packets: Vec<SentPkt>, _: Epoch) {
        let now = Instant::now();

        if let Some(waker) = self.loss_waker.take() {
            waker.wake();
        }

        for lost in packets {
            self.algorithm.on_congestion_event(&lost, now);
        }
    }

    fn set_loss_timer(&mut self) {
        let (earliest_loss_time, _) = self.get_loss_time_and_space();
        if let Some(earliest_loss_time) = earliest_loss_time {
            self.loss_timer.update(earliest_loss_time);
            return;
        }

        if self.is_anti_amplification_limit {
            // server's timer is not set if nothing can be sent
            self.loss_timer.cancel();
            return;
        }

        if self.no_ack_eliciting_in_flight() && self.server_completed_address_validation() {
            self.loss_timer.cancel();
            return;
        }

        if let Some(t) = self.get_pto_timeout() {
            self.loss_timer.update(t);
        }
    }

    // A.9. On Timeout
    fn on_loss_timeout(&mut self, now: Instant) {
        let (earliest_loss_time, space) = self.get_loss_time_and_space();
        // lost timeout
        if earliest_loss_time.is_some() {
            let loss_packet = self.remove_loss_packets(space, now);
            assert!(!loss_packet.is_empty());
            self.on_packets_lost(loss_packet, space);
            self.set_loss_timer();
            return;
        }

        // probe timeout
        if self.no_ack_eliciting_in_flight() {
            assert!(self.server_completed_address_validation());
            if self.is_handshake_done {
                self.pto_space = Some(Epoch::Handshake);
            } else {
                self.pto_space = Some(Epoch::Initial);
            }
        } else {
            let timeout = self.get_pto_timeout();
            if timeout.is_some() {
                self.pto_space = Some(Epoch::Data);
            }
        }
        self.pto_count += 1;

        if let Some(waker) = self.pto_waker.take() {
            waker.wake();
        }
        self.set_loss_timer();
    }

    fn get_loss_time_and_space(&self) -> (Option<Instant>, Epoch) {
        let mut time = self.loss_time[Epoch::Initial];
        let mut space = Epoch::Initial;
        for s in [Epoch::Handshake, Epoch::Data].iter() {
            if let Some(loss) = self.loss_time[*s] {
                if time.is_none() || loss < time.unwrap() {
                    time = Some(loss);
                    space = *s;
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
        if epoch == Epoch::Data && self.is_handshake_done {
            duration += self.max_ack_delay
        }
        duration * 2_u32.pow(self.pto_count)
    }

    fn get_pto_timeout(&self) -> Option<Instant> {
        let mut duration = self.get_pto_time(Epoch::Initial);
        if self.no_ack_eliciting_in_flight() {
            return Some(Instant::now() + duration);
        }

        let mut pto_time = None;
        for space in Epoch::iter() {
            if self.time_of_last_ack_eliciting_packet[*space].is_none() {
                continue;
            }
            if *space == Epoch::Data {
                // An endpoint MUST NOT set its PTO timer for the Application Data
                // packet number space until the handshake is confirmed
                if !self.is_handshake_done {
                    return pto_time;
                }
                duration += self.max_ack_delay * 2_u32.pow(self.pto_count);
            }
            let new_time = self.time_of_last_ack_eliciting_packet[*space].unwrap() + duration;
            if pto_time.is_none() || new_time < pto_time.unwrap() {
                pto_time = Some(new_time);
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
        if !loss_pn.is_empty() {
            self.loss_pns = Some((space, loss_pn));
        }
        loss_packets
    }

    fn slide_sent_packets(&mut self, space: Epoch) {
        while let Some(sent) = self.sent_packets[space].front() {
            if !sent.is_acked {
                break;
            }
            self.sent_packets[space].pop_front();
        }
    }

    fn no_ack_eliciting_in_flight(&self) -> bool {
        for space in Epoch::iter() {
            if self.time_of_last_ack_eliciting_packet[*space].is_some() {
                return false;
            }
        }
        true
    }

    fn server_completed_address_validation(&mut self) -> bool {
        // is server return true
        self.has_handshake_keys || self.is_handshake_done
    }

    fn process_ecn(&mut self, _: Epoch, _: EcnCounts) {
        todo!()
    }
}

/// Shared congestion controller
#[derive(Clone)]
pub struct ArcCC(Arc<Mutex<CongestionController>>);

impl ArcCC {
    pub fn new(algorithm: CongestionAlgorithm, max_ack_delay: Duration) -> Self {
        ArcCC(Arc::new(Mutex::new(CongestionController::new(
            algorithm,
            max_ack_delay,
        ))))
    }
}

impl super::CongestionControl for ArcCC {
    fn poll_send(&self, cx: &mut Context<'_>) -> Poll<usize> {
        let mut guard = self.0.lock().unwrap();

        let now = Instant::now();
        if guard.loss_timer.is_timeout(now) {
            guard.on_loss_timeout(now);
        }

        let srtt = guard.rtt.smoothed_rtt();
        let cwnd = guard.algorithm.cwnd();
        let mtu = MSS;
        let rate = guard.algorithm.pacing_rate();
        let tokens = guard.pacer.schedule(srtt, cwnd, mtu, now, rate);
        if tokens >= mtu {
            return Poll::Ready(tokens);
        }

        let mut need_ack = false;
        for epoch in Epoch::iter() {
            if guard.largest_ack_eliciting_packet[*epoch].is_some() {
                need_ack = true;
                break;
            }
        }
        // 1. 有 ack 要发送, 且距离上次发送时间大于 max ack dely
        // 2. 距离上次发送时间大于 max sent delay
        let elapsed = now.saturating_duration_since(guard.last_sent_time);
        if (need_ack && elapsed >= guard.max_ack_delay) || elapsed >= MAX_SENT_DELAY {
            return Poll::Ready(tokens);
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn need_ack(&self, space: Epoch) -> Option<(u64, Instant)> {
        let guard = self.0.lock().unwrap();
        if let Some(recved) = &guard.largest_ack_eliciting_packet[space] {
            return Some((recved.pn, recved.recv_time));
        }
        None
    }

    fn on_pkt_sent(
        &self,
        space: Epoch,
        pn: u64,
        is_ack_eliciting: bool,
        sent_bytes: usize,
        in_flight: bool,
        ack: Option<u64>,
    ) {
        let mut guard = self.0.lock().unwrap();
        let now = Instant::now();
        guard.on_packet_sent(pn, space, is_ack_eliciting, in_flight, sent_bytes, now);

        guard.last_sent_time = now;
        // 如果已经发送了 largest_ack_eliciting_packet ack, 就不用记录再发送
        if let (Some(ack_pn), Some(recved)) = (ack, &guard.largest_ack_eliciting_packet[space]) {
            if ack_pn >= recved.pn {
                guard.largest_ack_eliciting_packet[space] = None;
            }
        }
    }

    fn on_ack(&self, space: Epoch, ack_frame: &AckFrame) {
        let mut guard = self.0.lock().unwrap();
        let now = Instant::now();
        guard.on_ack_rcvd(space, ack_frame, now);
    }

    fn on_recv_pkt(&self, space: Epoch, pn: u64, is_ack_eliciting: bool) {
        let now = Instant::now();
        let recved = Recved { pn, recv_time: now };
        let mut guard = self.0.lock().unwrap();
        guard.on_datagram_rcvd(now);
        if !is_ack_eliciting {
            return;
        }

        if let Some(r) = &guard.largest_ack_eliciting_packet[space] {
            if pn > r.pn {
                guard.largest_ack_eliciting_packet[space] = Some(recved);
            }
        }
    }

    fn poll_lost(&self, cx: &mut Context<'_>) -> Poll<(Epoch, Vec<u64>)> {
        let mut guard = self.0.lock().unwrap();

        if let Some(loss) = guard.loss_pns.take() {
            return Poll::Ready(loss);
        }
        guard.loss_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    fn poll_indicate_ack(&self, cx: &mut Context<'_>) -> Poll<(Epoch, Vec<u64>)> {
        let mut guard = self.0.lock().unwrap();

        if let Some(acked) = guard.newly_ack_pns.take() {
            return Poll::Ready(acked);
        }
        guard.loss_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    fn poll_probe_timeout(&self, cx: &mut Context<'_>) -> Poll<Epoch> {
        let mut guard = self.0.lock().unwrap();
        if let Some(space) = guard.pto_space {
            return Poll::Ready(space);
        }
        guard.pto_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    fn get_pto_time(&self, epoch: Epoch) -> Duration {
        self.0.lock().unwrap().get_pto_time(epoch)
    }

    fn on_get_handshake_keys(&self) {
        let mut gurad = self.0.lock().unwrap();
        gurad.has_handshake_keys = true;
    }

    fn on_handshake_done(&self) {
        let mut guard = self.0.lock().unwrap();
        guard.is_handshake_done = true;
        guard.rtt.on_handshake_done();
    }

    fn anti_amplification_limit_off(&self) {
        let mut guard = self.0.lock().unwrap();
        guard.is_anti_amplification_limit = false;
    }

    fn anti_amplification_limit_on(&self) {
        let mut guard = self.0.lock().unwrap();
        guard.is_anti_amplification_limit = true;
    }
}

#[derive(Clone)]
pub struct Recved {
    pn: u64,
    recv_time: Instant,
}

#[derive(Clone)]
pub struct AckedPkt {
    pub pn: u64,
    pub time_sent: Instant,
    pub size: usize,
    pub rtt: Duration,
    pub delivered: usize,
    pub delivered_time: Instant,
    pub first_sent_time: Instant,
    pub is_app_limited: bool,
    pub tx_in_flight: usize,
    pub lost: u64,
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
            tx_in_flight: sent.tx_in_flight,
            lost: sent.lost,
        }
    }
}

#[derive(Eq, Clone, Debug)]
pub struct SentPkt {
    pub pn: u64,
    pub time_sent: Instant,
    pub size: usize,
    pub ack_eliciting: bool,
    pub in_flight: bool,
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
            ack_eliciting: false,
            in_flight: false,
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
    fn new(pn: u64, ack_eliciting: bool, in_flight: bool, size: usize, now: Instant) -> Self {
        SentPkt {
            pn,
            time_sent: now,
            size,
            ack_eliciting,
            in_flight,
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
            assert!(sent.ack_eliciting);
            assert!(sent.in_flight);
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
            assert!(sent.ack_eliciting);
            assert!(sent.in_flight);
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
        let ack_frame = AckFrame {
            largest: VarInt::from_u32(3),
            delay: VarInt::from_u32(100),
            first_range: VarInt::from_u32(2),
            ranges: vec![],
            ecn: None,
        };
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
        let ack_frame = AckFrame {
            largest: VarInt::from_u32(9),
            delay: VarInt::from_u32(100),
            first_range: VarInt::from_u32(0),
            ranges: vec![],
            ecn: None,
        };

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

    fn create_congestion_controller_for_test() -> CongestionController {
        CongestionController::new(CongestionAlgorithm::Bbr, Duration::from_millis(100))
    }
}
