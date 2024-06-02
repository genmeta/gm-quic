use crate::bbr::{INITIAL_CWND, MSS};
use crate::pacing::Pacer;
use crate::rtt::INITIAL_RTT;
use crate::{bbr, pacing, ObserveAck, ObserveLoss, RawRtt};
use qbase::frame::AckFrame;
use std::ops::{Index, IndexMut, RangeInclusive};
use std::{
    cmp::Ordering,
    collections::VecDeque,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};

const K_GRANULARITY: Duration = Duration::from_millis(1);
const K_PACKET_THRESHOLD: usize = 3;

pub enum CongestionAlgorithm {
    Bbr,
}

// imple RFC 9002 Appendix A. Loss Recovery
pub struct CongestionController<OA, OL> {
    // ack observer
    observe_ack: OA,
    // loss observer
    observe_loss: OL,
    // congestion controlle algorithm: bbr or cubic
    algorithm: Box<dyn Algorithm>,
    rtt: Arc<Mutex<RawRtt>>,
    loss_detection_timer: Option<Instant>,
    // The number of times a PTO has been sent without receiving an acknowledgment.
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
    sent_packets: [VecDeque<Sent>; Epoch::count()],
    // record recv packts, remove it when ack frame be ackd;
    largest_recved_packet: [Option<Recved>; Epoch::count()],
    // quic is in anti amplification
    anti_amplification: bool,
    // handshake state
    handshake_confirmed: bool,
    has_handshake_keys: bool,
    // pacer is used to control the burst rate
    pacer: pacing::Pacer,
}

impl<OA, OL> CongestionController<OA, OL>
where
    OA: ObserveAck,
    OL: ObserveLoss,
{
    // A.4. Initialization
    pub fn new(
        algorithm: CongestionAlgorithm,
        max_ack_delay: Duration,
        observe_ack: OA,
        observe_loss: OL,
    ) -> Self {
        let cc = match algorithm {
            CongestionAlgorithm::Bbr => Box::new(bbr::Bbr::new()),
        };

        let now = Instant::now();
        CongestionController {
            algorithm: cc,
            rtt: Arc::new(Mutex::new(RawRtt::default())),
            loss_detection_timer: None,
            max_ack_delay,
            pto_count: 0,
            time_of_last_ack_eliciting_packet: [None, None, None],
            largest_acked_packet: [None, None, None],
            loss_time: [None, None, None],
            sent_packets: [VecDeque::new(), VecDeque::new(), VecDeque::new()],
            largest_recved_packet: [None, None, None],
            anti_amplification: false,
            handshake_confirmed: false,
            has_handshake_keys: false,
            observe_ack,
            observe_loss,
            pacer: Pacer::new(INITIAL_RTT, INITIAL_CWND, MSS as u16, now, None),
        }
    }

    // A.5. On Sending a Packet
    pub fn on_packet_sent(
        &mut self,
        packet_number: u64,
        space: Epoch,
        ack_eliciting: bool,
        in_flight: bool,
        sent_bytes: usize,
        now: Instant,
    ) {
        let mut sent = Sent::new(packet_number, ack_eliciting, in_flight, sent_bytes, now);
        if in_flight {
            if ack_eliciting {
                self.time_of_last_ack_eliciting_packet[space] = Some(now);
            }
            self.algorithm.on_sent(&mut sent, sent_bytes, now);
            self.set_lost_detection_timer();
        }

        // 为了使用二分查找 ack packet，sent_packets 的序号必须是严格升序
        let len = self.sent_packets[space].len();
        if len > 0 {
            assert!(packet_number > self.sent_packets[space].get(len - 1).unwrap().pkt_num)
        }
        self.sent_packets[space].push_back(sent);
        self.pacer.on_sent(sent_bytes as u64);
    }

    // A.6. On Receiving a Datagram
    pub fn on_datagram_recv(&mut self, now: Instant) {
        // If this datagram unblocks the server, arm the PTO timer to avoid deadlock.
        if self.anti_amplification {
            self.set_lost_detection_timer();
            if let Some(loss_detection_timer) = self.loss_detection_timer {
                if loss_detection_timer < now {
                    // Execute PTO if it would have expired while the amplification limit applied.
                    self.on_loss_detection_timeout(now);
                }
            }
        }
    }

    // A.7. On Receiving an Acknowledgment
    pub fn on_ack_received(&mut self, space: Epoch, ack_frame: &AckFrame) {
        let largest_acked: u64 = ack_frame.largest.into();
        let ack_delay = Duration::from_micros(ack_frame.delay.into());
        let now = Instant::now();

        if let Some(pre_largest) = self.largest_acked_packet[space] {
            self.largest_acked_packet[space] = Some(pre_largest.max(largest_acked));
        } else {
            self.largest_acked_packet[space] = Some(largest_acked);
        }

        let (newly_acked_packets, latest_rtt) = self.detect_and_remove_ack_packet(space, ack_frame);
        if newly_acked_packets.is_empty() {
            return;
        }
        if let Some(latest_rtt) = latest_rtt {
            self.rtt
                .lock()
                .unwrap()
                .update(latest_rtt, ack_delay, self.handshake_confirmed);
        }
        // todo: Process ECN information if present.
        let lost_packets = self.detect_and_remove_lost_packets(space, now);
        if !lost_packets.is_empty() {
            self.on_packets_lost(lost_packets, space);
        }
        self.algorithm.on_ack(newly_acked_packets, now);

        if self.peer_completed_address_validation() {
            self.pto_count = 0;
        }
        self.set_lost_detection_timer();
    }

    pub fn detect_and_remove_ack_packet(
        &mut self,
        space: Epoch,
        ack_frame: &AckFrame,
    ) -> (VecDeque<Acked>, Option<Duration>) {
        let mut newly_acked_packets: VecDeque<Acked> = VecDeque::new();
        let largest_acked: u64 = ack_frame.largest.into();
        let mut latest_rtt = None;
        for range in ack_frame.iter() {
            for pn in range {
                let acked: Option<Acked> = self.sent_packets[space]
                    .binary_search_by_key(&pn, |p| p.pkt_num)
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
                }
            }
        }
        self.remove_consecutive_ack_packets(space);
        (newly_acked_packets, latest_rtt)
    }

    // A.8. Setting the Loss Detection Timer
    fn on_packets_lost(&mut self, packets: Vec<Sent>, space: Epoch) {
        let now = Instant::now();
        for lost in packets {
            self.algorithm.on_congestion_event(&lost, now);
            self.observe_loss.may_loss_pkt(space, lost.pkt_num);
        }
    }

    fn set_lost_detection_timer(&mut self) {
        let (earliest_loss_time, _) = self.get_loss_time_and_space();
        if let Some(earliest_loss_time) = earliest_loss_time {
            self.loss_detection_timer = Some(earliest_loss_time);
            return;
        }

        if self.anti_amplification {
            // server's timer is not set if nothing can be sent
            self.loss_detection_timer = None;
            return;
        }

        if self.no_ack_eliciting_in_flight() && self.peer_completed_address_validation() {
            self.loss_detection_timer = None;
            return;
        }
        let (timeout, _) = self.get_pto_time_and_space();
        self.loss_detection_timer = timeout;
    }

    // A.9. On Timeout
    fn on_loss_detection_timeout(&mut self, now: Instant) {
        let (earliest_loss_time, space) = self.get_loss_time_and_space();
        if earliest_loss_time.is_some() {
            let loss_packet = self.detect_and_remove_lost_packets(space, now);
            // 触发了 timeout loss 不为空
            assert!(!loss_packet.is_empty());
            self.on_packets_lost(loss_packet, space);
            self.set_lost_detection_timer();
            return;
        }

        if self.no_ack_eliciting_in_flight() {
            assert!(self.peer_completed_address_validation());
            if self.has_handshake_keys {
                todo!("sen one ack eliciting handshake packet")
            } else {
                todo!("send one ack eliciting padded Inital packet")
            }
        } else {
            let (timeout, _) = self.get_pto_time_and_space();
            if timeout.is_some() {
                todo!("send one ack eliciting packet in space")
            }
        }
        self.pto_count += 1;
        self.set_lost_detection_timer();
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

    fn get_pto_time_and_space(&self) -> (Option<Instant>, u8) {
        let smoothed_rtt = self.rtt.lock().unwrap().smoothed_rtt;
        let rttvar = self.rtt.lock().unwrap().rttvar;
        let mut duration = smoothed_rtt + std::cmp::max(K_GRANULARITY, rttvar * 4);

        if self.no_ack_eliciting_in_flight() {
            let eoch = if self.has_handshake_keys {
                Epoch::Handshake
            } else {
                Epoch::Initial
            };
            return (Some(Instant::now() + duration), eoch as u8);
        }

        let mut pto_timeout = None;
        let mut pto_space = Epoch::Initial;
        for space in EPOCHS.iter() {
            // no ack-eliciting packets in flight in space
            if self.no_ack_eliciting_in_flight() {
                continue;
            }
            if *space == Epoch::Data {
                if !self.handshake_confirmed {
                    return (pto_timeout, pto_space as u8);
                }
                duration += self.max_ack_delay * 2_u32.pow(self.pto_count);
            }

            if self.time_of_last_ack_eliciting_packet[*space].is_none() {
                continue;
            }

            let new_time = self.time_of_last_ack_eliciting_packet[*space].unwrap() + duration;
            if pto_timeout.is_none() || new_time < pto_timeout.unwrap() {
                pto_timeout = Some(new_time);
                pto_space = *space;
            }
        }
        (pto_timeout, pto_space as u8)
    }

    fn detect_and_remove_lost_packets(&mut self, space: Epoch, now: Instant) -> Vec<Sent> {
        assert!(self.largest_acked_packet[space].is_some());
        let largest_acked = self.largest_acked_packet[space].unwrap();
        self.loss_time[space] = None;

        let loss_delay = self.rtt.lock().unwrap().loss_delay();
        let lost_send_time = now.checked_sub(loss_delay).unwrap();

        let mut lost_packets = Vec::new();

        let mut largest_ack_index = 0;
        while largest_ack_index != self.sent_packets[space].len()
            && self.sent_packets[space][largest_ack_index].pkt_num < largest_acked
        {
            largest_ack_index += 1;
        }

        let mut i = 0;
        while i != self.sent_packets[space].len()
            && self.sent_packets[space][i].pkt_num < largest_acked
        {
            if self.sent_packets[space][i].is_acked {
                i += 1;
                continue;
            }
            // 距离 largest ack index 相差超过 threshold 即为丢包
            if self.sent_packets[space][i].time_sent <= lost_send_time
                || largest_ack_index - i >= K_PACKET_THRESHOLD
            {
                let lost_packet = self.sent_packets[space].remove(i);
                largest_ack_index -= 1;
                lost_packets.push(lost_packet.unwrap());
            } else {
                let loss_time = self.sent_packets[space][i].time_sent + loss_delay;
                self.loss_time[space] = match self.loss_time[space] {
                    Some(lt) => Some(lt.min(loss_time)),
                    None => Some(loss_time),
                };
                i += 1;
            }
        }

        self.remove_consecutive_ack_packets(space);
        lost_packets
    }

    // 移除头部连续被 acked 的包
    fn remove_consecutive_ack_packets(&mut self, space: Epoch) {
        while let Some(sent) = self.sent_packets[space].front() {
            if !sent.is_acked {
                break;
            }
            self.sent_packets[space].pop_front();
        }
    }

    fn no_ack_eliciting_in_flight(&self) -> bool {
        for space in EPOCHS.iter() {
            if self.time_of_last_ack_eliciting_packet[*space].is_some() {
                return false;
            }
        }
        true
    }

    fn peer_completed_address_validation(&mut self) -> bool {
        // is server return true
        self.has_handshake_keys || self.handshake_confirmed
    }
}

type ArcController<OA, OL> = Arc<Mutex<CongestionController<OA, OL>>>;
impl<OA, OL> super::CongestionControl for ArcController<OA, OL>
where
    OA: ObserveAck,
    OL: ObserveLoss,
{
    fn poll_send(&self, cx: &mut Context<'_>) -> Poll<usize> {
        let binding = self.clone();
        let mut cc = binding.lock().unwrap();

        let srtt = cc.rtt.clone().lock().unwrap().smoothed_rtt;
        let cwnd = cc.algorithm.cwnd();
        let mtu = MSS as u16;
        let now = Instant::now();
        let rate = cc.algorithm.pacing_rate();
        match cc.pacer.schedule(srtt, cwnd, mtu, now, rate) {
            Some(size) => Poll::Ready(size),
            None => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    fn need_ack(&self, space: Epoch) -> Option<(u64, Instant)> {
        let binding = self.clone();
        let cc = binding.lock().unwrap();
        if let Some(recved) = &cc.largest_recved_packet[space] {
            return Some((recved.pn, recved.recv_time));
        }
        None
    }

    fn on_pkt_sent(
        &self,
        space: Epoch,
        pn: u64,
        is_ack_elicition: bool,
        sent_bytes: usize,
        in_flight: bool,
        ack: Option<u64>,
    ) {
        let binding = self.clone();
        let mut cc = binding.lock().unwrap();
        let now = Instant::now();
        cc.on_packet_sent(pn, space, is_ack_elicition, in_flight, sent_bytes, now);

        // 如果已经发送了 largest_recved_packet ack, 就不用记录再发送
        if let (Some(ack_pn), Some(recved)) = (ack, &cc.largest_recved_packet[space]) {
            if ack_pn >= recved.pn {
                cc.largest_recved_packet[space] = None;
            }
        }
    }

    fn on_ack(&self, space: Epoch, ack_frame: &AckFrame) {
        let binding = self.clone();
        let mut cc = binding.lock().unwrap();
        cc.on_ack_received(space, ack_frame);
    }

    fn on_recv_pkt(&self, space: Epoch, pn: u64, is_ack_elicition: bool) {
        let now = Instant::now();
        let recved = Recved { pn, recv_time: now };
        let binding = self.clone();
        let mut cc = binding.lock().unwrap();
        cc.on_datagram_recv(now);
        if !is_ack_elicition {
            return;
        }

        if let Some(r) = &cc.largest_recved_packet[space] {
            if pn > r.pn {
                cc.largest_recved_packet[space] = Some(recved);
            }
        }
    }
}

#[derive(Clone)]
pub struct Recved {
    pn: u64,
    recv_time: Instant,
}

#[derive(Clone)]
pub struct Acked {
    pub pkt_num: u64,
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

impl From<Sent> for Acked {
    fn from(sent: Sent) -> Self {
        let now = Instant::now();
        Acked {
            pkt_num: sent.pkt_num,
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

#[derive(Eq, Clone)]
pub struct Sent {
    pub pkt_num: u64,
    pub time_sent: Instant,
    pub time_acked: Option<Instant>,
    pub time_lost: Option<Instant>,
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

impl Default for Sent {
    fn default() -> Self {
        Sent {
            pkt_num: 0,
            time_sent: Instant::now(),
            time_acked: None,
            time_lost: None,
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

impl Sent {
    fn new(pkt_num: u64, ack_eliciting: bool, in_flight: bool, size: usize, now: Instant) -> Self {
        Sent {
            pkt_num,
            time_sent: now,
            time_acked: None,
            time_lost: None,
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

impl PartialOrd for Sent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Sent {
    fn eq(&self, other: &Self) -> bool {
        self.pkt_num == other.pkt_num
    }
}

impl Ord for Sent {
    fn cmp(&self, other: &Self) -> Ordering {
        self.pkt_num.cmp(&other.pkt_num)
    }
}

pub trait Algorithm {
    fn on_sent(&mut self, sent: &mut Sent, sent_bytes: usize, now: Instant);

    fn on_ack(&mut self, packet: VecDeque<Acked>, now: Instant);

    fn on_congestion_event(&mut self, lost: &Sent, now: Instant);

    fn cwnd(&self) -> u64;

    fn pacing_rate(&self) -> Option<u64>;
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Epoch {
    Initial = 0,
    Handshake = 1,
    Data = 2,
}

static EPOCHS: [Epoch; 3] = [Epoch::Initial, Epoch::Handshake, Epoch::Data];

impl Epoch {
    pub fn epochs(range: RangeInclusive<Epoch>) -> &'static [Epoch] {
        &EPOCHS[*range.start() as usize..=*range.end() as usize]
    }

    pub const fn count() -> usize {
        3
    }
}

impl From<Epoch> for usize {
    fn from(e: Epoch) -> Self {
        e as usize
    }
}

impl<T> Index<Epoch> for [T]
where
    T: Sized,
{
    type Output = T;

    fn index(&self, index: Epoch) -> &Self::Output {
        self.index(usize::from(index))
    }
}

impl<T> IndexMut<Epoch> for [T]
where
    T: Sized,
{
    fn index_mut(&mut self, index: Epoch) -> &mut Self::Output {
        self.index_mut(usize::from(index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SlideWindow;

    const MAX_ACK_DELAY: std::time::Duration = Duration::from_millis(100);
    struct Mock;

    impl SlideWindow for Mock {
        fn inactivate(&mut self, _idx: u64) {}
    }

    impl ObserveAck for Mock {
        type Guard<'a> = Mock;

        fn guard(&self, _space: Epoch) -> Self::Guard<'static> {
            Mock
        }
    }

    impl ObserveLoss for Mock {
        fn may_loss_pkt(&self, _: Epoch, _: u64) {}
    }

    #[test]
    fn test_on_packet_sent_multiple_packets() {
        let mut congestion =
            CongestionController::new(CongestionAlgorithm::Bbr, MAX_ACK_DELAY, Mock, Mock);
        let now = Instant::now();
        for i in 1..=5 {
            congestion.on_packet_sent(i, Epoch::Initial, true, true, 1000, now);
        }
        assert_eq!(congestion.sent_packets[Epoch::Initial].len(), 5);
        for (i, sent) in congestion.sent_packets[Epoch::Initial].iter().enumerate() {
            assert_eq!(sent.pkt_num, i as u64 + 1);
            assert_eq!(sent.size, 1000);
            assert_eq!(sent.ack_eliciting, true);
            assert_eq!(sent.in_flight, true);
            assert_eq!(sent.time_lost, None);
            assert_eq!(sent.time_acked, None);
            assert_eq!(sent.time_sent, now);
        }
    }

    #[test]
    fn test_on_packet_sent_different_epochs() {
        let mut congestion =
            CongestionController::new(CongestionAlgorithm::Bbr, MAX_ACK_DELAY, Mock, Mock);
        let now = Instant::now();
        congestion.on_packet_sent(1, Epoch::Initial, true, true, 1000, now);
        congestion.on_packet_sent(2, Epoch::Handshake, true, true, 1000, now);
        congestion.on_packet_sent(3, Epoch::Data, true, true, 1000, now);
        assert_eq!(congestion.sent_packets[Epoch::Initial].len(), 1);
        assert_eq!(congestion.sent_packets[Epoch::Handshake].len(), 1);
        assert_eq!(congestion.sent_packets[Epoch::Data].len(), 1);
        for epoch in &[Epoch::Initial, Epoch::Handshake, Epoch::Data] {
            let sent = &congestion.sent_packets[*epoch][0];
            assert_eq!(sent.pkt_num, *epoch as u64 + 1);
            assert_eq!(sent.size, 1000);
            assert_eq!(sent.ack_eliciting, true);
            assert_eq!(sent.in_flight, true);
            assert_eq!(sent.time_lost, None);
            assert_eq!(sent.time_acked, None);
            assert_eq!(sent.time_sent, now);
        }
    }

    #[test]
    fn test_detect_and_remove_lost_packets() {
        let mut congestion =
            CongestionController::new(CongestionAlgorithm::Bbr, MAX_ACK_DELAY, Mock, Mock);
        let now = Instant::now();
        let space = Epoch::Initial;
        for i in 1..=5 {
            congestion.on_packet_sent(i, space, true, true, 1000, now);
        }
        // ack 5，检测出 1,2 因为乱序丢包
        congestion.largest_acked_packet[space] = Some(5);
        congestion.sent_packets[space][4].is_acked = true;
        congestion.sent_packets[space].pop_back();
        let lost_packets = congestion.detect_and_remove_lost_packets(space, now);
        assert_eq!(lost_packets.len(), 2);
        for (i, lost) in lost_packets.iter().enumerate() {
            assert_eq!(lost.pkt_num, i as u64 + 1);
        }
        assert_eq!(congestion.sent_packets[space].len(), 2);
        // loss delay =  333*1.25
        let loss_packets =
            congestion.detect_and_remove_lost_packets(space, now + Duration::from_millis(417));
        // 3,4 因为超时丢包
        assert_eq!(loss_packets.len(), 2);
        for (i, lost) in loss_packets.iter().enumerate() {
            assert_eq!(lost.pkt_num, i as u64 + 3);
        }
    }
}
