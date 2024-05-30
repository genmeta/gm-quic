use qbase::frame::AckFrame;
use std::{
    cmp::Ordering,
    collections::VecDeque,
    future::Future,
    ops::{Index, RangeInclusive},
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};

pub mod bbr;
pub mod rtt;
pub use rtt::Rtt;

pub mod delivery_rate;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Epoch {
    Initial = 0,
    Handshake = 1,
    Application = 2,
}

static EPOCHS: [Epoch; 3] = [Epoch::Initial, Epoch::Handshake, Epoch::Application];

impl Epoch {
    pub fn epochs(range: RangeInclusive<Epoch>) -> &'static [Epoch] {
        &EPOCHS[*range.start() as usize..=*range.end() as usize]
    }

    pub const fn count() -> usize {
        3
    }
}

impl Index<Epoch> for [u64] {
    type Output = u64;

    fn index(&self, index: Epoch) -> &u64 {
        &self[index as usize]
    }
}

pub trait CongestionControl {
    /// 轮询是否可以发包，若可以，返回可以发包的数据量，以及是否在包中携带AckFrame，若需携带AckFrame，则需
    /// 返回该Path接收到的最大数据包号及其收包时间，以供填充AckFrame中的largest和ack_delay字段。
    /// THINK: 每次发包都会轮询，并非一次轮询返回很大数据量，发很多个包才下次轮询，这是为了能随时询问是否该生成AckFrame。
    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        space: Epoch,
    ) -> Poll<(usize, Option<(u64, Instant)>)>;

    /// 每当发送一个数据包后，由Path的cc记录发包信息，供未来确认时计算RTT和发送速率，并减少发送信用
    /// 最后一个参数，是这次发包是否携带了ack frame，若没携带，是None；若携带了，则是ack frame的最大包号
    /// 若有Ack信息，也要记录下来。未来该包被确认，那么该AckFrame中largest之前的，接收到的包，通知ack观察者失活
    fn on_pkt_sent(
        &self,
        space: Epoch,
        pn: u64,
        is_ack_elicition: bool,
        sent_bytes: usize,
        in_flight: bool,
        ack: Option<u64>,
    );

    /// 当收到AckFrame，其中有该Path的部分包被确认，调用该函数，驱动拥塞控制算法演进
    /// 注意AckFrame中的largest也会通过该函数确认
    /// 如果该包中有ack frame，那么ack.largest之前的收包记录未来就不需要在AckFrame中再同步了，需通知ack观察者
    fn on_pkt_acked(&self, space: Epoch, ack_frame: &AckFrame);

    /// 处理AckFrame中的largest及ack_delay字段，供Path的cc采样rtt，不可重复采样
    /// 调用该函数后，也意味着AckFrame都被确认完了，可以判断Path过往发过的包，哪些丢了，并反馈
    /// #[deprecated("duplicate with on_ack")]
    /// fn on_rtt_sample(&mut self, space: Epoch, largest_pn: u64, ack_delay: Duration);

    /// 每当收到一个数据包，记录下，根据这些记录，决定下次发包时，是否需要带上AckFrame，作用于poll_send的返回值中
    /// 另外，这个记录不是持续增长的，得向前滑动，靠on_acked(pn)及该pn中有AckFrame记录驱动滑动
    fn on_recv_pkt(&self, space: Epoch, pn: u64, is_ack_elicition: bool);
}

pub trait ObserveLoss {
    /// 当收到AckFrame，largest_acked_pn都被确认了，那往前数3个没被ack的包，可判定为丢失
    /// 前3个数据包，如果超时时间过长，超过了PTO，也应判定为丢包，调用该函数，通知丢包观察者
    ///（丢包观察者可能是可靠空间的发送端，用于ARQ丢包重传机制，也可能是一个channel的sender）
    fn may_loss_pkt(&self, space: Epoch, pn: u64);
}

pub trait ObserveAck {
    /// 收包记录作为滑动窗口也要向前滑动；当一个Path的收包记录产生的AckFrame被对方收到时，那这个Path过往收到的包
    /// 都不必记录了，可以淘汰。
    /// 需知，一个Path收到的包不需要被记录，不代表其他Path的包也不需被记录。只有等各个path过去接收的包都不需要被记录，
    /// 那么Space级别的包号连续的不被记录的，才可以向前滑动
    /// #[deprecated]
    /// fn on_ack_be_acked(&self, space: Epoch, pn: u64);

    /// 其实用函数作用命名，可以如下命名，感觉更好一些
    /// 当发送的AckFrame被确认，那该AckFrame中的largest之前的，该path接收的包号，
    /// 都可以淘汰/失活了，不需再出现在后续的AckFrame中，即调用此函数通知外部观察者
    fn inactivate_rcvd_record(&self, space: Epoch, pn: u64);
}

const K_GRANULARITY: Duration = Duration::from_millis(1);
const K_PACKET_THRESHOLD: u64 = 3;
pub enum CongestionAlgorithm {
    Bbr,
}

pub struct Congestion {
    cc: Box<dyn Algorithm>,
    rtt: Arc<Mutex<Rtt>>,
    loss_detection_timer: Option<Instant>,
    pto_count: u32,
    max_ack_delay: Duration,
    time_of_last_ack_eliciting_packet: [Option<Instant>; Epoch::count()],
    largest_acked_packet: [u64; Epoch::count()],
    loss_time: [Option<Instant>; Epoch::count()],
    sent_packets: [VecDeque<Sent>; Epoch::count()],
    anti_amplification: bool,
    handshake_confirmed: bool,
    has_handshake_keys: bool,
}

impl Congestion {
    fn new(algorithm: CongestionAlgorithm) -> Self {
        let cc = match algorithm {
            CongestionAlgorithm::Bbr => Box::new(bbr::BBRState::new()),
        };

        Congestion {
            cc,
            rtt: Arc::new(Mutex::new(Rtt::default())),
            loss_detection_timer: None,
            // todo : read from transport parameters
            max_ack_delay: Duration::from_millis(0),
            pto_count: 0,
            time_of_last_ack_eliciting_packet: [None, None, None],
            largest_acked_packet: [u64::MAX, u64::MAX, u64::MAX],
            loss_time: [None, None, None],
            sent_packets: [VecDeque::new(), VecDeque::new(), VecDeque::new()],
            anti_amplification: false,
            handshake_confirmed: false,
            has_handshake_keys: false,
        }
    }

    fn on_packet_sent(
        &mut self,
        packet_number: u64,
        pn_space: Epoch,
        ack_eliciting: bool,
        in_flight: bool,
        sent_bytes: usize,
        now: Instant,
    ) {
        let pn_space = pn_space as usize;
        let mut sent = Sent {
            pkt_num: packet_number,
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: sent_bytes,
            ack_eliciting,
            in_flight,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
        };

        if in_flight {
            if ack_eliciting {
                self.time_of_last_ack_eliciting_packet[pn_space] = Some(now);
            }

            self.cc.on_packet_sent(&mut sent, sent_bytes, now);
            self.set_lost_detection_timer(now);
        }

        match self.sent_packets[pn_space].binary_search_by_key(&packet_number, |p| p.pkt_num) {
            Ok(_) => (),
            Err(idx) => self.sent_packets[pn_space].insert(idx, sent),
        }
    }

    // When a server is blocked by anti-amplification limits, receiving a datagram unblocks it
    fn on_datagram_recv(&mut self, now: Instant) {
        // If this datagram unblocks the server, arm the
        // PTO timer to avoid deadlock.
        if self.anti_amplification {
            self.set_lost_detection_timer(now);
            if let Some(loss_detection_timer) = self.loss_detection_timer {
                if loss_detection_timer < now {
                    // Execute PTO if it would have expired
                    // while the amplification limit applied.
                    self.on_loss_detection_timeout(now);
                }
            }
        }
    }

    fn on_packet_acked(&mut self, packet_number: u64, pn_space: Epoch, ack_delay: Duration) {
        self.largest_acked_packet[pn_space as usize] =
            if self.largest_acked_packet[pn_space as usize] == u64::MAX {
                packet_number
            } else {
                self.largest_acked_packet[pn_space as usize].max(packet_number)
            };

        let now = Instant::now();

        let sent: Option<Sent> = self.sent_packets[pn_space as usize]
            .binary_search_by_key(&packet_number, |p| p.pkt_num)
            .ok()
            .and_then(|idx| self.sent_packets[pn_space as usize].remove(idx));

        let acked = match sent {
            Some(sent) => Acked {
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
            },
            None => return,
        };

        let loss_packets = self.detect_and_remove_lost_packets(pn_space, now);
        if !loss_packets.is_empty() {
            self.on_packets_lost(loss_packets, pn_space, now);
        }

        self.cc.on_packet_acked(&acked, now);
    }

    fn on_packets_lost(&mut self, packets: Vec<Sent>, _pn_space: Epoch, now: Instant) {
        // todo: 通知 space 丢包的 pkt_num， 使用回调函数
        for lost in packets {
            self.cc.on_congestion_event(&lost, now);
        }
    }

    fn get_congestion_window(&self) -> u64 {
        self.cc.cwnd()
    }

    fn set_lost_detection_timer(&mut self, _now: Instant) {
        let (earliest_loss_time, _) = self.get_loss_time_and_space();
        if earliest_loss_time.is_some() {
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

    fn on_loss_detection_timeout(&mut self, now: Instant) {
        let (earliest_loss_time, space) = self.get_loss_time_and_space();
        if earliest_loss_time.is_some() {
            let loss_packet = self.detect_and_remove_lost_packets(space, now);
            // 触发了 timeout loss 不为空
            assert!(!loss_packet.is_empty());
            self.on_packets_lost(loss_packet, space, now);
            self.set_lost_detection_timer(now);
            return;
        }

        if self.no_ack_eliciting_in_flight() {
            assert!(self.peer_completed_address_validation());
            // if self.has_handshake_keys {
            //     // sen one ack eliciting handshake packet
            // } else {
            //     // send one ack eliciting padded Inital packet
            // }
        } else {
            let (timeout, space) = self.get_pto_time_and_space();
            if timeout.is_some() {
                // send one ack eliciting packet in space
            }
        }
        self.pto_count += 1;
        self.set_lost_detection_timer(now);
    }

    fn get_loss_time_and_space(&self) -> (Option<Instant>, Epoch) {
        let mut time = self.loss_time[Epoch::Initial as usize];
        let mut space = Epoch::Initial;
        for pn_space in [Epoch::Handshake, Epoch::Application].iter() {
            if let Some(loss) = self.loss_time[*pn_space as usize] {
                if time.is_none() || loss < time.unwrap() {
                    time = Some(loss);
                    space = *pn_space;
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
        for pn_space in [Epoch::Initial, Epoch::Handshake, Epoch::Application].iter() {
            // no ack-eliciting packets in flight in space
            if self.no_ack_eliciting_in_flight() {
                continue;
            }
            if *pn_space == Epoch::Application {
                if !self.handshake_confirmed {
                    return (pto_timeout, pto_space as u8);
                }
                duration += self.max_ack_delay * 2_u32.pow(self.pto_count);
            }

            if self.time_of_last_ack_eliciting_packet[*pn_space as usize].is_none() {
                continue;
            }

            let new_time =
                self.time_of_last_ack_eliciting_packet[*pn_space as usize].unwrap() + duration;
            if pto_timeout.is_none() || new_time < pto_timeout.unwrap() {
                pto_timeout = Some(new_time);
                pto_space = *pn_space;
            }
        }
        (pto_timeout, pto_space as u8)
    }

    fn detect_and_remove_lost_packets(&mut self, pn_space: Epoch, now: Instant) -> Vec<Sent> {
        let pn_space = pn_space as usize;
        let largest_acked = self.largest_acked_packet[pn_space];
        assert!(largest_acked != u64::MAX);
        self.loss_time[pn_space] = None;

        let loss_delay = self.rtt.lock().unwrap().loss_delay();
        let lost_send_time = now.checked_sub(loss_delay).unwrap();

        let mut lost_packets = Vec::new();

        let mut i = 0;
        while i != self.sent_packets[pn_space].len() {
            if self.sent_packets[pn_space][i].pkt_num > largest_acked {
                i += 1;
                continue;
            }

            // todo: 多路径下，不能用 largest_acked >= self.sent_packets[pn_space][i].pkt_num + K_PACKET_THRESHOLD
            if self.sent_packets[pn_space][i].time_sent <= lost_send_time
                || largest_acked >= self.sent_packets[pn_space][i].pkt_num + K_PACKET_THRESHOLD
            {
                let lost_packet = self.sent_packets[pn_space].remove(i);
                lost_packets.push(lost_packet.unwrap());
            } else {
                let loss_time = self.sent_packets[pn_space][i].time_sent + loss_delay;
                self.loss_time[pn_space] = match self.loss_time[pn_space] {
                    Some(lt) => Some(lt.min(loss_time)),
                    None => Some(loss_time),
                };
                i += 1;
            }
        }

        lost_packets
    }

    fn no_ack_eliciting_in_flight(&self) -> bool {
        for pn_space in [Epoch::Initial, Epoch::Handshake, Epoch::Application].iter() {
            if self.time_of_last_ack_eliciting_packet[*pn_space as usize].is_some() {
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

impl Future for Congestion {
    type Output = usize;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        // todo: read from cc
        let sent_bytes = 0;
        if sent_bytes == 0 {
            // todo: wait for congestion window to open
        } else {
            return Poll::Ready(sent_bytes);
        }
        todo!()
    }
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

    pub has_data: bool,
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
            has_data: false,
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
    fn init(&mut self);

    fn on_packet_sent(&mut self, sent: &mut Sent, sent_bytes: usize, now: Instant);

    fn on_packet_acked(&mut self, packet: &Acked, now: Instant);

    fn on_congestion_event(&mut self, lost: &Sent, now: Instant);

    fn cwnd(&self) -> u64;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_on_packet_sent_multiple_packets() {
        let mut congestion = Congestion::new(CongestionAlgorithm::Bbr);
        let now = Instant::now();
        for i in 1..=5 {
            congestion.on_packet_sent(i, Epoch::Initial, true, true, 1000, now);
        }
        assert_eq!(congestion.sent_packets[Epoch::Initial as usize].len(), 5);
        for (i, sent) in congestion.sent_packets[Epoch::Initial as usize]
            .iter()
            .enumerate()
        {
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
        let mut congestion = Congestion::new(CongestionAlgorithm::Bbr);
        let now = Instant::now();
        congestion.on_packet_sent(1, Epoch::Initial, true, true, 1000, now);
        congestion.on_packet_sent(2, Epoch::Handshake, true, true, 1000, now);
        congestion.on_packet_sent(3, Epoch::Application, true, true, 1000, now);
        assert_eq!(congestion.sent_packets[Epoch::Initial as usize].len(), 1);
        assert_eq!(congestion.sent_packets[Epoch::Handshake as usize].len(), 1);
        assert_eq!(
            congestion.sent_packets[Epoch::Application as usize].len(),
            1
        );
        for epoch in &[Epoch::Initial, Epoch::Handshake, Epoch::Application] {
            let sent = &congestion.sent_packets[*epoch as usize][0];
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
        let mut congestion = Congestion::new(CongestionAlgorithm::Bbr);
        let now = Instant::now();
        let pn_space = Epoch::Initial;
        for i in 1..=5 {
            congestion.on_packet_sent(i, pn_space, true, true, 1000, now);
        }
        // ack 5，检测出 1,2 因为乱序丢包
        congestion.largest_acked_packet[pn_space as usize] = 5;
        congestion.sent_packets[pn_space as usize].pop_back();
        let lost_packets = congestion.detect_and_remove_lost_packets(pn_space, now);
        assert_eq!(lost_packets.len(), 2);
        for (i, lost) in lost_packets.iter().enumerate() {
            assert_eq!(lost.pkt_num, i as u64 + 1);
        }
        assert_eq!(congestion.sent_packets[pn_space as usize].len(), 2);
        // loss delay =  333*1.25
        let loss_packets =
            congestion.detect_and_remove_lost_packets(pn_space, now + Duration::from_millis(417));
        // 3,4 因为超时丢包
        assert_eq!(loss_packets.len(), 2);
        for (i, lost) in loss_packets.iter().enumerate() {
            assert_eq!(lost.pkt_num, i as u64 + 3);
        }
    }

    #[test]
    fn test_on_packet_acked() {
        let mut congestion = Congestion::new(CongestionAlgorithm::Bbr);
        let now = Instant::now();
        let pn_space = Epoch::Initial;
        for i in 1..=5 {
            congestion.on_packet_sent(i, pn_space, true, true, 1000, now);
        }
        congestion.on_packet_acked(3, pn_space, Duration::from_secs(0));
        assert_eq!(congestion.sent_packets[pn_space as usize].len(), 4);
        assert!(congestion.sent_packets[pn_space as usize]
            .iter()
            .all(|p| p.pkt_num != 3));

        for i in 6..10 {
            congestion.on_packet_sent(i, pn_space, true, true, 1000, now);
        }
        // 1,2,4,5,6,7,8,9 收到 8，检测出 1,2,4,5 因为乱序丢包, 只剩下 6,7,9
        congestion.on_packet_acked(8, pn_space, Duration::from_secs(0));
        assert_eq!(congestion.sent_packets[pn_space as usize].len(), 3);
    }
}
