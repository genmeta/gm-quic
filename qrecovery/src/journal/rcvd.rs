use std::{
    collections::HashSet,
    sync::{Arc, RwLock},
};

use bytes::BufMut;
use qbase::{
    frame::AckFrame,
    net::tx::Signals,
    packet::{InvalidPacketNumber, Package, PacketNumber, PacketWriter},
    util::{IndexDeque, IndexError},
    varint::{VARINT_MAX, VarInt},
};
use tokio::time::{Duration, Instant};

/// 收包记录有以下几种状态
/// - Empty：收包记录为空，未收到该包
/// - PacketReceived：（收包时间，最晚ack时间，过期时间）, 如果路径没有驱动 ack，由这里驱动
/// - AckSent：（ack_eliciting，收包时间,淘汰时间，确认了这个包的包号集合），如果set里的任意包号被确认了，则转换成 AckConfirmed 状态
/// - AckConfirmed：（ack_eliciting，收包时间，淘汰时间）
#[derive(Debug, Clone, PartialEq, Eq, Default)]
enum State {
    #[default]
    Empty,
    PacketReceived(Instant, Option<Instant>, Instant),
    AckSent(bool, Instant, Instant, HashSet<u64>),
    AckConfirmed(bool, Instant, Instant),
}

impl State {
    // 是否要打包到 ack frame 中，如果需要，PacketReceived 状态转换成 AckSent 状态， AckSent 状态记录 pn
    fn track_packet_in_ack_frame(&mut self, pn: u64) -> bool {
        match self {
            State::PacketReceived(recv_time, latest_ack_time, expire_time) => {
                *self = State::AckSent(
                    latest_ack_time.is_some(),
                    *recv_time,
                    *expire_time,
                    [pn].into(),
                );
                true
            }
            State::AckSent(_, _, _, pns) => {
                pns.insert(pn);
                true
            }
            State::AckConfirmed(_, _, _) => true,
            State::Empty => false,
        }
    }

    fn could_expire(&self, now: Instant) -> bool {
        match self {
            State::Empty => true,
            State::AckConfirmed(ack_eliciting, _, expire_time) => {
                !ack_eliciting || *expire_time < now
            }
            _ => false,
        }
    }
}

/// 纯碎的一个收包记录，主要用于：
/// - 记录包有无收到
/// - 根据某个largest pktno，生成ack frame（ack frame不能超过buf大小）
/// - 确定记录不再需要，可以被丢弃，滑走
#[derive(Debug, Default)]
struct RcvdJournal {
    queue: IndexDeque<State, VARINT_MAX>,
    max_ack_delay: Option<Duration>,
    packet_include_ack: HashSet<u64>,
    earliest_not_ack_time: Option<(u64, Instant)>,
}

impl RcvdJournal {
    fn with_capacity(capacity: usize, max_ack_delay: Option<Duration>) -> Self {
        Self {
            queue: IndexDeque::with_capacity(capacity),
            max_ack_delay,
            packet_include_ack: HashSet::new(),
            earliest_not_ack_time: None,
        }
    }

    fn decode_pn(&mut self, pkt_number: PacketNumber) -> Result<u64, InvalidPacketNumber> {
        let expected_pn = self.queue.largest();
        let pn = pkt_number.decode(expected_pn);
        if pn < self.queue.offset() {
            return Err(InvalidPacketNumber::TooOld);
        }

        match self.queue.get(pn) {
            Some(State::Empty) | None => Ok(pn),
            _ => Err(InvalidPacketNumber::Duplicate),
        }
    }

    fn on_rcvd_pn(&mut self, pn: u64, is_ack_eliciting: bool, pto: Duration) {
        let now = tokio::time::Instant::now();
        let ack_time = if is_ack_eliciting {
            Some(now + self.max_ack_delay.unwrap_or_default())
        } else {
            None
        };
        let expire_time = now + pto * 3;
        if let Some(record) = self.queue.get_mut(pn) {
            assert!(matches!(record, State::Empty));
            *record = State::PacketReceived(now, ack_time, expire_time);
        } else if let Err(e @ IndexError::ExceedLimit(..)) = self
            .queue
            .insert(pn, State::PacketReceived(now, ack_time, expire_time))
        {
            panic!("packet number never exceed limit: {e}")
        }
        if is_ack_eliciting && self.earliest_not_ack_time.is_none() {
            self.earliest_not_ack_time = Some((pn, now));
        }
    }

    fn on_rcvd_ack(&mut self, ack_frame: &AckFrame) {
        let acked_pns: std::collections::HashSet<_> = ack_frame
            .iter()
            .flat_map(|range| range.clone())
            .filter(|pn| self.packet_include_ack.contains(pn))
            .collect();

        self.packet_include_ack.retain(|pn| !acked_pns.contains(pn));

        for record in self.queue.iter_mut() {
            if let State::AckSent(ack_eliciting, recv_time, expire_time, pns) = record {
                if pns.iter().any(|pn| acked_pns.contains(pn)) {
                    *record = State::AckConfirmed(*ack_eliciting, *recv_time, *expire_time);
                }
            }
        }
        self.rotate_queue();
    }

    fn rotate_queue(&mut self) {
        let now = tokio::time::Instant::now();
        while self
            .queue
            .front()
            .is_some_and(|(_pn, state)| state.could_expire(now))
        {
            self.queue.pop_front();
        }
    }

    fn gen_ack_frame_util(
        &mut self,
        pn: u64,
        largest: u64,
        rcvd_time: Instant,
        mut capacity: usize,
    ) -> Result<AckFrame, Signals> {
        let mut pkts = self
            .queue
            .enumerate_mut()
            .rev()
            .skip_while(|(pktno, _)| *pktno > largest);

        // Minimum length with at least ACK frame type, largest, delay, range count, first_range (at least 1 byte for 0)
        let largest = VarInt::from_u64(largest).unwrap();
        let delay = rcvd_time.elapsed().as_micros() as u64;
        let delay = VarInt::from_u64(delay).unwrap();
        let mut first_range = 0_u32;
        for (_, s) in pkts.by_ref() {
            if s.track_packet_in_ack_frame(pn) {
                first_range += 1;
            } else {
                break;
            }
        }
        first_range = first_range.saturating_sub(1);

        let first_range = VarInt::from(first_range);
        // Frame type + Largest Acknowledged + First Ack Range + Ack Range Count
        let min_len =
            1 + largest.encoding_size() + delay.encoding_size() + first_range.encoding_size() + 1;
        if capacity < min_len {
            return Err(Signals::CONGESTION);
        }
        capacity -= min_len;

        fn range_count_size_increment(range_count: usize) -> usize {
            match range_count {
                // 接下来需要2字节编码
                len if len == (1 << 6) - 1 => 1, // 2 - 1
                // 接下来需要4字节编码
                len if len == (1 << 14) - 1 => 2, // 4 - 2
                // 接下来需要8字节编码
                len if len == (1 << 30) - 1 => 4, // 8 - 4
                // 放不下了，不可能走到这里
                len if len == (1 << 62) - 1 => panic!("range count too large"),
                _ => 0,
            }
        }

        let mut ranges = vec![];

        use core::ops::ControlFlow::*;
        let (Continue((gap, ack, last_is_acked)) | Break((gap, ack, last_is_acked))) = pkts
            .try_fold(
                // take_while第一个被判否的元素会被消耗，如果它是gap那这里有gap=1，如果是因为迭代器没有更多元素这里gap=1也不影响
                (1, 0, false),
                |(gap, ack, last_is_acked), (_pktno, state)| {
                    let range_count = ranges.len();
                    match (last_is_acked, state.track_packet_in_ack_frame(pn)) {
                        // 本range结束了，看看是否放得下本range，开始新的range
                        (true, false) => {
                            // 修正
                            let gap = VarInt::from_u32(gap - 1);
                            let ack = VarInt::from_u32(ack - 1);
                            let size = range_count_size_increment(range_count)
                                + gap.encoding_size()
                                + ack.encoding_size();
                            if capacity < size {
                                // last_is_acked为false，不会被填进去
                                return Break((0, 0, false));
                            }
                            capacity -= size;
                            ranges.push((gap, ack));
                            Continue((1, 0, state.track_packet_in_ack_frame(pn)))
                        }
                        // 如果当前是ack，增加ack，保持gap不变
                        (false | true, true) => {
                            Continue((gap, ack + 1, state.track_packet_in_ack_frame(pn)))
                        }
                        // 当前和之前都是gap，增加gap
                        (false, false) => {
                            Continue((gap + 1, ack, state.track_packet_in_ack_frame(pn)))
                        }
                    }
                },
            );
        // 处理最后一个未来完成的range
        if last_is_acked {
            let gap = VarInt::from_u32(gap - 1);
            let ack = VarInt::from_u32(ack - 1);
            let size = range_count_size_increment(ranges.len())
                + gap.encoding_size()
                + ack.encoding_size();
            if capacity > size {
                // capacity -= size; unnecessary, never read latter
                ranges.push((gap, ack));
            }
        }
        self.packet_include_ack.insert(pn);
        if let Some((pn, _)) = self.earliest_not_ack_time {
            if largest >= pn {
                self.earliest_not_ack_time = None;
            }
        }
        Ok(AckFrame::new(largest, delay, first_range, ranges, None))
    }

    fn need_ack(&self) -> Option<(u64, Instant)> {
        let now = tokio::time::Instant::now();
        let (_, earliest_not_ack_time) = self.earliest_not_ack_time?;
        let max_ack_delay = self.max_ack_delay.unwrap_or_default();
        if earliest_not_ack_time + max_ack_delay >= now {
            return None;
        }
        let (largest, state) = self.queue.back()?;
        let recv_time = match state {
            State::PacketReceived(rt, _, _)
            | State::AckSent(_, rt, _, _)
            | State::AckConfirmed(_, rt, _) => *rt,
            _ => return None,
        };

        Some((largest, recv_time))
    }
}

/// Records for received packets, decode the packet number and generate ack frames.
// 接收数据包队列，各处共享的，判断包是否收到以及生成ack frame，只需要读锁；
// 记录新收到的数据包，或者失活旧数据包并滑走，才需要写锁。
#[derive(Debug, Clone, Default)]
pub struct ArcRcvdJournal {
    inner: Arc<RwLock<RcvdJournal>>,
}

impl ArcRcvdJournal {
    /// Create a new empty records with the given `capacity`.
    ///
    /// The number of records can exceed the `capacity` specified at creation time, but the internel
    /// implementation strvies to avoid reallocation.
    pub fn with_capacity(capacity: usize, max_ack_delay: Option<Duration>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(RcvdJournal::with_capacity(
                capacity,
                max_ack_delay,
            ))),
        }
    }

    /// Decode the pn from peer's packet to actual packer number.
    ///
    /// See [`RFC`](https://www.rfc-editor.org/rfc/rfc9000.html#name-sample-packet-number-decodi)
    /// for more details about decode packet number.
    ///
    /// If the packet is too old or has been received, or the pn is too big, this method will return
    /// an error.
    ///
    /// Note that although the packet number successful decoded, it does not mean that the packet is
    /// valid, and the frames in it are valid.
    ///
    /// The registered packet must be valid, successfully decrypted, and the frames in it must be
    /// valid.
    // 当新收到一个数据包，如果这个包很旧，那么大概率意味着是重复包，直接丢弃。
    // 如果这个数据包号是最大的，那么它之前的空档都是尚未收到的，得记为未收到。
    // 注意，包号合法，不代表的包内容合法，必须等到包被正确解密且其中帧被正确解出后，才能确认收到。
    pub fn decode_pn(&self, encoded_pn: PacketNumber) -> Result<u64, InvalidPacketNumber> {
        self.inner.write().unwrap().decode_pn(encoded_pn)
    }

    /// Register the packet has been recieved.
    ///
    /// The registered packet must be valid, successfully decrypted, and the frames in it must be
    /// valid.
    // 当包号合法，且包被完全解密，且包中的帧都正确之后，记录该包已经收到。
    pub fn on_rcvd_pn(&self, pn: u64, is_ack_eliciting: bool, pto: Duration) {
        self.inner
            .write()
            .unwrap()
            .on_rcvd_pn(pn, is_ack_eliciting, pto);
    }

    /// Generate an ack frame which ack the received frames until `largest`.
    ///
    /// This method will write an ack frame into the `buf`. The `Ack Delay` field of the frame is
    /// the argument `recv_time` as microsec, the `Largest Acknowledged` field of the frame is the
    /// `largest` frame, the ranges in ack frame will not exceed `largest`.
    pub fn gen_ack_frame_util(
        &self,
        pn: u64,
        largest: u64,
        rcvd_time: Instant,
        capacity: usize,
    ) -> Result<AckFrame, Signals> {
        self.inner
            .write()
            .unwrap()
            .gen_ack_frame_util(pn, largest, rcvd_time, capacity)
    }

    pub fn on_rcvd_ack(&self, ack_frame: &AckFrame) {
        self.inner.write().unwrap().on_rcvd_ack(ack_frame);
    }

    pub fn need_ack(&self) -> Option<(u64, Instant)> {
        self.inner.read().unwrap().need_ack()
    }

    pub fn revise_max_ack_delay(&self, max_ack_delay: Duration) {
        self.inner.write().unwrap().max_ack_delay = Some(max_ack_delay);
    }

    pub fn ack_package<'r>(&'r self, need_ack: Option<(u64, Instant)>) -> AckPackege<'r> {
        AckPackege {
            journal: self,
            need_ack,
        }
    }
}

pub struct AckPackege<'r> {
    journal: &'r ArcRcvdJournal,
    need_ack: Option<(u64, Instant)>,
}

impl<'r, Target> Package<Target> for AckPackege<'r>
where
    Target: AsRef<PacketWriter<'r>> + ?Sized,
    AckFrame: Package<Target>,
{
    fn dump(&mut self, target: &mut Target) -> Result<(), Signals> {
        self.need_ack
            .or_else(|| self.journal.need_ack())
            .ok_or(Signals::TRANSPORT)
            .and_then(|(largest_ack, rcvd_time)| {
                self.journal.gen_ack_frame_util(
                    target.as_ref().packet_number(),
                    largest_ack,
                    rcvd_time,
                    target.as_ref().remaining_mut(),
                )
            })?
            .dump(target)
            .unwrap();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rcvd_pkt_records() {
        let records = ArcRcvdJournal::with_capacity(16, None);
        assert_eq!(records.decode_pn(PacketNumber::encode(1, 0)), Ok(1));
        assert_eq!(records.inner.read().unwrap().queue.len(), 0);

        let pto = Duration::from_millis(100);
        records.on_rcvd_pn(1, true, pto);

        assert_eq!(records.inner.read().unwrap().queue.len(), 2);
        assert_eq!(
            records.inner.read().unwrap().queue.get(0).unwrap(),
            &State::Empty
        );

        assert!(matches!(
            records.inner.read().unwrap().queue.get(1).unwrap(),
            State::PacketReceived(_, _, _)
        ));

        let ack_frame = records.gen_ack_frame_util(0, 1, Instant::now(), 1200);

        assert_eq!(&ack_frame.unwrap().largest(), &1);
        assert!(
            records
                .inner
                .read()
                .unwrap()
                .packet_include_ack
                .contains(&0)
        );

        assert!(matches!(
            records.inner.read().unwrap().queue.get(1).unwrap(),
            State::AckSent(true, _, _, _)
        ));

        let ack_frame = AckFrame::new(0_u32.into(), 100_u32.into(), 0_u32.into(), vec![], None);

        records.on_rcvd_ack(&ack_frame);

        assert_eq!(records.inner.read().unwrap().queue.len(), 1);
        let binding = records.inner.read().unwrap();
        let record = binding.queue.get(1).unwrap();
        assert!(matches!(record, State::AckConfirmed(_, _, _)));
    }

    #[test]
    fn gen_ack_frame() {
        let rcvd_state = State::PacketReceived(Instant::now(), None, Instant::now());
        let unrcvd_state = State::Empty;
        let mut queue = IndexDeque::with_capacity(45);
        for idx in 1..11 {
            queue.insert(idx, rcvd_state.clone()).unwrap();
        }
        for idx in 11..12 {
            queue.insert(idx, unrcvd_state.clone()).unwrap();
        }
        for idx in 12..45 {
            queue.insert(idx, rcvd_state.clone()).unwrap();
        }
        for idx in 45..50 {
            queue.insert(idx, unrcvd_state.clone()).unwrap();
        }
        for idx in 50..55 {
            queue.insert(idx, rcvd_state.clone()).unwrap();
        }

        let mut rcvd_jornal = RcvdJournal {
            queue,
            max_ack_delay: None,
            packet_include_ack: Default::default(),
            earliest_not_ack_time: None,
        };

        let ack = rcvd_jornal
            .gen_ack_frame_util(0, 52, Instant::now(), 1000)
            .unwrap();
        assert_eq!(
            ack.ranges(),
            &vec![
                (VarInt::from_u32(50 - 45 - 1), VarInt::from_u32(45 - 12 - 1)),
                (VarInt::from_u32(12 - 11 - 1), VarInt::from_u32(11 - 1 - 1))
            ]
        );
        assert_eq!(ack.first_range(), 2)
    }
}
