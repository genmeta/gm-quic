use std::{
    sync::{Arc, RwLock},
    time::Instant,
};

use qbase::{
    frame::{io::WriteFrame, AckFrame},
    packet::PacketNumber,
    util::IndexDeque,
    varint::{VarInt, VARINT_MAX},
};
use qlog::quic::transport::PacketDroppedTrigger;
use thiserror::Error;

/// Packet有收到/没收到2种状态，状态也有有效/失活2种状态，失活的可以滑走
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct State {
    is_active: bool,
    is_received: bool,
}

impl Default for State {
    fn default() -> Self {
        Self {
            is_active: true,
            is_received: false,
        }
    }
}

impl State {
    fn new_rcvd() -> Self {
        Self {
            is_active: true,
            is_received: true,
        }
    }

    #[inline]
    fn inactivate(&mut self) {
        self.is_active = false;
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum InvalidPacketNumber {
    #[error("packet number too old")]
    TooOld,
    #[error("packet number too large")]
    TooLarge,
    #[error("packet with this number has been received")]
    HasRcvd,
}

impl From<InvalidPacketNumber> for PacketDroppedTrigger {
    fn from(value: InvalidPacketNumber) -> Self {
        match value {
            InvalidPacketNumber::TooOld | InvalidPacketNumber::TooLarge => {
                PacketDroppedTrigger::Genera
            }
            InvalidPacketNumber::HasRcvd => PacketDroppedTrigger::Duplicate,
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
}

impl RcvdJournal {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            queue: IndexDeque::with_capacity(capacity),
        }
    }

    fn decode_pn(&mut self, pkt_number: PacketNumber) -> Result<u64, InvalidPacketNumber> {
        let expected_pn = self.queue.largest();
        let pn = pkt_number.decode(expected_pn);
        if pn < self.queue.offset() {
            return Err(InvalidPacketNumber::TooOld);
        }

        if let Some(&State {
            is_received: true, ..
        }) = self.queue.get(pn)
        {
            return Err(InvalidPacketNumber::HasRcvd);
        }
        Ok(pn)
    }

    fn on_rcvd_pn(&mut self, pn: u64) {
        if let Some(record) = self.queue.get_mut(pn) {
            record.is_received = true;
        } else {
            self.queue
                .insert(pn, State::new_rcvd())
                .expect("packet number never exceed limit");
        }
    }

    #[tracing::instrument(level = "trace", skip(self))]
    fn gen_ack_frame_util(
        &self,
        largest: u64,
        rcvd_time: Instant,
        mut capacity: usize,
    ) -> Option<AckFrame> {
        let mut pkts = self
            .queue
            .iter_with_idx()
            .rev()
            .skip_while(|(pktno, _)| *pktno > largest)
            .inspect(|(pktno, state)| tracing::trace!(pktno, ?state));

        // Minimum length with at least ACK frame type, largest, delay, range count, first_range (at least 1 byte for 0)
        let largest = VarInt::from_u64(largest).unwrap();
        let delay = rcvd_time.elapsed().as_micros() as u64;
        let delay = VarInt::from_u64(delay).unwrap();
        // Frame type + Largest Acknowledged + First Ack Range + Ack Range Count
        let min_len = 1 + largest.encoding_size() + delay.encoding_size() + 1 + 1;
        if capacity < min_len {
            return None;
        }
        capacity -= min_len;

        let first_range = pkts.by_ref().take_while(|(_, s)| s.is_received).count() - 1;
        let first_range = VarInt::try_from(first_range).unwrap();

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
                    match (last_is_acked, state.is_received) {
                        // 本range结束了，看看是否放得下本range，开始新的range
                        (true, false) => {
                            // 修正
                            let gap = VarInt::from_u32(gap - 1);
                            let ack = VarInt::from_u32(ack - 1);
                            if capacity
                                < range_count_size_increment(range_count)
                                    + gap.encoding_size()
                                    + ack.encoding_size()
                            {
                                return Break((0, 0, false));
                            }
                            ranges.push((gap, ack));
                            Continue((1, 0, state.is_received))
                        }
                        // 如果当前是ack，增加ack，保持gap不变
                        (false | true, true) => Continue((gap, ack + 1, state.is_received)),
                        // 当前和之前都是gap，增加gap
                        (false, false) => Continue((gap + 1, ack, state.is_received)),
                    }
                },
            );
        // 处理最后一个未来完成的range
        if last_is_acked {
            let gap = VarInt::from_u32(gap - 1);
            let ack = VarInt::from_u32(ack - 1);
            if capacity
                > range_count_size_increment(ranges.len())
                    + gap.encoding_size()
                    + ack.encoding_size()
            {
                ranges.push((gap, ack));
            }
        }
        Some(AckFrame::new(largest, delay, first_range, ranges, None))
    }

    fn read_ack_frame_util(
        &self,
        mut buf: &mut [u8],
        largest: u64,
        recv_time: Instant,
    ) -> Option<usize> {
        // TODO: 未来替换成，不用申请Vec先生成AckFrame，从largest往后开始成对生成
        let buf_len = buf.len();
        let ack_frame = self.gen_ack_frame_util(largest, recv_time, buf_len)?;
        buf.put_frame(&ack_frame);
        Some(buf_len - buf.len())
    }

    fn rotate(&mut self, pns: impl IntoIterator<Item = u64>) {
        for pn in pns.into_iter() {
            if let Some(record) = self.queue.get_mut(pn) {
                record.inactivate();
            }
        }
        let n = self.queue.iter().take_while(|s| !s.is_active).count();
        self.queue.advance(n)
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
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(RcvdJournal::with_capacity(capacity))),
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
    /// valid, and the frames in it is valid.
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
    pub fn register_pn(&self, pn: u64) {
        self.inner.write().unwrap().on_rcvd_pn(pn);
    }

    pub fn gen_ack_frame_util(
        &self,
        largest: u64,
        rcvd_time: Instant,
        capacity: usize,
    ) -> Option<AckFrame> {
        self.inner
            .read()
            .unwrap()
            .gen_ack_frame_util(largest, rcvd_time, capacity)
    }

    /// Generate an ack frame which ack the received frames until `largest`.
    ///
    /// This method will write an ack frame into the `buf`. The `Ack Delay` field of the frame is
    /// the argument `recv_time` as microsec, the `Largest Acknowledged` field of the frame is the
    /// `largest` frame, the ranges in ack frame will not exceed `largest`.
    pub fn read_ack_frame_util(
        &self,
        buf: &mut [u8],
        largest: u64,
        recv_time: Instant,
    ) -> Option<usize> {
        self.inner
            .read()
            .unwrap()
            .read_ack_frame_util(buf, largest, recv_time)
    }

    pub fn rotate(&self, pns: impl IntoIterator<Item = u64>) {
        self.inner.write().unwrap().rotate(pns);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rcvd_pkt_records() {
        let records = ArcRcvdJournal::default();
        assert_eq!(records.decode_pn(PacketNumber::encode(1, 0)), Ok(1));
        assert_eq!(records.inner.read().unwrap().queue.len(), 0);

        records.register_pn(1);
        assert_eq!(records.inner.read().unwrap().queue.len(), 2);

        assert_eq!(
            records.inner.read().unwrap().queue.get(0).unwrap(),
            &State {
                is_active: true,
                is_received: false
            }
        );
        assert_eq!(
            records.inner.read().unwrap().queue.get(1).unwrap(),
            &State {
                is_active: true,
                is_received: true
            }
        );

        assert_eq!(records.decode_pn(PacketNumber::encode(30, 0)), Ok(30));
        records.register_pn(30);
        records.rotate(5..10);
        assert_eq!(records.inner.read().unwrap().queue.len(), 31);

        records.rotate(0..5);
        assert_eq!(records.inner.read().unwrap().queue.len(), 21);

        assert_eq!(
            records.decode_pn(PacketNumber::encode(9, 0)),
            Err(InvalidPacketNumber::TooOld)
        );
    }

    #[test]
    fn gen_ack_frame() {
        let rcvd_state = State {
            is_active: true,
            is_received: true,
        };
        let unrcvd_state = State {
            is_active: true,
            is_received: false,
        };
        let mut queue = IndexDeque::with_capacity(45);
        for idx in 1..11 {
            queue.insert(idx, rcvd_state).unwrap();
        }
        for idx in 11..12 {
            queue.insert(idx, unrcvd_state).unwrap();
        }
        for idx in 12..45 {
            queue.insert(idx, rcvd_state).unwrap();
        }
        for idx in 45..50 {
            queue.insert(idx, unrcvd_state).unwrap();
        }
        for idx in 50..55 {
            queue.insert(idx, rcvd_state).unwrap();
        }

        let rcvd_jornal = RcvdJournal { queue };

        let ack = rcvd_jornal
            .gen_ack_frame_util(52, Instant::now(), 1000)
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
