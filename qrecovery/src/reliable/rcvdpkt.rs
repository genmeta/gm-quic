use std::{
    sync::{Arc, RwLock, RwLockWriteGuard},
    time::Instant,
};

use qbase::{
    frame::{io::WriteFrame, AckFrame},
    packet::PacketNumber,
    util::IndexDeque,
    varint::{VarInt, VARINT_MAX},
};
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

/// 纯碎的一个收包记录，主要用于：
/// - 记录包有无收到
/// - 根据某个largest pktno，生成ack frame（ack frame不能超过buf大小）
/// - 确定记录不再需要，可以被丢弃，滑走
#[derive(Debug, Default)]
struct RcvdPktRecords {
    queue: IndexDeque<State, VARINT_MAX>,
}

impl RcvdPktRecords {
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

    fn gen_ack_frame_util(
        &self,
        (largest, recv_time): (u64, Instant),
        mut capacity: usize,
    ) -> Option<AckFrame> {
        let mut iter = self
            .queue
            .iter_with_idx()
            .rev()
            .skip_while(|(pktno, _)| *pktno > largest);

        // 注意assert中的next消耗掉一个单位，若要去掉assert，first_range还需减1
        assert!(
            iter.by_ref()
                .next()
                .expect("largest in recv pkt records must be record")
                .1
                .is_received
        );

        let largest = VarInt::from_u64(largest).unwrap();
        let delay = VarInt::from_u64(recv_time.elapsed().as_micros() as u64).unwrap();
        // Minimum length with at least ACK frame type, largest, delay, range count, first_range (at least 1 byte for 0)
        let min_len = 1 + largest.encoding_size() + delay.encoding_size() + 1 + 1;
        if capacity < min_len {
            return None;
        }
        capacity -= min_len;

        let first_range = iter.by_ref().take_while(|(_, s)| s.is_received).count();
        let mut ack_range_count = 0u64;
        let mut ranges = Vec::with_capacity(16);
        loop {
            let additional_count_encoding = if ack_range_count == (1 << 6) - 1 {
                1 // 下一个ack_range_count需要用2字节编码了
            } else if ack_range_count == (1 << 30) - 1 {
                2 // 下一个ack_range_count需要用4字节编码了
            } else if ack_range_count == (1 << 62) - 1 {
                4 // 下一个ack_range_count需要用8字节编码了
            } else {
                0
            };
            if capacity <= additional_count_encoding {
                break;
            }
            capacity -= additional_count_encoding;

            if iter.next().is_none() {
                break;
            }
            let gap = iter.by_ref().take_while(|(_, s)| !s.is_received).count();

            if iter.next().is_none() {
                break;
            }
            let acked = iter.by_ref().take_while(|(_, s)| s.is_received).count();

            let gap = VarInt::try_from(gap).unwrap();
            let acked = VarInt::try_from(acked).unwrap();
            if capacity < gap.encoding_size() + acked.encoding_size() {
                break;
            }
            capacity -= gap.encoding_size() + acked.encoding_size();

            ranges.push((gap, acked));
            ack_range_count += 1;
        }

        Some(AckFrame {
            largest,
            delay,
            first_range: unsafe { VarInt::from_u64_unchecked(first_range as u64) },
            ranges,
            ecn: None,
        })
    }

    fn read_ack_frame_util(
        &self,
        mut buf: &mut [u8],
        largest: u64,
        recv_time: Instant,
    ) -> Option<usize> {
        // TODO: 未来替换成，不用申请Vec先生成AckFrame，从largest往后开始成对生成
        let buf_len = buf.len();
        let ack_frame = self.gen_ack_frame_util((largest, recv_time), buf_len)?;
        buf.put_frame(&ack_frame);
        Some(buf_len - buf.len())
    }

    fn retire(&mut self, pn: u64) {
        if let Some(record) = self.queue.get_mut(pn) {
            record.inactivate();
        }
    }

    fn slide_retired(&mut self) {
        let n = self.queue.iter().take_while(|s| !s.is_active).count();
        self.queue.advance(n)
    }
}

/// Records for received packets, decode the packet number and generate ack frames.
// 接收数据包队列，各处共享的，判断包是否收到以及生成ack frame，只需要读锁；
// 记录新收到的数据包，或者失活旧数据包并滑走，才需要写锁。
#[derive(Debug, Clone, Default)]
pub struct ArcRcvdPktRecords {
    inner: Arc<RwLock<RcvdPktRecords>>,
}

impl ArcRcvdPktRecords {
    /// Create a new empty records with the given `capacity`.
    ///
    /// The number of records can exceed the `capacity` specified at creation time, but the internel
    /// implementation strvies to avoid reallocation.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(RcvdPktRecords::with_capacity(capacity))),
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

    pub fn write(&self) -> ArcRcvdPktRecordsWriter<'_> {
        ArcRcvdPktRecordsWriter {
            guard: self.inner.write().unwrap(),
        }
    }
}

/// 适合一个Path认为它的ack都被处理了之后，哪些收到的包的状态没用了，
/// 将其失活，最终再看是否可以将收包队列向前滑动。
pub struct ArcRcvdPktRecordsWriter<'a> {
    guard: RwLockWriteGuard<'a, RcvdPktRecords>,
}

impl ArcRcvdPktRecordsWriter<'_> {
    /// 各路径自行反馈哪些数据包过期了，不必再在AckFrame反馈。
    /// 队首连续的失活状态记录可以滑走，避免收包队列持续增长。
    pub fn retire(&mut self, pn: u64) {
        self.guard.retire(pn);
    }
}

impl Drop for ArcRcvdPktRecordsWriter<'_> {
    fn drop(&mut self) {
        self.guard.slide_retired();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rcvd_pkt_records() {
        let records = ArcRcvdPktRecords::default();
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
        {
            let mut writer = records.write();
            for i in 5..10 {
                writer.retire(i);
            }
        }
        assert_eq!(records.inner.read().unwrap().queue.len(), 31);

        {
            let mut writer = records.write();
            for i in 0..5 {
                writer.retire(i);
            }
        }
        assert_eq!(records.inner.read().unwrap().queue.len(), 21);

        assert_eq!(
            records.decode_pn(PacketNumber::encode(9, 0)),
            Err(InvalidPacketNumber::TooOld)
        );
    }
}
