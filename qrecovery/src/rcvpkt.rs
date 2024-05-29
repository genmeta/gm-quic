use crate::index_deque::IndexDeque;
use qbase::{
    frame::AckFrame,
    varint::{VarInt, VARINT_MAX},
};
use std::{
    sync::{Arc, RwLock, RwLockWriteGuard},
    time::Instant,
};
use thiserror::Error;

/// 接收到的数据包有以下几种状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct State {
    // 当一个数据包的状态，未反馈给发送方，或者不确定发送方收到了该反馈
    is_active: bool,
    // 当一个数据包的状态变得无用，比如已被重传或者已被确认了，该状态将变的无用
    is_received: bool,
}

impl Default for State {
    fn default() -> Self {
        // 默认一个包没被收到
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
pub enum Error {
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
pub struct RcvdPktRecords {
    queue: IndexDeque<State, VARINT_MAX>,
}

impl RcvdPktRecords {
    fn recv_pkt(&mut self, pkt_no: u64) -> Result<(), Error> {
        if pkt_no < self.queue.offset() {
            return Err(Error::TooOld);
        }
        // TODO: or pkt_no maybe much more larger than self.queue.largest()

        if let Some(record) = self.queue.get_mut(pkt_no) {
            if record.is_received {
                return Err(Error::HasRcvd);
            }
            record.is_received = true;
        } else {
            self.queue
                .insert(pkt_no, State::new_rcvd())
                .expect("packet number never exceed limit");
        }
        Ok(())
    }

    fn gen_ack_frame_util(
        &self,
        (largest, recv_time): (u64, Instant),
        _capacity: usize,
    ) -> AckFrame {
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
        let first_range = iter.by_ref().take_while(|(_, s)| s.is_received).count();

        let mut ranges = Vec::with_capacity(16);
        loop {
            if iter.next().is_none() {
                break;
            }
            let gap = iter.by_ref().take_while(|(_, s)| !s.is_received).count();

            if iter.next().is_none() {
                break;
            }
            let acked = iter.by_ref().take_while(|(_, s)| s.is_received).count();

            ranges.push(unsafe {
                (
                    VarInt::from_u64_unchecked(gap as u64),
                    VarInt::from_u64_unchecked(acked as u64),
                )
            });
        }

        AckFrame {
            largest: unsafe { VarInt::from_u64_unchecked(largest) },
            delay: unsafe { VarInt::from_u64_unchecked(recv_time.elapsed().as_micros() as u64) },
            first_range: unsafe { VarInt::from_u64_unchecked(first_range as u64) },
            ranges,
            ecn: None,
        }
    }

    fn inactivate(&mut self, pkt_no: u64) {
        if let Some(record) = self.queue.get_mut(pkt_no) {
            record.inactivate();
        }
    }

    fn slide_inactive(&mut self) {
        let n = self.queue.iter().take_while(|s| !s.is_active).count();
        self.queue.advance(n)
    }
}

/// 接收数据包队列，各处共享的，判断包是否收到以及生成ack frame，只需要读锁；
/// 记录新收到的数据包，或者失活旧数据包并滑走，才需要写锁。
#[derive(Debug, Clone, Default)]
pub struct ArcRcvdPktRecords {
    inner: Arc<RwLock<RcvdPktRecords>>,
}

impl ArcRcvdPktRecords {
    /// 当新收到一个数据包，如果这个包很旧，那么大概率意味着是重复包，直接丢弃。
    /// 如果这个数据包号是最大的，那么它之后的空档都是尚未收到的，得记为未收到。
    /// 最后，将该包标记为已收到。
    pub fn recv_pkt(&self, pkt_no: u64) -> Result<(), Error> {
        self.inner.write().unwrap().recv_pkt(pkt_no)
    }

    /// 生成一个AckFrame，largest是最大的包号，须知largest不一定是收到的最大包号，
    /// 而是某个Path收到的最大包号，此AckFrame除了确认数据包，还将用于该Path的RTT采样以及拥塞控制。
    pub fn gen_ack_frame_util(
        &self,
        (largest, recv_time): (u64, Instant),
        capacity: usize,
    ) -> AckFrame {
        self.inner
            .read()
            .unwrap()
            .gen_ack_frame_util((largest, recv_time), capacity)
    }

    pub fn writer(&self) -> ArcRcvdPktRecordsWriter<'_> {
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
    pub fn inactivate(&mut self, pkt_no: u64) {
        self.guard.inactivate(pkt_no);
    }
}

impl Drop for ArcRcvdPktRecordsWriter<'_> {
    fn drop(&mut self) {
        self.guard.slide_inactive();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rcvd_pkt_records() {
        let records = ArcRcvdPktRecords::default();
        assert_eq!(records.recv_pkt(1), Ok(()));
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

        assert_eq!(records.recv_pkt(30), Ok(()));
        {
            let mut writer = records.writer();
            for i in 5..10 {
                writer.inactivate(i);
            }
        }
        assert_eq!(records.inner.read().unwrap().queue.len(), 31);
        {
            let mut writer = records.writer();
            for i in 0..5 {
                writer.inactivate(i);
            }
        }
        assert_eq!(records.inner.read().unwrap().queue.len(), 21);

        assert_eq!(records.recv_pkt(9), Err(Error::TooOld));
    }
}
