use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, MutexGuard},
};

use qbase::{frame::*, packet::PacketNumber, util::IndexDeque, varint::VARINT_MAX};

#[derive(Debug, Clone)]
pub enum SentRecord {
    Reliable(ReliableFrame),
    Data(DataFrame),
    Ack(AckRecord),
}

/// 记录发送的数据包的状态，包括
/// - Flighting: 数据包正在传输中
/// - Acked: 数据包已经被确认
/// - Lost: 数据包丢失
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SentPktState {
    Flighting(u16),
    Acked(u16),
    Lost(u16),
}

impl SentPktState {
    fn nframes(&self) -> usize {
        match self {
            SentPktState::Flighting(n) => *n as usize,
            SentPktState::Acked(n) => *n as usize,
            SentPktState::Lost(n) => *n as usize,
        }
    }

    fn be_acked(&mut self) -> usize {
        match *self {
            SentPktState::Flighting(n) => {
                *self = SentPktState::Acked(n);
                n as usize
            }
            SentPktState::Acked(_) => 0,
            SentPktState::Lost(n) => {
                *self = SentPktState::Acked(n);
                n as usize
            }
        }
    }

    fn maybe_loss(&mut self) -> usize {
        match *self {
            SentPktState::Flighting(n) => {
                *self = SentPktState::Lost(n);
                n as usize
            }
            SentPktState::Acked(_) => 0,
            SentPktState::Lost(_) => 0,
        }
    }
}

/// 记录已经发送的帧，尽最大努力省略内存分配。
/// queue记录着所有发送过的帧，records记录着顺序发送的数据包包含几个帧，以及这些数据包的状态。
/// 发送数据包的时候，往其中写入数据包的帧，
/// 接收到确认的时候，更新数据包的状态，被确认就什么都不做；丢失的数据包，得重新发送
#[derive(Debug, Default)]
struct RawSentPktRecords {
    queue: VecDeque<SentRecord>,
    // 记录着每个包的内容，其实是一个数字，该数字对应着queue中的record数量
    records: IndexDeque<SentPktState, VARINT_MAX>,
    largest_acked_pktno: u64,
}

impl RawSentPktRecords {
    fn record_reliable_frame(&mut self, frame: ReliableFrame) {
        self.queue.push_back(SentRecord::Reliable(frame));
    }

    fn record_data_frame(&mut self, frame: DataFrame) {
        self.queue.push_back(SentRecord::Data(frame));
    }

    fn record_ack_frame(&mut self, frame: AckFrame) {
        self.queue.push_back(SentRecord::Ack(frame.into()));
    }

    fn on_pkt_acked(&mut self, pn: u64) -> impl Iterator<Item = SentRecord> + '_ {
        let mut len = 0;
        let offset = self
            .records
            .iter_with_idx()
            .take_while(|(pkt_idx, _)| *pkt_idx < pn)
            .map(|(_, s)| s.nframes())
            .sum::<usize>();
        if let Some(s) = self.records.get_mut(pn) {
            len = s.be_acked();
        }
        self.queue
            .range_mut(offset..offset + len)
            .map(|f| f.clone())
    }

    fn may_loss_pkt(&mut self, pn: u64) -> impl Iterator<Item = SentRecord> + '_ {
        let mut len = 0;
        let offset = self
            .records
            .iter_with_idx()
            .take_while(|(pkt_idx, _)| *pkt_idx < pn)
            .map(|(_, s)| s.nframes())
            .sum::<usize>();
        if let Some(s) = self.records.get_mut(pn) {
            len = s.maybe_loss();
        }
        self.queue
            .range_mut(offset..offset + len)
            .map(|f| f.clone())
    }

    fn auto_drain(&mut self) {
        let (n, f) = self
            .records
            .iter()
            .filter(|s| !matches!(s, SentPktState::Flighting(_)))
            .fold((0usize, 0usize), |(n, f), s| (n + 1, f + s.nframes()));
        self.records.advance(n);
        let _ = self.queue.drain(..f);
    }
}

#[derive(Debug, Default, Clone)]
pub struct ArcSentPktRecords(Arc<Mutex<RawSentPktRecords>>);

impl ArcSentPktRecords {
    pub fn receive(&self) -> RecvGuard {
        RecvGuard {
            inner: self.0.lock().unwrap(),
        }
    }

    pub fn send(&self) -> SendGuard {
        let inner = self.0.lock().unwrap();
        let origin_len = inner.queue.len();
        SendGuard { origin_len, inner }
    }
}

pub struct RecvGuard<'a> {
    inner: MutexGuard<'a, RawSentPktRecords>,
}

impl RecvGuard<'_> {
    pub fn update_largest(&mut self, largest: u64) {
        if largest > self.inner.largest_acked_pktno {
            self.inner.largest_acked_pktno = largest;
        }
    }

    pub fn on_pkt_acked(&mut self, pn: u64) -> impl Iterator<Item = SentRecord> + '_ {
        self.inner.on_pkt_acked(pn)
    }

    pub fn may_loss_pkt(&mut self, pn: u64) -> impl Iterator<Item = SentRecord> + '_ {
        self.inner.may_loss_pkt(pn)
    }
}

impl Drop for RecvGuard<'_> {
    fn drop(&mut self) {
        self.inner.auto_drain();
    }
}

pub struct SendGuard<'a> {
    origin_len: usize,
    inner: MutexGuard<'a, RawSentPktRecords>,
}

impl SendGuard<'_> {
    pub fn next_pn(&self) -> (u64, PacketNumber) {
        let pn = self.inner.records.largest();
        let encoded_pn = PacketNumber::encode(pn, self.inner.largest_acked_pktno);
        (pn, encoded_pn)
    }

    pub fn record_reliable_frame(&mut self, frame: ReliableFrame) {
        self.inner.record_reliable_frame(frame);
    }

    pub fn record_data_frame(&mut self, frame: DataFrame) {
        self.inner.record_data_frame(frame);
    }

    pub fn record_ack_frame(&mut self, frame: AckFrame) {
        self.inner.record_ack_frame(frame);
    }
}

impl Drop for SendGuard<'_> {
    fn drop(&mut self) {
        let nframes = self.inner.queue.len() - self.origin_len;
        self.inner
            .records
            .push_back(SentPktState::Flighting(nframes as u16))
            .expect("packet number never overflow");
    }
}
