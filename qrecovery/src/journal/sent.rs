use std::{
    collections::VecDeque,
    ops::DerefMut,
    sync::{Arc, Mutex, MutexGuard},
};

use deref_derive::{Deref, DerefMut};
use qbase::{
    error::{Error, ErrorKind},
    frame::{AckFrame, BeFrame},
    packet::PacketNumber,
    util::IndexDeque,
    varint::VARINT_MAX,
};

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
#[derive(Debug, Default, Deref, DerefMut)]
struct SentJournal<T> {
    #[deref]
    queue: VecDeque<T>,
    // 记录着每个包的内容，其实是一个数字，该数字对应着queue中的record数量
    records: IndexDeque<SentPktState, VARINT_MAX>,
    largest_acked_pktno: u64,
}

impl<T: Clone> SentJournal<T> {
    fn on_pkt_acked(&mut self, pn: u64) -> impl Iterator<Item = T> + '_ {
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

    fn may_loss_pkt(&mut self, pn: u64) -> impl Iterator<Item = T> + '_ {
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
}

impl<T> SentJournal<T> {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            queue: VecDeque::with_capacity(capacity * 4),
            records: IndexDeque::with_capacity(capacity),
            largest_acked_pktno: 0,
        }
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

/// Records for sent packets and frames in them.
///
/// [`DataStreams`] need to be aware of frame acknowledgment or possible loss, and so does [`CryptoStream`].
/// This structure records some frames (type T) in each packet sent, and feeds back the frames in
/// these packets to [`DataStreams`] and [`CryptoStream`] when the packet is acknowledged or may be
/// lost.
///
/// The interfaces are on the [`NewPacketGuard`] structure and the [`RotateGuard`] structure, read their
/// documentation for more. This structure only provide the methods to create them.
///
/// If multiple tasks are recording at the same time, the recording will become confusing, so the
/// [`NewPacketGuard`] and the [`RotateGuard`] are designed to be `Guard`, which means that they hold a
/// [`MutexGuard`].
///
///
/// [`DataStreams`]: crate::streams::DataStreams
/// [`CryptoStream`]: crate::crypto::CryptoStream
#[derive(Debug, Default)]
pub struct ArcSentJournal<T>(Arc<Mutex<SentJournal<T>>>);

impl<T> Clone for ArcSentJournal<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> ArcSentJournal<T> {
    /// Create a new empty records with the given `capatity`.
    ///
    /// The number of records can exceed the `capacity` specified at creation time, but the internel
    /// implementation strvies to avoid reallocation.
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Arc::new(Mutex::new(SentJournal::with_capacity(capacity))))
    }

    /// Return a [`RotateGuard`] to resolve the ack frame from peer.
    pub fn rotate(&self) -> RotateGuard<'_, T> {
        RotateGuard {
            inner: self.0.lock().unwrap(),
        }
    }

    /// Return a [`NewPacketGuard`] to get the next pn and record frames in the packet.
    pub fn new_packet(&self) -> NewPacketGuard<'_, T> {
        let inner = self.0.lock().unwrap();
        let origin_len = inner.queue.len();
        NewPacketGuard {
            necessary: false,
            origin_len,
            inner,
        }
    }
}

/// Handle the peer's ack frame and feed back the frames in the acknowledged or possibly lost packets to other components.
pub struct RotateGuard<'a, T> {
    inner: MutexGuard<'a, SentJournal<T>>,
}

impl<T: Clone> RotateGuard<'_, T> {
    /// Handle the [`Largest Acknowledged`] field of the ack frame from peer.
    ///
    /// [`Largest Acknowleged`]: https://www.rfc-editor.org/rfc/rfc9000.html#name-ack-frames
    pub fn update_largest(&mut self, f: &AckFrame) -> Result<(), Error> {
        if f.largest > self.largest_pn() {
            return Err(Error::new(
                ErrorKind::ProtocolViolation,
                f.frame_type(),
                "ack frame largest pn is larger than the largest pn sent",
            ));
        }
        if f.largest > self.inner.largest_acked_pktno {
            self.inner.largest_acked_pktno = f.largest.into_inner();
        }
        Ok(())
    }

    /// Called when the packet sent is acked by peer, return the frames in that packet.
    pub fn on_pkt_acked(&mut self, pn: u64) -> impl Iterator<Item = T> + '_ {
        self.inner.on_pkt_acked(pn)
    }

    /// Called when the packet sent may lost, reutrn the frames in that packet.
    pub fn may_loss_pkt(&mut self, pn: u64) -> impl Iterator<Item = T> + '_ {
        self.inner.may_loss_pkt(pn)
    }

    /// Return the packet number of the last packet sent(the largest packet number).
    pub fn largest_pn(&self) -> u64 {
        self.inner.records.largest()
    }
}

impl<T> Drop for RotateGuard<'_, T> {
    fn drop(&mut self) {
        self.inner.auto_drain();
    }
}

/// Provide the [encoded] packet number to assemble a packet, and record the frames in packet which
/// will be send.
///
/// One [`NewPacketGuard`] correspond to a packet.
///
/// Even if the next packet number is obtained, the packet may not be sent out. If the packet is not
/// sent out, the packet number will not be consumed.
///
/// Call [`NewPacketGuard::record_trivial`] or [`NewPacketGuard::record_frame`] means that the packet will be
/// correspond to this [`NewPacketGuard`] will be sent, and the packet number will be consumed when the
/// [`NewPacketGuard`] dropped.
///
/// [encoded]: https://www.rfc-editor.org/rfc/rfc9000.html#name-sample-packet-number-encodi
#[derive(Debug)]
pub struct NewPacketGuard<'a, T> {
    necessary: bool,
    origin_len: usize,
    inner: MutexGuard<'a, SentJournal<T>>,
}

impl<T> NewPacketGuard<'_, T> {
    /// Provide a packet number and its [encoded] form to assemble a packet.
    ///
    /// Call this method multipes on the same [`NewPacketGuard`] will result the same pn.
    ///
    /// [encoded]: https://www.rfc-editor.org/rfc/rfc9000.html#name-sample-packet-number-encodi
    pub fn pn(&self) -> (u64, PacketNumber) {
        let pn = self.inner.records.largest();
        // TODO: peer可能给出一个错误的ACK，令这里发生下溢
        let encoded_pn = PacketNumber::encode(pn, self.inner.largest_acked_pktno);
        (pn, encoded_pn)
    }

    /// Records trivial frames that do not need retransmission, such as Padding, Ping, and Ack.
    /// However, this packet does occupy a packet number. Even if no other reliable frames are sent,
    /// it still needs to be recorded, with the number of reliable frames in this packet being 0.
    pub fn record_trivial(&mut self) {
        self.necessary = true;
    }

    /// Records a frame in the packet being sent.
    ///
    /// Once this method or [`NewPacketGuard::record_trivial`] called, the packet number will be consumed.
    ///
    /// When the packet is acked, or may loss, the frames in packet will been fed back to the
    /// components which sent them.
    pub fn record_frame(&mut self, frame: T) {
        self.inner.deref_mut().push_back(frame);
    }
}

impl<T> Drop for NewPacketGuard<'_, T> {
    fn drop(&mut self) {
        let nframes = self.inner.queue.len() - self.origin_len;
        if self.necessary || nframes > 0 {
            self.inner
                .records
                .push_back(SentPktState::Flighting(nframes as u16))
                .expect("packet number never overflow");
        }
    }
}
