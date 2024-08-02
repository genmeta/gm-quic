use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, MutexGuard},
};

use deref_derive::{Deref, DerefMut};
use enum_dispatch::enum_dispatch;
use qbase::{
    frame::{DataFrame, ReliableFrame},
    util::Burst,
};

pub mod rcvdpkt;
pub mod sentpkt;

#[derive(Debug, Clone, Eq, PartialEq)]
#[enum_dispatch(BeFrame)]
pub enum GuaranteedFrame {
    Data(DataFrame),
    Reliable(ReliableFrame),
}

#[derive(Debug, Default, Deref, DerefMut)]
pub struct RawReliableFrameDeque(VecDeque<ReliableFrame>);

impl RawReliableFrameDeque {
    pub fn with_capacity(capacity: usize) -> Self {
        Self(VecDeque::with_capacity(capacity))
    }
}

impl<'a, T> Extend<&'a T> for RawReliableFrameDeque
where
    T: Into<ReliableFrame> + Clone,
{
    fn extend<I: IntoIterator<Item = &'a T>>(&mut self, iter: I) {
        self.0.extend(iter.into_iter().cloned().map(Into::into));
    }
}

/// 对于Initial和Handshake空间，仅需负责CryptoFrame的可靠传输；
/// 但CryptoFrame的可靠性由CryptoStream保证，因此不需要额外的可靠帧。
/// 对与Data空间，则需负责上述ReliableFrame的可靠传输
///
/// # Example
/// ```rust
/// use qbase::frame::HandshakeDoneFrame;
/// use qrecovery::reliable::ArcReliableFrameDeque;
///
/// let mut reliable_frame_deque = ArcReliableFrameDeque::with_capacity(10);
/// reliable_frame_deque.extend([&HandshakeDoneFrame]);
///
/// let reliable_frame_deque = ArcReliableFrameDeque::with_capacity(10);
/// reliable_frame_deque.lock_guard().extend([&HandshakeDoneFrame]);
/// ```
#[derive(Debug, Default, Clone)]
pub struct ArcReliableFrameDeque(Arc<Mutex<RawReliableFrameDeque>>);

impl ArcReliableFrameDeque {
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Arc::new(Mutex::new(RawReliableFrameDeque::with_capacity(
            capacity,
        ))))
    }

    pub fn lock_guard(&self) -> MutexGuard<'_, RawReliableFrameDeque> {
        self.0.lock().unwrap()
    }

    /// TODO: 写入可靠帧
    pub fn try_read(&self, burst: &mut Burst, buf: &mut [u8]) -> Option<(ReliableFrame, usize)> {
        todo!()
    }
}

impl<'a, T> Extend<&'a T> for ArcReliableFrameDeque
where
    T: Into<ReliableFrame> + Clone,
{
    /// 代价是，要对ArcReliableFrameDeque进行可变引用才行
    fn extend<I: IntoIterator<Item = &'a T>>(&mut self, iter: I) {
        self.lock_guard().extend(iter);
    }
}

#[cfg(test)]
mod tests {}
