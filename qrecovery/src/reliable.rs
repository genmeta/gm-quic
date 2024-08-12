use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, MutexGuard},
};

use deref_derive::{Deref, DerefMut};
use enum_dispatch::enum_dispatch;
use qbase::frame::{io::WriteFrame, BeFrame, CryptoFrame, ReliableFrame, StreamFrame};

pub mod rcvdpkt;
pub mod sentpkt;

#[derive(Debug, Clone, Eq, PartialEq)]
#[enum_dispatch(BeFrame)]
pub enum GuaranteedFrame {
    Stream(StreamFrame),
    Crypto(CryptoFrame),
    Reliable(ReliableFrame),
}

#[derive(Debug, Default, Deref, DerefMut)]
pub struct RawReliableFrameDeque(VecDeque<ReliableFrame>);

impl RawReliableFrameDeque {
    fn with_capacity(capacity: usize) -> Self {
        Self(VecDeque::with_capacity(capacity))
    }

    fn try_read(&mut self, mut buf: &mut [u8]) -> Option<(ReliableFrame, usize)> {
        let frame = self.0.front()?;
        if frame.max_encoding_size() <= buf.len() || frame.encoding_size() <= buf.len() {
            let buf_len = buf.len();
            buf.put_frame(frame);
            Some((self.0.pop_front().unwrap(), buf_len - buf.len()))
        } else {
            None
        }
    }
}

impl<T> Extend<T> for RawReliableFrameDeque
where
    T: Into<ReliableFrame>,
{
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        self.0.extend(iter.into_iter().map(Into::into));
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
/// reliable_frame_deque.extend([HandshakeDoneFrame]);
///
/// let reliable_frame_deque = ArcReliableFrameDeque::with_capacity(10);
/// reliable_frame_deque.lock_guard().extend([HandshakeDoneFrame]);
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

    pub fn try_read(&self, buf: &mut [u8]) -> Option<(ReliableFrame, usize)> {
        self.lock_guard().try_read(buf)
    }
}

impl<T> Extend<T> for ArcReliableFrameDeque
where
    T: Into<ReliableFrame>,
{
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        self.lock_guard().extend(iter);
    }
}

#[cfg(test)]
mod tests {}
