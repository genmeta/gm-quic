//! The reliable transmission for frames.
use std::{
    collections::VecDeque,
    ops::Deref,
    sync::{Arc, Mutex, MutexGuard},
};

use bytes::BufMut;
use enum_dispatch::enum_dispatch;
use qbase::{
    frame::{io::WriteFrame, BeFrame, CryptoFrame, ReliableFrame, SendFrame, StreamFrame},
    packet::MarshalFrame,
};

/// The kind of frame which guaratend to be received by peer.
///
/// The bundle of [`StreamFrame`], [`CryptoFrame`] and [`ReliableFrame`].
#[derive(Debug, Clone, Eq, PartialEq)]
#[enum_dispatch(BeFrame)]
pub enum GuaranteedFrame {
    Stream(StreamFrame),
    Crypto(CryptoFrame),
    Reliable(ReliableFrame),
}

/// A deque for data space to send reliable frames.
///
/// Like its name, it is just a queue. [`DataStreams`] or other components that need to send reliable
/// frames write frames to this queue by calling [`SendFrame::send_frame`]. The transport layer can
/// read the frames in the queue and encode them into the send buffer by calling [`try_read`].
///
/// # Example
/// ```rust
/// use qbase::frame::{HandshakeDoneFrame, SendFrame};
/// use qrecovery::reliable::ArcReliableFrameDeque;
///
/// let mut reliable_frame_deque = ArcReliableFrameDeque::with_capacity(10);
/// reliable_frame_deque.send_frame([HandshakeDoneFrame]);
/// ```
///
/// [`try_read`]: ArcReliableFrameDeque::try_read
/// [`DataStreams`]: crate::streams::DataStreams
#[derive(Debug, Default, Clone)]
pub struct ArcReliableFrameDeque(Arc<Mutex<VecDeque<ReliableFrame>>>);

impl ArcReliableFrameDeque {
    /// Create a new empty deque with at least the specified capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Arc::new(Mutex::new(VecDeque::with_capacity(capacity))))
    }

    fn lock_guard(&self) -> MutexGuard<'_, VecDeque<ReliableFrame>> {
        self.0.lock().unwrap()
    }

    /// Try to read the frame in deque and encode it into the `buf`.
    ///
    /// If the remaining bytes of `buf` is not enough to encode the frame, or there are no frame
    /// in the deque, this method will return [`None`], the `buf` will not be changed.
    ///
    /// If the read success, the frame and the number of bytes written will be return.
    pub fn try_read(&self, mut buf: &mut [u8]) -> Option<(ReliableFrame, usize)> {
        let mut deque = self.0.lock().unwrap();
        let frame = deque.front()?;
        if frame.max_encoding_size() <= buf.len() || frame.encoding_size() <= buf.len() {
            let buf_len = buf.len();
            buf.put_frame(frame);
            Some((deque.pop_front().unwrap(), buf_len - buf.len()))
        } else {
            None
        }
    }

    pub fn try_load_frames_into<B, P>(&self, packet: &mut P)
    where
        B: BufMut,
        P: Deref<Target = B> + MarshalFrame<ReliableFrame>,
    {
        let mut deque = self.0.lock().unwrap();
        while let Some(frame) = deque.front() {
            if frame.max_encoding_size() > packet.remaining_mut()
                && frame.encoding_size() > packet.remaining_mut()
            {
                return;
            }
            packet.dump_frame(deque.pop_front().unwrap());
        }
    }
}

impl<T> SendFrame<T> for ArcReliableFrameDeque
where
    T: Into<ReliableFrame>,
{
    fn send_frame<I: IntoIterator<Item = T>>(&self, iter: I) {
        self.lock_guard().extend(iter.into_iter().map(Into::into));
    }
}
