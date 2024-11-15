//! The reliable transmission for frames.
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, MutexGuard},
};

use enum_dispatch::enum_dispatch;
use qbase::frame::{io::WriteFrame, BeFrame, CryptoFrame, ReliableFrame, SendFrame, StreamFrame};

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
    /// If the read success, the frame read be return.
    pub fn try_read(&self, buf: &mut impl WriteFrame<ReliableFrame>) -> Option<ReliableFrame> {
        let mut deque = self.0.lock().unwrap();
        let frame = deque.front()?;
        let buf_size = buf.remaining_mut();
        if frame.max_encoding_size() <= buf_size || frame.encoding_size() <= buf_size {
            buf.put_frame(frame);
            Some(deque.pop_front().unwrap())
        } else {
            None
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
