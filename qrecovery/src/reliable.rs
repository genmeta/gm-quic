//! The reliable transmission for frames.
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, MutexGuard},
};

use bytes::BufMut;
use enum_dispatch::enum_dispatch;
use qbase::{
    frame::{BeFrame, CryptoFrame, ReliableFrame, SendFrame, StreamFrame},
    net::{DataWakers, SendLimiter},
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
/// ```rust, no_run
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
pub struct ArcReliableFrameDeque {
    frames: Arc<Mutex<VecDeque<ReliableFrame>>>,
    wakers: DataWakers,
}

impl ArcReliableFrameDeque {
    /// Create a new empty deque with at least the specified capacity.
    pub fn with_capacity_and_wakers(capacity: usize, wakers: DataWakers) -> Self {
        Self {
            frames: Arc::new(Mutex::new(VecDeque::with_capacity(capacity))),
            wakers,
        }
    }

    fn frames_guard(&self) -> MutexGuard<'_, VecDeque<ReliableFrame>> {
        self.frames.lock().unwrap()
    }

    /// Try to load the frame in deque and encode it into the `packet`.
    pub fn try_load_frames_into<P>(&self, packet: &mut P) -> Result<(), SendLimiter>
    where
        P: BufMut + MarshalFrame<ReliableFrame>,
    {
        let mut deque = self.frames_guard();
        if deque.is_empty() {
            return Err(SendLimiter::NO_UNLIMITED_DATA);
        }
        while let Some(frame) = deque.front() {
            if frame.max_encoding_size() > packet.remaining_mut()
                && frame.encoding_size() > packet.remaining_mut()
            {
                return Err(SendLimiter::BUFFER_TOO_SMALL);
            }
            packet.dump_frame(deque.pop_front().unwrap());
        }
        Ok(())
    }
}

impl<T> SendFrame<T> for ArcReliableFrameDeque
where
    T: Into<ReliableFrame>,
{
    fn send_frame<I: IntoIterator<Item = T>>(&self, iter: I) {
        self.wakers.wake_all();
        self.frames_guard().extend(iter.into_iter().map(Into::into));
    }
}
