//! The reliable transmission for frames.
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, MutexGuard},
};

use qbase::{
    frame::{EncodeSize, FrameFeature, SendFrame},
    net::tx::{ArcSendWakers, Signals},
    packet::Package,
};

/// A deque for data space to send reliable frames.
///
/// Like its name, it is just a queue. [`DataStreams`] or other components that need to send reliable
/// frames write frames to this queue by calling [`SendFrame::send_frame`]. The transport layer can
/// load the frames from the queue into the packet by calling [`try_load_frames_into`].
///
/// # Example
/// ```rust, no_run
/// use qbase::frame::{HandshakeDoneFrame, SendFrame, ReliableFrame};
/// use qrecovery::reliable::ArcReliableFrameDeque;
/// # let data_wakers = Default::default();
/// let mut reliable_frame_deque = ArcReliableFrameDeque::<ReliableFrame>::with_capacity_and_wakers(10, data_wakers);
/// reliable_frame_deque.send_frame([HandshakeDoneFrame]);
/// ```
///
/// [`DataStreams`]: crate::streams::DataStreams
/// [`try_load_frames_into`]: ArcReliableFrameDeque::try_load_frames_into
#[derive(Debug, Default)]
pub struct ArcReliableFrameDeque<F> {
    frames: Arc<Mutex<VecDeque<F>>>,
    tx_wakers: ArcSendWakers,
}

impl<F> Clone for ArcReliableFrameDeque<F> {
    fn clone(&self) -> Self {
        Self {
            frames: self.frames.clone(),
            tx_wakers: self.tx_wakers.clone(),
        }
    }
}

impl<F> ArcReliableFrameDeque<F> {
    /// Create a new empty deque with at least the specified capacity.
    pub fn with_capacity_and_wakers(capacity: usize, tx_wakers: ArcSendWakers) -> Self {
        Self {
            frames: Arc::new(Mutex::new(VecDeque::with_capacity(capacity))),
            tx_wakers,
        }
    }

    fn frames_guard(&self) -> MutexGuard<'_, VecDeque<F>> {
        self.frames.lock().unwrap()
    }

    /// Try to load the frame in deque and encode it into the `packet`.
    pub fn try_load_frames_into<P: ?Sized>(&self, packet: &mut P) -> Result<(), Signals>
    where
        for<'a> &'a F: Package<P>,
    {
        let mut deque = self.frames_guard();
        if deque.is_empty() {
            return Err(Signals::TRANSPORT);
        }
        while let Some(mut frame) = deque.front() {
            frame.dump(packet)?;
            deque.pop_front();
        }
        Ok(())
    }
}

impl<F, P: ?Sized> Package<P> for ArcReliableFrameDeque<F>
where
    for<'a> &'a F: Package<P>,
{
    fn dump(&mut self, packet: &mut P) -> Result<(), Signals> {
        self.try_load_frames_into(packet)
    }
}

impl<T, F> SendFrame<T> for ArcReliableFrameDeque<F>
where
    F: EncodeSize + FrameFeature,
    T: Into<F>,
{
    fn send_frame<I: IntoIterator<Item = T>>(&self, iter: I) {
        self.tx_wakers.wake_all_by(Signals::TRANSPORT);
        self.frames_guard().extend(iter.into_iter().map(Into::into));
    }
}
