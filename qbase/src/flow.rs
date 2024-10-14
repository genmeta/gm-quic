use std::{
    ops::{Deref, DerefMut},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, MutexGuard,
    },
    task::{Context, Poll, Waker},
};

use futures::{task::AtomicWaker, Future};
use thiserror::Error;

use crate::{
    error::Error as QuicError,
    frame::{DataBlockedFrame, MaxDataFrame, ReceiveFrame},
    varint::VarInt,
};

/// Connection-level global Stream Flow Control in the sending direction,
/// regulated by the peer's `initial_max_data` transport parameter
/// and updated by the [`MaxDataFrame`] sent by the peer.
///
/// Private controler in [`ArcSendControler`].
#[derive(Debug, Default)]
struct RawSendControler {
    total_sent: u64,
    max_data: u64,
    blocked_waker: Option<Waker>,
    wakers: Vec<Waker>,
}

impl RawSendControler {
    fn with_initial(initial_max_data: u64) -> Self {
        Self {
            total_sent: 0,
            max_data: initial_max_data,
            blocked_waker: None,
            wakers: Vec::with_capacity(4),
        }
    }

    fn poll_would_block(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<DataBlockedFrame, QuicError>> {
        debug_assert!(self.total_sent <= self.max_data);
        if self.total_sent == self.max_data {
            Poll::Ready(Ok(DataBlockedFrame {
                limit: VarInt::from_u64(self.total_sent)
                    .expect("max_data of flow controller is very very hard to exceed 2^62 - 1"),
            }))
        } else {
            self.blocked_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    fn register_waker(&mut self, waker: Waker) {
        self.wakers.push(waker);
    }

    fn wake_all(&mut self) {
        if let Some(waker) = self.blocked_waker.take() {
            waker.wake();
        }
        for waker in self.wakers.drain(..) {
            waker.wake();
        }
    }

    fn increase_limit(&mut self, max_data: u64) {
        if max_data > self.max_data {
            self.max_data = max_data;
            for waker in self.wakers.drain(..) {
                waker.wake();
            }
        }
    }
}

/// Shared connection-level Stream Flow Control in the sending direction,
/// regulated by the peer's `initial_max_data` transport parameter
/// and updated by the [`MaxDataFrame`] received from the peer.
///
/// Only the new data sent in [`StreamFrame`](`crate::frame::StreamFrame`) counts toward this limit.
/// Retransmitted stream data does not count towards this limit.
///
/// When flow control is 0,
/// retransmitted stream data can still be sent,
/// but new data cannot be sent.
/// When the stream has no data to retransmit,
/// meaning all old data has been successfully acknowledged,
/// it is necessary to wait for the receiver's [`MaxDataFrame`]`
/// to increase the connection-level flow control limit.
///
/// To avoid having to pause sending tasks while waiting for the [`MaxDataFrame`],
/// the receiver should promptly send the [`MaxDataFrame`]
/// to increase the flow control limit,
/// ensuring that the sender always has enough space to send smoothly.
/// An extreme yet simple strategy is to set the flow control limit to infinity from the start,
/// causing the connection-level flow control to never reach its limit,
/// effectively rendering it useless.
#[derive(Clone, Debug)]
pub struct ArcSendControler(Arc<Mutex<Result<RawSendControler, QuicError>>>);

impl ArcSendControler {
    /// Creates a new [`ArcSendControler`] with `initial_max_data`.
    ///
    /// `initial_max_data` should be known to each other after the handshake is
    /// completed. If sending data in 0-RTT space, `initial_max_data` should be
    /// the value from the previous connection.
    ///
    /// `initial_max_data` is allowed to be 0, which is reasonable when creating a
    /// connection without knowing the peer's `iniitial_max_data` setting.
    pub fn with_initial(initial_max_data: u64) -> Self {
        Self(Arc::new(Mutex::new(Ok(RawSendControler::with_initial(
            initial_max_data,
        )))))
    }

    fn increase_limit(&self, max_data: u64) {
        let mut guard = self.0.lock().unwrap();
        if let Ok(inner) = guard.deref_mut() {
            inner.increase_limit(max_data);
        }
    }

    /// For external monitoring, whether it is blocked.
    /// If blocked, a [`DataBlockedFrame`] needs to be sent to the other party.
    pub fn would_block(&self) -> WouldBlock {
        WouldBlock(&self.0)
    }

    /// Return the available size of new data bytes that can be sent to peer.
    /// If some QUIC error occured, it would return the error directly.
    ///
    /// # Note
    ///
    /// After obtaining flow control,
    /// it is likely that new stream data will be sent subsequently,
    /// and then updating the flow control.
    /// During this process,
    /// other sending tasks must not modify the flow control simultaneously.
    /// Therefore, the flow controller in the period between obtaining flow control
    /// and finally updating(or maybe not) the flow control should be exclusive.
    pub fn credit(&self) -> Result<Credit<'_>, QuicError> {
        let guard = self.0.lock().unwrap();
        if let Err(e) = guard.deref() {
            return Err(e.clone());
        }
        Ok(Credit(guard))
    }

    /// Register a waker to be woken up when the flow control limit is increased.
    ///
    /// When flow control is 0,
    /// retransmitted stream data can still be sent,
    /// but new data cannot be sent.
    /// When the stream has no data to retransmit,
    /// meaning all old data has been successfully acknowledged.
    /// Meanwhile, it is necessary to register the waker
    /// waiting for the receiver's [`MaxDataFrame`]
    /// to increase the connection-level flow control limit.
    pub fn register_waker(&self, waker: Waker) {
        let mut guard = self.0.lock().unwrap();
        if let Ok(inner) = guard.deref_mut() {
            inner.register_waker(waker);
        }
    }

    /// Connection-level Stream Flow Control can only be terminated
    /// if the connection encounters an error
    pub fn on_error(&self, error: &QuicError) {
        let mut guard = self.0.lock().unwrap();
        if guard.deref().is_err() {
            return;
        }
        if let Ok(inner) = guard.deref_mut() {
            inner.wake_all();
        }
        *guard = Err(error.clone());
    }
}

/// [`ArcSendControler`] need to receive [`MaxDataFrame`] from peer
/// to increase flow control limit continuely.
impl ReceiveFrame<MaxDataFrame> for ArcSendControler {
    type Output = ();

    fn recv_frame(&self, frame: &MaxDataFrame) -> Result<Self::Output, QuicError> {
        self.increase_limit(frame.max_data.into_inner());
        Ok(())
    }
}

/// Represents a future that resolves when the flow control limit is reached.
/// At that time, a [`DataBlockedFrame`] needs to be sent to the peer.
pub struct WouldBlock<'sc>(&'sc Mutex<Result<RawSendControler, QuicError>>);

impl Future for WouldBlock<'_> {
    type Output = Result<DataBlockedFrame, QuicError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut guard = self.0.lock().unwrap();
        match guard.deref_mut() {
            Ok(inner) => inner.poll_would_block(cx),
            Err(e) => Poll::Ready(Err(e.clone())),
        }
    }
}

/// Exclusive access to the flow control limit.
///
/// As mentioned in the [`ArcSendControler::credit`] method,
/// the flow controller in the period between obtaining flow control
/// and finally updating(or maybe not) the flow control should be exclusive.
pub struct Credit<'a>(MutexGuard<'a, Result<RawSendControler, QuicError>>);

impl Credit<'_> {
    /// Return the available amount of new stream data that can be sent.
    pub fn available(&self) -> usize {
        match self.0.deref() {
            Ok(inner) => (inner.max_data - inner.total_sent) as usize,
            Err(_) => unreachable!(),
        }
    }

    /// Updates the amount of new data sent.
    pub fn post_sent(mut self, amount: usize) {
        match self.0.deref_mut() {
            Ok(inner) => {
                debug_assert!(inner.total_sent + amount as u64 <= inner.max_data);
                inner.total_sent += amount as u64;
                if inner.total_sent == inner.max_data {
                    if let Some(waker) = inner.blocked_waker.take() {
                        waker.wake();
                    }
                }
            }
            Err(_) => unreachable!(),
        }
    }
}

/// Overflow error, i.e. the flow control limit is exceeded while receiving.
/// See [`ErrorKind::FlowControl`](`crate::error::ErrorKind::FlowControl`).
#[derive(Debug, Clone, Copy, Error)]
#[error("Flow Control exceed {0} bytes on receiving")]
pub struct Overflow(usize);

/// Receiver's flow controller for managing the flow limit of incoming stream data.
#[derive(Debug, Default)]
struct RecvController {
    total_rcvd: AtomicU64,
    max_data: AtomicU64,
    step: u64,
    is_closed: AtomicBool,
    waker: AtomicWaker,
}

impl RecvController {
    /// Creates a new [`RecvController`] with the specified `initial_max_data`.
    fn with_initial(initial_max_data: u64) -> Self {
        Self {
            total_rcvd: AtomicU64::new(0),
            max_data: AtomicU64::new(initial_max_data),
            step: initial_max_data / 2,
            is_closed: AtomicBool::new(false),
            waker: AtomicWaker::new(),
        }
    }

    /// Handles the event when new data is received.
    ///
    /// The data must be new, old retransmitted data does not count. Whether the data is
    /// new or not will be determined by each stream after delivering the data packet to them.
    /// The amount of new data will be passed as the `amount` parameter.
    fn on_new_rcvd(&self, amount: usize) -> Result<usize, Overflow> {
        debug_assert!(!self.is_closed.load(Ordering::Relaxed));

        self.total_rcvd.fetch_add(amount as u64, Ordering::Release);
        let total_rcvd = self.total_rcvd.load(Ordering::Acquire);
        let max_data = self.max_data.load(Ordering::Acquire);
        if total_rcvd <= max_data {
            if total_rcvd + self.step >= max_data {
                self.waker.wake();
            }
            Ok(amount)
        } else {
            Err(Overflow((total_rcvd - max_data) as usize))
        }
    }

    /// Polls for an increase in the receive window limit.
    fn poll_incr_limit(&self, cx: &mut Context<'_>) -> Poll<Option<MaxDataFrame>> {
        if self.is_closed.load(Ordering::Acquire) {
            Poll::Ready(None)
        } else {
            let max_data = self.max_data.load(Ordering::Acquire);
            let total_rcvd = self.total_rcvd.load(Ordering::Acquire);

            if total_rcvd + self.step >= max_data {
                self.max_data.fetch_add(self.step, Ordering::Release);
                Poll::Ready(Some(MaxDataFrame {
                    max_data: VarInt::from_u64(self.max_data.load(Ordering::Acquire))
                        .expect("max_data of flow controller is very very hard to exceed 2^62 - 1"),
                }))
            } else {
                self.waker.register(cx.waker());
                Poll::Pending
            }
        }
    }

    /// Terminate the receiver's flow control.
    fn terminate(&self) {
        if !self.is_closed.swap(true, Ordering::Release) {
            // Call wake() precisely once to prevent unnecessary wake-ups caused by multiple close calls.
            self.waker.wake();
        }
    }
}

/// Shared receiver's flow controller for managing the incoming stream data flow.
///
/// Flow control on the receiving end,
/// primarily used to regulate the data flow sent by the sender.
/// Since the receive buffer is limited,
/// if the application layer cannot read the data in time,
/// the receive buffer will not expand, and the sender must be suspended.
///
/// The sender must never send new stream data exceeding
/// the flow control limit of the receiver advertised,
/// otherwise it will be considered a [`FlowControl`](`crate::error::ErrorKind::FlowControl`) error.
///
/// Additionally, the flow control on the receiving end also needs to
/// promptly send a [`MaxDataFrame`] to the sender after the application layer reads the data,
/// to expand the receive window since more receive buffer space is freed up,
/// and to inform the sender that more data can be sent.
#[derive(Debug, Default, Clone)]
pub struct ArcRecvController(Arc<RecvController>);

impl ArcRecvController {
    /// Creates a new [`ArcRecvController`] with local `initial_max_data` transport parameter.
    pub fn with_initial(initial_max_data: u64) -> Self {
        Self(Arc::new(RecvController::with_initial(initial_max_data)))
    }

    /// Updates the total received data size and checks if the flow control limit is exceeded
    /// when new stream data is received.
    ///
    /// As mentioned in [`ArcSendControler`], if the flow control limit is exceeded,
    /// an [`Overflow`] error will be returned.
    pub fn on_new_rcvd(&self, amount: usize) -> Result<usize, Overflow> {
        self.0.on_new_rcvd(amount)
    }

    /// Return a future that resolves when the receive window limit is increased.
    /// At that time, a [`MaxDataFrame`] needs to be sent to the sender.
    /// And this is a continuous monitoring process until the connection ends.
    pub fn incr_limit(&self) -> IncrLimit {
        IncrLimit(self.0.clone())
    }

    /// Terminate the receiver's flow control if QUIC connection error occurs.
    pub fn terminate(&self) {
        self.0.terminate();
    }
}

/// [`ArcRecvController`] need to receive [`DataBlockedFrame`] from peer.
///
/// However, the receiver may also not be able to immediately expand the receive window
/// and must wait for the application layer to read the data to free up more space
/// in the receive buffer.
impl ReceiveFrame<DataBlockedFrame> for ArcRecvController {
    type Output = ();

    fn recv_frame(&self, _frame: &DataBlockedFrame) -> Result<Self::Output, QuicError> {
        // Do nothing, just print a log
        Ok(())
    }
}

/// `IncrLimit` future resolves when the receive window limit is increased,
/// which is returned by [`ArcRecvController::incr_limit`].
///
/// At that time, a [`MaxDataFrame`] needs to be sent to the sender.
/// And this is a continuous monitoring process until the connection ends.
pub struct IncrLimit(Arc<RecvController>);

impl Future for IncrLimit {
    type Output = Option<MaxDataFrame>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.poll_incr_limit(cx)
    }
}

/// Connection-level flow controller, including an [`ArcSendControler`] as the sending side
/// and an [`ArcRecvController`] as the receiving side.
#[derive(Debug, Clone)]
pub struct FlowController {
    pub sender: ArcSendControler,
    pub recver: ArcRecvController,
}

impl FlowController {
    /// Creates a new `FlowController` with the specified initial send and receive window sizes.
    ///
    /// Unfortunately, at the beginning, the peer's `initial_max_data` is unknown.
    /// Therefore, peer's `initial_max_data` can be set to 0 initially,
    /// and then updated later after obtaining the peer's `initial_max_data` setting.
    pub fn with_parameter(peer_initial_max_data: u64, local_initial_max_data: u64) -> Self {
        Self {
            sender: ArcSendControler::with_initial(peer_initial_max_data),
            recver: ArcRecvController::with_initial(local_initial_max_data),
        }
    }

    /// Updates the initial send window size,
    /// which should be the peer's `initial_max_data` transport parameter.
    /// So once the peer's [`Parameters`](`crate::config::Parameters`) are obtained,
    /// this method should be called immediately.
    pub fn reset_send_window(&self, snd_wnd: u64) {
        self.sender.increase_limit(snd_wnd);
    }

    /// Returns the connection-level flow controller in the sending direction.
    pub fn sender(&self) -> ArcSendControler {
        self.sender.clone()
    }

    /// Returns the connection-level flow controller in the receiving direction.
    pub fn recver(&self) -> ArcRecvController {
        self.recver.clone()
    }

    /// Handles the error event of the QUIC connection.
    ///
    /// It will makes
    /// the connection-level stream flow controller in the sending direction become unavailable,
    /// and the connection-level stream flow controller in the receiving direction terminate.
    pub fn on_conn_error(&self, error: &QuicError) {
        self.sender.on_error(error);
        self.recver.terminate();
    }
}
