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
    frame::{DataBlockedFrame, MaxDataFrame},
    varint::VarInt,
};

/// All data sent in STREAM frames counts toward this limit.
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

    fn recv_max_data_frame(&mut self, frame: &MaxDataFrame) {
        let max_data = frame.max_data.into_inner();
        if max_data > self.max_data {
            self.max_data = max_data;
            for waker in self.wakers.drain(..) {
                waker.wake();
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct ArcSendControler(Arc<Mutex<Result<RawSendControler, QuicError>>>);

impl ArcSendControler {
    /// Creates a new `SendControler` with the specified initial maximum data.
    ///
    /// `initial_max_data` should be known to each other after the handshake is
    /// completed. If sending data in 0RTT space, `initial_max_data` should be
    /// the value from the previous connection.
    ///
    /// `initial_max_data` is allowed to be 0, which is reasonable when creating a
    /// connection without knowing the peer's setting.
    pub fn with_initial(initial_max_data: u64) -> Self {
        Self(Arc::new(Mutex::new(Ok(RawSendControler::with_initial(
            initial_max_data,
        )))))
    }

    /// Increasing Flow Control Limits by receiving a MAX_DATA frame from peer.
    pub fn recv_max_data_frame(&self, frame: &MaxDataFrame) {
        let mut guard = self.0.lock().unwrap();
        if let Ok(send_ctrl) = guard.deref_mut() {
            send_ctrl.recv_max_data_frame(frame);
        }
    }

    /// For external listening, whether it is blocked.
    /// If so, a DataBlockedFrame needs to be sent to the other party.
    pub fn would_block(&self) -> WouldBlock {
        WouldBlock(self.clone())
    }

    /// Apply for sending data. If it has meet error, it will return Err directly.
    pub fn credit(&self) -> Result<Credit<'_>, QuicError> {
        let guard = self.0.lock().unwrap();
        if let Err(e) = guard.deref() {
            return Err(e.clone());
        }
        Ok(Credit(guard))
    }

    /// Only when new data needs to be sent but is restricted by flow control, the send
    /// task will be registered on the flow control. When the flow control is 0, it may
    /// not require to register the send task on the flow control, as there may still be
    /// retransmission data that can be sent.
    pub fn register_waker(&self, waker: Waker) {
        let mut guard = self.0.lock().unwrap();
        if let Ok(inner) = guard.deref_mut() {
            inner.register_waker(waker);
        }
    }

    /// Flow control can only be terminated if the connection encounters an error
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

pub struct WouldBlock(ArcSendControler);

impl Future for WouldBlock {
    type Output = Result<DataBlockedFrame, QuicError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut guard = self.0 .0.lock().unwrap();
        match guard.deref_mut() {
            Ok(inner) => inner.poll_would_block(cx),
            Err(e) => Poll::Ready(Err(e.clone())),
        }
    }
}

/// Represents the credit for sending data.
pub struct Credit<'a>(MutexGuard<'a, Result<RawSendControler, QuicError>>);

impl Credit<'_> {
    /// Return the available amount of data that can be sent.
    pub fn available(&self) -> usize {
        match self.0.deref() {
            Ok(inner) => (inner.max_data - inner.total_sent) as usize,
            Err(_) => unreachable!(),
        }
    }

    /// Updates the amount of data sent.
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

/// Represents an overflow error when the flow control limit is exceeded.
#[derive(Debug, Clone, Copy, Error)]
#[error("Flow Control exceed {0} bytes on receiving")]
pub struct Overflow(usize);

/// Receiver flow controller for managing the flow of incoming data packets.
#[derive(Debug, Default)]
struct RecvController {
    total_rcvd: AtomicU64,
    max_data: AtomicU64,
    step: u64,
    is_closed: AtomicBool,
    waker: AtomicWaker,
}

impl RecvController {
    /// Creates a new `RecvController` with the specified initial maximum data.
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

    /// Closes the receiver.
    fn on_error(&self) {
        if !self.is_closed.swap(true, Ordering::Release) {
            // Call wake() precisely once to prevent unnecessary wake-ups caused by multiple close calls.
            self.waker.wake();
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct ArcRecvController(Arc<RecvController>);

impl ArcRecvController {
    /// Creates a new `ArcRecvController` with the specified initial maximum data.
    pub fn with_initial(initial_max_data: u64) -> Self {
        Self(Arc::new(RecvController::with_initial(initial_max_data)))
    }

    /// Handles the event when new data is received.
    pub fn on_new_rcvd(&self, amount: usize) -> Result<usize, Overflow> {
        self.0.on_new_rcvd(amount)
    }

    /// Polls for an increase in the receive window limit.
    pub fn incr_limit(&self) -> IncrLimit {
        IncrLimit(self.0.clone())
    }

    /// Closes the receiver if connection meets error.
    pub fn on_error(&self) {
        self.0.on_error();
    }
}

pub struct IncrLimit(Arc<RecvController>);

impl Future for IncrLimit {
    type Output = Option<MaxDataFrame>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.poll_incr_limit(cx)
    }
}

/// Represents a flow controller for managing the flow of data.
#[derive(Debug, Clone)]
pub struct FlowController {
    sender: ArcSendControler,
    recver: ArcRecvController,
}

impl FlowController {
    /// Creates a new `FlowController` with the specified initial send and receive window sizes.
    pub fn with_initial(peer_initial_max_data: u64, local_initial_max_data: u64) -> Self {
        Self {
            sender: ArcSendControler::with_initial(peer_initial_max_data),
            recver: ArcRecvController::with_initial(local_initial_max_data),
        }
    }

    pub fn sender(&self) -> &ArcSendControler {
        &self.sender
    }

    pub fn recver(&self) -> &ArcRecvController {
        &self.recver
    }
}
