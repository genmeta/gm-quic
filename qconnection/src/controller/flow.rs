use std::{
    ops::Deref,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, MutexGuard,
    },
    task::{Context, Poll, Waker},
};

use futures::{task::AtomicWaker, Future};
use qbase::varint::VARINT_MAX;
use thiserror::Error;

/// All data sent in STREAM frames counts toward this limit.
#[derive(Debug, Default)]
struct RawSendControler {
    total_sent: u64,
    max_data: u64,
    wakers: Vec<Waker>,
}

impl RawSendControler {
    fn with_initial(initial_max_data: u64) -> Self {
        Self {
            total_sent: 0,
            max_data: initial_max_data,
            wakers: Vec::with_capacity(4),
        }
    }

    fn permit(&mut self, max_data: u64) {
        debug_assert!(max_data <= VARINT_MAX);
        // the new max_data != previous self.max_data, meaning fetch_max update successfully
        if max_data != self.max_data {
            for waker in self.wakers.drain(..) {
                waker.wake();
            }
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ArcSendControler(Arc<Mutex<RawSendControler>>);

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
        Self(Arc::new(Mutex::new(RawSendControler::with_initial(
            initial_max_data,
        ))))
    }

    /// Increasing Flow Control Limits by receiving a MAX_DATA frame from peer.
    pub fn permit(&self, max_data: u64) {
        self.0.lock().unwrap().permit(max_data);
    }

    /// Apply for sending data.
    ///
    /// # Returns
    ///
    /// - If there is sufficient flow control, return `Credit` indicating the maximum
    ///   amount of data the sender can send. When calling `apply` without calling
    ///   `Credit::post_sent` or dropping `Credit`, `apply` cannot be called again.
    /// - If there is insufficient flow control, return `Err`, and the sender needs to
    ///   call `notify.notified().await` to wait.
    pub fn poll_apply(&self, cx: &mut Context<'_>) -> Poll<Credit<'_>> {
        let mut guard = self.0.lock().unwrap();
        if guard.max_data > guard.total_sent {
            Poll::Ready(Credit {
                amount: (guard.max_data - guard.total_sent) as usize,
                guard,
            })
        } else {
            guard.wakers.push(cx.waker().clone());
            Poll::Pending
        }
    }
}

/// Represents the credit for sending data.
pub struct Credit<'a> {
    amount: usize,
    guard: MutexGuard<'a, RawSendControler>,
}

impl Credit<'_> {
    /// Returns the available amount of data that can be sent.
    pub fn available(&self) -> usize {
        self.amount
    }

    /// Updates the amount of data sent.
    pub fn post_sent(mut self, amount: usize) {
        debug_assert!(amount <= self.amount);
        self.guard.total_sent += amount as u64;
    }
}

/// Represents an overflow error when the flow control limit is exceeded.
#[derive(Debug, Clone, Copy, Error)]
#[error("Flow Control exceed {0} bytes on receiving")]
pub struct Overflow(usize);

/// Receiver flow controller for managing the flow of incoming data packets.
#[derive(Debug, Default)]
pub struct RecvController {
    total_rcvd: AtomicU64,
    max_data: AtomicU64,
    step: u64,
    is_closed: AtomicBool,
    waker: AtomicWaker,
}

impl RecvController {
    /// Creates a new `RecvController` with the specified initial maximum data.
    pub fn with_initial(initial_max_data: u64) -> Self {
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
    pub fn on_new_rcvd(&self, amount: usize) -> Result<usize, Overflow> {
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
    ///
    /// # Returns
    ///
    /// - `Poll::Ready(Some(limit))` if an increase in the receive window limit is available.
    /// - `Poll::Ready(None)` if the receiver is closed and no further increase is possible.
    /// - `Poll::Pending` if an increase in the receive window limit is not yet available.
    pub fn poll_incr_limit(&self, cx: &mut Context<'_>) -> Poll<Option<u64>> {
        if self.is_closed.load(Ordering::Acquire) {
            Poll::Ready(None)
        } else {
            let max_data = self.max_data.load(Ordering::Acquire);
            let total_rcvd = self.total_rcvd.load(Ordering::Acquire);

            if total_rcvd + self.step >= max_data {
                self.max_data.fetch_add(self.step, Ordering::Release);
                Poll::Ready(Some(max_data + self.step))
            } else {
                self.waker.register(cx.waker());
                Poll::Pending
            }
        }
    }

    /// Closes the receiver.
    pub fn close(&self) {
        if !self.is_closed.swap(true, Ordering::Release) {
            // Call wake() precisely once to prevent unnecessary wake-ups caused by multiple close calls.
            self.waker.wake();
        }
    }
}

/// Represents a flow controller for managing the flow of data.
#[derive(Debug, Default)]
pub struct FlowController {
    pub sender: ArcSendControler,
    pub recver: RecvController,
}

impl FlowController {
    /// Creates a new `FlowController` with the specified initial send and receive window sizes.
    fn with_initial(peer_initial_max_data: u64, local_initial_max_data: u64) -> Self {
        Self {
            sender: ArcSendControler::with_initial(peer_initial_max_data),
            recver: RecvController::with_initial(local_initial_max_data),
        }
    }
}

/// A sendable and receivable shared connection-level flow controller.
#[derive(Debug, Default, Clone)]
pub struct ArcFlowController(Arc<FlowController>);

impl ArcFlowController {
    /// Creates a new `ArcFlowController` with the specified initial send and receive window sizes.
    pub fn with_initial(peer_initial_max_data: u64, local_initial_max_data: u64) -> Self {
        Self(Arc::new(FlowController::with_initial(
            peer_initial_max_data,
            local_initial_max_data,
        )))
    }
}

impl Deref for ArcFlowController {
    type Target = FlowController;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ArcFlowController {
    /// Asynchronously waits for an increase in the receive window limit.
    pub fn incr_limit(&self) -> IncrLimit {
        IncrLimit(self.clone())
    }
}

pub struct IncrLimit(ArcFlowController);

impl Future for IncrLimit {
    type Output = Option<u64>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.recver.poll_incr_limit(cx)
    }
}
