use std::{
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

/// Therefore, after receiving packets from an address that is not yet validated,
/// an endpoint MUST limit the amount of data it sends to the unvalidated address
/// to N(three) times the amount of data received from that address.
#[derive(Debug, Default)]
struct RawAntiAmplifier<const N: usize> {
    // Each time data is received, credit is increased;
    // each time data is sent, credit is consumed.
    credit: usize,
    // If the credit is exhausted, it needs to wait until
    // new data is received before it can continue to send.
    waker: Option<Waker>,
}

impl<const N: usize> RawAntiAmplifier<N> {
    /// Store N * amount of credit
    fn deposit(&mut self, amount: usize) {
        self.credit += amount.saturating_mul(N);
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }

    /// poll_apply must only be called by one at a time, and the amount of data sent
    /// must be feed back to the anti-amplifier before poll_apply can be called again.
    fn poll_apply(&mut self, cx: &mut Context<'_>, amount: usize) -> Poll<usize> {
        debug_assert!(amount > 0);
        if self.credit == 0 {
            assert!(self.waker.is_none());
            self.waker = Some(cx.waker().clone());
            Poll::Pending
        } else {
            Poll::Ready(std::cmp::min(self.credit, amount))
        }
    }

    fn consume(&mut self, amount: usize) {
        assert!(amount <= self.credit);
        self.credit -= amount;
    }
}

/// A sendable and receivable shared controller for anti-N-times amplification attack
#[derive(Debug, Default, Clone)]
pub struct ArcAntiAmplifier<const N: usize>(Arc<Mutex<RawAntiAmplifier<N>>>);

impl<const N: usize> ArcAntiAmplifier<N> {
    /// When data is received, store it as N times the sendable credit.
    pub fn deposit(&self, amount: usize) {
        self.0.lock().unwrap().deposit(amount);
    }

    /// poll_apply cannot be abstracted into a Future, because there is no need to remember amount.
    /// Once it is awakened from waiting, the amount of data to apply for after waiting will be
    /// different, and needs to be recalculated.
    pub fn poll_apply(&self, cx: &mut Context<'_>, amount: usize) -> Poll<usize> {
        self.0.lock().unwrap().poll_apply(cx, amount)
    }

    /// Wait until the data of 'amount' is really sent, then the remaining send credit should be
    /// updated in time. Do not call poll_apply before updating to avoid double amplification.
    pub fn post_sent(&self, amount: usize) {
        self.0.lock().unwrap().consume(amount);
    }
}
