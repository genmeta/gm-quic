use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll, Waker},
};

use futures::task::AtomicWaker;

pub(super) const ANTI_FACTOR: usize = 3;
/// Therefore, after receiving packets from an address that is not yet validated,
/// an endpoint MUST limit the amount of data it sends to the unvalidated address
/// to N(three) times the amount of data received from that address.
#[derive(Debug, Default)]
struct AntiAmplifier<const N: usize> {
    // Each time data is received, credit is increased;
    // each time data is sent, credit is consumed.
    credit: AtomicUsize,
    // If the credit is exhausted, it needs to wait until
    // new data is received before it can continue to send.
    waker: AtomicWaker,
}

impl<const N: usize> AntiAmplifier<N> {
    /// Store N * amount of credit
    fn deposit(&self, amount: usize) {
        if 0 == self.credit.fetch_add(amount * N, Ordering::AcqRel) {
            self.waker.wake();
        }
    }

    /// This function must only be called by one at a time, and the amount of data sent
    /// must be feed back to the anti-amplifier before poll_apply can be called again.
    fn poll_get_credit(&self, cx: &mut Context<'_>) -> Poll<Option<usize>> {
        let credit = self.credit.load(Ordering::Acquire);
        if credit == 0 {
            self.waker.register(cx.waker());
            Poll::Pending
        } else {
            Poll::Ready(Some(credit))
        }
    }

    fn post_sent(&self, amount: usize) {
        self.credit.fetch_sub(amount, Ordering::AcqRel);
    }

    fn is_ready(&self) -> bool {
        self.credit.load(Ordering::Acquire) > 0
    }

    fn waker(&self) -> Option<Waker> {
        self.waker.take()
    }
}

/// A sendable and receivable shared controller for anti-N-times amplification attack
#[derive(Debug, Default, Clone)]
pub struct ArcAntiAmplifier<const N: usize>(Arc<AntiAmplifier<N>>);

impl<const N: usize> ArcAntiAmplifier<N> {
    /// When data is received, store it as N times the sendable credit.
    pub fn deposit(&self, amount: usize) {
        self.0.deposit(amount);
    }

    /// This function cannot be abstracted into a Future, because there is no
    /// need to remember amount. Once it is awakened from waiting, the amount
    /// of data to apply for after waiting will be different, and needs to be
    /// recalculated.
    pub fn poll_get_credit(&self, cx: &mut Context<'_>) -> Poll<Option<usize>> {
        self.0.poll_get_credit(cx)
    }

    /// Wait until the data of 'amount' is really sent, then the remaining send
    /// credit should be updated in time. Do not call poll_apply before updating
    /// to avoid double amplification.
    pub fn post_sent(&self, amount: usize) {
        self.0.post_sent(amount);
    }

    pub fn is_ready(&self) -> bool {
        self.0.is_ready()
    }

    pub fn waker(&self) -> Option<Waker> {
        self.0.waker()
    }
}

#[cfg(test)]
mod tests {
    use std::task::Context;

    use futures::task::noop_waker_ref;

    use super::*;

    #[test]
    fn test_deposit_and_poll_apply() {
        let anti_amplifier = ArcAntiAmplifier::<3>::default();
        let mut cx = Context::from_waker(noop_waker_ref());

        // Initially, no credit
        assert_eq!(anti_amplifier.poll_get_credit(&mut cx), Poll::Pending);

        // Deposit 1 unit of data, should add 3 units of credit
        anti_amplifier.deposit(1);
        assert_eq!(anti_amplifier.0.credit.load(Ordering::Acquire), 3);

        // Apply for 2 units of data, should return 2 units
        assert_eq!(
            anti_amplifier.poll_get_credit(&mut cx),
            Poll::Ready(Some(3))
        );
        assert_eq!(anti_amplifier.0.credit.load(Ordering::Acquire), 3);

        anti_amplifier.post_sent(3);

        // No credit left, should return Pending
        assert_eq!(anti_amplifier.poll_get_credit(&mut cx), Poll::Pending);
    }

    #[test]
    fn test_multiple_deposits() {
        let anti_amplifier = ArcAntiAmplifier::<3>::default();
        let mut cx = Context::from_waker(noop_waker_ref());

        // Deposit 1 unit of data, should add 3 units of credit
        anti_amplifier.deposit(1);
        assert_eq!(anti_amplifier.0.credit.load(Ordering::Acquire), 3);

        // Deposit another 1 unit of data, should add another 3 units of credit
        anti_amplifier.deposit(1);
        assert_eq!(anti_amplifier.0.credit.load(Ordering::Acquire), 6);

        // Apply for 5 units of data, should return 5 units
        assert_eq!(
            anti_amplifier.poll_get_credit(&mut cx),
            Poll::Ready(Some(6))
        );
        assert_eq!(anti_amplifier.0.credit.load(Ordering::Acquire), 6);

        // Post sent 5 units, should reduce credit by 5
        anti_amplifier.post_sent(5);
        assert_eq!(anti_amplifier.0.credit.load(Ordering::Acquire), 1);
    }
}
