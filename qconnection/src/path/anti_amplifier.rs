use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicU8, AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

use deref_derive::Deref;
use futures::task::AtomicWaker;

pub const DEFAULT_ANTI_FACTOR: usize = 3;
/// Therefore, after receiving packets from an address that is not yet validated,
/// an endpoint MUST limit the amount of data it sends to the unvalidated address
/// to N(three) times the amount of data received from that address.
#[derive(Debug, Default)]
pub struct AntiAmplifier<const N: usize> {
    // Each time data is received, credit is increased;
    // each time data is sent, credit is consumed.
    credit: AtomicUsize,
    // If the credit is exhausted, it needs to wait until
    // new data is received before it can continue to send.
    waker: AtomicWaker,
    state: AtomicU8,
}

impl<const N: usize> AntiAmplifier<N> {
    const NORMAL: u8 = 0;
    const GRANTED: u8 = 1;
    const ABORTED: u8 = 2;

    /// Store N * amount of credit
    pub fn on_rcvd(&self, amount: usize) {
        if self.state.load(Ordering::Acquire) != Self::NORMAL {
            return;
        }
        self.credit.fetch_add(amount * N, Ordering::AcqRel);
        self.waker.wake();
    }

    /// This function must only be called by one at a time, and the amount of data sent
    /// must be feed back to the anti-amplifier before poll_apply can be called again.
    pub fn poll_balance(&self, cx: &mut Context<'_>) -> Poll<Option<usize>> {
        let state = self.state.load(Ordering::Acquire);
        if state == Self::GRANTED {
            Poll::Ready(Some(usize::MAX))
        } else if state == Self::ABORTED {
            Poll::Ready(None)
        } else {
            let credit = self.credit.load(Ordering::Acquire);
            if credit == 0 {
                self.waker.register(cx.waker());

                // 再次检查，以防grant、abort在self.waker赋值前被调用，导致任务死掉
                let state = self.state.load(Ordering::Acquire);
                if state == Self::NORMAL {
                    Poll::Pending
                } else {
                    self.waker.take();
                    if state == Self::GRANTED {
                        Poll::Ready(Some(usize::MAX))
                    } else {
                        Poll::Ready(None)
                    }
                }
            } else {
                Poll::Ready(Some(credit))
            }
        }
    }

    pub fn on_sent(&self, amount: usize) {
        if self.state.load(Ordering::Acquire) == Self::NORMAL {
            self.credit.fetch_sub(amount, Ordering::AcqRel);
        }
    }

    pub fn grant(&self) {
        if self
            .state
            .compare_exchange(
                Self::NORMAL,
                Self::GRANTED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            self.waker.wake();
        }
    }

    pub fn abort(&self) {
        if self
            .state
            .compare_exchange(
                Self::NORMAL,
                Self::ABORTED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            self.waker.wake();
        }
    }
}

/// A sendable and receivable shared controller for anti-N-times amplification attack
#[derive(Debug, Default, Clone, Deref)]
pub struct ArcAntiAmplifier<const N: usize>(Arc<AntiAmplifier<N>>);

impl<const N: usize> ArcAntiAmplifier<N> {
    pub fn balance(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<const N: usize> Future for ArcAntiAmplifier<N> {
    type Output = Option<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<usize>> {
        self.0.poll_balance(cx)
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
        assert_eq!(anti_amplifier.poll_balance(&mut cx), Poll::Pending);

        // Deposit 1 unit of data, should add 3 units of credit
        anti_amplifier.on_rcvd(1);
        assert_eq!(anti_amplifier.credit.load(Ordering::Acquire), 3);

        // Apply for 2 units of data, should return 2 units
        assert_eq!(anti_amplifier.poll_balance(&mut cx), Poll::Ready(Some(3)));
        assert_eq!(anti_amplifier.credit.load(Ordering::Acquire), 3);

        anti_amplifier.on_sent(3);

        // No credit left, should return Pending
        assert_eq!(anti_amplifier.poll_balance(&mut cx), Poll::Pending);
    }

    #[test]
    fn test_multiple_deposits() {
        let anti_amplifier = ArcAntiAmplifier::<3>::default();
        let mut cx = Context::from_waker(noop_waker_ref());

        // Deposit 1 unit of data, should add 3 units of credit
        anti_amplifier.on_rcvd(1);
        assert_eq!(anti_amplifier.credit.load(Ordering::Acquire), 3);

        // Deposit another 1 unit of data, should add another 3 units of credit
        anti_amplifier.on_rcvd(1);
        assert_eq!(anti_amplifier.credit.load(Ordering::Acquire), 6);

        // Apply for 5 units of data, should return 5 units
        assert_eq!(anti_amplifier.poll_balance(&mut cx), Poll::Ready(Some(6)));
        assert_eq!(anti_amplifier.credit.load(Ordering::Acquire), 6);

        // Post sent 5 units, should reduce credit by 5
        anti_amplifier.on_sent(5);
        assert_eq!(anti_amplifier.credit.load(Ordering::Acquire), 1);
    }
}
