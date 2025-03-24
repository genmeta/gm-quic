use std::sync::{
    Mutex,
    atomic::{AtomicU8, AtomicUsize, Ordering},
};

use qbase::net::tx::{ArcSendWaker, Signals};

pub const DEFAULT_ANTI_FACTOR: usize = 3;
/// Therefore, after receiving packets from an address that is not yet validated,
/// an endpoint MUST limit the amount of data it sends to the unvalidated address
/// to N(three) times the amount of data received from that address.
#[derive(Debug, Default)]
pub struct AntiAmplifier<const N: usize = DEFAULT_ANTI_FACTOR> {
    // Each time data is received, credit is increased;
    // each time data is sent, credit is consumed.
    credit: AtomicUsize,
    // If the credit is exhausted, it needs to wait until
    // new data is received before it can continue to send.
    tx_waker: Mutex<Option<ArcSendWaker>>,
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
        let waker = self.tx_waker.lock().unwrap();
        if let Some(waker) = waker.as_ref() {
            waker.wake_by(Signals::CREDIT);
        }
    }

    /// This function must only be called by one at a time, and the amount of data sent
    /// must be feed back to the anti-amplifier before poll_apply can be called again.
    pub fn balance(&self, tx_waker: ArcSendWaker) -> Result<Option<usize>, Signals> {
        self.tx_waker.lock().unwrap().replace(tx_waker.clone());
        match self.state.load(Ordering::Acquire) {
            Self::GRANTED => Ok(Some(usize::MAX)),
            Self::ABORTED => Ok(None),
            Self::NORMAL => {
                let credit = self.credit.load(Ordering::Acquire);
                if credit == 0 {
                    // 再次检查，以防grant、abort在self.waker赋值前被调用，导致任务死掉
                    let state = self.state.load(Ordering::Acquire);
                    if state == Self::NORMAL {
                        Err(Signals::CREDIT)
                    } else {
                        tx_waker.wake_by(Signals::CREDIT);
                        if state == Self::GRANTED {
                            Ok(Some(usize::MAX))
                        } else {
                            Ok(None)
                        }
                    }
                } else {
                    Ok(Some(credit))
                }
            }
            _ => unreachable!(),
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
            let waker = self.tx_waker.lock().unwrap();
            if let Some(waker) = waker.as_ref() {
                waker.wake_by(Signals::CREDIT);
            }
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
            let waker = self.tx_waker.lock().unwrap();
            if let Some(waker) = waker.as_ref() {
                waker.wake_by(Signals::CREDIT);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_deposit_and_poll_apply() {
        let anti_amplifier = AntiAmplifier::<3>::default();
        let waker = ArcSendWaker::new();
        // Initially, no credit
        assert_eq!(anti_amplifier.balance(waker.clone()), Err(Signals::CREDIT));

        // Deposit 1 unit of data, should add 3 units of credit
        anti_amplifier.on_rcvd(1);
        assert_eq!(anti_amplifier.credit.load(Ordering::Acquire), 3);

        // Apply for 2 units of data, should return 2 units
        assert_eq!(anti_amplifier.balance(waker.clone()), Ok(Some(3)));
        assert_eq!(anti_amplifier.credit.load(Ordering::Acquire), 3);

        anti_amplifier.on_sent(3);

        // No credit left, should return Pending
        assert_eq!(anti_amplifier.balance(waker.clone()), Err(Signals::CREDIT));
    }

    #[test]
    fn test_multiple_deposits() {
        let anti_amplifier = AntiAmplifier::<3>::default();

        // Deposit 1 unit of data, should add 3 units of credit
        anti_amplifier.on_rcvd(1);
        assert_eq!(anti_amplifier.credit.load(Ordering::Acquire), 3);

        // Deposit another 1 unit of data, should add another 3 units of credit
        anti_amplifier.on_rcvd(1);
        assert_eq!(anti_amplifier.credit.load(Ordering::Acquire), 6);

        let waker = ArcSendWaker::new();
        // Apply for 5 units of data, should return 5 units
        assert_eq!(anti_amplifier.balance(waker.clone()), Ok(Some(6)));
        assert_eq!(anti_amplifier.credit.load(Ordering::Acquire), 6);

        // Post sent 5 units, should reduce credit by 5
        anti_amplifier.on_sent(5);
        assert_eq!(anti_amplifier.credit.load(Ordering::Acquire), 1);
    }
}
