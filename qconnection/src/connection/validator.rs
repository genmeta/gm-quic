use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

use futures::task::AtomicWaker;

#[derive(Default)]
pub struct AddrValidator {
    waker: AtomicWaker,
    state: AtomicU8,
}

impl AddrValidator {
    const NORMAL: u8 = 0;
    const VALIDATED: u8 = 1;
    const ABORTED: u8 = 2;

    pub fn validate(&self) {
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

#[derive(Clone, Default)]
pub struct ArcAddrValidator(pub Arc<AddrValidator>);

impl Future for ArcAddrValidator {
    type Output = bool;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let state = self.0.state.load(Ordering::Acquire);
        match state {
            AddrValidator::NORMAL => {
                self.0.waker.register(cx.waker());
                Poll::Pending
            }
            AddrValidator::VALIDATED => Poll::Ready(true),
            AddrValidator::ABORTED => Poll::Ready(false),
            _ => unreachable!("invalid state"),
        }
    }
}
