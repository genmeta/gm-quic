use std::{
    mem,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Wake, Waker},
};

use smallvec::SmallVec;

#[derive(Debug)]
pub struct Wakers<const N: usize = 4> {
    wakers: Mutex<SmallVec<[Waker; N]>>,
}

impl<const N: usize> Wake for Wakers<N> {
    fn wake(self: Arc<Self>) {
        self.wake_all();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wake_all();
    }
}

impl<const N: usize> Default for Wakers<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Wakers<N> {
    pub const fn new() -> Self {
        Self {
            wakers: Mutex::new(SmallVec::new_const()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, SmallVec<[Waker; N]>> {
        self.wakers.lock().expect("Wakers mutex poisoned")
    }

    pub fn register(&self, waker: &Waker) -> bool {
        let mut wakers = self.lock();
        if !wakers.iter().any(|w| w.will_wake(waker)) {
            wakers.push(waker.clone());
        };
        wakers.len() == 1
    }

    pub fn wake_all(&self) {
        for waker in { mem::replace(&mut *self.lock(), SmallVec::new_const()) }.drain(..) {
            waker.wake();
        }
    }

    pub fn to_waker(self: &Arc<Self>) -> Waker {
        Waker::from(self.clone())
    }

    pub fn combine_with<T>(
        self: &Arc<Self>,
        cx: &mut Context<'_>,
        poll: impl FnOnce(&mut Context<'_>) -> Poll<T>,
    ) -> Poll<T> {
        if !self.register(cx.waker()) {
            return Poll::Pending;
        }
        poll(&mut Context::from_waker(&self.to_waker()))
    }
}

impl<const N: usize> Drop for Wakers<N> {
    fn drop(&mut self) {
        self.wake_all();
    }
}
