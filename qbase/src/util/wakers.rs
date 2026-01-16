use std::{
    mem,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Wake, Waker},
    usize,
};

use smallvec::SmallVec;

#[derive(Debug, Clone)]
pub struct WakerVec<const N: usize = 4> {
    wakers: SmallVec<[Waker; N]>,
}

impl<const N: usize> Default for WakerVec<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> WakerVec<N> {
    pub const fn new() -> Self {
        Self {
            wakers: SmallVec::new_const(),
        }
    }

    pub fn register(&mut self, waker: &Waker) -> bool {
        if !self.wakers.iter().any(|w| w.will_wake(waker)) {
            self.wakers.push(waker.clone());
            return self.wakers.len() == 1;
        }
        true
    }

    pub fn wake_all(&mut self) {
        for waker in self.wakers.drain(..) {
            waker.wake();
        }
    }
}

impl<const N: usize> Drop for WakerVec<N> {
    fn drop(&mut self) {
        self.wake_all();
    }
}

#[derive(Debug)]
pub struct Wakers<const N: usize = 4> {
    wakers: Mutex<WakerVec<N>>,
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
            wakers: Mutex::new(WakerVec::new()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, WakerVec<N>> {
        self.wakers.lock().expect("Wakers mutex poisoned")
    }

    pub fn register(&self, waker: &Waker) -> bool {
        self.lock().register(waker)
    }

    pub fn wake_all(&self) {
        { mem::replace(&mut *self.lock(), WakerVec::new()) }.wake_all()
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
