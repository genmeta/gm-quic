use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
};

use futures::Stream;

use crate::frame::SendFrame;

#[derive(Debug)]
pub struct AsyncDeque<T> {
    queue: Option<VecDeque<T>>,
    waker: Option<Waker>,
}

impl<T> AsyncDeque<T> {
    pub fn push(&mut self, value: T) {
        if let Some(queue) = &mut self.queue {
            queue.push_back(value);
            if let Some(waker) = self.waker.take() {
                waker.wake();
            }
        }
    }

    pub fn poll_pop(&mut self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        match &mut self.queue {
            Some(queue) => {
                if let Some(frame) = queue.pop_front() {
                    Poll::Ready(Some(frame))
                } else if let Some(ref waker) = self.waker {
                    if !waker.will_wake(cx.waker()) {
                        panic!("Multiple tasks are attempting to wait on the same AsyncDeque.");
                    }
                    // same waker, no need to update again
                    Poll::Pending
                } else {
                    // no waker, register the current waker
                    self.waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
            None => Poll::Ready(None),
        }
    }

    pub fn len(&self) -> usize {
        self.queue.as_ref().map(|v| v.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn close(&mut self) {
        self.queue = None;
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }
}

#[derive(Debug)]
pub struct ArcAsyncDeque<T>(Arc<Mutex<AsyncDeque<T>>>);

impl<T> ArcAsyncDeque<T> {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(AsyncDeque {
            queue: Some(VecDeque::with_capacity(8)),
            waker: None,
        })))
    }

    pub fn lock_guard(&self) -> MutexGuard<'_, AsyncDeque<T>> {
        self.0.lock().unwrap()
    }

    pub fn push(&self, value: T) {
        self.lock_guard().push(value);
    }

    pub fn pop(&self) -> Self {
        self.clone()
    }

    pub fn poll_pop(&self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        self.lock_guard().poll_pop(cx)
    }

    pub fn len(&self) -> usize {
        self.lock_guard().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn close(&self) {
        self.lock_guard().close();
    }
}

impl<T> Default for ArcAsyncDeque<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Clone for ArcAsyncDeque<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> Future for ArcAsyncDeque<T> {
    type Output = Option<T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.poll_pop(cx)
    }
}

impl<T: Unpin> Stream for AsyncDeque<T> {
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().poll_pop(cx)
    }
}

impl<T> Extend<T> for ArcAsyncDeque<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        self.send_frame(iter);
    }
}

impl<F> SendFrame<F> for ArcAsyncDeque<F> {
    fn send_frame<I: IntoIterator<Item = F>>(&self, iter: I) {
        let mut guard = self.0.lock().unwrap();
        if let Some(queue) = &mut guard.queue {
            queue.extend(iter);
            if let Some(waker) = guard.waker.take() {
                waker.wake();
            }
        }
    }
}
