use std::{
    collections::VecDeque,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
};

use futures::Stream;

#[derive(Debug)]
struct AsyncDeque<T> {
    queue: Option<VecDeque<T>>,
    waker: Option<Waker>,
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

    pub fn push(&self, value: T) {
        let mut guard = self.0.lock().unwrap();
        if let Some(queue) = &mut guard.queue {
            queue.push_back(value);
            if let Some(waker) = guard.waker.take() {
                waker.wake();
            }
        }
    }

    pub fn pop(&self) -> Option<T> {
        let mut guard = self.0.lock().unwrap();
        guard.queue.as_mut().and_then(|q| q.pop_front())
    }

    pub fn len(&self) -> usize {
        self.0
            .lock()
            .unwrap()
            .queue
            .as_ref()
            .map(|v| v.len())
            .unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn close(&self) {
        let mut guard = self.0.lock().unwrap();
        guard.queue = None;
        if let Some(waker) = guard.waker.take() {
            waker.wake();
        }
    }

    // pub fn writer<'a>(&'a self) -> ArcFrameQueueWriter<'a, T> {
    pub fn writer(&self) -> ArcAsyncDequeWriter<'_, T> {
        let guard = self.0.lock().unwrap();
        let old_len = guard.queue.as_ref().map(|q| q.len()).unwrap_or(0);
        ArcAsyncDequeWriter { guard, old_len }
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

impl<T> Stream for ArcAsyncDeque<T> {
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut guard = self.0.lock().unwrap();
        match &mut guard.queue {
            Some(queue) => {
                if let Some(frame) = queue.pop_front() {
                    Poll::Ready(Some(frame))
                } else {
                    guard.waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
            None => Poll::Ready(None),
        }
    }
}

impl<T> Extend<T> for ArcAsyncDeque<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        let mut guard = self.0.lock().unwrap();
        if let Some(queue) = &mut guard.queue {
            queue.extend(iter);
            if let Some(waker) = guard.waker.take() {
                waker.wake();
            }
        }
    }
}

pub struct ArcAsyncDequeWriter<'a, T> {
    guard: MutexGuard<'a, AsyncDeque<T>>,
    old_len: usize,
}

impl<T> ArcAsyncDequeWriter<'_, T> {
    pub fn push(&mut self, value: T) {
        match &mut self.guard.queue {
            Some(queue) => queue.push_back(value),
            None => panic!("queue is closed"),
        }
    }

    pub fn rollback(&mut self) {
        match &mut self.guard.queue {
            Some(queue) => {
                queue.truncate(self.old_len);
            }
            None => panic!("queue is closed"),
        }
    }
}

impl<T> Drop for ArcAsyncDequeWriter<'_, T> {
    fn drop(&mut self) {
        if let Some(queue) = &mut self.guard.queue {
            if queue.len() > self.old_len {
                if let Some(waker) = self.guard.waker.take() {
                    waker.wake();
                }
            }
        }
    }
}
