use futures::Stream;
use std::{
    collections::VecDeque,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
};

#[derive(Debug)]
struct AsyncQueue<T> {
    queue: Option<VecDeque<T>>,
    waker: Option<Waker>,
}

#[derive(Debug)]
pub struct ArcAsyncQueue<T>(Arc<Mutex<AsyncQueue<T>>>);

impl<T> ArcAsyncQueue<T> {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(AsyncQueue {
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

    pub fn close(&self) {
        let mut queue = self.0.lock().unwrap();
        queue.queue = None;
        if let Some(waker) = queue.waker.take() {
            waker.wake();
        }
    }

    // pub fn writer<'a>(&'a self) -> ArcFrameQueueWriter<'a, T> {
    pub fn writer(&self) -> ArcAsyncQueueWriter<'_, T> {
        let guard = self.0.lock().unwrap();
        let old_len = guard.queue.as_ref().map(|q| q.len()).unwrap_or(0);
        ArcAsyncQueueWriter { guard, old_len }
    }
}

impl<T> Default for ArcAsyncQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Clone for ArcAsyncQueue<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> Stream for ArcAsyncQueue<T> {
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

pub struct ArcAsyncQueueWriter<'a, T> {
    guard: MutexGuard<'a, AsyncQueue<T>>,
    old_len: usize,
}

impl<T> ArcAsyncQueueWriter<'_, T> {
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

impl<T> Drop for ArcAsyncQueueWriter<'_, T> {
    fn drop(&mut self) {
        match &mut self.guard.queue {
            Some(queue) => {
                if queue.len() > self.old_len {
                    if let Some(waker) = self.guard.waker.take() {
                        waker.wake();
                    }
                }
            }
            None => {}
        }
    }
}
