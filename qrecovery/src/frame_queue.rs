use futures::Stream;
use std::{
    collections::VecDeque,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
};

#[derive(Debug)]
struct FrameQueue<T> {
    queue: Option<VecDeque<T>>,
    waker: Option<Waker>,
}

#[derive(Debug)]
pub struct ArcFrameQueue<T>(Arc<Mutex<FrameQueue<T>>>);

impl<T> ArcFrameQueue<T> {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(FrameQueue {
            queue: Some(VecDeque::with_capacity(8)),
            waker: None,
        })))
    }

    pub fn close(&self) {
        let mut queue = self.0.lock().unwrap();
        queue.queue = None;
        if let Some(waker) = queue.waker.take() {
            waker.wake();
        }
    }

    // pub fn writer<'a>(&'a self) -> ArcFrameQueueWriter<'a, T> {
    pub fn writer(&self) -> ArcFrameQueueWriter<'_, T> {
        let guard = self.0.lock().unwrap();
        let old_len = guard.queue.as_ref().map(|q| q.len()).unwrap_or(0);
        ArcFrameQueueWriter { guard, old_len }
    }
}

impl<T> Default for ArcFrameQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Clone for ArcFrameQueue<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> Stream for ArcFrameQueue<T> {
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

pub struct ArcFrameQueueWriter<'a, T> {
    guard: MutexGuard<'a, FrameQueue<T>>,
    old_len: usize,
}

impl<T> ArcFrameQueueWriter<'_, T> {
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

impl<T> Drop for ArcFrameQueueWriter<'_, T> {
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
