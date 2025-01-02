use std::{
    collections::VecDeque,
    pin::Pin,
    sync::{Arc, Mutex, RwLock},
    task::{Context, Poll},
};

use futures::task::AtomicWaker;

struct BoundQueueInner<T> {
    queue: Mutex<VecDeque<T>>,
    read_waker: AtomicWaker,
    write_waker: AtomicWaker,
}

pub struct BoundQueue<T> {
    inner: RwLock<Arc<BoundQueueInner<T>>>,
}

impl<T> BoundQueue<T> {
    pub fn new(size: usize) -> Self {
        assert!(size > 0, "size must be greater than 0");
        Self {
            inner: RwLock::new(Arc::new(BoundQueueInner {
                queue: Mutex::new(VecDeque::with_capacity(size)),
                read_waker: AtomicWaker::new(),
                write_waker: AtomicWaker::new(),
            })),
        }
    }

    pub async fn send(&self, item: T) -> Result<(), T> {
        let mut item = Some(item);
        core::future::poll_fn(|cx| {
            let inner = self.inner.read().unwrap();
            let mut queue = inner.queue.lock().unwrap();
            if queue.capacity() == 0 {
                let item = item.take().unwrap();
                return core::task::Poll::Ready(Err(item));
            } else if queue.len() == queue.capacity() {
                inner.write_waker.register(cx.waker());
                core::task::Poll::Pending
            } else {
                inner.read_waker.wake();
                let item = item.take().unwrap();
                queue.push_back(item);
                core::task::Poll::Ready(Ok(()))
            }
        })
        .await
    }

    pub fn close(&self) {
        let inner = self.inner.write().unwrap();
        // queue.cap() == 0 indicates that the queue is closed
        core::mem::take(&mut *inner.queue.lock().unwrap());
        inner.read_waker.wake();
        inner.write_waker.wake();
    }

    pub fn receiver(&self) -> Receiver<T> {
        let mut inner = self.inner.write().unwrap();

        // close the current queue, wake the receiver
        // queue.cap() == 0 indicates that the queue is closed
        let queue = core::mem::take(&mut *inner.queue.lock().unwrap());
        inner.read_waker.wake();

        let read_waker = AtomicWaker::new();

        // keep the write waker
        let write_waker = AtomicWaker::new();
        if let Some(previous_waker) = inner.write_waker.take() {
            write_waker.register(&previous_waker);
        }

        *inner = Arc::new(BoundQueueInner {
            queue: queue.into(),
            read_waker,
            write_waker,
        });
        Receiver {
            inner: inner.clone(),
        }
    }
}

pub struct Receiver<T> {
    inner: Arc<BoundQueueInner<T>>,
}

impl<T> futures::Stream for Receiver<T> {
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut queue = self.inner.queue.lock().unwrap();
        if queue.capacity() == 0 {
            return Poll::Ready(None);
        }
        if let Some(item) = queue.pop_front() {
            self.inner.write_waker.wake();
            Poll::Ready(Some(item))
        } else {
            self.inner.read_waker.register(cx.waker());
            Poll::Pending
        }
    }
}
