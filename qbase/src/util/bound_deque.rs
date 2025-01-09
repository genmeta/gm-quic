use std::{
    collections::VecDeque,
    pin::Pin,
    sync::{Arc, Mutex, RwLock},
    task::{Context, Poll},
};

use futures::task::AtomicWaker;

struct BoundQueueInner<T> {
    // it should be Box<[T]>, use VecDeque for avoiding implement ring buffer
    queue: Mutex<VecDeque<T>>,
    read_waker: AtomicWaker,
    write_waker: AtomicWaker,
}

impl<T> BoundQueueInner<T> {
    /// Close the queue and return all items in the queue.
    fn close(&self) -> VecDeque<T> {
        self.read_waker.wake();
        self.write_waker.wake();
        core::mem::take(&mut *self.queue.lock().unwrap())
    }
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
                core::task::Poll::Ready(Err(item))
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
        self.inner.read().unwrap().close();
    }

    pub fn receiver(&self) -> Receiver<T> {
        let mut inner = self.inner.write().unwrap();

        // close the Receiver
        let queue = inner.close();

        *inner = Arc::new(BoundQueueInner {
            queue: queue.into(),
            read_waker: AtomicWaker::new(),
            write_waker: AtomicWaker::new(),
        });
        Receiver {
            inner: inner.clone(),
        }
    }
}

impl<T> Drop for BoundQueue<T> {
    fn drop(&mut self) {
        self.close();
    }
}

pub struct Receiver<T> {
    inner: Arc<BoundQueueInner<T>>,
}

impl<T> Receiver<T> {
    pub fn close(&self) {
        self.inner.close();
    }
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

#[cfg(test)]
mod tests {
    use futures::StreamExt;

    use super::*;

    #[tokio::test]
    async fn test_send_receive() {
        let queue = Arc::new(BoundQueue::new(2));

        tokio::spawn({
            let queue = queue.clone();
            async move {
                queue.send(1).await.unwrap();
                queue.send(2).await.unwrap();
            }
        });

        let mut receiver = queue.receiver();
        assert_eq!(receiver.next().await, Some(1));
        assert_eq!(receiver.next().await, Some(2));
    }

    #[tokio::test]
    async fn test_queue_full() {
        let queue = Arc::new(BoundQueue::new(1));

        tokio::spawn({
            let queue = queue.clone();
            async move {
                queue.send(1).await.unwrap();
                assert!(queue.send(2).await.is_err());
            }
        });

        let mut receiver = queue.receiver();
        assert_eq!(receiver.next().await, Some(1));
    }
}
