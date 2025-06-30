use std::{self, sync::Arc};

use futures::{SinkExt, StreamExt, channel::mpsc, lock::Mutex};

struct BoundQueueInner<T> {
    tx: mpsc::Sender<T>,
    rx: Mutex<mpsc::Receiver<T>>,
}

pub struct BoundQueue<T>(Arc<BoundQueueInner<T>>);

impl<T> Clone for BoundQueue<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> BoundQueue<T> {
    #[inline]
    pub fn new(size: usize) -> Self {
        let (tx, rx) = mpsc::channel(size);
        Self(Arc::new(BoundQueueInner { tx, rx: rx.into() }))
    }

    #[inline]
    pub fn try_send(&self, item: T) -> Result<(), mpsc::TrySendError<T>> {
        self.0.tx.clone().try_send(item)
    }

    #[inline]
    pub async fn send(&self, item: T) -> Result<(), mpsc::SendError> {
        self.0.tx.clone().send(item).await
    }

    #[inline]
    pub async fn recv(&self) -> Option<T> {
        self.0.rx.lock().await.next().await
    }

    #[inline]
    pub fn close(&self) {
        self.0.tx.clone().close_channel();
    }

    #[inline]
    pub fn is_closed(&self) -> bool {
        self.0.tx.is_closed()
    }

    #[inline]
    pub fn same_queue(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[tokio::test]
    async fn test_send_receive() {
        let queue = Arc::new(BoundQueue::new(2));

        tokio::spawn({
            let queue = queue.clone();
            async move {
                assert!(queue.send(1).await.is_ok());
                assert!(queue.send(2).await.is_ok());
            }
        });

        assert_eq!(queue.recv().await, Some(1));
        assert_eq!(queue.recv().await, Some(2));
    }
}
