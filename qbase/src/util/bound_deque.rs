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
    pub fn new(size: usize) -> Self {
        let (tx, rx) = mpsc::channel(size);
        Self(Arc::new(BoundQueueInner { tx, rx: rx.into() }))
    }

    pub async fn send(&self, item: T) {
        _ = self.0.tx.clone().send(item).await
    }

    pub async fn recv(&self) -> Option<T> {
        self.0.rx.lock().await.next().await
    }

    pub fn close(&self) {
        self.0.tx.clone().close_channel();
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
                queue.send(1).await;
                queue.send(2).await;
            }
        });

        assert_eq!(queue.recv().await, Some(1));
        assert_eq!(queue.recv().await, Some(2));
    }
}
