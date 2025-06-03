use std::{collections::VecDeque, sync::Mutex};

use tokio::sync::Notify;

/// Bound multi-producer multi-consumer (mpmc) channel.
#[derive(Debug)]
pub struct Channel<T> {
    deque: Mutex<Option<VecDeque<T>>>,
    send_notify: Notify,
    recv_notify: Notify,
}

impl<T> Channel<T> {
    /// Create a new empty channel.
    pub fn new(size: usize) -> Self {
        Self {
            deque: Some(VecDeque::with_capacity(size)).into(),
            send_notify: Default::default(),
            recv_notify: Default::default(),
        }
    }

    /// Send an item to the channel.
    ///
    /// If the channel is closed, the item is returned as [`Err`].
    pub async fn send(&self, mut item: T) -> Result<(), T> {
        let fut = self.send_notify.notified();
        tokio::pin!(fut);

        loop {
            // because the Notify::notify_one will only store one permit,
            // we need to enable the notified to avoid missing the notification
            fut.as_mut().enable();

            item = match self.try_send(item) {
                Ok(()) => return Ok(()),
                Err(TrySendError::Full(item)) => {
                    fut.as_mut().await;
                    fut.set(self.send_notify.notified());
                    item
                }
                Err(TrySendError::Closed(item)) => return Err(item),
            }
        }
    }

    pub fn try_send(&self, item: T) -> Result<(), TrySendError<T>> {
        let mut deque_guard = self.deque.lock().unwrap();

        match deque_guard.as_mut() {
            Some(deque) => {
                if deque.len() < deque.capacity() {
                    deque.push_back(item);
                    self.recv_notify.notify_one();
                    Ok(())
                } else {
                    Err(TrySendError::Full(item))
                }
            }
            None => Err(TrySendError::Closed(item)),
        }
    }

    /// Close the channel, return all unrecieved items.
    ///
    /// All unrecieved items will be dropped, and all pending [`Channel::recv`] calls will return [`None`].
    ///
    /// If the channel is already closed, this call will have no effect, and return [`None`]
    pub fn close(&self) -> Option<VecDeque<T>> {
        let mut deque = self.deque.lock().unwrap();
        self.recv_notify.notify_waiters();
        deque.take()
    }

    /// Check if the channel is closed.
    pub fn is_closed(&self) -> bool {
        self.deque.lock().unwrap().is_none()
    }

    /// Try to recieve an item from the channel.
    ///
    /// If the channel is empty, [`TryRecvError::Empty`] is returned.
    /// If the channel is closed, [`TryRecvError::Closed`] is returned.
    pub fn try_recv(&self) -> Result<T, TryRecvError> {
        let mut deque_guard = self.deque.lock().unwrap();
        let deque = deque_guard.as_mut().ok_or(TryRecvError::Closed)?;
        if !deque.is_empty() {
            self.send_notify.notify_one();
        }
        deque.pop_front().ok_or(TryRecvError::Empty)
    }

    /// Recieve an item from the channel.
    ///
    /// If the channel is empty, the call will wait until an item is sent.
    ///
    /// If the channel is closed, [`None`] is returned.
    pub async fn recv(&self) -> Option<T> {
        let fut = self.recv_notify.notified();
        tokio::pin!(fut);

        loop {
            // because the Notify::notify_one will only store one permit,
            // we need to enable the notified to avoid missing the notification
            fut.as_mut().enable();

            match self.try_recv() {
                Ok(item) => return Some(item),
                Err(TryRecvError::Empty) => {
                    fut.as_mut().await;
                    fut.set(self.recv_notify.notified());
                }
                Err(TryRecvError::Closed) => return None,
            }
        }
    }
}

/// Error type for [`Channel::try_send`].
#[derive(thiserror::Error, Debug, Clone, Copy)]
pub enum TrySendError<T> {
    #[error("channel is full")]
    Full(T),
    #[error("channel is closed")]
    Closed(T),
}

/// Error type for [`Channel::try_recv`].
#[derive(thiserror::Error, Debug, Clone, Copy)]
pub enum TryRecvError {
    #[error("channel is empty")]
    Empty,
    #[error("channel is closed")]
    Closed,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[tokio::test]
    async fn channel() {
        let ch = Arc::new(Channel::new(64));
        let ch2 = ch.clone();
        assert_eq!(ch.send(0).await, Ok(()));

        let t1 = tokio::spawn(async move {
            assert_eq!(ch.recv().await, Some(0));
            assert_eq!(ch.recv().await, Some(1));
            assert_eq!(ch.recv().await, Some(2));
            assert_eq!(ch.recv().await, Some(3));
            assert_eq!(ch.recv().await, None);
        });

        let t2 = tokio::spawn(async move {
            assert_eq!(ch2.send(1).await, Ok(()));
            tokio::task::yield_now().await;
            assert_eq!(ch2.send(2).await, Ok(()));
            tokio::task::yield_now().await;
            assert_eq!(ch2.send(3).await, Ok(()));
            tokio::task::yield_now().await;
            ch2.close();
            assert_eq!(ch2.send(4).await, Err(4));
            assert_eq!(ch2.send(5).await, Err(5));
        });

        t1.await.unwrap();
        t2.await.unwrap();
    }
}
