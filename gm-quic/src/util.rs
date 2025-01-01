use std::{collections::VecDeque, path::Path, sync::Mutex};

use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use tokio::sync::Notify;

pub struct Certificate(Vec<CertificateDer<'static>>);

impl From<Vec<CertificateDer<'static>>> for Certificate {
    fn from(cert: Vec<CertificateDer<'static>>) -> Self {
        Self(cert)
    }
}

pub trait ToCertificate {
    fn to_certificate(self) -> Vec<CertificateDer<'static>>;
}

impl ToCertificate for Certificate {
    fn to_certificate(self) -> Vec<CertificateDer<'static>> {
        self.0
    }
}

impl<P: AsRef<Path>> ToCertificate for P {
    fn to_certificate(self) -> Vec<CertificateDer<'static>> {
        CertificateDer::pem_file_iter(self.as_ref())
            .expect("failed to open cert file")
            .collect::<Result<Vec<_>, _>>()
            .expect("failed to parse cert file")
    }
}

pub struct PrivateKey(PrivateKeyDer<'static>);

impl From<PrivateKeyDer<'static>> for PrivateKey {
    fn from(key: PrivateKeyDer<'static>) -> Self {
        Self(key)
    }
}

pub trait ToPrivateKey {
    fn to_private_key(self) -> PrivateKeyDer<'static>;
}

impl ToPrivateKey for PrivateKey {
    fn to_private_key(self) -> PrivateKeyDer<'static> {
        self.0
    }
}

impl<P: AsRef<Path>> ToPrivateKey for P {
    fn to_private_key(self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::from_pem_file(self.as_ref()).expect("failed to parse private key file")
    }
}

/// Unbound multi-producer multi-consumer (mpmc) channel.
#[derive(Debug)]
pub struct Channel<T> {
    deque: Mutex<Option<VecDeque<T>>>,
    notify: Notify,
}

impl<T> Channel<T> {
    /// Create a new empty channel.
    pub fn new() -> Self {
        Self {
            deque: Some(VecDeque::new()).into(),
            notify: Default::default(),
        }
    }

    /// Send an item to the channel.
    ///
    /// If the channel is closed, the item is returned as [`Err`].
    pub fn send(&self, item: T) -> Result<(), T> {
        let mut deque_guard = self.deque.lock().unwrap();

        match deque_guard.as_mut() {
            None => Err(item),
            Some(deque) => {
                deque.push_back(item);
                drop(deque_guard);
                self.notify.notify_one();
                Ok(())
            }
        }
    }

    /// Close the channel.
    ///
    /// All unrecieved items will be dropped, and all pending [`Channel::recv`] calls will return [`None`].
    pub fn close(&self) {
        drop(self.deque.lock().unwrap().take());
        self.notify.notify_waiters();
    }

    /// Try to recieve an item from the channel.
    ///
    /// If the channel is empty, [`TryRecvError::Empty`] is returned.
    /// If the channel is closed, [`TryRecvError::Closed`] is returned.
    pub fn try_recv(&self) -> Result<T, TryRecvError> {
        let mut deque_guard = self.deque.lock().unwrap();
        let deque = deque_guard.as_mut().ok_or(TryRecvError::Closed)?;
        deque.pop_front().ok_or(TryRecvError::Empty)
    }

    /// Recieve an item from the channel.
    ///
    /// If the channel is empty, the call will wait until an item is sent.
    ///
    /// If the channel is closed, [`None`] is returned.
    pub async fn recv(&self) -> Option<T> {
        let fut = self.notify.notified();
        tokio::pin!(fut);

        loop {
            // because the Notify::notify_one will only store one permit,
            // we need to enable the notified to avoid missing the notification
            fut.as_mut().enable();

            match self.try_recv() {
                Ok(item) => return Some(item),
                Err(TryRecvError::Empty) => {
                    fut.as_mut().await;
                    fut.set(self.notify.notified());
                }
                Err(TryRecvError::Closed) => return None,
            }
        }
    }
}

/// Error type for [`Channel::try_recv`].
#[derive(thiserror::Error, Debug, Clone, Copy)]
pub enum TryRecvError {
    #[error("channel is empty")]
    Empty,
    #[error("channel is closed")]
    Closed,
}

impl<T> Default for Channel<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[tokio::test]
    async fn chennel() {
        let ch = Arc::new(Channel::new());
        let ch2 = ch.clone();
        assert_eq!(ch.send(0), Ok(()));

        let t1 = tokio::spawn(async move {
            assert_eq!(ch.recv().await, Some(0));
            assert_eq!(ch.recv().await, Some(1));
            assert_eq!(ch.recv().await, Some(2));
            assert_eq!(ch.recv().await, Some(3));
            assert_eq!(ch.recv().await, None);
        });

        let t2 = tokio::spawn(async move {
            assert_eq!(ch2.send(1), Ok(()));
            tokio::task::yield_now().await;
            assert_eq!(ch2.send(2), Ok(()));
            tokio::task::yield_now().await;
            assert_eq!(ch2.send(3), Ok(()));
            tokio::task::yield_now().await;
            ch2.close();
            assert_eq!(ch2.send(4), Err(4));
            assert_eq!(ch2.send(5), Err(5));
        });

        t1.await.unwrap();
        t2.await.unwrap();
    }
}
