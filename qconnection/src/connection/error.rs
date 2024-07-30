use std::{
    future::Future,
    ops::DerefMut,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use qbase::{error::Error, frame::ConnectionCloseFrame};

#[derive(Debug, Clone)]
enum RawConnError {
    Pending(Option<Waker>),
    App(Error),
    Closing(Error),
    Draining(Error),
}

impl Default for RawConnError {
    fn default() -> Self {
        Self::Pending(None)
    }
}

#[derive(Default, Debug, Clone)]
pub struct ConnError(Arc<Mutex<RawConnError>>);

impl ConnError {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn error_occur(&self) -> ConnErrorOccur {
        ConnErrorOccur(self.clone())
    }

    pub fn recv_ccf(&self, ccf: ConnectionCloseFrame) {
        let mut guard = self.0.lock().unwrap();
        let RawConnError::Pending(waker) = guard.deref_mut() else {
            return;
        };

        if let Some(waker) = waker.take() {
            waker.wake();
        }

        *guard = RawConnError::Draining(Error::from(ccf));
    }

    pub fn on_error(&self, error: Error) {
        let mut guard = self.0.lock().unwrap();
        let RawConnError::Pending(waker) = guard.deref_mut() else {
            return;
        };

        if let Some(waker) = waker.take() {
            waker.wake();
        }

        *guard = RawConnError::Closing(error);
    }

    pub fn error(&self, error: Error) {
        let mut guard = self.0.lock().unwrap();
        let RawConnError::Pending(waker) = guard.deref_mut() else {
            return;
        };

        if let Some(waker) = waker.take() {
            waker.wake();
        }

        *guard = RawConnError::App(error);
    }
}

/// impl Future::Output = (error: [`Error`], is_active: [`bool`])
pub struct ConnErrorOccur(ConnError);

impl Future for ConnErrorOccur {
    type Output = (Error, bool);

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut guard = self.0 .0.lock().unwrap();
        match std::mem::take(guard.deref_mut()) {
            RawConnError::Pending(_) => {
                *guard = RawConnError::Pending(Some(cx.waker().clone()));
                Poll::Pending
            }
            RawConnError::Closing(error) | RawConnError::App(error) => Poll::Ready((error, true)),
            RawConnError::Draining(error) => Poll::Ready((error, false)),
        }
    }
}
#[cfg(test)]
mod tests {
    use qbase::{error::ErrorKind, frame::FrameType::Padding};

    use super::*;

    #[tokio::test]
    async fn test_rcvd_ccf() {
        let conn_error = ConnError::new();

        let task = tokio::spawn({
            let conn_error = conn_error.clone();
            async move {
                let (_, is_active) = conn_error.error_occur().await;
                assert!(!is_active);
            }
        });

        let ccf = ConnectionCloseFrame::new(ErrorKind::Internal, None, "Test close frame".into());
        conn_error.recv_ccf(ccf);

        _ = task.await;
    }

    #[tokio::test]
    async fn test_transmit_error() {
        let conn_error = ConnError::new();

        let task = tokio::spawn({
            let conn_error = conn_error.clone();
            async move {
                let (_, is_active) = conn_error.error_occur().await;
                assert!(is_active);
            }
        });

        let error = Error::new(ErrorKind::Internal, Padding, "Test transmit error");
        conn_error.on_error(error);

        _ = task.await;
    }

    #[tokio::test]
    async fn test_app_error() {
        let conn_error = ConnError::new();

        let task = tokio::spawn({
            let conn_error = conn_error.clone();
            async move {
                let (_, is_active) = conn_error.error_occur().await;
                assert!(is_active);
            }
        });

        let error = Error::new(ErrorKind::Internal, Padding, "Test app error");
        conn_error.error(error);

        _ = task.await;
    }
}
