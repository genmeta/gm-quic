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
    Transmite(Error),
    App(Error),
    Peer(Error),
}

impl Default for RawConnError {
    fn default() -> Self {
        Self::Pending(None)
    }
}

#[derive(Default, Debug, Clone)]
pub struct ConnErrorTrigger(Arc<Mutex<RawConnError>>);

impl ConnErrorTrigger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn error_occur(&self) -> ConnErrorOccur {
        ConnErrorOccur::new(self.clone())
    }

    pub fn rcvd_ccf(&self, ccf: ConnectionCloseFrame) {
        let mut guard = self.0.lock().unwrap();
        let RawConnError::Pending(waker) = guard.deref_mut() else {
            return;
        };

        if let Some(waker) = waker.take() {
            waker.wake();
        }

        *guard = RawConnError::Peer(Error::from(ccf));
    }

    pub fn transmit_error(&self, error: Error) {
        let mut guard = self.0.lock().unwrap();
        let RawConnError::Pending(waker) = guard.deref_mut() else {
            return;
        };

        if let Some(waker) = waker.take() {
            waker.wake();
        }

        *guard = RawConnError::Transmite(error);
    }

    pub fn app_error(&self, error: Error) {
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

pub struct ConnErrorOccur(ConnErrorTrigger);

impl ConnErrorOccur {
    pub fn new(error: ConnErrorTrigger) -> Self {
        Self(error)
    }
}

pub struct ConnError {
    pub error: Error,
    pub is_active: bool,
}

impl Future for ConnErrorOccur {
    type Output = ConnError;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut guard = self.0 .0.lock().unwrap();
        match std::mem::take(guard.deref_mut()) {
            RawConnError::Pending(_) => {
                *guard = RawConnError::Pending(Some(cx.waker().clone()));
                Poll::Pending
            }
            RawConnError::Transmite(error) | RawConnError::App(error) => Poll::Ready(ConnError {
                error,
                is_active: true,
            }),
            RawConnError::Peer(error) => Poll::Ready(ConnError {
                error,
                is_active: false,
            }),
        }
    }
}
