use std::{
    future::Future,
    ops::DerefMut,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use qbase::{error::Error, frame::ConnectionCloseFrame};

#[derive(Debug, Clone, Default)]
enum ConnErrorState {
    #[default]
    None,
    Pending(Waker),
    App(Error),
    Closing(Error),
    Draining(Error),
}

/// Connection error, which is None first, and external can poll query whether an error has occurred.
/// Upon receiving a connection close frame or some other kind of error occured, it will notify external.
///
/// # Example
/// ```rust
/// use qbase::error::{Error, ErrorKind};
/// use qconnection::error::ConnError;
///
/// # async fn demo() {
/// let conn_err = ConnError::default();
/// tokio::spawn({
///     let conn_err = conn_err.clone();
///     async move {
///        let is_active = conn_err.await;
///        // or you can `let (error, is_active) = conn_err.did_error_occur().await;``
///         assert!(is_active);
///    }
/// });
/// conn_err.on_error(Error::with_default_fty(ErrorKind::Internal, "Test error"));
/// # }
/// ```
#[derive(Default, Debug, Clone)]
pub struct ConnError(Arc<Mutex<ConnErrorState>>);

impl ConnError {
    /// If there is an error, return an error, otherwise return None
    pub fn get_error(&self) -> Option<Error> {
        let guard = self.0.lock().unwrap();
        match *guard {
            ConnErrorState::Closing(ref error) | ConnErrorState::App(ref error) => {
                Some(error.clone())
            }
            ConnErrorState::Draining(ref error) => Some(error.clone()),
            _ => None,
        }
    }

    /// Just for being more semantic, it will return the same cloned instance.
    pub fn did_error_occur(&self) -> Self {
        self.clone()
    }

    /// When a connection close frame is received, it will change the state and wake the external if necessary.
    pub fn on_ccf_rcvd(&self, ccf: &ConnectionCloseFrame) {
        let mut guard = self.0.lock().unwrap();
        // ccf具有最高的优先级
        if let ConnErrorState::Pending(waker) = guard.deref_mut() {
            waker.wake_by_ref();
        }
        *guard = ConnErrorState::Draining(Error::from(ccf.clone()));
    }

    pub fn on_error(&self, error: Error) {
        let mut guard = self.0.lock().unwrap();
        match guard.deref_mut() {
            ConnErrorState::None => {
                *guard = ConnErrorState::Closing(error);
            }
            ConnErrorState::Pending(waker) => {
                waker.wake_by_ref();
                *guard = ConnErrorState::Closing(error);
            }
            _ => {}
        }
    }

    /// App actively close the connection with an error
    pub fn set_app_error(&self, error: Error) {
        let mut guard = self.0.lock().unwrap();
        match guard.deref_mut() {
            ConnErrorState::None => {
                *guard = ConnErrorState::App(error);
            }
            ConnErrorState::Pending(waker) => {
                waker.wake_by_ref();
                *guard = ConnErrorState::App(error);
            }
            _ => {}
        }
    }
}

/// impl Future::Output = (error: [`Error`], is_active: [`bool`])
impl Future for ConnError {
    type Output = bool;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut guard = self.0.lock().unwrap();
        match guard.deref_mut() {
            ConnErrorState::None | ConnErrorState::Pending(_) => {
                *guard = ConnErrorState::Pending(cx.waker().clone());
                Poll::Pending
            }
            ConnErrorState::Closing(_) | ConnErrorState::App(_) => Poll::Ready(true),
            ConnErrorState::Draining(_) => Poll::Ready(false),
        }
    }
}
#[cfg(test)]
mod tests {
    use qbase::{error::ErrorKind, frame::FrameType::Padding};

    use super::*;

    #[tokio::test]
    async fn test_rcvd_ccf() {
        let conn_error = ConnError::default();

        let task = tokio::spawn({
            let conn_error = conn_error.clone();
            async move {
                let is_active = conn_error.await;
                assert!(!is_active);
            }
        });

        let ccf = ConnectionCloseFrame::new(ErrorKind::Internal, None, "Test close frame".into());
        conn_error.on_ccf_rcvd(&ccf);

        _ = task.await;
    }

    #[tokio::test]
    async fn test_peer_error() {
        let conn_error = ConnError::default();

        let task = tokio::spawn({
            let conn_error = conn_error.clone();
            async move {
                let is_active = conn_error.await;
                assert!(is_active);
            }
        });

        let error = Error::new(ErrorKind::Internal, Padding, "Test transmit error");
        conn_error.on_error(error);

        _ = task.await;
    }

    #[tokio::test]
    async fn test_app_error() {
        let conn_error = ConnError::default();

        let task = tokio::spawn({
            let conn_error = conn_error.clone();
            async move {
                let is_active = conn_error.did_error_occur().await;
                assert!(is_active);
            }
        });

        let error = Error::new(ErrorKind::Internal, Padding, "Test app error");
        conn_error.set_app_error(error);

        _ = task.await;
    }
}
