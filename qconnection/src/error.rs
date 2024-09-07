use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use qbase::{
    error::Error,
    frame::ConnectionCloseFrame,
    util::{AsyncCell, GetRef},
};

#[derive(Debug, Clone)]
pub enum ConnErrorKind {
    Application(Error),
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
///        let (_err, is_active) = conn_err.error_occur().await;
///        // or you can `let (error, is_active) = conn_err.error_occur().await;``
///         assert!(is_active);
///    }
/// });
/// conn_err.on_error(Error::with_default_fty(ErrorKind::Internal, "Test error"));
/// # }
/// ```
#[derive(Default, Debug, Clone)]
pub struct ConnError(Arc<AsyncCell<ConnErrorKind>>);

impl ConnError {
    /// Returns a `ConnError` instance that can be used to track connection errors.
    ///
    /// This method simply clones the current `ConnError` instance and returns it.
    /// The returned instance can then be used to poll for connection errors using its `Future` implementation.
    pub fn error_occur(&self) -> ConnErrorOccured {
        ConnErrorOccured(self.0.get())
    }

    /// When a connection close frame is received, it will change the state and wake the external if necessary.
    pub fn on_ccf_rcvd(&self, ccf: &ConnectionCloseFrame) {
        _ = self
            .0
            .write(ConnErrorKind::Draining(Error::from(ccf.clone())));
    }

    pub fn on_error(&self, error: Error) {
        let mut state = self.0.get_inner();
        if state.is_pending() {
            _ = state.write(ConnErrorKind::Closing(error));
        }
    }

    /// App actively close the connection with an error
    pub fn set_app_error(&self, error: Error) {
        let mut state = self.0.get_inner();
        if state.is_pending() {
            _ = state.write(ConnErrorKind::Application(error));
        }
    }
}

/// A future that resolves when a connection error occurs.
///
/// This future is used to track the state of a connection and determine whether it is closing
/// due to an application error or draining gracefully. It implements the `Future` trait, allowing
/// it to be polled for completion.
pub struct ConnErrorOccured<'e>(GetRef<'e, ConnErrorKind>);

impl Future for ConnErrorOccured<'_> {
    /// The output of the `ConnError` future.
    ///
    /// `true` indicates that the connection is closing or has been closed due to an application error.
    /// `false` indicates that the connection is draining and will be closed gracefully.
    type Output = (Error, bool);

    /// Polls the `ConnError` future for completion.
    ///
    /// This method checks the internal state of the connection error.
    ///
    /// - If the state is `None` or `Pending`, it registers the current waker and returns `Poll::Pending`.
    /// - If the state is `Closing` or `App`, it returns `Poll::Ready(true)`, indicating that the connection is closing or has been closed due to an application error.
    /// - If the state is `Draining`, it returns `Poll::Ready(false)`, indicating that the connection is draining and will be closed gracefully.
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match core::task::ready!(self.get_mut().0.poll(cx).map(|cell| cell.as_ref().cloned()))
            .expect("connection error shound never be retired")
        {
            ConnErrorKind::Application(e) => Poll::Ready((e, true)),
            ConnErrorKind::Closing(e) => Poll::Ready((e, true)),
            ConnErrorKind::Draining(e) => Poll::Ready((e, false)),
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
                let (_, is_active) = conn_error.error_occur().await;
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
        let conn_error = ConnError::default();

        let task = tokio::spawn({
            let conn_error = conn_error.clone();
            async move {
                let (_, is_active) = conn_error.error_occur().await;
                assert!(is_active);
            }
        });

        let error = Error::new(ErrorKind::Internal, Padding, "Test app error");
        conn_error.set_app_error(error);

        _ = task.await;
    }
}
