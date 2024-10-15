use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use qbase::{
    error::{Error, ErrorKind},
    frame::ConnectionCloseFrame,
    util::Future,
};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnErrorKind {
    Application,
    Transport,
    CcfReceived,
    NoViablePath,
}

/// Connection error, which is None first, and external can poll query whether an error has occurred.
/// Upon receiving a connection close frame or some other kind of error occured, it will notify external.
///
/// # Example
/// ```rust
/// use qbase::error::{Error, ErrorKind};
/// use qconnection::error::{ConnError, ConnErrorKind};
///
/// # async fn demo() {
/// let conn_err = ConnError::default();
/// tokio::spawn({
///     let conn_err = conn_err.clone();
///     async move {
///        let (_err, kind) = conn_err.await;
///         assert_eq!(kind, ConnErrorKind::Transport);
///    }
/// });
/// conn_err.on_error(Error::with_default_fty(ErrorKind::Internal, "Test error"));
/// # }
/// ```
#[derive(Default, Debug, Clone)]
pub struct ConnError(Arc<Future<(Error, ConnErrorKind)>>);

impl ConnError {
    /// Returns a `ConnError` instance that can be used to track connection errors.
    ///
    /// This method simply clones the current `ConnError` instance and returns it.
    /// The returned instance can then be used to poll for connection errors using its `Future` implementation.
    pub fn did_error_occur(&self) -> Self {
        self.clone()
    }

    /// When a connection close frame is received, it will change the state and wake the external if necessary.
    pub fn on_ccf_rcvd(&self, ccf: &ConnectionCloseFrame) {
        _ = self
            .0
            .assign((Error::from(ccf.clone()), ConnErrorKind::CcfReceived));
    }

    pub fn on_error(&self, error: Error) {
        _ = self.0.assign((error, ConnErrorKind::Transport));
    }

    /// App actively close the connection with an error
    pub fn set_app_error(&self, error: Error) {
        _ = self.0.assign((error, ConnErrorKind::Application));
    }

    pub fn no_viable_path(&self) {
        _ = self.0.assign((
            // the error wont been read(
            Error::with_default_fty(ErrorKind::NoViablePath, "No viable path"),
            ConnErrorKind::NoViablePath,
        ));
    }
}

/// A future that resolves when a connection error occurs.
///
/// This future is used to track the state of a connection and determine whether it is closing
/// due to an application error or draining gracefully. It implements the `Future` trait, allowing
/// it to be polled for completion.
impl std::future::Future for ConnError {
    /// The output of the `ConnError` future.
    type Output = (Error, ConnErrorKind);

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.poll_get(cx)
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
                let (_, kind) = conn_error.await;
                assert_eq!(kind, ConnErrorKind::CcfReceived);
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
                let (_, kind) = conn_error.await;
                assert_eq!(kind, ConnErrorKind::Transport);
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
                let (_, kind) = conn_error.did_error_occur().await;
                assert_eq!(kind, ConnErrorKind::Application);
            }
        });

        let error = Error::new(ErrorKind::Internal, Padding, "Test app error");
        conn_error.set_app_error(error);

        _ = task.await;
    }
}
