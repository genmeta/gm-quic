use std::{
    future::Future,
    ops::{Deref, DerefMut},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use crate::{
    error::{Error, ErrorKind},
    frame::HandshakeDoneFrame,
};

#[derive(Debug, Default, Clone)]
pub struct ClientHandshake(Arc<Mutex<bool>>);

impl ClientHandshake {
    fn is_handshake_done(&self) -> bool {
        *self.0.lock().unwrap()
    }

    fn recv_handshake_done_frame(&self, _frame: HandshakeDoneFrame) {
        *self.0.lock().unwrap() = true;
    }
}

#[derive(Debug, Clone)]
pub struct ServerHandshake(Arc<Mutex<Result<Option<bool>, Waker>>>);

impl Default for ServerHandshake {
    fn default() -> Self {
        ServerHandshake(Arc::new(Mutex::new(Ok(Some(false)))))
    }
}

impl ServerHandshake {
    fn is_handshake_done(&self) -> bool {
        let guard = self.0.lock().unwrap();
        matches!(guard.deref(), Ok(Some(true)))
    }

    fn poll_is_done(&self, cx: &mut Context<'_>) -> Poll<Option<()>> {
        let mut guard = self.0.lock().unwrap();
        match guard.deref_mut() {
            Ok(Some(true)) => Poll::Ready(Some(())),
            Ok(Some(false)) => {
                *guard = Err(cx.waker().clone());
                Poll::Pending
            }
            Err(ref mut w) => {
                w.clone_from(cx.waker());
                Poll::Pending
            }
            Ok(None) => Poll::Ready(None),
        }
    }

    fn is_done(&self) -> ServerHandshake {
        // because itself impl Future<Output=bool>, can be awaited for the result
        self.clone()
    }

    fn done(&self) {
        let mut guard = self.0.lock().unwrap();
        match guard.deref_mut() {
            Ok(Some(false)) => *guard = Ok(Some(true)),
            Err(w) => {
                w.wake_by_ref();
                *guard = Ok(Some(true));
            }
            _ => (),
        }
    }

    fn abort(&self) {
        let mut guard = self.0.lock().unwrap();
        match guard.deref_mut() {
            Err(w) => {
                w.wake_by_ref();
                *guard = Ok(None);
            }
            Ok(Some(false)) => *guard = Ok(None),
            _ => (),
        }
    }
}

impl Future for ServerHandshake {
    type Output = Option<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.poll_is_done(cx)
    }
}

#[derive(Debug, Clone)]
pub enum Handshake {
    Client(ClientHandshake),
    Server(ServerHandshake),
}

impl Handshake {
    pub fn new_client() -> Self {
        Handshake::Client(ClientHandshake::default())
    }

    pub fn new_server() -> Self {
        Handshake::Server(ServerHandshake::default())
    }

    pub fn is_handshake_done(&self) -> bool {
        match self {
            Handshake::Client(h) => h.is_handshake_done(),
            Handshake::Server(h) => h.is_handshake_done(),
        }
    }

    /// See [RFC 9000 section 19.20](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.20):
    /// A HANDSHAKE_DONE frame can only be sent by the server. Servers MUST NOT send a HANDSHAKE_DONE
    /// frame before completing the handshake. A server MUST treat receipt of a HANDSHAKE_DONE frame
    /// as a connection error of type PROTOCOL_VIOLATION.
    pub fn recv_handshake_done_frame(&self, frame: HandshakeDoneFrame) -> Result<(), Error> {
        match self {
            Handshake::Client(h) => {
                h.recv_handshake_done_frame(frame);
                Ok(())
            }
            _ => Err(Error::with_default_fty(
                ErrorKind::ProtocolViolation,
                "Server received a HANDSHAKE_DONE frame",
            )),
        }
    }

    /// Just like `recv_handshake_done_frame`, a client must wait for a HANDSHAKE_DONE frame to be done.
    /// or it should return a PROTOCOL_VIOLATION error.
    pub fn done(&self) -> Result<(), Error> {
        match self {
            Handshake::Server(h) => {
                h.done();
                Ok(())
            }
            _ => Err(Error::with_default_fty(
                ErrorKind::ProtocolViolation,
                "Client handshake must wait for a HANDSHAKE_DONE frame to be done",
            )),
        }
    }

    /// Bypass role check. If it returns a Some(future), a task needs to be created to listen
    /// for when to send the HANDSHAKE_DONE frame.
    /// # Example
    /// ```rust
    /// use qbase::handshake::Handshake;
    ///
    /// # async fn monitor_hs_done(handshake: Handshake) {
    /// if let Some(is_handshake_done) = handshake.is_done() {
    ///     tokio::spawn(async move {
    ///         match is_handshake_done.await {
    ///             Some(_) => { /* send HANDSHAKE_DONE frame */ },
    ///             None => { /* abort the handshake, do nothing */ },
    ///         }
    ///     });
    /// }
    /// # }
    /// ```
    pub fn is_done(&self) -> Option<ServerHandshake> {
        match self {
            Handshake::Server(h) => Some(h.is_done()),
            _ => None,
        }
    }

    pub fn abort(&self) {
        if let Handshake::Server(h) = self {
            h.abort()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::task::Poll;

    use super::HandshakeDoneFrame;
    use crate::error::{Error, ErrorKind};

    #[test]
    fn test_client_handshake() {
        let handshake = super::Handshake::new_client();
        assert_eq!(handshake.is_handshake_done(), false);

        let ret = handshake.recv_handshake_done_frame(HandshakeDoneFrame);
        assert_eq!(ret, Ok(()));
        assert_eq!(handshake.is_handshake_done(), true);
    }

    #[test]
    fn test_client_handshake_done() {
        let handshake = super::Handshake::new_client();
        assert_eq!(handshake.is_handshake_done(), false);

        let ret = handshake.done();
        assert_eq!(
            ret,
            Err(Error::with_default_fty(
                ErrorKind::ProtocolViolation,
                "Client handshake must wait for a HANDSHAKE_DONE frame to be done",
            ))
        );
    }

    #[test]
    fn test_server_handshake() {
        let handshake = super::Handshake::new_server();
        assert_eq!(handshake.is_handshake_done(), false);

        let ret = handshake.done();
        assert_eq!(ret, Ok(()));
        assert_eq!(handshake.is_handshake_done(), true);
    }

    #[test]
    fn test_server_recv_handshake_done_frame() {
        let handshake = super::Handshake::new_server();
        assert_eq!(handshake.is_handshake_done(), false);

        let ret = handshake.recv_handshake_done_frame(HandshakeDoneFrame);
        assert_eq!(
            ret,
            Err(Error::with_default_fty(
                ErrorKind::ProtocolViolation,
                "Server received a HANDSHAKE_DONE frame",
            ))
        );
    }

    #[test]
    fn test_server_send_handshake_done_frame() {
        let handshake = super::Handshake::new_server();
        let waker = futures::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);

        let ret = handshake.is_done().unwrap().poll_is_done(&mut cx);
        assert_eq!(ret, Poll::Pending);

        let ret = handshake.done();
        assert!(ret.is_ok());

        let ret = handshake.is_done().unwrap().poll_is_done(&mut cx);
        assert_eq!(ret, Poll::Ready(Some(())));
    }
}
