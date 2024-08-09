use std::{
    future::Future,
    ops::{Deref, DerefMut},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll, Waker},
};

use crate::{
    error::{Error, ErrorKind},
    frame::HandshakeDoneFrame,
    streamid::Role,
};

#[derive(Debug, Default, Clone)]
pub struct ClientHandshake(Arc<AtomicBool>);

impl ClientHandshake {
    fn is_handshake_done(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    fn recv_handshake_done_frame(&self, _frame: &HandshakeDoneFrame) {
        self.0.store(true, Ordering::Release);
    }
}

/// Server handshake status, divided into:
/// - Ok(Some(false)), handshake not successful, initial state;
/// - Err(waker), external query before handshake is successful, and external
///   waiting for handshake to complete to send HandshakeDone frame;
/// - Ok(Some(true)), handshake successful, changed to this state through the
///   done function, and waker is awakened.
/// - Ok(None) indicates that the handshake was abandoned halfway, the connection
///   ended before the handshake was completed.
///
/// The handshake is considered complete when the client's 1rtt data packet is successfully decrypted.
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
    pub fn with_role(role: Role) -> Self {
        match role {
            Role::Client => Handshake::Client(ClientHandshake::default()),
            Role::Server => Handshake::Server(ServerHandshake::default()),
        }
    }

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
    pub fn recv_handshake_done_frame(&self, frame: &HandshakeDoneFrame) -> Result<(), Error> {
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
    /// So as a client, it just print a warning log.
    pub fn done(&self) {
        match self {
            Handshake::Server(h) => h.done(),
            _ => println!("WARN: it doesn't make sense to call done() on a client handshake"),
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

    pub fn role(&self) -> Role {
        match self {
            Handshake::Client(_) => Role::Client,
            Handshake::Server(_) => Role::Server,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::HandshakeDoneFrame;
    use crate::error::{Error, ErrorKind};

    #[test]
    fn test_client_handshake() {
        let handshake = super::Handshake::new_client();
        assert!(!handshake.is_handshake_done());

        let ret = handshake.recv_handshake_done_frame(&HandshakeDoneFrame);
        assert!(ret.is_ok());
        assert!(handshake.is_handshake_done());
    }

    #[test]
    fn test_client_handshake_done() {
        let handshake = super::Handshake::new_client();
        assert!(!handshake.is_handshake_done());

        handshake.done();
        assert!(!handshake.is_handshake_done());
    }

    #[test]
    fn test_server_handshake() {
        let handshake = super::Handshake::new_server();
        assert!(!handshake.is_handshake_done());

        handshake.done();
        assert!(handshake.is_handshake_done());
    }

    #[test]
    fn test_server_recv_handshake_done_frame() {
        let handshake = super::Handshake::new_server();
        assert!(!handshake.is_handshake_done());

        let ret = handshake.recv_handshake_done_frame(&HandshakeDoneFrame);
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
        assert!(ret.is_pending());

        handshake.done();

        let ret = handshake.is_done().unwrap().poll_is_done(&mut cx);
        assert!(ret.is_ready());
    }
}
