use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use crate::{
    error::{Error, ErrorKind},
    frame::{HandshakeDoneFrame, ReceiveFrame, SendFrame},
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
pub struct ServerHandshake<T>
where
    T: SendFrame<HandshakeDoneFrame> + Clone,
{
    is_done: Arc<AtomicBool>,
    output: T,
}

impl<T> ServerHandshake<T>
where
    T: SendFrame<HandshakeDoneFrame> + Clone,
{
    fn new(output: T) -> Self {
        ServerHandshake {
            is_done: Arc::new(AtomicBool::new(false)),
            output,
        }
    }

    fn is_handshake_done(&self) -> bool {
        self.is_done.load(Ordering::Acquire)
    }

    fn done(&self) {
        if self
            .is_done
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.output.send_frame([HandshakeDoneFrame]);
        }
    }
}

#[derive(Debug, Clone)]
pub enum Handshake<T>
where
    T: SendFrame<HandshakeDoneFrame> + Clone,
{
    Client(ClientHandshake),
    Server(ServerHandshake<T>),
}

impl<T> Handshake<T>
where
    T: SendFrame<HandshakeDoneFrame> + Clone,
{
    pub fn new(role: Role, output: T) -> Self {
        match role {
            Role::Client => Handshake::Client(ClientHandshake::default()),
            Role::Server => Handshake::Server(ServerHandshake::new(output)),
        }
    }

    pub fn new_client() -> Self {
        Handshake::Client(ClientHandshake::default())
    }

    pub fn new_server(output: T) -> Self {
        Handshake::Server(ServerHandshake::new(output))
    }

    pub fn is_handshake_done(&self) -> bool {
        match self {
            Handshake::Client(h) => h.is_handshake_done(),
            Handshake::Server(h) => h.is_handshake_done(),
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

    pub fn role(&self) -> Role {
        match self {
            Handshake::Client(_) => Role::Client,
            Handshake::Server(_) => Role::Server,
        }
    }
}

/// See [RFC 9000 section 19.20](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.20):
/// A HANDSHAKE_DONE frame can only be sent by the server. Servers MUST NOT send a HANDSHAKE_DONE
/// frame before completing the handshake. A server MUST treat receipt of a HANDSHAKE_DONE frame
/// as a connection error of type PROTOCOL_VIOLATION.
impl<T> ReceiveFrame<HandshakeDoneFrame> for Handshake<T>
where
    T: SendFrame<HandshakeDoneFrame> + Clone,
{
    type Output = ();

    fn recv_frame(&self, frame: &HandshakeDoneFrame) -> Result<(), Error> {
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
}

#[cfg(test)]
mod tests {
    use super::{HandshakeDoneFrame, ServerHandshake};
    use crate::{
        error::{Error, ErrorKind},
        frame::ReceiveFrame,
        util::ArcAsyncDeque,
    };

    #[test]
    fn test_client_handshake() {
        let handshake = super::Handshake::<ArcAsyncDeque<_>>::new_client();
        assert!(!handshake.is_handshake_done());

        let ret = handshake.recv_frame(&HandshakeDoneFrame);
        assert!(ret.is_ok());
        assert!(handshake.is_handshake_done());
    }

    #[test]
    fn test_client_handshake_done() {
        let handshake = super::Handshake::<ArcAsyncDeque<_>>::new_client();
        assert!(!handshake.is_handshake_done());

        handshake.done();
        assert!(!handshake.is_handshake_done());
    }

    #[test]
    fn test_server_handshake() {
        let handshake = super::Handshake::new_server(ArcAsyncDeque::new());
        assert!(!handshake.is_handshake_done());

        handshake.done();
        assert!(handshake.is_handshake_done());
    }

    #[test]
    fn test_server_recv_handshake_done_frame() {
        let handshake = super::Handshake::new_server(ArcAsyncDeque::new());
        assert!(!handshake.is_handshake_done());

        let ret = handshake.recv_frame(&HandshakeDoneFrame);
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
        let handshake = ServerHandshake::new(ArcAsyncDeque::new());
        handshake.done();
        assert!(handshake.is_handshake_done());
        assert_eq!(handshake.output.len(), 1);
    }
}
