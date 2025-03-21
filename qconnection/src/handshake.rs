use qbase::{
    error::Error,
    frame::{HandshakeDoneFrame, ReceiveFrame, SendFrame},
    sid::Role,
};

use crate::events::{ArcEventBroker, EmitEvent, Event};

pub type RawHandshake<T> = qbase::handshake::Handshake<T>;

/// A wrapper of [`qbase::handshake::Handshake`] that will emit [`Event::Handshaked`] when the handshake is done.
///
/// Read the documentation of [`qbase::handshake::Handshake`] for more information.
#[derive(Clone)]
pub struct Handshake<T>
where
    T: SendFrame<HandshakeDoneFrame> + Clone,
{
    inner: RawHandshake<T>,
    broker: ArcEventBroker,
}

impl<T> Handshake<T>
where
    T: SendFrame<HandshakeDoneFrame> + Clone,
{
    pub fn new(raw: RawHandshake<T>, broker: ArcEventBroker) -> Self {
        Self { inner: raw, broker }
    }

    pub fn on_key_upgrade(&self) {
        self.inner.on_key_upgrade();
    }

    pub fn done(&self) {
        if self.inner.done() {
            self.broker.emit(Event::Handshaked);
        }
    }

    pub fn role(&self) -> Role {
        self.inner.role()
    }
}

impl<T> ReceiveFrame<HandshakeDoneFrame> for Handshake<T>
where
    T: SendFrame<HandshakeDoneFrame> + Clone,
{
    type Output = ();

    fn recv_frame(&self, frame: &HandshakeDoneFrame) -> Result<(), Error> {
        if self.inner.recv_frame(frame)? {
            self.broker.emit(Event::Handshaked);
        }
        Ok(())
    }
}
