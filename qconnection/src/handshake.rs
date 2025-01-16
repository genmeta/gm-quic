use std::sync::Arc;

use qbase::{
    error::Error,
    frame::{HandshakeDoneFrame, ReceiveFrame, SendFrame},
    sid::Role,
};
use qcongestion::ObserveHandshake;

use crate::events::{EmitEvent, Event};

pub type RawHandshake<T> = qbase::handshake::Handshake<T>;

/// A wrapper of [`qbase::handshake::Handshake`] that will emit [`Event::Handshaked`] when the handshake is done.
///
/// Read the documentation of [`qbase::handshake::Handshake`] for more information.
#[derive(Clone)]
pub struct Handshake<T>
where
    T: SendFrame<HandshakeDoneFrame> + Clone,
{
    inner: qbase::handshake::Handshake<T>,
    broker: Arc<dyn EmitEvent + Send + Sync>,
}

impl<T> Handshake<T>
where
    T: SendFrame<HandshakeDoneFrame> + Clone,
{
    pub fn new(raw: RawHandshake<T>, broker: Arc<dyn EmitEvent + Send + Sync>) -> Self {
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

impl<T> ObserveHandshake for Handshake<T>
where
    T: SendFrame<HandshakeDoneFrame> + Clone + Send + Sync,
{
    fn role(&self) -> qbase::sid::Role {
        self.inner.role()
    }

    fn is_handshake_done(&self) -> bool {
        self.inner.is_handshake_done()
    }

    fn is_getting_keys(&self) -> bool {
        self.inner.is_getting_keys()
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
