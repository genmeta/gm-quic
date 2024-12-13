use futures::channel::mpsc;
use qbase::{error::Error, frame::ConnectionCloseFrame};

#[derive(Debug, Clone)]
pub enum ConnEvent {
    ReceivedCcf(ConnectionCloseFrame),
    ApplicationClose,
    TransportError(Error),
    NoViablePath,
}

impl From<ConnectionCloseFrame> for ConnEvent {
    fn from(v: ConnectionCloseFrame) -> Self {
        Self::ReceivedCcf(v)
    }
}

impl From<Error> for ConnEvent {
    fn from(v: Error) -> Self {
        Self::TransportError(v)
    }
}

impl From<qbase::packet::error::Error> for ConnEvent {
    fn from(v: qbase::packet::error::Error) -> Self {
        Self::TransportError(v.into())
    }
}

#[derive(Debug, Clone)]
pub struct ConnEventBroker {
    tx: mpsc::UnboundedSender<ConnEvent>,
}

impl ConnEventBroker {
    pub fn publish(&self, event: ConnEvent) {
        _ = self.tx.unbounded_send(event);
    }
}

pub struct ConnEventHandler {
    rx: mpsc::UnboundedReceiver<ConnEvent>,
}

impl ConnEventHandler {
    pub fn watch(self) {
        _ = self;
    }
}

pub fn pair() -> (ConnEventBroker, ConnEventHandler) {
    let (tx, rx) = mpsc::unbounded();
    (ConnEventBroker { tx }, ConnEventHandler { rx })
}
