use std::convert::Infallible;

use futures::channel::mpsc;
use qbase::{error::Error, frame::ConnectionCloseFrame};

use super::util::subscribe;

pub enum ConnEvent {
    ApplicationClose,
    TransportError(Error),
    ReceivedCcf(ConnectionCloseFrame),
}

impl From<Error> for ConnEvent {
    fn from(v: Error) -> Self {
        Self::TransportError(v)
    }
}

impl From<ConnectionCloseFrame> for ConnEvent {
    fn from(v: ConnectionCloseFrame) -> Self {
        Self::ReceivedCcf(v)
    }
}

#[derive(Debug, Clone)]
pub struct EventBroker {
    tx: mpsc::UnboundedSender<ConnEvent>,
}

impl subscribe::Subscribe<ConnEvent> for EventBroker {
    type Error = Infallible;

    fn deliver(&self, event: ConnEvent) -> Result<(), Self::Error> {
        _ = self.tx.unbounded_send(event);
        Ok(())
    }
}

pub struct ConnEvents {
    rx: mpsc::UnboundedReceiver<ConnEvent>,
}

impl futures::Stream for ConnEvents {
    type Item = ConnEvent;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        core::pin::Pin::new(&mut self.get_mut().rx).poll_next(cx)
    }
}

pub fn pipeline() -> (EventBroker, ConnEvents) {
    let (tx, rx) = mpsc::unbounded();
    (EventBroker { tx }, ConnEvents { rx })
}
