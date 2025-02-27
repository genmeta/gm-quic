use std::sync::Arc;

use qbase::{
    error::Error,
    frame::ConnectionCloseFrame,
    net::{Link, Pathway},
};
use tokio::sync::mpsc;

/// The events that can be emitted by a quic connection
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    // The connection is handshaked
    Handshaked,
    // Received a packet from a new path and successfully decrypted the packet
    ProbedNewPath(Pathway, Link),
    // Path become inactivated, or removed by application
    PathInactivated(Pathway, Link),
    // An Error occurred during the connection, will enter the closing state
    Failed(Error),
    // Received a connection close frame, will enter the draining state
    Closed(ConnectionCloseFrame),
    // Received a stateless reset, will enter the draining state
    StatelessReset,
    // The connection is terminated completely
    Terminated,
}

pub trait EmitEvent: Send + Sync {
    fn emit(&self, event: Event);
}

#[derive(Clone)]
pub struct ArcEventBroker(Arc<dyn EmitEvent>);

impl ArcEventBroker {
    pub fn new<E: EmitEvent + 'static>(event_broker: E) -> Self {
        Self(Arc::new(event_broker))
    }
}

impl EmitEvent for ArcEventBroker {
    fn emit(&self, event: Event) {
        tracing::info!(?event, "event occurs");
        self.0.emit(event);
    }
}

impl EmitEvent for mpsc::UnboundedSender<Event> {
    fn emit(&self, event: Event) {
        let _ = self.send(event);
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::mpsc;

    use super::*;

    #[test]
    fn test_emit_event() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        tx.emit(Event::Handshaked);
        assert_eq!(rx.try_recv().unwrap(), Event::Handshaked);
    }
}
