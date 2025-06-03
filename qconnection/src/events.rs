use std::sync::Arc;

use qbase::{
    error::QuicError,
    frame::ConnectionCloseFrame,
    net::{
        address::BindAddr,
        route::{Link, Pathway},
    },
};
use qevent::quic::connectivity::{BaseConnectionStates, GranularConnectionStates};
use tokio::sync::mpsc;

use crate::state::ConnState;

/// The events that can be emitted by a quic connection
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    // The connection is handshaked
    Handshaked,
    // Received a packet from a new path and successfully decrypted the packet
    ProbedNewPath(Pathway, Link),
    // Path become inactivated, or removed by application
    PathInactivated(BindAddr, Pathway, Link),
    // An Error occurred during the connection, will enter the closing state
    Failed(QuicError),
    // The connection is closed by application, just a notification
    ApplicationClose,
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
pub struct ArcEventBroker {
    conn_state: ConnState,
    raw_broker: Arc<dyn EmitEvent>,
}

impl ArcEventBroker {
    pub fn new<E: EmitEvent + 'static>(conn_state: ConnState, event_broker: E) -> Self {
        Self {
            conn_state,
            raw_broker: Arc::new(event_broker),
        }
    }
}

impl EmitEvent for ArcEventBroker {
    fn emit(&self, event: Event) {
        match &event {
            Event::Handshaked => {
                let handshaked_state = GranularConnectionStates::HandshakeConfirmed;
                if self.conn_state.update(handshaked_state.into()).is_none() {
                    return;
                }
            }
            Event::ApplicationClose | Event::Failed(..) => {
                let terminator = GranularConnectionStates::Closing;
                if self.conn_state.update(terminator.into()).is_none() {
                    return;
                }
            }
            Event::Closed(..) => {
                let draining_state = GranularConnectionStates::Draining;
                if self.conn_state.update(draining_state.into()).is_none() {
                    return;
                }
            }
            Event::Terminated => {
                let terminated_state = BaseConnectionStates::Closed;
                self.conn_state.update(terminated_state.into());
            }
            Event::StatelessReset => todo!("unsupported"),
            _ => { /* path create/inactive: no need */ }
        };
        tracing::info!(status = ?event, "connection");
        self.raw_broker.emit(event);
    }
}

impl EmitEvent for mpsc::UnboundedSender<Event> {
    fn emit(&self, event: Event) {
        _ = self.send(event);
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
