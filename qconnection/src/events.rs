use std::sync::Arc;

use qbase::{
    error::{Error, QuicError},
    frame::ConnectionCloseFrame,
    net::{
        addr::BindUri,
        route::{Link, Pathway},
    },
};
use qevent::quic::connectivity::{BaseConnectionStates, GranularConnectionStates};
use tokio::sync::mpsc;

use crate::state::ArcConnState;

/// The events that can be emitted by a quic connection
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    // The connection is handshaked
    Handshaked,
    // Received a packet from a new path and successfully decrypted the packet
    ProbedNewPath(Pathway, Link),
    // Path become deactivated, or removed by application
    PathDeactivated(BindUri, Pathway, Link),
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
    conn_state: ArcConnState,
    raw_broker: Arc<dyn EmitEvent>,
}

impl ArcEventBroker {
    pub fn new<E: EmitEvent + 'static>(conn_state: ArcConnState, event_broker: E) -> Self {
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
                let state = GranularConnectionStates::HandshakeConfirmed;
                if self.conn_state.update(state.into(), || None).is_none() {
                    return;
                }
            }
            Event::ApplicationClose => {
                let state = GranularConnectionStates::Closing;
                let reason = || Some("application close".to_string());
                if self.conn_state.update(state.into(), reason).is_none() {
                    return;
                }
            }
            Event::Failed(error) => {
                let state = GranularConnectionStates::Closing;
                let reason = || Some(error.to_string());
                if self.conn_state.update(state.into(), reason).is_none() {
                    return;
                }
            }
            Event::Closed(ccf) => {
                let state = GranularConnectionStates::Draining;
                let reason = || Some(Error::from(ccf.clone()).to_string());
                if self.conn_state.update(state.into(), reason).is_none() {
                    return;
                }
            }
            Event::Terminated => {
                let state = BaseConnectionStates::Closed;
                self.conn_state.update(state.into(), || None);
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
