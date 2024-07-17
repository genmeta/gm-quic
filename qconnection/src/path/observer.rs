use qcongestion::{ObserveAntiAmplification, ObserveHandshake};

use super::{anti_amplifier::ANTI_FACTOR, ArcAntiAmplifier};
use crate::connection::state::{ArcConnectionState, ConnectionState};

#[derive(Debug, Clone)]
pub struct HandShakeObserver(ArcConnectionState);

impl HandShakeObserver {
    pub fn new(state: ArcConnectionState) -> Self {
        Self(state)
    }
}

impl ObserveHandshake for HandShakeObserver {
    fn is_handshake_done(&self) -> bool {
        self.0.get_state() >= ConnectionState::HandshakeDone
    }

    fn has_handshake_keys(&self) -> bool {
        self.0.get_state() >= ConnectionState::Handshaking
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionObserver {
    pub handshake_observer: HandShakeObserver,
}

impl ObserveHandshake for ConnectionObserver {
    fn is_handshake_done(&self) -> bool {
        self.handshake_observer.is_handshake_done()
    }

    fn has_handshake_keys(&self) -> bool {
        self.handshake_observer.has_handshake_keys()
    }
}

#[derive(Debug, Clone)]
pub struct PathObserver(ArcAntiAmplifier<ANTI_FACTOR>);

impl PathObserver {
    pub fn new(anti_amplifier: ArcAntiAmplifier<ANTI_FACTOR>) -> Self {
        Self(anti_amplifier)
    }
}

impl ObserveAntiAmplification for PathObserver {
    fn is_anti_amplification(&self) -> bool {
        self.0.is_ready()
    }
}
#[cfg(test)]
mod tests {}
