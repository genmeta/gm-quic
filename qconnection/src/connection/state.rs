use std::sync::{atomic::AtomicU8, Arc};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd)]
pub enum ConnectionState {
    Initial = 0,
    Handshaking = 1,
    HandshakeDone = 2,
    Closing = 3,
    Draining = 4,
    Closed = 5,
}

#[derive(Default, Clone)]
pub struct ArcConnectionState(Arc<AtomicU8>);

impl ArcConnectionState {
    pub fn new(state: ConnectionState) -> Self {
        Self(AtomicU8::new(state as _).into())
    }

    pub fn get_state(&self) -> ConnectionState {
        match self.0.load(std::sync::atomic::Ordering::Acquire) {
            0 => ConnectionState::Initial,
            1 => ConnectionState::Handshaking,
            2 => ConnectionState::HandshakeDone,
            3 => ConnectionState::Closing,
            4 => ConnectionState::Draining,
            _ => unreachable!(),
        }
    }

    pub(super) fn set_state(&self, state: ConnectionState) {
        self.0
            .store(state as u8, std::sync::atomic::Ordering::Release);
    }
}
