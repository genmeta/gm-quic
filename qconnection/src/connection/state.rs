use std::sync::{atomic::AtomicU8, Arc};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd)]
pub enum ConnectionState {
    Initial = 0,
    Handshake = 1,
    // 这个状态有用吗？
    HandshakeDone = 2,
    Closing = 3,
    Draining = 4,
}

#[derive(Default, Debug)]
struct RawConnectionState {
    // Encoding the state into a single byte
    state: AtomicU8,
}

impl RawConnectionState {
    fn get_state(&self) -> ConnectionState {
        match self.state.load(std::sync::atomic::Ordering::Acquire) {
            0 => ConnectionState::Initial,
            1 => ConnectionState::Handshake,
            2 => ConnectionState::HandshakeDone,
            3 => ConnectionState::Closing,
            4 => ConnectionState::Draining,
            _ => unreachable!(),
        }
    }

    fn set_state(&self, state: ConnectionState) {
        self.state
            .store(state as u8, std::sync::atomic::Ordering::Release);
    }
}

impl RawConnectionState {}

#[derive(Default, Debug, Clone)]
pub struct ArcConnectionState(Arc<RawConnectionState>);

impl ArcConnectionState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_state(&self) -> ConnectionState {
        self.0.get_state()
    }

    pub fn set_state(&self, state: ConnectionState) {
        self.0.set_state(state)
    }
}
