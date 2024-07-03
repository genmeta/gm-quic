use std::sync::{atomic::AtomicU8, Arc};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Handshaking = 0,
    // 这个状态有用吗？
    HandshakeDone = 1,
    Closing = 2,
    Draining = 3,
}

#[derive(Default, Debug)]
struct RawConnectionState {
    // Encoding the state into a single byte
    state: AtomicU8,
}

impl RawConnectionState {
    fn get_state(&self) -> ConnectionState {
        match self.state.load(std::sync::atomic::Ordering::Acquire) {
            0 => ConnectionState::Handshaking,
            1 => ConnectionState::HandshakeDone,
            2 => ConnectionState::Closing,
            3 => ConnectionState::Draining,
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
