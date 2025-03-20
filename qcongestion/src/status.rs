use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug)]
pub struct ConnectionStatus {
    is_server: AtomicBool,
    has_handshake_key: AtomicBool,
    has_received_handshake_ack: AtomicBool,
    is_handshake_confirmed: AtomicBool,
    is_at_anti_amplification_limit: AtomicBool,
}

impl ConnectionStatus {
    pub fn new(is_server: bool) -> Self {
        Self {
            is_server: AtomicBool::new(is_server),
            has_handshake_key: AtomicBool::new(false),
            has_received_handshake_ack: AtomicBool::new(false),
            is_handshake_confirmed: AtomicBool::new(false),
            is_at_anti_amplification_limit: AtomicBool::new(false),
        }
    }

    pub fn is_server(&self) -> bool {
        self.is_server.load(Ordering::Relaxed)
    }

    pub fn has_handshake_key(&self) -> bool {
        self.has_handshake_key.load(Ordering::Relaxed)
    }

    pub fn got_handshake_key(&self) {
        self.has_handshake_key.store(true, Ordering::Relaxed);
    }

    pub fn has_received_handshake_ack(&self) -> bool {
        self.has_received_handshake_ack.load(Ordering::Relaxed)
    }

    pub fn received_handshake_ack(&self) {
        self.has_received_handshake_ack
            .store(true, Ordering::Relaxed);
    }

    pub fn is_handshake_confirmed(&self) -> bool {
        self.is_handshake_confirmed.load(Ordering::Relaxed)
    }

    pub fn handshake_confirmed(&self) {
        self.is_handshake_confirmed.store(true, Ordering::Relaxed);
    }

    pub fn is_at_anti_amplification_limit(&self) -> bool {
        self.is_at_anti_amplification_limit.load(Ordering::Relaxed)
    }

    pub fn enter_anti_amplification_limit(&self) {
        self.is_at_anti_amplification_limit
            .store(true, Ordering::Release);
    }

    pub fn release_anti_amplification_limit(&self) {
        self.is_at_anti_amplification_limit
            .store(false, Ordering::Release);
    }
}
