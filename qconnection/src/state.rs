use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc,
};

use qlog::quic::connectivity::{
    BaseConnectionStates, ConnectionState as QlogConnectionState, GranularConnectionStates,
};

#[derive(Default, Clone)]
pub struct ConnState(Arc<AtomicU8>);

impl ConnState {
    pub fn new() -> Self {
        Self(Arc::new(AtomicU8::new(0)))
    }

    pub fn try_entry_attempted(&self) -> bool {
        let attempted = encode(BaseConnectionStates::Attempted.into());
        self.0
            .compare_exchange(0, attempted, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    pub fn update(&self, state: QlogConnectionState) -> Option<QlogConnectionState> {
        decode(self.0.swap(encode(state), Ordering::Release))
    }

    pub fn set(&self, state: QlogConnectionState) {
        self.0.store(encode(state), Ordering::Release);
    }

    pub fn load(&self) -> Option<QlogConnectionState> {
        decode(self.0.load(Ordering::Acquire))
    }
}

macro_rules! mapping {
    ($( $a:ident ::$ b:ident ( $c:ident :: $d:ident ) => $number:literal, )*) => {
        pub fn decode(code: u8) -> Option<QlogConnectionState> {
            match code {
                $( $number => Some($a::$b($c::$d)), )*
                _ => None,
            }
        }

        pub fn encode(state: QlogConnectionState) -> u8 {
            match state {
                $( $a::$b($c::$d) => $number, )*
            }
        }
    };
}

mapping! {
    QlogConnectionState::Base(BaseConnectionStates::Attempted) => 1,
    QlogConnectionState::Base(BaseConnectionStates::HandshakeStarted) => 2,
    QlogConnectionState::Base(BaseConnectionStates::HandshakeComplete) => 3,
    QlogConnectionState::Base(BaseConnectionStates::Closed) => 4,
    QlogConnectionState::Granular(GranularConnectionStates::PeerValidated) => 5,
    QlogConnectionState::Granular(GranularConnectionStates::EarlyWrite) => 6,
    QlogConnectionState::Granular(GranularConnectionStates::HandshakeConfirmed) => 7,
    // infact, unreliable
    QlogConnectionState::Granular(GranularConnectionStates::Closing) => 8,
    QlogConnectionState::Granular(GranularConnectionStates::Draining) => 9,
    QlogConnectionState::Granular(GranularConnectionStates::Closed) => 10,
}
