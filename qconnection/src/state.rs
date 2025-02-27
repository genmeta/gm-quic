use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};

use qinterface::path::Link;
use qlog::quic::{
    Owner,
    connectivity::{
        BaseConnectionStates, ConnectionStarted, ConnectionState as QlogConnectionState,
        ConnectionStateUpdated, GranularConnectionStates,
    },
    transport::ParametersSet,
};

use crate::Components;

#[derive(Default, Clone)]
pub struct ConnState(Arc<AtomicU8>);

impl ConnState {
    pub fn new() -> Self {
        Self(Arc::new(AtomicU8::new(0)))
    }

    /// Attempt to set the connection state from None to `BaseConnectionStates::Attempted`.
    ///
    /// Returns true if the state was successfully set to `BaseConnectionStates::Attempted`.
    ///
    /// Called when creating paths. If it returns true, it means that the path is the first path to connect.
    pub fn try_entry_attempted(&self, components: &Components, link: Link) -> bool {
        let attempted = encode(BaseConnectionStates::Attempted.into());
        let success = self
            .0
            .compare_exchange(0, attempted, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();

        if success {
            qlog::event!(ConnectionStateUpdated {
                new: BaseConnectionStates::Attempted,
            });
            qlog::event!(ConnectionStarted {
                socket: { (link.src(), link.dst()) } // cid不在这一层，未知
            });
            match components.handshake.role() {
                qbase::sid::Role::Client => qlog::event!(ParametersSet {
                    owner: Owner::Local,
                    client_parameters: components.parameters.client().expect("unreachable"),
                }),
                qbase::sid::Role::Server => qlog::event!(ParametersSet {
                    owner: Owner::Local,
                    server_parameters: components.parameters.server().expect("unreachable"),
                }),
            }
        }
        success
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
