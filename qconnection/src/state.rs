use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
};

use qbase::{error::Error, net::route::Link, role::Role};
use qevent::{
    quic::{
        Owner,
        connectivity::{
            BaseConnectionStates, ConnectionStarted, ConnectionState as QlogConnectionState,
            ConnectionStateUpdated, GranularConnectionStates,
        },
        transport::ParametersSet,
    },
    telemetry::Instrument,
};
use tokio::sync::Semaphore;
use tracing::Instrument as _;

use crate::Components;

#[derive(Clone)]
pub struct ArcConnState {
    state: Arc<AtomicU8>,
    handshaked: Arc<Semaphore>,
    terminated: Arc<Semaphore>,
}

impl Default for ArcConnState {
    fn default() -> Self {
        Self {
            state: Default::default(),
            handshaked: Arc::new(Semaphore::new(0)),
            terminated: Arc::new(Semaphore::new(0)),
        }
    }
}

impl ArcConnState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Attempt to set the connection state from None to `BaseConnectionStates::Attempted`.
    ///
    /// Returns true if the state was successfully set to `BaseConnectionStates::Attempted`.
    ///
    /// Called when creating paths. If it returns true, it means that the path is the first path to connect.
    pub fn try_entry_attempted(&self, components: &Components, link: Link) -> Result<bool, Error> {
        let attempted = encode(BaseConnectionStates::Attempted.into());
        let success = self
            .state
            .compare_exchange(0, attempted, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();

        if success {
            // same as Self::update
            qevent::event!(ConnectionStateUpdated {
                new: BaseConnectionStates::Attempted,
            });
            qevent::event!(ConnectionStarted {
                socket: { (link.src(), link.dst()) } // cid不在这一层，未知
            });

            match components.role() {
                Role::Client => {
                    let lock_guard = components.parameters.lock_guard();
                    if let Some(local_parameters) =
                        lock_guard.as_ref().ok().and_then(|p| p.client())
                    {
                        qevent::event!(ParametersSet {
                            owner: Owner::Local,
                            client_parameters: local_parameters.as_ref(),
                        })
                    }
                }
                Role::Server => {
                    let lock_guard = components.parameters.lock_guard();
                    if let Some(local_parameters) =
                        lock_guard.as_ref().ok().and_then(|p| p.server())
                    {
                        qevent::event!(ParametersSet {
                            owner: Owner::Local,
                            server_parameters: local_parameters.as_ref(),
                        })
                    }
                }
            };
        }
        Ok(success)
    }

    /// Try to update the connection state, return the old state if successful.
    pub fn update(&self, state: QlogConnectionState) -> Option<QlogConnectionState> {
        let new_state_code = encode(state);
        let mut old_state_code = self.state.load(Ordering::Acquire);
        loop {
            if new_state_code <= old_state_code {
                return None;
            }
            match self.state.compare_exchange(
                old_state_code,
                new_state_code,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_old_state_code) => {
                    // when server received a initial packet but failed to decrypt it, connection state will
                    // enter Closing directly without enter Attempted.
                    let old_state =
                        decode(old_state_code).unwrap_or(BaseConnectionStates::Attempted.into());
                    match state {
                        QlogConnectionState::Granular(
                            GranularConnectionStates::HandshakeConfirmed,
                        ) => {
                            self.handshaked.add_permits(1024);
                        }
                        QlogConnectionState::Granular(GranularConnectionStates::Closing)
                        | QlogConnectionState::Granular(GranularConnectionStates::Draining) => {
                            self.handshaked.close();
                            self.terminated.add_permits(1024);
                        }
                        _ => {}
                    }
                    qevent::event!(ConnectionStateUpdated {
                        new: state,
                        old: old_state
                    });
                    return Some(old_state);
                }
                Err(current_state_code) => old_state_code = current_state_code,
            }
        }
    }

    pub fn handshaked(&self) -> impl Future<Output = bool> + Send {
        let handshaked = self.handshaked.clone();
        async move { handshaked.acquire().await.is_ok() }
            .instrument_in_current()
            .in_current_span()
    }

    pub fn terminated(&self) -> impl Future<Output = ()> + Send {
        let terminated = self.terminated.clone();
        async move {
            _ = terminated
                .acquire()
                .await
                .expect("terminated semaphore should never be closed")
        }
        .instrument_in_current()
        .in_current_span()
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
                _ => unreachable!("base closed and granular closed are repeated, use the base one"),
            }
        }
    };
}

mapping! {
    QlogConnectionState::Base(BaseConnectionStates::Attempted) => 1,
    QlogConnectionState::Base(BaseConnectionStates::HandshakeStarted) => 2, // miss
    QlogConnectionState::Granular(GranularConnectionStates::PeerValidated) => 3, // miss
    QlogConnectionState::Granular(GranularConnectionStates::EarlyWrite) => 4, // miss
    QlogConnectionState::Base(BaseConnectionStates::HandshakeComplete) => 5, // miss
    QlogConnectionState::Granular(GranularConnectionStates::HandshakeConfirmed) => 6,
    QlogConnectionState::Granular(GranularConnectionStates::Closing) => 7,
    QlogConnectionState::Granular(GranularConnectionStates::Draining) => 8,
    // QlogConnectionState::Granular(GranularConnectionStates::Closed) => 9,
    QlogConnectionState::Base(BaseConnectionStates::Closed) => 9,
}
