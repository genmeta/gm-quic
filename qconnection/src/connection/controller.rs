use std::{
    ops::DerefMut,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
};

use futures::Future;
use qbase::{error::Error, frame::ConnectionCloseFrame};

use super::{ArcConnectionState, ConnectionState, ConnectionStateData};

#[derive(Clone)]
pub struct ArcConnectionController {
    pub state: ArcConnectionState,
    data: Arc<Mutex<ConnectionStateData>>,
    wakers: Arc<[Mutex<Vec<Waker>>; 6]>,
}

impl ArcConnectionController {
    pub fn new(data: ConnectionStateData) -> Self {
        Self {
            state: ArcConnectionState::new(data.cur_state()),
            wakers: Default::default(),
            data: Mutex::new(data).into(),
        }
    }

    pub fn get_state(&self) -> ConnectionState {
        self.state.get_state()
    }

    fn set_state(&self, state: ConnectionState) {
        if state <= self.get_state() {
            return;
        }

        self.wakers[..=state as _]
            .iter()
            .map(|lock| lock.lock().unwrap())
            .flat_map(|mut wakers| std::mem::take(wakers.deref_mut()))
            .for_each(|waker| {
                waker.wake();
            });
        self.state.set_state(state)
    }

    pub fn enter_handshake(&self) {
        if self.get_state() >= ConnectionState::Handshaking {
            return;
        }
        self.set_state(ConnectionState::Handshaking);
        let mut guard = self.data.lock().unwrap();
        let state_data = guard.deref_mut();
        let cur_state_data = std::mem::replace(state_data, ConnectionStateData::Invalid);
        *state_data = match cur_state_data {
            ConnectionStateData::Initial {
                hs_pkt_queue,
                hs_keys,
                hs_space,
                zero_rtt_pkt_queue,
                zero_rtt_keys,
                one_rtt_pkt_queue,
                one_rtt_keys,
                data_space,
                flow_ctrl,
                spin,
                datagram_flow,
                conn_err_tx,
                rcvd_ccf_tx,
                init_keys,
                ..
            } => {
                init_keys.invalid();
                ConnectionStateData::Handshaking {
                    hs_pkt_queue,
                    hs_keys,
                    hs_space,
                    zero_rtt_pkt_queue,
                    zero_rtt_keys,
                    one_rtt_pkt_queue,
                    one_rtt_keys,
                    data_space,
                    flow_ctrl,
                    spin,
                    datagram_flow,
                    conn_err_tx,
                    rcvd_ccf_tx,
                }
            }
            _ => unreachable!(),
        };
    }

    pub fn enter_handshake_done(&self) {
        if self.get_state() >= ConnectionState::Normal {
            return;
        }
        self.set_state(ConnectionState::Normal);
        let mut guard = self.data.lock().unwrap();
        let state_data = guard.deref_mut();
        let cur_state_data = std::mem::replace(state_data, ConnectionStateData::Invalid);
        *state_data = match cur_state_data {
            ConnectionStateData::Handshaking {
                one_rtt_pkt_queue,
                one_rtt_keys,
                data_space,
                flow_ctrl,
                spin,
                datagram_flow,
                conn_err_tx,
                rcvd_ccf_tx,
                hs_keys,
                zero_rtt_keys,
                ..
            } => {
                hs_keys.invalid();
                zero_rtt_keys.invalid();
                ConnectionStateData::Normal {
                    one_rtt_pkt_queue,
                    one_rtt_keys,
                    data_space,
                    flow_ctrl,
                    spin,
                    datagram_flow,
                    conn_err_tx,
                    rcvd_ccf_tx,
                }
            }
            _ => unreachable!(),
        };
    }

    pub fn handle_connection_error(&self, error: Error) {
        let mut guard = self.data.lock().unwrap();
        let state_data = guard.deref_mut();
        match state_data {
            ConnectionStateData::Initial { conn_err_tx, .. }
            | ConnectionStateData::Handshaking { conn_err_tx, .. }
            | ConnectionStateData::Normal { conn_err_tx, .. } => {
                if let Some(tx) = conn_err_tx.take() {
                    let _ = tx.send(error);
                }
            }
            _ => {}
        }
    }

    pub(super) fn enter_closing(&self, ccf: ConnectionCloseFrame) {
        if self.get_state() >= ConnectionState::Closing {
            return;
        }
        let mut guard = self.data.lock().unwrap();
        let state_data = guard.deref_mut();
        let cur_state_data = std::mem::replace(state_data, ConnectionStateData::Invalid);
        let rcvd_ccf_tx = match cur_state_data {
            ConnectionStateData::Initial {
                init_keys,
                hs_keys,
                zero_rtt_keys,
                one_rtt_keys,
                rcvd_ccf_tx,
                ..
            } => {
                init_keys.invalid();
                hs_keys.invalid();
                zero_rtt_keys.invalid();
                one_rtt_keys.invalid();
                rcvd_ccf_tx
            }
            ConnectionStateData::Handshaking {
                hs_keys,
                zero_rtt_keys,
                one_rtt_keys,
                rcvd_ccf_tx,
                ..
            } => {
                hs_keys.invalid();
                zero_rtt_keys.invalid();
                one_rtt_keys.invalid();
                rcvd_ccf_tx
            }
            ConnectionStateData::Normal {
                one_rtt_keys,
                rcvd_ccf_tx,
                ..
            } => {
                one_rtt_keys.invalid();
                rcvd_ccf_tx
            }
            _ => None,
        };
        *state_data = ConnectionStateData::Closing {
            ccf: ccf.into(),
            rcvd_ccf_tx,
        };
    }

    pub fn handle_connection_close_frame(&self, ccf: ConnectionCloseFrame) {
        let mut guard = self.data.lock().unwrap();
        let state_data = guard.deref_mut();
        let tx = match state_data {
            ConnectionStateData::Initial { rcvd_ccf_tx, .. }
            | ConnectionStateData::Handshaking { rcvd_ccf_tx, .. }
            | ConnectionStateData::Normal { rcvd_ccf_tx, .. } => rcvd_ccf_tx.take(),
            _ => None,
        };
        if let Some(tx) = tx {
            let _ = tx.send(ccf);
        }
    }

    pub(super) fn enter_draining(&self) {
        if self.get_state() >= ConnectionState::Draining {
            return;
        }
        self.set_state(ConnectionState::Draining);
        let mut guard = self.data.lock().unwrap();
        let state_data = guard.deref_mut();
        match state_data {
            ConnectionStateData::Initial {
                init_keys,
                hs_keys,
                zero_rtt_keys,
                one_rtt_keys,
                ..
            } => {
                init_keys.invalid();
                hs_keys.invalid();
                zero_rtt_keys.invalid();
                one_rtt_keys.invalid();
            }
            ConnectionStateData::Handshaking {
                hs_keys,
                zero_rtt_keys,
                one_rtt_keys,
                ..
            } => {
                hs_keys.invalid();
                zero_rtt_keys.invalid();
                one_rtt_keys.invalid();
            }
            ConnectionStateData::Normal { one_rtt_keys, .. } => {
                one_rtt_keys.invalid();
            }
            _ => {}
        };
        *state_data = ConnectionStateData::Draining {};
    }

    pub(super) fn enter_closed(&self) {
        if self.get_state() >= ConnectionState::Draining {
            return;
        }
        self.set_state(ConnectionState::Closed);
        let mut guard = self.data.lock().unwrap();
        let state_data = guard.deref_mut();
        match state_data {
            ConnectionStateData::Initial {
                init_keys,
                hs_keys,
                zero_rtt_keys,
                one_rtt_keys,
                ..
            } => {
                init_keys.invalid();
                hs_keys.invalid();
                zero_rtt_keys.invalid();
                one_rtt_keys.invalid();
            }
            ConnectionStateData::Handshaking {
                hs_keys,
                zero_rtt_keys,
                ..
            } => {
                hs_keys.invalid();
                zero_rtt_keys.invalid();
            }
            ConnectionStateData::Normal { one_rtt_keys, .. } => {
                one_rtt_keys.invalid();
            }
            _ => {}
        };
        *state_data = ConnectionStateData::Invalid;
    }

    pub fn on_enter_state(&self, state: ConnectionState) -> OnEnterState {
        OnEnterState {
            wake_on: state,
            state: self.clone(),
        }
    }

    pub fn state_data_guard(&self) -> MutexGuard<'_, ConnectionStateData> {
        self.data.lock().unwrap()
    }
}

pub struct OnEnterState {
    wake_on: ConnectionState,
    state: ArcConnectionController,
}

impl Future for OnEnterState {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.wake_on <= self.state.get_state() {
            return Poll::Ready(());
        }

        self.state.wakers[self.wake_on as usize]
            .lock()
            .unwrap()
            .push(cx.waker().clone());

        Poll::Pending
    }
}
