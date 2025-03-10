use std::{
    io, mem,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use qbase::{cid::ConnectionId, error::Error, frame::ConnectionCloseFrame, net::route::Pathway};
use qinterface::queue::RcvdPacketQueue;

use crate::{ArcLocalCids, Components, path::ArcPathContexts};

pub struct ClosingState {
    last_recv_time: Mutex<Instant>,
    rcvd_packets: AtomicUsize,
    scid: Option<ConnectionId>,
    dcid: Option<ConnectionId>,
    ccf: ConnectionCloseFrame,
    paths: ArcPathContexts,
    rcvd_pkt_q: Arc<RcvdPacketQueue>,
}

impl ClosingState {
    pub fn new(ccf: ConnectionCloseFrame, components: &Components) -> Self {
        Self {
            last_recv_time: Mutex::new(Instant::now()),
            rcvd_packets: AtomicUsize::new(0),
            scid: components.cid_registry.local.initial_scid(),
            dcid: components.cid_registry.remote.latest_dcid(),
            ccf,
            paths: components.paths.clone(),
            rcvd_pkt_q: components.rcvd_pkt_q.clone(),
        }
    }

    pub fn should_send(&self) -> bool {
        let mut last_recv_time_guard = self.last_recv_time.lock().unwrap();
        let received_packets = self.rcvd_packets.fetch_add(1, Ordering::AcqRel);
        let since_last_rcvd =
            core::mem::replace(&mut *last_recv_time_guard, Instant::now()).elapsed();
        since_last_rcvd > Duration::from_secs(1) || received_packets % 3 == 0
    }

    pub async fn try_send_with<W>(&self, pathway: Pathway, write: W)
    where
        W: FnOnce(
            &mut [u8],
            Option<ConnectionId>,
            Option<ConnectionId>,
            &ConnectionCloseFrame,
        ) -> Option<usize>,
    {
        let Some(path) = self.paths.get(&pathway) else {
            return;
        };
        let Ok(mss) = path.interface().max_segment_size() else {
            return;
        };

        let mut datagram = vec![0; mss];
        match write(&mut datagram, self.scid, self.dcid, &self.ccf) {
            Some(written) if written > 0 => {
                _ = path
                    .send_packets(&[io::IoSlice::new(&datagram[..written])])
                    .await;
            }
            _ => {}
        };
    }

    pub fn rcvd_pkt_q(&self) -> &RcvdPacketQueue {
        &self.rcvd_pkt_q
    }
}

#[derive(Clone)]
enum State {
    Closing(Arc<ClosingState>),
    Draining,
}

#[derive(Clone)]
pub struct Termination {
    // for generate io::Error
    error: Error,
    // keep this to keep the routing
    _local_cids: ArcLocalCids,
    state: State,
}

impl Termination {
    pub fn closing(error: Error, local_cids: ArcLocalCids, state: Arc<ClosingState>) -> Self {
        Self {
            error,
            _local_cids: local_cids,
            state: State::Closing(state),
        }
    }

    pub fn draining(error: Error, local_cids: ArcLocalCids) -> Self {
        Self {
            error,
            _local_cids: local_cids,
            state: State::Draining,
        }
    }

    pub fn error(&self) -> Error {
        self.error.clone()
    }

    pub fn enter_draining(&mut self) {
        if let State::Closing(rvd_pkt_buf) = mem::replace(&mut self.state, State::Draining) {
            rvd_pkt_buf.rcvd_pkt_q.close_all();
        }
    }
}
