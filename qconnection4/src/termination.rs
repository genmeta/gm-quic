use std::mem;

use qbase::error::Error;

use crate::{ArcLocalCids, ArcRcvdPacketBuffer};

#[derive(Clone, Default)]
enum State {
    Closing(ArcRcvdPacketBuffer),
    #[default]
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
    pub fn closing(
        error: Error,
        local_cids: ArcLocalCids,
        rvd_pkt_buf: ArcRcvdPacketBuffer,
    ) -> Self {
        Self {
            error,
            _local_cids: local_cids,
            state: State::Closing(rvd_pkt_buf),
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
        if let State::Closing(rvd_pkt_buf) = mem::take(&mut self.state) {
            rvd_pkt_buf.close();
        }
    }
}
