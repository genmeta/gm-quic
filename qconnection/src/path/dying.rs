use std::{
    future::Future,
    io::{self, IoSlice},
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use qudp::ArcUsc;

use super::{Pathway, ViaPathway};

// Connection Closing State 时，只需要发送一个 CCF 包
// 最小化持有状态
#[derive(Clone)]
pub(super) struct DyingPath {
    pub(super) ccf_pkt: Vec<u8>,
    pub(super) pto: Duration,
    usc: ArcUsc,
    pathway: Pathway,
}

impl DyingPath {
    pub fn new(usc: ArcUsc, pathway: Pathway, ccf_pkt: Vec<u8>, pto: Duration) -> Self {
        Self {
            usc,
            pto,
            ccf_pkt,
            pathway,
        }
    }

    pub fn send_ccf(&self) -> io::Result<()> {
        todo!("remove path state")
        // self.usc.sync_send(self.ccf_pkt, hdr);
    }
}
