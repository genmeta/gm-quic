use std::{
    future::Future,
    io::IoSlice,
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
    pub(super) ccf_pkt: Arc<Mutex<Vec<u8>>>,
    pub(super) pto: Duration,
    usc: ArcUsc,
    pathway: Pathway,
}

impl DyingPath {
    pub fn new(usc: ArcUsc, pathway: Pathway, ccf_pkt: Vec<u8>, pto: Duration) -> Self {
        Self {
            usc,
            pto,
            ccf_pkt: Arc::new(Mutex::new(ccf_pkt)),
            pathway,
        }
    }

    pub fn send_ccf(&self) -> Sender {
        Sender(self.clone())
    }
}

pub(super) struct Sender(DyingPath);

impl Future for Sender {
    type Output = std::io::Result<usize>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut dying = self.get_mut().0.clone();

        let ccf_pkt = dying.ccf_pkt.lock().unwrap();
        let ioslice = IoSlice::new(ccf_pkt.as_slice());

        dying
            .usc
            .poll_send_via_pathway(&[ioslice], dying.pathway, cx)
    }
}
