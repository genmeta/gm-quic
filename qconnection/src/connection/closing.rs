use std::{
    future::Future,
    ops::DerefMut,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use qbase::{
    error::Error,
    frame::ConnectionCloseFrame,
    packet::{long, DataHeader, DataPacket},
};
use qudp::ArcUsc;

use super::{
    scope::{data::ClosingOneRttScope, handshake::ClosingHandshakeScope, RecvPacket},
    CidRegistry,
};
use crate::path::{ArcPathes, Pathway};

#[derive(Clone)]
pub struct ClosingConnection {
    pub pathes: ArcPathes,
    pub cid_registry: CidRegistry,
    pub hs: Option<ClosingHandshakeScope>,
    pub one_rtt: Option<ClosingOneRttScope>,
    pub final_ccf: ConnectionCloseFrame,

    pub rcvd_packets: Arc<AtomicUsize>,
    pub last_send_ccf: Arc<Mutex<Instant>>,
    pub revd_ccf: RcvdCcf,
}

impl ClosingConnection {
    pub fn new(
        error: Error,
        pathes: ArcPathes,
        cid_registry: CidRegistry,
        hs: Option<ClosingHandshakeScope>,
        one_rtt: Option<ClosingOneRttScope>,
    ) -> Self {
        Self {
            pathes,
            cid_registry,
            hs,
            one_rtt,
            final_ccf: ConnectionCloseFrame::from(error),
            rcvd_packets: Arc::new(AtomicUsize::new(0)),
            last_send_ccf: Arc::new(Mutex::new(Instant::now())),
            revd_ccf: RcvdCcf::default(),
        }
    }

    // 记录收到的包数量，和收包时间，判断是否需要重发CCF；
    pub fn recv_packet_via_pathway(&mut self, packet: DataPacket, _pathway: Pathway, _usc: ArcUsc) {
        self.rcvd_packets.fetch_add(1, Ordering::Release);
        // TODO: 数值从配置中读取, 还是直接固定值?
        let mut last_send_ccf = self.last_send_ccf.lock().unwrap();
        if self.rcvd_packets.load(Ordering::Relaxed) > 5
            || last_send_ccf.elapsed() > Duration::from_millis(100)
        {
            self.rcvd_packets.store(0, Ordering::Release);
            *last_send_ccf = Instant::now();
            // TODO: 调用 usc 直接发送 报文
            // usc.poll_send_via_pathway(iovecs, pathway, cx);
        }
        drop(last_send_ccf);

        match packet.header {
            DataHeader::Short(_) => self.parse_1rtt_packet(packet),
            DataHeader::Long(long::DataHeader::Handshake(_)) => self.parse_hs_packet(packet),
            _ => { /* turstless, just ignore */ }
        };
    }

    fn parse_hs_packet(&self, packet: DataPacket) {
        if let Some(hs_scope) = &self.hs {
            if hs_scope.has_rcvd_ccf(packet) {
                self.revd_ccf.on_ccf_rcvd();
            }
        }
    }

    fn parse_1rtt_packet(&self, packet: DataPacket) {
        if let Some(one_rtt_scope) = &self.one_rtt {
            if one_rtt_scope.has_rcvd_ccf(packet) {
                self.revd_ccf.on_ccf_rcvd();
            }
        }
    }

    pub fn get_rcvd_ccf(&self) -> RcvdCcf {
        self.revd_ccf.clone()
    }
}

#[derive(Debug, Clone, Default)]
enum RcvdCcfState {
    #[default]
    None,
    Pending(Waker),
    Rcvd,
}

#[derive(Default, Debug, Clone)]
pub struct RcvdCcf(Arc<Mutex<RcvdCcfState>>);

impl RcvdCcf {
    pub fn did_recv(&self) -> Self {
        self.clone()
    }

    pub fn on_ccf_rcvd(&self) {
        let mut guard = self.0.lock().unwrap();
        if let RcvdCcfState::Pending(waker) = guard.deref_mut() {
            waker.wake_by_ref();
        }
        *guard = RcvdCcfState::Rcvd;
    }
}

impl Future for RcvdCcf {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut guard = self.0.lock().unwrap();
        match guard.deref_mut() {
            RcvdCcfState::None | RcvdCcfState::Pending(_) => {
                *guard = RcvdCcfState::Pending(cx.waker().clone());
                Poll::Pending
            }
            RcvdCcfState::Rcvd => Poll::Ready(()),
        }
    }
}
