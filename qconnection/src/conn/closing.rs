use std::{
    future::Future,
    io::IoSlice,
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
    cid::ConnectionId,
    error::Error,
    frame::ConnectionCloseFrame,
    packet::{long, DataHeader, DataPacket},
};

use super::scope::{data::ClosingOneRttScope, handshake::ClosingHandshakeScope, RecvPacket};
use crate::{path::Pathway, usc::ArcUsc};

pub struct CcfPackets {
    handshake: Option<([u8; qcongestion::MSS], usize)>,
    one_rtt: Option<([u8; qcongestion::MSS], usize)>,
}

impl CcfPackets {
    pub fn new(
        hs: Option<&ClosingHandshakeScope>,
        one_rtt: Option<&ClosingOneRttScope>,
        error: &Error,
        last_dcid: ConnectionId,
        initial_scid: ConnectionId,
    ) -> Self {
        let ccf = ConnectionCloseFrame::from(error.clone());
        let handshake = hs.map({
            |hs| {
                let mut packet = [0; qcongestion::MSS];
                let size = hs.assemble_ccf_packet(&mut packet, &ccf, initial_scid, last_dcid);
                (packet, size)
            }
        });
        let one_rtt = one_rtt.map({
            |one_rtt| {
                let mut packet = [0; qcongestion::MSS];
                let size = one_rtt.assemble_ccf_packet(&mut packet, &ccf, last_dcid);
                (packet, size)
            }
        });
        Self { handshake, one_rtt }
    }

    pub fn handshake(&self) -> Option<IoSlice> {
        self.handshake
            .as_ref()
            .map(|(packet, size)| IoSlice::new(&packet[..*size]))
    }

    pub fn one_rtt(&self) -> Option<IoSlice> {
        self.one_rtt
            .as_ref()
            .map(|(packet, size)| IoSlice::new(&packet[..*size]))
    }
}

#[derive(Clone)]
pub struct ClosingConnection {
    pub local_cids: Vec<ConnectionId>,
    pub hs: Option<ClosingHandshakeScope>,
    pub one_rtt: Option<ClosingOneRttScope>,
    pub error: Error,

    pub rcvd_packets: Arc<AtomicUsize>,
    pub last_send_ccf: Arc<Mutex<Instant>>,
    pub revd_ccf: RcvdCcf,

    pub ccf_packets: Option<Arc<CcfPackets>>,
}

impl ClosingConnection {
    pub fn new(
        error: Error,
        local_cids: Vec<ConnectionId>,
        hs: Option<ClosingHandshakeScope>,
        one_rtt: Option<ClosingOneRttScope>,
        initial_scid: ConnectionId,
        last_dcid: Option<ConnectionId>,
    ) -> Self {
        let ccf_packets = last_dcid.map(|last_dcid| {
            let hs = hs.as_ref();
            let one_rtt = one_rtt.as_ref();
            CcfPackets::new(hs, one_rtt, &error, last_dcid, initial_scid)
        });
        Self {
            local_cids,
            hs,
            one_rtt,
            error,
            rcvd_packets: Arc::new(AtomicUsize::new(0)),
            last_send_ccf: Arc::new(Mutex::new(Instant::now())),
            revd_ccf: RcvdCcf::default(),
            ccf_packets: ccf_packets.map(Arc::new),
        }
    }

    // 记录收到的包数量，和收包时间，判断是否需要重发CCF；
    pub async fn recv_packet_via_pathway(
        &mut self,
        packet: DataPacket,
        pathway: Pathway,
        usc: ArcUsc,
    ) {
        self.rcvd_packets.fetch_add(1, Ordering::Release);

        let should_send_ccf = {
            let mut last_send_ccf = self.last_send_ccf.lock().unwrap();

            // TODO: 数值从配置中读取, 还是直接固定值?
            if self.rcvd_packets.load(Ordering::Acquire) > 5
                || last_send_ccf.elapsed() > Duration::from_millis(100)
            {
                self.rcvd_packets.store(0, Ordering::Release);
                *last_send_ccf = Instant::now();
                true
            } else {
                false
            }
        };

        match packet.header {
            DataHeader::Short(_) => self.parse_1rtt_packet(packet),
            DataHeader::Long(long::DataHeader::Handshake(_)) => self.parse_hs_packet(packet),
            _ => { /* turstless, just ignore */ }
        };

        if should_send_ccf {
            self.send_ccf(&usc, pathway).await;
        }
    }

    pub async fn send_ccf(&self, usc: &ArcUsc, pathway: Pathway) {
        if let Some(ccf_packets) = self.ccf_packets.as_ref() {
            let packets: &[IoSlice] = match (ccf_packets.handshake(), ccf_packets.one_rtt()) {
                (Some(hs_packet), Some(one_rtt_packet)) => &[hs_packet, one_rtt_packet],
                (Some(hs_packet), None) => &[hs_packet],
                (None, Some(one_rtt_packet)) => &[one_rtt_packet],
                _ => return,
            };
            _ = usc.send_all_via_pathway(packets, pathway).await;
        }
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
