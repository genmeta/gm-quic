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
    frame::{ConnectionCloseFrame, Frame, FrameReader},
    packet::{
        decrypt::{decrypt_packet, remove_protection_of_short_packet},
        header::GetType,
        keys::ArcOneRttPacketKeys,
        DataHeader, DataPacket,
    },
};
use qrecovery::reliable::rcvdpkt::ArcRcvdPktRecords;
use qudp::ArcUsc;

use super::{raw::RawConnection, CidRegistry};
use crate::path::{ArcPathes, Pathway};

#[derive(Clone)]
pub struct ClosingConnection {
    pub pathes: ArcPathes,
    pub cid_registry: CidRegistry,
    pub rcvd_pkt_records: ArcRcvdPktRecords,
    pub one_rtt_keys: (
        Arc<dyn rustls::quic::HeaderProtectionKey>,
        ArcOneRttPacketKeys,
    ),
    pub rcvd_packets: Arc<AtomicUsize>,
    pub last_send_ccf: Arc<Mutex<Instant>>,
    pub revd_ccf: RcvdCcf,
}

impl From<RawConnection> for ClosingConnection {
    fn from(conn: RawConnection) -> Self {
        let pathes = conn.pathes;
        let cid_registry = conn.cid_registry;
        let data_space = conn.data.space;
        let one_rtt_keys = match conn.data.one_rtt_keys.invalid() {
            Some((hpk, pk)) => (hpk.local, pk),
            _ => unreachable!(),
        };
        let error = conn.error;
        let error = error.get_error().unwrap();
        conn.flow_ctrl.on_error(&error);

        let _ccf = ConnectionCloseFrame::from(error);
        Self {
            pathes,
            cid_registry,
            rcvd_pkt_records: data_space.rcvd_packets(),
            one_rtt_keys,
            rcvd_packets: Arc::new(AtomicUsize::new(0)),
            last_send_ccf: Arc::new(Mutex::new(Instant::now())),
            revd_ccf: RcvdCcf::default(),
        }
    }
}

impl ClosingConnection {
    // 记录收到的包数量，和收包时间，判断是否需要重发CCF；
    pub fn recv_packet_via_pathway(
        &mut self,
        mut packet: DataPacket,
        _pathway: Pathway,
        _usc: ArcUsc,
    ) {
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

        if let DataHeader::Short(h) = packet.header {
            let pkt_type = h.get_type();
            let (undecoded_pn, key_phase) = match remove_protection_of_short_packet(
                self.one_rtt_keys.0.as_ref(),
                packet.bytes.as_mut(),
                packet.offset,
            ) {
                Ok(Some(pn)) => pn,
                Ok(None) => return,
                Err(_e) => {
                    // conn_error.on_error(e);
                    return;
                }
            };

            let pn = match self.rcvd_pkt_records.decode_pn(undecoded_pn) {
                Ok(pn) => pn,
                // TooOld/TooLarge/HasRcvd
                Err(_e) => return,
            };
            let body_offset = packet.offset + undecoded_pn.size();
            let pk = self.one_rtt_keys.1.lock_guard().get_remote(key_phase, pn);
            decrypt_packet(pk.as_ref(), pn, packet.bytes.as_mut(), body_offset).unwrap();
            let body = packet.bytes.split_off(body_offset);

            let ccf = FrameReader::new(body.freeze(), pkt_type)
                .filter_map(|frame| frame.ok())
                .find_map(|frame| {
                    if let (Frame::Close(ccf), _) = frame {
                        Some(ccf)
                    } else {
                        None
                    }
                });

            if ccf.is_some() {
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
