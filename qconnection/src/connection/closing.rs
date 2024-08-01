use std::{
    future::Future,
    ops::DerefMut,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use dashmap::DashMap;
use qbase::{
    cid::Registry,
    error::Error,
    frame::{ConnectionCloseFrame, Frame, FrameReader},
    packet::{header::GetType, keys::ArcOneRttKeys, SpacePacket},
};
use qrecovery::{
    reliable::rcvdpkt::ArcRcvdPktRecords,
    space::{DataSpace, Epoch},
};
use qudp::ArcUsc;

use crate::{
    connection::PacketPayload,
    error::ConnError,
    path::{ArcPath, Pathway},
};

pub struct ClosingConnection {
    pathes: DashMap<Pathway, ArcPath>,
    cid_registry: Registry,
    rcvd_pkt_records: ArcRcvdPktRecords,
    one_rtt_keys: ArcOneRttKeys,
    rcvd_packets: usize,
    last_send_ccf: Instant,
    revd_ccf: RcvdCcf,
}

impl ClosingConnection {
    pub fn new(
        pathes: DashMap<Pathway, ArcPath>,
        cid_registry: Registry,
        data_space: DataSpace,
        one_rtt_keys: ArcOneRttKeys,
        error: Error,
    ) -> Self {
        let ccf = ConnectionCloseFrame::from(error);

        pathes
            .iter()
            .for_each(|path| path.enter_closing(ccf.clone(), Epoch::Data));

        Self {
            pathes,
            cid_registry,
            rcvd_pkt_records: data_space.rcvd_packets(),
            one_rtt_keys,
            rcvd_packets: 0,
            last_send_ccf: Instant::now(),
            revd_ccf: RcvdCcf::default(),
        }
    }

    // 记录收到的包数量，和收包时间，判断是否需要重发CCF；
    pub fn recv_packet_via_path(&mut self, packet: SpacePacket, pathway: Pathway, usc: ArcUsc) {
        self.rcvd_packets += 1;
        // TODO: 数值从配置中读取, 还是直接固定值?
        if self.rcvd_packets > 5 || self.last_send_ccf.elapsed() > Duration::from_millis(100) {
            self.rcvd_packets = 0;
            self.last_send_ccf = Instant::now();
            // TODO: 调用 dying path 直接发送 ccf
            // usc.poll_send_via_pathway(iovecs, pathway, cx);
        }

        if let SpacePacket::OneRtt(packet) = packet {
            let pkt_type = packet.header.get_type();
            let decode_pn = |pn| self.rcvd_pkt_records.decode_pn(pn).ok();
            let payload_opt: Option<PacketPayload> = None;
            // let payload_opt =  decode_short_header_packet(packet, &self.one_rtt_keys, decode_pn).await;

            if let Some(payload) = payload_opt {
                let ccf = FrameReader::new(payload.payload, pkt_type)
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
    }

    pub fn get_path(&self, pathway: Pathway, _usc: &ArcUsc) -> Option<ArcPath> {
        self.pathes.get(&pathway).map(|path| path.value().clone())
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
