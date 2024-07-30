use std::{
    future::{poll_fn, Future},
    io::IoSlice,
    net::SocketAddr,
    ops::Index,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{ready, Context, Poll, Waker},
    time::Duration,
};

use anti_amplifier::{ArcAntiAmplifier, ANTI_FACTOR};
use dashmap::DashMap;
use qbase::{
    cid::{ArcCidCell, ConnectionId, Registry},
    flow::FlowController,
    frame::{
        io::{WritePathChallengeFrame, WritePathResponseFrame},
        BeFrame, PathChallengeFrame, PathResponseFrame,
    },
    packet::{
        keys::{ArcKeys, ArcOneRttKeys},
        SpinBit,
    },
    util::TransportLimit,
};
use qcongestion::{
    congestion::{ArcCC, CongestionAlgorithm, MSS},
    CongestionControl,
};
use qrecovery::space::{Epoch, Space};
use qudp::{ArcUsc, BATCH_SIZE};

pub mod anti_amplifier;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct RelayAddr {
    pub agent: SocketAddr, // 代理人
    pub addr: SocketAddr,
}

/// 无论哪种Pathway，socket都必须绑定local地址
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Pathway {
    Direct {
        local: SocketAddr,
        remote: SocketAddr,
    },
    Relay {
        local: RelayAddr,
        remote: RelayAddr,
    },
}

// TODO: form connection
#[derive(Clone)]
pub struct AllSpaces([Option<Space>; 3]);
impl Index<Epoch> for AllSpaces {
    type Output = Option<Space>;

    fn index(&self, index: Epoch) -> &Self::Output {
        &self.0[index as usize]
    }
}

#[derive(Clone)]
pub struct AllKeys {
    init_keys: ArcKeys,
    handshaking_keys: ArcKeys,
    zero_rtt_keys: ArcKeys,
    one_rtt_keys: ArcOneRttKeys,
}

#[derive(Clone)]
struct RawPath {
    usc: ArcUsc,
    cc: ArcCC,
    spaces: AllSpaces,
    keys: AllKeys,
    anti_amplifier: ArcAntiAmplifier<ANTI_FACTOR>,
    flow_controller: FlowController,
    pathway: Pathway,
    dcid: ArcCidCell,
    scid: ConnectionId,
    token: Vec<u8>,
    spin: SpinBit,
    challenge_buffer: Arc<Mutex<Option<PathChallengeFrame>>>,
    response_buffer: Arc<Mutex<Option<PathResponseFrame>>>,
    response_listner: ArcResponseListener,
}

#[derive(Clone)]
pub enum ResponseListener {
    Init,
    Pending(Waker),
    Response(PathResponseFrame),
    Inactive,
}

#[derive(Clone)]
struct ArcResponseListener(Arc<Mutex<ResponseListener>>);

impl Future for ArcResponseListener {
    type Output = PathResponseFrame;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut listner = self.0.lock().unwrap();
        match *listner {
            ResponseListener::Init => {
                *listner = ResponseListener::Pending(cx.waker().clone());
                Poll::Pending
            }
            ResponseListener::Pending(_) => Poll::Pending,
            ResponseListener::Response(resp) => Poll::Ready(resp),
            ResponseListener::Inactive => unreachable!("inactive response listener"),
        }
    }
}

impl RawPath {
    // TODO: 从 connection 构造，不需要这么多参数
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        usc: ArcUsc,
        pathway: Pathway,
        spaces: AllSpaces,
        keys: AllKeys,
        flow_controller: FlowController,
        dcid: ArcCidCell,
        scid: ConnectionId,
        token: Vec<u8>,
        spin: SpinBit,
    ) -> Self {
        let cc = ArcCC::new(CongestionAlgorithm::Bbr, Duration::from_micros(100));
        let anti_amplifier = ArcAntiAmplifier::<3>::default();
        Self {
            usc,
            cc,
            anti_amplifier,
            spaces,
            keys,
            pathway,
            flow_controller,
            dcid,
            scid,
            token,
            spin,
            challenge_buffer: Arc::new(Mutex::new(None)),
            response_buffer: Arc::new(Mutex::new(None)),
            response_listner: ArcResponseListener(Arc::new(Mutex::new(ResponseListener::Init))),
        }
    }

    pub fn read<'a>(
        &self,
        bufs: &'a mut Vec<Vec<u8>>,
        scid: ConnectionId,
        dcid: ConnectionId,
        token: Vec<u8>,
        spin: SpinBit,
    ) -> ArcReader<'a> {
        let reader = PacketReader {
            buffers: bufs,
            cc: self.cc.clone(),
            anti_amplifier: self.anti_amplifier.clone(),
            flow_controler: self.flow_controller.clone(),
            spaces: self.spaces.clone(),
            keys: self.keys.clone(),
            dcid,
            scid,
            rest_token: token,
            spin,
            challenge_buffer: self.challenge_buffer.clone(),
            response_buffer: self.response_buffer.clone(),
        };
        ArcReader(Arc::new(Mutex::new(reader)))
    }

    pub fn recv_response(&mut self, frame: PathResponseFrame) {
        let mut guard = self.response_listner.0.lock().unwrap();
        match &*guard {
            ResponseListener::Init => unreachable!("recv esponse before send challenge"),
            ResponseListener::Pending(waker) => {
                waker.wake_by_ref();
                *guard = ResponseListener::Response(frame);
            }
            ResponseListener::Response(resp) => {
                if resp != &frame {
                    *guard = ResponseListener::Response(frame);
                }
            }
            ResponseListener::Inactive => {}
        }
    }

    pub fn recv_challenge(&mut self, frame: &PathChallengeFrame) {
        self.response_buffer.lock().unwrap().replace(frame.into());
    }
}

#[derive(Clone)]
struct ArcReader<'a>(Arc<Mutex<PacketReader<'a>>>);

struct PacketReader<'a> {
    buffers: &'a mut Vec<Vec<u8>>,
    cc: ArcCC,
    anti_amplifier: ArcAntiAmplifier<3>,
    flow_controler: FlowController,
    spaces: AllSpaces,
    dcid: ConnectionId,
    scid: ConnectionId,
    rest_token: Vec<u8>,
    keys: AllKeys,
    spin: SpinBit,
    challenge_buffer: Arc<Mutex<Option<PathChallengeFrame>>>,
    response_buffer: Arc<Mutex<Option<PathResponseFrame>>>,
}

impl<'a> Future for ArcReader<'a> {
    type Output = usize;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        //let  buffers = self.0.lock().unwrap().buffers;
        let buffers = &mut self.0.lock().unwrap().buffers;
        let guard = self.0.lock().unwrap();

        let cc_alow = ready!(guard.cc.poll_send(cx));
        let anti_amplifier_alow = ready!(guard.anti_amplifier.poll_get_credit(cx));

        let credit = if let Ok(credit) = guard.flow_controler.sender().credit() {
            credit
        } else {
            return Poll::Pending;
        };

        let mut limit = TransportLimit::new(anti_amplifier_alow, cc_alow, credit.available());

        let mut total_sent: usize = 0;

        let mut pkt_count = 0;
        for buffer in (*buffers).iter_mut() {
            if limit.available() == 0 {
                break;
            }
            // todo: pack packet
        }
        Poll::Ready(pkt_count)
    }
}

impl<'a> PacketReader<'a> {
    fn send_challenge(&self, mut buf: &mut [u8], limit: &mut TransportLimit) -> usize {
        let mut guard = self.challenge_buffer.lock().unwrap();
        if let Some(challeng) = *guard {
            let size: usize = challeng.encoding_size();
            if limit.available() >= size {
                guard.take();
                limit.record_write(size);
                buf.put_path_challenge_frame(&challeng);
            }
            return size;
        }
        0
    }

    fn send_response(&self, mut buf: &mut [u8], limit: &mut TransportLimit) -> usize {
        let mut guard = self.response_buffer.lock().unwrap();
        if let Some(resp) = *guard {
            let size: usize = resp.encoding_size();
            if limit.available() >= size {
                guard.take();
                limit.record_write(size);
                buf.put_path_response_frame(&resp);
            }
            return size;
        }
        0
    }
}

enum PathState {
    Alive(RawPath),
    Dying,
    Dead,
}

#[derive(Clone)]
pub struct ArcPath(Arc<Mutex<PathState>>);

// TODO: 从 connection 构造，不需要这么多参数
#[allow(clippy::too_many_arguments)]
pub fn create_path(
    usc: ArcUsc,
    pathway: Pathway,
    spaces: AllSpaces,
    keys: AllKeys,
    flow_controller: FlowController,
    cid_registry: Registry,
    spin: SpinBit,
    scid: ConnectionId,
    token: Vec<u8>,
    pathes: DashMap<Pathway, ArcPath>,
) -> ArcPath {
    let dcid = cid_registry.remote.apply_cid();
    let raw_path = RawPath::new(
        usc,
        pathway,
        spaces,
        keys,
        flow_controller,
        dcid,
        scid,
        token.clone(),
        spin,
    );
    let arc_path = ArcPath(Arc::new(Mutex::new(PathState::Alive(raw_path.clone()))));

    // 发送任务
    let send_handle = tokio::spawn({
        let path = raw_path.clone();

        async move {
            let dcid = path.dcid.clone().await;

            // todo: 直接传 IoSliceMut
            let mut buffers = vec![vec![0u8; MSS]; BATCH_SIZE];
            let reader = path.read(&mut buffers, scid, dcid, token.clone(), spin);

            let (src, dst) = match &pathway {
                Pathway::Direct { local, remote } => (*local, *remote),
                // todo: append relay hdr
                Pathway::Relay { local, remote } => (local.addr, remote.agent),
            };

            let hdr = qudp::PacketHeader {
                src,
                dst,
                ttl: 64,
                ecn: None,
                seg_size: MSS as u16,
                gso: true,
            };
            loop {
                let pkt_count = reader.clone().await;
                let io_slices: Vec<IoSlice<'_>> = buffers
                    .iter()
                    .take(pkt_count)
                    .map(|buf| IoSlice::new(buf))
                    .collect();

                let ret = poll_fn(|cx| path.usc.poll_send(&io_slices, &hdr, cx)).await;
                match ret {
                    Ok(_) => todo!(),
                    Err(_) => todo!(),
                }
            }
        }
    });

    arc_path
}
