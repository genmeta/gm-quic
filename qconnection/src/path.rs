#![allow(dead_code)]

use std::{
    future::{poll_fn, Future},
    io::IoSlice,
    net::SocketAddr,
    ops::Index,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::Duration,
};

use anti_amplifier::{ArcAntiAmplifier, ANTI_FACTOR};
use dashmap::DashMap;
use qbase::{
    cid::{ArcCidCell, ConnectionId, Registry},
    flow::FlowController,
    frame::{
        io::{WritePathChallengeFrame, WritePathResponseFrame},
        BeFrame, ConnectionCloseFrame, PathChallengeFrame, PathResponseFrame,
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

    pub fn recv_challenge(&mut self, frame: PathChallengeFrame) {
        self.response_buffer
            .lock()
            .unwrap()
            .replace((&frame).into());
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

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        todo!("read from sapce")
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

struct DyingPath {
    usc: ArcUsc,
    pathway: Pathway,
    ccf_pkt: Arc<Mutex<Vec<u8>>>,
    send_ccf_handle: Option<tokio::task::JoinHandle<()>>,
}

impl DyingPath {
    fn poll_send_ccf(&self, cx: &mut Context<'_>) {
        let buffer = self.ccf_pkt.lock().unwrap();
        let io_slices = [IoSlice::new(&buffer[..])];

        // todo: 改成 usc poll_send_via_pathway
        let (src, dst) = match &self.pathway {
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

        log::trace!("send ccf to {}", dst);
        let _ = self.usc.poll_send(&io_slices, &hdr, cx);
    }
}

enum PathState {
    Alive(RawPath),
    Dying(DyingPath),
    Dead,
}

#[derive(Clone)]
pub struct ArcPath(Arc<Mutex<PathState>>);

impl ArcPath {
    fn recv_challenge(&self, frame: PathChallengeFrame) {
        let mut guard = self.0.lock().unwrap();
        if let PathState::Alive(path) = &mut *guard {
            path.recv_challenge(frame)
        }
    }

    fn recv_response(&self, frame: PathResponseFrame) {
        let mut guard = self.0.lock().unwrap();
        if let PathState::Alive(path) = &mut *guard {
            path.recv_response(frame)
        }
    }

    fn has_been_inactivated(&self) -> HasBeenInactivated {
        HasBeenInactivated(self.clone())
    }

    fn enter_dying(&self, _ccf: ConnectionCloseFrame) {
        // todo: pack ccf enter dying
    }

    pub fn enter_dead(&self) {
        let mut guard = self.0.lock().unwrap();
        match *guard {
            PathState::Alive(_) => {
                *guard = PathState::Dead;
            }
            PathState::Dying(_) => {
                *guard = PathState::Dead;
            }
            PathState::Dead => {}
        }
    }
}

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
    // TODO: 离开 alive 时终止
    let send_handle = tokio::spawn({
        let path = raw_path.clone();

        async move {
            let dcid = path.dcid.clone().await;

            // TODO: 直接传 IoSliceMut
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

    // 路径验证任务
    let verify_handle = tokio::spawn({
        let _anti_amplifier = raw_path.anti_amplifier.clone();
        let cc = raw_path.cc.clone();
        let challenge_buffer = raw_path.challenge_buffer.clone();
        let response_listner = raw_path.response_listner.clone();

        async move {
            let challenge = PathChallengeFrame::random();
            challenge_buffer.lock().unwrap().replace(challenge);

            for _ in 0..3 {
                let pto = cc.get_pto_time(Epoch::Data);
                let listener = response_listner.clone();
                match tokio::time::timeout(pto, listener).await {
                    Ok(resp) => {
                        if resp == (&challenge).into() {
                            // 路径验证成功, 解除抗放大攻击
                            // anti_amplifier.on_path_verified();
                            break;
                        }
                    }
                    Err(_) => {
                        // TODO: enter dying
                    }
                }
            }
        }
    });

    let cc_handle = tokio::spawn({
        let spaces = raw_path.spaces.clone();
        let cc = raw_path.cc.clone();
        async move {
            loop {
                tokio::select! {
                    (epoch, _loss) = cc.may_loss() => {
                        let _space = &spaces[epoch];

                    },
                    epoch = cc.probe_timeout() => {
                       let _space = &spaces[epoch];
                    },
                    (epoch, _acked) = cc.indicate_ack() => {
                        let _space = &spaces[epoch];

                    },
                }
            }
        }
    });

    // 失活检测任务
    tokio::spawn({
        let path = arc_path.clone();
        let pathes = pathes.clone();
        async move {
            path.has_been_inactivated().await;
            send_handle.abort();
            verify_handle.abort();
            cc_handle.abort();
            pathes.remove(&pathway);
        }
    });

    arc_path
}

struct HasBeenInactivated(ArcPath);

impl Future for HasBeenInactivated {
    type Output = ();

    fn poll(self: std::pin::Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        match *self.0 .0.lock().unwrap() {
            PathState::Alive(_) => Poll::Pending,
            PathState::Dying(_) => Poll::Ready(()),
            PathState::Dead => Poll::Ready(()),
        }
    }
}
