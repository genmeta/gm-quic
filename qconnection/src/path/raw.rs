use std::{
    future::{poll_fn, Future},
    io::{IoSlice, IoSliceMut},
    ops::Index,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::Duration,
    vec,
};

use qbase::{
    cid::{ArcCidCell, ConnectionId},
    flow::FlowController,
    frame::{
        io::{WritePathChallengeFrame, WritePathResponseFrame},
        AckFrame, BeFrame, ConnectionCloseFrame, PathChallengeFrame, PathResponseFrame,
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

use super::{
    anti_amplifier::{ArcAntiAmplifier, ANTI_FACTOR},
    Pathway, ViaPathway,
};

// TODO: form connection
#[derive(Clone)]
pub(super) struct AllSpaces([Option<Space>; 3]);
impl Index<Epoch> for AllSpaces {
    type Output = Option<Space>;

    fn index(&self, index: Epoch) -> &Self::Output {
        &self.0[index as usize]
    }
}

#[derive(Clone)]
pub(super) struct AllKeys {
    init_keys: ArcKeys,
    handshaking_keys: ArcKeys,
    zero_rtt_keys: ArcKeys,
    one_rtt_keys: ArcOneRttKeys,
}

#[derive(Clone)]
pub(super) struct RawPath {
    pub(super) usc: ArcUsc,
    pub(super) pathway: Pathway,
    cc: ArcCC,
    spaces: AllSpaces,
    keys: AllKeys,
    anti_amplifier: ArcAntiAmplifier<ANTI_FACTOR>,
    flow_controller: FlowController,
    dcid: ArcCidCell,
    scid: ConnectionId,
    token: Vec<u8>,
    spin: SpinBit,
    challenge_buffer: Arc<Mutex<Option<PathChallengeFrame>>>,
    response_buffer: Arc<Mutex<Option<PathResponseFrame>>>,
    response_listner: ArcResponseListener,
    handle: Handle,
}

impl RawPath {
    // TODO: 从 connection 构造，不需要这么多参数
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
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

        let mut path = Self {
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
            handle: Handle::default(),
        };

        let send_handle = tokio::spawn({
            let mut path = path.clone();
            async move {
                let mut buffers = vec![vec![0u8; MSS]; BATCH_SIZE];
                let io_slices: Vec<IoSliceMut> =
                    buffers.iter_mut().map(|buf| IoSliceMut::new(buf)).collect();

                let reader = path.packet_reader(io_slices);
                loop {
                    let ioves = reader.clone().await;
                    let ret =
                        poll_fn(|cx| path.usc.poll_send_via_pathway(&ioves, pathway, cx)).await;
                    match ret {
                        Ok(_) => todo!(),
                        Err(_) => todo!(),
                    }
                }
            }
        });

        // 路径验证任务
        let verify_handle = tokio::spawn({
            let path = path.clone();

            async move {
                let challenge = PathChallengeFrame::random();
                path.challenge_buffer.lock().unwrap().replace(challenge);

                for _ in 0..3 {
                    let pto = path.cc.get_pto_time(Epoch::Data);
                    let listener = path.response_listner.clone();
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
            let spaces = path.spaces.clone();
            let cc = path.cc.clone();
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

        let handle = Handle {
            send_handle: Arc::new(Mutex::new(Some(send_handle))),
            verify_handle: Arc::new(Mutex::new(Some(verify_handle))),
            cc_handle: Arc::new(Mutex::new(Some(cc_handle))),
        };
        path.handle = handle;
        path
    }

    fn packet_reader<'a>(&self, io_slices: Vec<IoSliceMut<'a>>) -> ArcPacketReader<'a> {
        let reader = PacketReader {
            io_slices,
            cc: self.cc.clone(),
            anti_amplifier: self.anti_amplifier.clone(),
            flow_controler: self.flow_controller.clone(),
            spaces: self.spaces.clone(),
            keys: self.keys.clone(),
            dcid: self.dcid.clone(),
            scid: self.scid,
            rest_token: self.token.clone(),
            spin: self.spin,
            challenge_buffer: self.challenge_buffer.clone(),
            response_buffer: self.response_buffer.clone(),
        };
        ArcPacketReader(Arc::new(Mutex::new(reader)))
    }

    pub(super) fn recv_response(&mut self, frame: PathResponseFrame) {
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

    pub(super) fn recv_challenge(&mut self, frame: PathChallengeFrame) {
        self.response_buffer
            .lock()
            .unwrap()
            .replace((&frame).into());
    }

    pub(super) fn read_connection_close_frame(
        &self,
        _frame: ConnectionCloseFrame,
        _epoch: Epoch,
    ) -> Vec<u8> {
        // 结束 alive 状态时，打包一个 ccf 包
        todo!()
    }

    pub(super) fn pto_time(&self) -> Duration {
        self.cc.get_pto_time(Epoch::Data)
    }

    pub(super) fn on_ack(&self, epoch: Epoch, ack: &AckFrame) {
        self.cc.on_ack(epoch, ack);
    }

    pub(super) fn on_recv_pkt(&self, epoch: Epoch, pn: u64, is_ack_eliciting: bool) {
        self.cc.on_recv_pkt(epoch, pn, is_ack_eliciting);
    }
}

impl Drop for RawPath {
    fn drop(&mut self) {
        if let Some(h) = self.handle.send_handle.lock().unwrap().take() {
            h.abort();
        }
        if let Some(h) = self.handle.verify_handle.lock().unwrap().take() {
            h.abort();
        }
        if let Some(h) = self.handle.cc_handle.lock().unwrap().take() {
            h.abort();
        }
    }
}

#[derive(Clone)]
struct ArcPacketReader<'a>(Arc<Mutex<PacketReader<'a>>>);

struct PacketReader<'a> {
    io_slices: Vec<IoSliceMut<'a>>,
    cc: ArcCC,
    anti_amplifier: ArcAntiAmplifier<3>,
    flow_controler: FlowController,
    spaces: AllSpaces,
    dcid: ArcCidCell,
    scid: ConnectionId,
    rest_token: Vec<u8>,
    keys: AllKeys,
    spin: SpinBit,
    challenge_buffer: Arc<Mutex<Option<PathChallengeFrame>>>,
    response_buffer: Arc<Mutex<Option<PathResponseFrame>>>,
}

impl<'a> Future for ArcPacketReader<'a> {
    type Output = Vec<IoSlice<'a>>;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        let ioslices = &mut self.0.lock().unwrap().io_slices;
        let guard = self.0.lock().unwrap();

        for ioslice in ioslices.iter_mut() {
            let _buf = ioslice.as_mut();
            for &epoch in Epoch::iter() {
                let _space = &guard.spaces[epoch];
            }
            // todo: read packet from all space
        }
        todo!()
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

#[derive(Clone, Default)]
struct Handle {
    send_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    verify_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    cc_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

#[derive(Clone)]
pub(super) enum ResponseListener {
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
