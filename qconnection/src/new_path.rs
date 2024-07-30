use std::{
    io::IoSlice,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::Duration,
};

use dashmap::DashMap;
use futures::{future::poll_fn, ready, Future};
use qbase::{
    cid::{ArcCidCell, ConnectionId, Registry},
    flow::FlowController,
    frame::{
        io::{WriteConnectionCloseFrame, WritePathChallengeFrame, WritePathResponseFrame},
        BeFrame, ConnectionCloseFrame, PathChallengeFrame, PathResponseFrame,
    },
    packet::{keys::AllKeys, SpinBit},
    util::TransportLimit,
};
use qcongestion::{
    congestion::{ArcCC, CongestionAlgorithm, MSS},
    CongestionControl,
};
use qrecovery::space::{Epoch, ReliableTransmit, SpaceRead, Spaces};
use qudp::{ArcUsc, BATCH_SIZE};

use crate::{
    path::{ArcAntiAmplifier, Pathway},
    transmit,
};

enum PathState {
    Alive(RawPath),
    Dying(DyingPath),
    Dead,
}

#[derive(Clone)]
struct RawPath {
    usc: ArcUsc,
    cc: ArcCC,
    spaces: Spaces,
    keys: AllKeys,
    anti_amplifier: ArcAntiAmplifier<3>,
    flow_controller: FlowController,
    pathway: Pathway,
    dcid: ArcCidCell,
    // 创建 path 时直接传进来
    scid: ConnectionId,
    token: Vec<u8>,
    spin: SpinBit,
    challenge_buffer: Arc<Mutex<Option<PathChallengeFrame>>>,
    response_buffer: Arc<Mutex<Option<PathResponseFrame>>>,
    response_listner: ArcResponseListener,
}

impl RawPath {
    fn new(
        usc: ArcUsc,
        pathway: Pathway,
        spaces: Spaces,
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
        let reader = ReadIntoPacket {
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

#[derive(Clone)]
struct ArcReader<'a>(Arc<Mutex<ReadIntoPacket<'a>>>);
struct ReadIntoPacket<'a> {
    buffers: &'a mut Vec<Vec<u8>>,
    cc: ArcCC,
    anti_amplifier: ArcAntiAmplifier<3>,
    flow_controler: FlowController,
    spaces: Spaces,
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

            let mut buf = &mut buffer[0..];
            for &epoch in Epoch::iter() {
                let space = if let Some(space) = guard.spaces[epoch].as_ref() {
                    space
                } else {
                    continue;
                };

                let (hdr, max_header_size) = transmit::build_header(
                    epoch,
                    guard.scid,
                    guard.dcid,
                    guard.spin,
                    guard.rest_token.clone(),
                );

                let (_, body_buf) = buf.split_at_mut(max_header_size);
                let (pn, pn_size) = space.read_pn(body_buf, &mut limit);
                let mut body_buf = &mut body_buf[pn_size..];

                let mut challenge_size = 0;

                // todo: 有 path challenge 时需要保证包至少有 1200 字节
                let len = guard.send_challenge(body_buf, &mut limit);
                challenge_size += len;
                body_buf = &mut body_buf[len..];

                if epoch == Epoch::Data {
                    let len = guard.send_response(body_buf, &mut limit);
                    body_buf = &mut body_buf[len..];
                    challenge_size += len;
                }

                let ack_pkt = guard.cc.need_ack(epoch);
                let (frame_size, is_ack_eliciting) =
                    space.read_frame(&mut limit, body_buf, ack_pkt);

                let body_len = pn_size + frame_size + challenge_size;
                space.read_finish();

                let sent_bytes =
                    transmit::encrypt_packet(buf, &hdr, pn, pn_size, body_len, &guard.keys);

                let ack = ack_pkt.map(|ack| ack.0);
                guard.cc.on_pkt_sent(
                    epoch,
                    pn,
                    is_ack_eliciting,
                    sent_bytes,
                    is_ack_eliciting,
                    ack,
                );
                buf = &mut buf[0..sent_bytes];
                if sent_bytes == 0 {
                    break;
                } else {
                    total_sent += sent_bytes;
                    pkt_count += 1;
                }
            }
        }
        // 扣除流控和抗放大攻击
        credit.post_sent(total_sent);
        guard.anti_amplifier.post_sent(total_sent);

        Poll::Ready(pkt_count)
    }
}

impl<'a> ReadIntoPacket<'a> {
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
        let mut buffer = self.ccf_pkt.lock().unwrap();
        let io_slices = [IoSlice::new(&mut buffer[..])];

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

#[derive(Clone)]
pub struct ArcPath(Arc<Mutex<PathState>>);

impl ArcPath {
    // 当连接主动关闭进入 closing 时，所有 path 都应该进入 dying 状态，并发送 ccf
    pub fn enter_dying(&self, ccf: ConnectionCloseFrame, epoch: Epoch) {
        let mut guard = self.0.lock().unwrap();

        match *guard {
            PathState::Alive(ref mut path) => {
                tokio::spawn({
                    let rwa_path = path.clone();
                    let arc_path = self.clone();
                    async move {
                        // 进入 dying 之前打包 ccf
                        let space = if let Some(space) = &rwa_path.spaces[epoch] {
                            space
                        } else {
                            log::error!("space {:?} is none", epoch);
                            return;
                        };

                        let dcid = rwa_path.dcid.await;
                        let (hdr, hdr_size) = transmit::build_header(
                            epoch,
                            rwa_path.scid,
                            dcid,
                            rwa_path.spin,
                            rwa_path.token,
                        );
                        let mut buffer = vec![0; MSS];

                        let buf = &mut buffer[0..];
                        // not limit when sending ccf
                        let mut limit = TransportLimit::new(None, usize::MAX, usize::MAX);
                        let (_, body_buf) = buf.split_at_mut(hdr_size);
                        let (pn, pn_size) = space.read_pn(body_buf, &mut limit);
                        let mut body_buf = &mut body_buf[pn_size..];

                        body_buf.put_connection_close_frame(&ccf);

                        let body_len = pn_size + ccf.encoding_size();
                        space.read_finish();

                        let sent_bytes = transmit::encrypt_packet(
                            buf,
                            &hdr,
                            pn,
                            pn_size,
                            body_len,
                            &rwa_path.keys,
                        );

                        buffer = buffer[..sent_bytes].to_vec();

                        let mut guard = arc_path.0.lock().unwrap();

                        *guard = PathState::Dying(DyingPath {
                            usc: rwa_path.usc.clone(),
                            ccf_pkt: Arc::new(Mutex::new(buffer)),
                            pathway: rwa_path.pathway,
                            send_ccf_handle: None,
                        });
                    }
                });
            }
            _ => {
                unreachable!();
            }
        }
    }

    pub fn inactivate(&self) {
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

    fn has_been_inactivated(&self) -> HasBeenInactivated {
        HasBeenInactivated(self.clone())
    }
}

pub fn create_path(
    usc: ArcUsc,
    pathway: Pathway,
    spaces: Spaces,
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

    // 路径验证任务
    let verify_handle = tokio::spawn({
        let anti_amplifier = raw_path.anti_amplifier.clone();
        let cc = raw_path.cc.clone();
        let challenge_buffer = raw_path.challenge_buffer.clone();
        let response_listner = raw_path.response_listner.clone();
        let path = arc_path.clone();

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
                        path.inactivate();
                    }
                }
            }
        }
    });

    // 拥塞控制反馈
    let cc_handle = tokio::spawn({
        let spaces = raw_path.spaces.clone();
        let cc = raw_path.cc.clone();
        async move {
            loop {
                tokio::select! {
                    (epoch, loss) = cc.may_loss() => {
                        let space = &spaces[epoch];
                        if let Some(space) = space {
                            for pn in loss {
                                space.may_loss_pkt(pn);
                            }
                    }
                    },
                    epoch = cc.probe_timeout() => {
                       let space = &spaces[epoch];
                        if let Some(space) = space {
                            space.probe_timeout();
                        }
                    },
                    (epoch, acked) = cc.indicate_ack() => {
                        let space = &spaces[epoch];
                        if let Some(space) = space {
                            for pn in acked {
                                space.may_loss_pkt(pn);
                            }
                        }
                    },
                }
            }
        }
    });

    // 失活检测任务
    let dying_handle = tokio::spawn({
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
