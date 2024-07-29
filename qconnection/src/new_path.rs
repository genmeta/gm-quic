use std::{
    array,
    io::{self, IoSlice, IoSliceMut},
    mem,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Wake, Waker},
    time::Duration,
};

use dashmap::DashMap;
use futures::{future::poll_fn, ready, Future};
use qbase::{
    cid::{ArcCidCell, ConnectionId, Registry, MAX_CID_SIZE},
    flow::FlowController,
    frame::{
        io::{WriteConnectionCloseFrame, WritePathChallengeFrame, WritePathResponseFrame},
        BeFrame, ConnectionCloseFrame, PathChallengeFrame, PathResponseFrame,
    },
    packet::{header::Encode, keys::AllKeys, Header, LongHeaderBuilder, OneRttHeader, SpinBit},
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
    // todo: 整改 id_registry
    dcid: ArcCidCell,
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
        let current_state = &*guard; // 不可变借用
        match current_state {
            ResponseListener::Init => unreachable!("recv esponse before send challenge"),
            ResponseListener::Pending(waker) => {
                waker.wake_by_ref();
                *guard = ResponseListener::Response(frame); // 可变借用
            }
            ResponseListener::Response(resp) => {
                if resp != &frame {
                    *guard = ResponseListener::Response(frame); // 可变借用
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
enum ResponseListener {
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
            ResponseListener::Inactive => unreachable!(),
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

                let (hdr, max_header_size) = match epoch {
                    Epoch::Initial => {
                        let inital_hdr = LongHeaderBuilder::with_cid(guard.dcid, guard.scid)
                            .initial(guard.rest_token.clone());
                        let size = inital_hdr.size() + 2; // 2 bytes reserved for packet length, max 16KB
                        (Header::Initial(inital_hdr), size)
                    }
                    Epoch::Handshake => {
                        let handshake_hdr =
                            LongHeaderBuilder::with_cid(guard.dcid, guard.scid).handshake();
                        let size = handshake_hdr.size() + 2;
                        (Header::Handshake(handshake_hdr), size)
                    }
                    Epoch::Data => {
                        // todo: 可能有 0 RTT 数据要发送
                        // 如果 data space 有数据，但是没有 1 rtt 密钥, 有 0 rtt 密钥
                        let data_hdr = OneRttHeader {
                            spin: guard.spin,
                            dcid: guard.dcid,
                        };
                        let size = data_hdr.size() + 2;
                        (Header::OneRtt(data_hdr), size)
                    }
                };

                let (_, body_buf) = buf.split_at_mut(max_header_size);
                let (pn, pn_size) = space.read_pn(body_buf, &mut limit);
                let mut body_buf = &mut body_buf[pn_size..];

                let mut challenge_size = 0;
                if epoch == Epoch::Data {
                    // todo: 有 path challenge 时需要保证包至少有 1200 字节
                    let len = guard.send_challenge(body_buf, &mut limit);
                    challenge_size += len;
                    body_buf = &mut body_buf[len..];
                    let len = guard.send_response(body_buf, &mut limit);
                    body_buf = &mut body_buf[len..];
                    challenge_size += len;
                }

                let ack_pkt = guard.cc.need_ack(epoch);
                let (frame_size, is_ack_eliciting) =
                    space.read_frame(&mut limit, body_buf, ack_pkt);

                let body_len = pn_size + frame_size + challenge_size;
                space.read_finish();

                let sent_bytes = match hdr {
                    Header::Initial(header) => {
                        let fill_policy = transmit::FillPolicy::Redundancy;
                        let (_, sent_bytes) = transmit::encrypt_long_header_space(
                            buf,
                            &header,
                            pn,
                            pn_size,
                            body_len,
                            fill_policy,
                            &guard.keys.initial_keys.clone().unwrap(),
                        );
                        sent_bytes
                    }
                    Header::Handshake(header) => {
                        let fill_policy = transmit::FillPolicy::Redundancy;
                        let (_, sent_bytes) = transmit::encrypt_long_header_space(
                            buf,
                            &header,
                            pn,
                            pn_size,
                            body_len,
                            fill_policy,
                            &guard.keys.handshake_keys.clone().unwrap(),
                        );
                        sent_bytes
                    }
                    Header::OneRtt(header) => transmit::encrypt_1rtt_space(
                        buf,
                        &header,
                        guard.keys.one_rtt_keys.clone().unwrap(),
                        pn,
                        pn_size,
                        body_len,
                    ),
                    _ => {
                        todo!("send 0rtt retry VN packet");
                    }
                };

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
    ccf_buffer: Arc<Mutex<Vec<u8>>>,
}

#[derive(Clone)]
pub struct ArcPath(Arc<Mutex<PathState>>);

impl ArcPath {
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

    fn enter_dying(&self, ccf: ConnectionCloseFrame) {
        let mut guard = self.0.lock().unwrap();
        match *guard {
            PathState::Alive(ref mut path) => {
                let mut buf = Vec::with_capacity(ccf.encoding_size());
                buf.put_connection_close_frame(&ccf);
                let ccf_buffer = Arc::new(Mutex::new(buf));
                // todo: 生成加密的 ccf，并发送
                *guard = PathState::Dying(DyingPath {
                    usc: path.usc.clone(),
                    ccf_buffer,
                });
            }
            PathState::Dying(_) => {}
            PathState::Dead => {}
        }
    }

    fn enter_dead(&self) {}
}

pub fn create_path(
    usc: ArcUsc,
    pathway: Pathway,
    spaces: Spaces,
    keys: AllKeys,
    flow_controller: FlowController,
    cid_registry: Registry,
    spin: SpinBit,
    pathes: DashMap<Pathway, ArcPath>,
) -> ArcPath {
    let dcid = cid_registry.remote.apply_cid();
    let raw_path = RawPath::new(usc, pathway, spaces, keys, flow_controller, dcid);
    let arc_path = ArcPath(Arc::new(Mutex::new(PathState::Alive(raw_path.clone()))));

    // 发送任务
    let send_handle = tokio::spawn({
        let path = raw_path.clone();

        async move {
            let predicate = |_: &ConnectionId| true;
            let (scid, token) = match cid_registry.local.issue_cid(MAX_CID_SIZE, predicate).await {
                Ok(frame) => {
                    let token = (*frame.reset_token).to_vec();
                    let scid = frame.id;
                    // todo: put frame into space queue
                    (scid, token)
                }
                Err(_) => {
                    return;
                }
            };

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
            PathState::Dying(_) => Poll::Pending,
            PathState::Dead => Poll::Ready(()),
        }
    }
}
