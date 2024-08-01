use std::{
    future::{poll_fn, Future},
    io::{IoSlice, IoSliceMut},
    mem,
    ops::Deref,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{ready, Context, Poll, Waker},
    time::Duration,
    vec,
};

use bytes::BufMut;
use qbase::{
    cid::{ArcCidCell, ConnectionId, MAX_CID_SIZE},
    flow::FlowController,
    frame::{AckFrame, ConnectionCloseFrame, PathChallengeFrame, PathResponseFrame},
    packet::{LongHeaderBuilder, OneRttHeader, SpinBit},
    util::Burst,
};
use qcongestion::{
    congestion::{ArcCC, CongestionAlgorithm, MSS},
    CongestionControl,
};
use qrecovery::space::Epoch;
use qudp::{ArcUsc, BATCH_SIZE};

use super::{
    anti_amplifier::{ArcAntiAmplifier, ANTI_FACTOR},
    util::PathFrameBuffer,
    Pathway, ViaPathway,
};
use crate::{connection::raw::RawConnection, transmit::SpaceReaders};

#[derive(Clone)]
pub(super) struct RawPath {
    pub(super) usc: ArcUsc,
    pub(super) pathway: Pathway,
    space_readers: SpaceReaders,
    cc: ArcCC,
    //  抗放大攻击控制器, 服务端地址验证之前有效
    anti_amplifier: Option<ArcAntiAmplifier<ANTI_FACTOR>>,
    flow_ctrl: FlowController,
    dcid: ArcCidCell,
    // 长包头使用的原始 SCID，不会被淘汰
    origin_cid: ConnectionId,
    token: Vec<u8>,
    spin: SpinBit,
    challenge_buffer: PathFrameBuffer<PathChallengeFrame>,
    response_buffer: PathFrameBuffer<PathResponseFrame>,
    response_listner: ArcResponseListener,
    handle: Handle,
}

impl RawPath {
    pub(super) fn new(usc: ArcUsc, pathway: Pathway, connection: &RawConnection) -> Self {
        let cc = ArcCC::new(CongestionAlgorithm::Bbr, Duration::from_micros(100));
        let anti_amplifier = Some(ArcAntiAmplifier::<ANTI_FACTOR>::default());

        let dcid = connection.cid_registry.remote.apply_cid();

        // TODO: 从cid_registry.local 随便选一个能用的
        // 到 1 rtt 空间不再需要
        let (scid, token) = (ConnectionId::random_gen(MAX_CID_SIZE), Vec::new());

        let space_readers = SpaceReaders::new(connection);
        let mut path = Self {
            usc,
            cc,
            anti_amplifier,
            space_readers,
            pathway,
            flow_ctrl: connection.flow_ctrl.clone(),
            dcid,
            origin_cid: scid,
            token,
            spin: SpinBit::default(),
            challenge_buffer: PathFrameBuffer::default(),
            response_buffer: PathFrameBuffer::default(),
            response_listner: ArcResponseListener(Arc::new(Mutex::new(ResponseListener::Init))),
            handle: Handle::default(),
        };

        let send_handle = tokio::spawn({
            let mut path = path.clone();
            async move {
                let mut buffers = vec![vec![0u8; MSS]; BATCH_SIZE];
                let io_slices: Vec<IoSliceMut> =
                    buffers.iter_mut().map(|buf| IoSliceMut::new(buf)).collect();

                let dcid = path.dcid.clone().await;
                let reader = path.packet_reader(dcid, io_slices);
                loop {
                    let count = reader.clone().await;
                    let ioves: Vec<IoSlice<'_>> = buffers
                        .iter()
                        .take(count)
                        .map(|buf| IoSlice::new(buf))
                        .collect();

                    let ret = path.usc.send_via_pathway(ioves.as_slice(), pathway).await;
                    match ret {
                        Ok(_) => todo!(),
                        Err(_) => todo!(),
                    }
                }
            }
        });

        let verify_handle = tokio::spawn({
            let mut path = path.clone();
            async move {
                let challenge = PathChallengeFrame::random();

                for _ in 0..3 {
                    // Write to the buffer, and the sending task actually sends it
                    // Reliability is not maintained through reliable transmission, but a stop-and-wait protocol
                    path.challenge_buffer.write(challenge);
                    let pto = path.cc.get_pto_time(Epoch::Data);
                    let listener = path.response_listner.clone();

                    match tokio::time::timeout(pto, listener).await {
                        Ok(Some(resp)) if resp.deref() == challenge.deref() => {
                            path.anti_amplifier.take();
                        }
                        // listner inactive, stop the task
                        Ok(None) => break,
                        // timout or reponse don't match, try again
                        _ => continue,
                    }
                }
            }
        });

        let cc_handle = tokio::spawn({
            let cc = path.cc.clone();
            let space_readers = path.space_readers.clone();
            async move {
                loop {
                    tokio::select! {
                        (epoch, loss) = cc.may_loss() => space_readers.may_loss(epoch, loss),
                        // epoch = cc.probe_timeout() => todo!("probe timeout")
                        (epoch, acked) = cc.indicate_ack() => space_readers.retire(epoch,acked),
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

    fn packet_reader<'a>(
        &self,
        dcid: ConnectionId,
        io_slices: Vec<IoSliceMut<'a>>,
    ) -> ArcPacketReader<'a> {
        let reader = PacketReader {
            io_slices,
            cc: self.cc.clone(),
            anti_amplifier: self.anti_amplifier.clone(),
            flow_controler: self.flow_ctrl.clone(),
            space_readers: self.space_readers.clone(),
            dcid,
            scid: self.origin_cid,
            rest_token: self.token.clone(),
            spin: self.spin.clone(),
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
        self.response_buffer.write(frame.into());
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
        let mut guard = self.response_listner.0.lock().unwrap();
        let _ = mem::replace(&mut *guard, ResponseListener::Inactive);
    }
}

#[derive(Clone)]
struct ArcPacketReader<'a>(Arc<Mutex<PacketReader<'a>>>);

struct PacketReader<'a> {
    io_slices: Vec<IoSliceMut<'a>>,
    cc: ArcCC,
    anti_amplifier: Option<ArcAntiAmplifier<3>>,
    flow_controler: FlowController,
    space_readers: SpaceReaders,
    dcid: ConnectionId,
    scid: ConnectionId,
    rest_token: Vec<u8>,
    spin: SpinBit,
    challenge_buffer: PathFrameBuffer<PathChallengeFrame>,
    response_buffer: PathFrameBuffer<PathResponseFrame>,
}

impl<'a> Future for ArcPacketReader<'a> {
    type Output = usize;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let ioslices = &mut self.0.lock().unwrap().io_slices;
        let mut guard = self.0.lock().unwrap();

        let congestion_control = ready!(guard.cc.poll_send(cx));
        let anti_amplification = if let Some(anti_amplifier) = guard.anti_amplifier.as_ref() {
            match anti_amplifier.poll_get_credit(cx) {
                Poll::Ready(credit) => {
                    guard.cc.anti_amplification_limit_off();
                    credit
                }
                Poll::Pending => {
                    guard.cc.anti_amplification_limit_on();
                    return Poll::Pending;
                }
            }
        } else {
            guard.cc.anti_amplification_limit_off();
            None
        };
        let send_controller = guard.flow_controler.sender();
        let flow_credit = match send_controller.credit() {
            Ok(credit) => credit,
            Err(_) => return Poll::Pending,
        };

        let inital_hdr =
            LongHeaderBuilder::with_cid(guard.dcid, guard.scid).initial(guard.rest_token.clone());
        let handshake_hdr = LongHeaderBuilder::with_cid(guard.dcid, guard.scid).handshake();
        let one_rtt_hdr = OneRttHeader {
            spin: guard.spin,
            dcid: guard.dcid,
        };

        let mut burst = Burst::new(
            anti_amplification,
            congestion_control,
            flow_credit.available(),
        );

        let mut count: usize = 0;
        for ioslice in ioslices.iter_mut() {
            let mut buffer = ioslice.as_mut();
            let origin = buffer.remaining_mut();
            let need_ack = guard.cc.need_ack(Epoch::Initial);
            let (pkt_size, pn, is_ack_eliciting) = guard.space_readers.read_long_header_space(
                buffer,
                &inital_hdr,
                &mut burst,
                Epoch::Initial,
                need_ack,
            );

            let ack = need_ack.map(|ack| ack.0);
            guard.cc.on_pkt_sent(
                Epoch::Initial,
                pn,
                is_ack_eliciting,
                pkt_size,
                is_ack_eliciting,
                ack,
            );

            buffer = &mut buffer[pkt_size..];

            let need_ack = guard.cc.need_ack(Epoch::Handshake);
            let (pkt_size, pn, is_ack_eliciting) = guard.space_readers.read_long_header_space(
                buffer,
                &handshake_hdr,
                &mut burst,
                Epoch::Handshake,
                need_ack,
            );

            guard.cc.on_pkt_sent(
                Epoch::Handshake,
                pn,
                is_ack_eliciting,
                pkt_size,
                is_ack_eliciting,
                ack,
            );
            buffer = &mut buffer[pkt_size..];

            let n = guard.challenge_buffer.read(buffer, &mut burst);
            buffer = &mut buffer[n..];
            let n = guard.response_buffer.read(buffer, &mut burst);
            buffer = &mut buffer[n..];

            let need_ack = guard.cc.need_ack(Epoch::Data);
            let (pkt_size, pn, is_ack_eliciting) =
                guard
                    .space_readers
                    .read_one_rtt_space(buffer, &mut burst, &one_rtt_hdr, need_ack);
            guard.cc.on_pkt_sent(
                Epoch::Handshake,
                pn,
                is_ack_eliciting,
                pkt_size,
                is_ack_eliciting,
                ack,
            );

            buffer = &mut buffer[pkt_size..];
            if origin - buffer.remaining_mut() > 0 {
                count += 1;
            }
            if buffer.remaining_mut() > 0 {
                break;
            }
        }
        // TODO: flow_credit 扣除发送的总数据
        Poll::Ready(count)
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
    type Output = Option<PathResponseFrame>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut listner = self.0.lock().unwrap();
        match *listner {
            ResponseListener::Init => {
                *listner = ResponseListener::Pending(cx.waker().clone());
                Poll::Pending
            }
            ResponseListener::Pending(_) => Poll::Pending,
            ResponseListener::Response(resp) => Poll::Ready(Some(resp)),
            ResponseListener::Inactive => Poll::Ready(None),
        }
    }
}
