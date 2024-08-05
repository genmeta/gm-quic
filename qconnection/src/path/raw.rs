use std::{
    future::Future,
    io::{IoSliceMut},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{ready, Context, Poll, Waker},
    time::Duration,
};

use qbase::{
    cid::{ArcCidCell, ConnectionId, MAX_CID_SIZE},
    flow::FlowController,
    frame::{AckFrame, PathChallengeFrame, PathResponseFrame},
    packet::{LongHeaderBuilder, OneRttHeader, SpinBit},
    util::Burst,
};
use qcongestion::{
    congestion::{ArcCC, CongestionAlgorithm},
    CongestionControl,
};
use qrecovery::space::Epoch;
use qudp::{ArcUsc};

use super::{
    anti_amplifier::{ArcAntiAmplifier, ANTI_FACTOR},
    util::PathFrameBuffer,
    Pathway,
};
use crate::connection::raw::RawConnection;

#[derive(Clone)]
pub struct RawPath {
    pub(super) usc: ArcUsc,
    pub(super) pathway: Pathway,
    pub(super) response_listner: ArcResponseListener,
    pub(super) cc: ArcCC,
    pub(super) anti_amplifier: Option<ArcAntiAmplifier<ANTI_FACTOR>>,
    pub(super) flow_ctrl: FlowController,
    pub(super) dcid: ArcCidCell,
    pub(super) origin_cid: ConnectionId,
    pub(super) token: Vec<u8>,
    pub(super) spin: SpinBit,
    pub(super) challenge_buffer: PathFrameBuffer<PathChallengeFrame>,
    pub(super) response_buffer: PathFrameBuffer<PathResponseFrame>,
    pub(super) inactive_waker: Arc<Mutex<Option<Waker>>>,
}

impl RawPath {
    pub(super) fn new(usc: ArcUsc, pathway: Pathway, connection: &RawConnection) -> Self {
        let cc = ArcCC::new(CongestionAlgorithm::Bbr, Duration::from_micros(100));
        let anti_amplifier = Some(ArcAntiAmplifier::<ANTI_FACTOR>::default());

        let dcid = connection.cid_registry.remote.apply_cid();

        // TODO: 从cid_registry.local 随便选一个能用的
        // 到 1 rtt 空间不再需要
        let (scid, token) = (ConnectionId::random_gen(MAX_CID_SIZE), Vec::new());

        Self {
            usc,
            cc,
            anti_amplifier,
            pathway,
            flow_ctrl: connection.flow_ctrl.clone(),
            dcid,
            origin_cid: scid,
            token,
            spin: SpinBit::default(),
            challenge_buffer: PathFrameBuffer::default(),
            response_buffer: PathFrameBuffer::default(),
            response_listner: ArcResponseListener::new(),
            inactive_waker: Arc::new(Mutex::new(None)),
        }
    }

    pub(super) fn packet_reader<'a>(
        &self,
        dcid: ConnectionId,
        io_slices: Vec<IoSliceMut<'a>>,
    ) -> ArcPacketReader<'a> {
        let reader = PacketReader {
            io_slices,
            cc: self.cc.clone(),
            anti_amplifier: self.anti_amplifier.clone(),
            flow_controler: self.flow_ctrl.clone(),
            dcid,
            scid: self.origin_cid,
            rest_token: self.token.clone(),
            spin: self.spin,
            challenge_buffer: self.challenge_buffer.clone(),
            response_buffer: self.response_buffer.clone(),
        };
        ArcPacketReader(Arc::new(Mutex::new(reader)))
    }

    pub fn recv_response(&mut self, frame: PathResponseFrame) {
        let mut guard = self.response_listner.0.lock().unwrap();
        guard.recv_response(frame);
    }

    pub fn recv_challenge(&mut self, frame: PathChallengeFrame) {
        self.response_buffer.write(frame.into());
    }

    pub fn pto_time(&self) -> Duration {
        self.cc.get_pto_time(Epoch::Data)
    }

    pub fn on_ack(&self, epoch: Epoch, ack: &AckFrame) {
        self.cc.on_ack(epoch, ack);
    }

    pub fn on_recv_pkt(&self, epoch: Epoch, pn: u64, is_ack_eliciting: bool) {
        self.cc.on_recv_pkt(epoch, pn, is_ack_eliciting);
    }

    pub(super) fn inactive(&mut self) {
        self.dcid.retire();
        self.response_listner.0.lock().unwrap().inactive();
    }

    pub(super) fn is_inactive(&self) -> bool {
        let listner = self.response_listner.0.lock().unwrap();
        matches!(*listner, ResponseListener::Inactive)
    }
}

#[derive(Clone)]
pub(super) struct ArcPacketReader<'a>(Arc<Mutex<PacketReader<'a>>>);

struct PacketReader<'a> {
    io_slices: Vec<IoSliceMut<'a>>,
    cc: ArcCC,
    anti_amplifier: Option<ArcAntiAmplifier<3>>,
    flow_controler: FlowController,
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
        let guard = self.0.lock().unwrap();

        let congestion_control = ready!(guard.cc.poll_send(cx));
        // TODO: 连接第一个 path 已经过握手的地址验证，无需再路径验证
        let anti_amplification = if let Some(anti_amplifier) = guard.anti_amplifier.as_ref() {
            match anti_amplifier.poll_get_credit(cx) {
                Poll::Ready(credit) => credit,
                Poll::Pending => return Poll::Pending,
            }
        } else {
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

        let burst = Burst::new(
            anti_amplification,
            congestion_control,
            flow_credit.available(),
        );

        let count: usize = 0;
        /*
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

            let n = guard.challenge_buffer.read(&mut burst, buffer);
            buffer = &mut buffer[n..];
            let n = guard.response_buffer.read(&mut burst, buffer);
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
        */
        // TODO: flow_credit 扣除发送的总数据
        Poll::Ready(count)
    }
}

#[derive(Clone)]
pub(super) enum ResponseListener {
    Init,
    Pending(Waker),
    Response(PathResponseFrame),
    Inactive,
}

impl ResponseListener {
    fn recv_response(&mut self, frame: PathResponseFrame) {
        match self {
            ResponseListener::Init => unreachable!("recv esponse before send challenge"),
            ResponseListener::Pending(waker) => {
                waker.wake_by_ref();
                *self = ResponseListener::Response(frame);
            }
            ResponseListener::Response(resp) => {
                if resp != &frame {
                    *self = ResponseListener::Response(frame);
                }
            }
            ResponseListener::Inactive => {}
        }
    }

    fn inactive(&mut self) {
        if let ResponseListener::Pending(waker) = self {
            waker.wake_by_ref();
        }
        *self = ResponseListener::Inactive;
    }
}

#[derive(Clone)]
pub(super) struct ArcResponseListener(Arc<Mutex<ResponseListener>>);

impl ArcResponseListener {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(ResponseListener::Init)))
    }
}

impl Future for ArcResponseListener {
    type Output = Option<PathResponseFrame>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut listner = self.0.lock().unwrap();
        match *listner {
            ResponseListener::Init | ResponseListener::Pending(_) => {
                *listner = ResponseListener::Pending(cx.waker().clone());
                Poll::Pending
            }
            ResponseListener::Response(resp) => Poll::Ready(Some(resp)),
            ResponseListener::Inactive => Poll::Ready(None),
        }
    }
}
