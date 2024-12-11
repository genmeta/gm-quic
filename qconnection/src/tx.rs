use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{ready, Context, Poll},
    time::Instant,
};

use deref_derive::{Deref, DerefMut};
use qbase::{
    cid::{ArcCidCell, BorrowedCid, ConnectionId},
    frame::{
        io::{WriteDataFrame, WriteFrame},
        AckFrame, BeFrame, CryptoFrame, PathChallengeFrame, PathResponseFrame, PingFrame,
        ReliableFrame, StreamFrame,
    },
    packet::{
        header::{io::WriteHeader, EncodeHeader},
        signal::SpinBit,
        AssembledPacket, MarshalDataFrame, MarshalFrame, MarshalPathFrame, PacketWriter,
    },
    util::{DescribeData, WriteData},
    Epoch,
};
use qcongestion::{ArcCC, CongestionControl};
use qrecovery::{
    journal::{ArcSentJournal, NewPacketGuard},
    reliable::{ArcReliableFrameDeque, GuaranteedFrame},
};

use crate::{
    conn::{
        space::{DataSpace, HandshakeSpace, InitialSpace},
        Credit, FlowController,
    },
    path::{ArcAntiAmplifier, Constraints, SendBuffer, DEFAULT_ANTI_FACTOR},
};

/// 发送一个数据包，
#[derive(Deref, DerefMut)]
pub struct PacketMemory<'b, 's, F> {
    #[deref]
    writer: PacketWriter<'b>,
    // 不同空间的send guard类型不一样
    guard: NewPacketGuard<'s, F>,
}

impl<'b, 's, F> PacketMemory<'b, 's, F> {
    pub fn new<H>(
        header: H,
        buf: &'b mut [u8],
        tag_len: usize,
        journal: &'s ArcSentJournal<F>,
    ) -> Option<Self>
    where
        H: EncodeHeader,
        for<'a> &'a mut [u8]: WriteHeader<H>,
    {
        let guard = journal.new_packet();
        let pn = guard.pn();
        let writer = PacketWriter::new(&header, buf, pn, tag_len)?;
        Some(Self { writer, guard })
    }
}

impl<F> PacketMemory<'_, '_, F> {
    pub fn dump_ack_frame(&mut self, frame: AckFrame) {
        self.writer.dump_frame(frame);
        self.guard.record_trivial();
    }

    pub fn dump_ping_frame(&mut self, frame: PingFrame) {
        self.writer.dump_frame(frame);
        self.guard.record_trivial();
    }
}

/// 对IH空间有效
impl<'b, D> MarshalDataFrame<CryptoFrame, D> for PacketMemory<'b, '_, CryptoFrame>
where
    D: DescribeData,
    PacketWriter<'b>: WriteData<D> + WriteDataFrame<CryptoFrame, D>,
{
    fn dump_frame_with_data(&mut self, frame: CryptoFrame, data: D) -> Option<CryptoFrame> {
        self.writer
            .dump_frame_with_data(frame, data)
            .and_then(|frame| {
                self.guard.record_frame(frame);
                None
            })
    }
}

impl<'b> MarshalPathFrame<PathChallengeFrame> for PacketMemory<'b, '_, GuaranteedFrame>
where
    PacketWriter<'b>: WriteFrame<PathChallengeFrame>,
{
    fn dump_path_frame(&mut self, frame: PathChallengeFrame) {
        self.writer.dump_frame(frame);
        self.guard.record_trivial();
    }
}

impl<'b> MarshalPathFrame<PathResponseFrame> for PacketMemory<'b, '_, GuaranteedFrame>
where
    PacketWriter<'b>: WriteFrame<PathResponseFrame>,
{
    fn dump_path_frame(&mut self, frame: PathResponseFrame) {
        self.writer.dump_frame(frame);
        self.guard.record_trivial();
    }
}

impl<'b, F> MarshalFrame<F> for PacketMemory<'b, '_, GuaranteedFrame>
where
    F: BeFrame + Into<ReliableFrame>,
    PacketWriter<'b>: WriteFrame<F>,
{
    fn dump_frame(&mut self, frame: F) -> Option<F> {
        self.writer.dump_frame(frame).and_then(|frame| {
            self.guard
                .record_frame(GuaranteedFrame::Reliable(frame.into()));
            None
        })
    }
}

impl<'b, D> MarshalDataFrame<CryptoFrame, D> for PacketMemory<'b, '_, GuaranteedFrame>
where
    D: DescribeData,
    PacketWriter<'b>: WriteData<D> + WriteDataFrame<CryptoFrame, D>,
{
    fn dump_frame_with_data(&mut self, frame: CryptoFrame, data: D) -> Option<CryptoFrame> {
        self.writer
            .dump_frame_with_data(frame, data)
            .and_then(|frame| {
                self.guard.record_frame(GuaranteedFrame::Crypto(frame));
                None
            })
    }
}

impl<'b, D> MarshalDataFrame<StreamFrame, D> for PacketMemory<'b, '_, GuaranteedFrame>
where
    D: DescribeData,
    PacketWriter<'b>: WriteData<D> + WriteDataFrame<StreamFrame, D>,
{
    fn dump_frame_with_data(&mut self, frame: StreamFrame, data: D) -> Option<StreamFrame> {
        self.writer
            .dump_frame_with_data(frame, data)
            .and_then(|frame| {
                self.guard.record_frame(GuaranteedFrame::Stream(frame));
                None
            })
    }
}

impl<'b, F> TryFrom<PacketMemory<'b, '_, F>> for PacketWriter<'b> {
    type Error = ();

    fn try_from(packet: PacketMemory<'b, '_, F>) -> Result<Self, Self::Error> {
        if packet.writer.is_empty() {
            Err(())
        } else {
            Ok(packet.writer)
        }
    }
}

type DcidCell = ArcCidCell<ArcReliableFrameDeque>;

pub struct Transaction<'a> {
    scid: ConnectionId,
    borrowed_dcid: BorrowedCid<'a, ArcReliableFrameDeque>,
    cc: &'a ArcCC,
    flow_limit: Credit<'a>,
    constraints: Constraints,
}

impl<'a> Transaction<'a> {
    pub fn prepare(
        scid: ConnectionId,
        dcid: &'a DcidCell,
        cc: &'a ArcCC,
        anti_amplifier: &'a ArcAntiAmplifier<DEFAULT_ANTI_FACTOR>,
        flow_ctrl: &'a FlowController,
    ) -> PrepareTransaction<'a> {
        PrepareTransaction {
            scid,
            dcid,
            cc,
            anti_amplifier,
            flow_ctrl,
        }
    }

    pub fn scid(&self) -> ConnectionId {
        self.scid
    }

    pub fn dcid(&self) -> ConnectionId {
        *self.borrowed_dcid
    }

    pub fn need_ack(&self, epoch: Epoch) -> Option<(u64, Instant)> {
        self.cc.need_ack(epoch)
    }

    pub fn flow_limit(&self) -> usize {
        self.flow_limit.available()
    }

    pub fn load_initial_space<'b>(
        &mut self,
        buf: &'b mut [u8],
        initial_space: &InitialSpace,
    ) -> Option<(AssembledPacket<'b>, Option<u64>)> {
        initial_space.try_assemble(self, self.constraints.constrain(buf))
    }

    pub fn load_0rtt_data<'b>(
        &mut self,
        buf: &'b mut [u8],
        path_challenge_frames: &SendBuffer<PathChallengeFrame>,
        data_space: &DataSpace,
    ) -> Option<(AssembledPacket<'b>, usize)> {
        data_space.try_assemble_0rtt(self, path_challenge_frames, self.constraints.constrain(buf))
    }

    pub fn load_handshake_space<'b>(
        &mut self,
        buf: &'b mut [u8],
        hs_space: &HandshakeSpace,
    ) -> Option<(AssembledPacket<'b>, Option<u64>)> {
        hs_space.try_assemble(self, self.constraints.constrain(buf))
    }

    pub fn load_1rtt_data<'b>(
        &mut self,
        buf: &'b mut [u8],
        spin: &Arc<AtomicBool>,
        path_challenge_frames: &SendBuffer<PathChallengeFrame>,
        path_response_frames: &SendBuffer<PathResponseFrame>,
        data_space: &DataSpace,
    ) -> Option<(AssembledPacket<'b>, Option<u64>, usize)> {
        let spin = SpinBit::from(spin.load(Ordering::Relaxed));
        data_space.try_assemble_1rtt(
            self,
            spin,
            path_challenge_frames,
            path_response_frames,
            self.constraints.constrain(buf),
        )
    }

    pub fn commit(
        &mut self,
        epoch: Epoch,
        packet: &AssembledPacket<'_>,
        fresh_data: usize,
        ack: Option<u64>,
    ) {
        self.constraints.commit(packet.size(), packet.in_flight());
        self.flow_limit.post_sent(fresh_data);
        self.cc.on_pkt_sent(
            epoch,
            packet.pn(),
            packet.is_ack_eliciting(),
            packet.size(),
            packet.in_flight(),
            ack,
        );
    }
}

pub struct PrepareTransaction<'a> {
    scid: ConnectionId,
    dcid: &'a DcidCell,
    cc: &'a ArcCC,
    anti_amplifier: &'a ArcAntiAmplifier<DEFAULT_ANTI_FACTOR>,
    flow_ctrl: &'a FlowController,
}

impl<'a> Future for PrepareTransaction<'a> {
    type Output = Option<Transaction<'a>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let send_quota = ready!(self.cc.poll_send(cx));
        let Some(credit_limit) = ready!(self.anti_amplifier.poll_balance(cx)) else {
            return Poll::Ready(None);
        };
        let Ok(flow_limit) = self.flow_ctrl.send_limit() else {
            return Poll::Ready(None);
        };
        let Some(borrowed_dcid) = ready!(self.dcid.poll_borrow_cid(cx)) else {
            return Poll::Ready(None);
        };

        Poll::Ready(Some(Transaction {
            scid: self.scid,
            borrowed_dcid,
            cc: self.cc,
            flow_limit,
            constraints: Constraints::new(send_quota, credit_limit),
        }))
    }
}
