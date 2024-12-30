use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Instant,
};

use deref_derive::{Deref, DerefMut};
use qbase::{
    cid,
    frame::{
        io::{WriteDataFrame, WriteFrame},
        AckFrame, BeFrame, CryptoFrame, DatagramFrame, PathChallengeFrame, PathResponseFrame,
        PingFrame, ReliableFrame, StreamFrame,
    },
    packet::{
        header::{io::WriteHeader, EncodeHeader},
        signal::SpinBit,
        AssembledPacket, MarshalDataFrame, MarshalFrame, MarshalPathFrame, PacketWriter,
    },
    util::{DescribeData, WriteData},
    Epoch,
};
use qcongestion::CongestionControl;
use qrecovery::{journal, reliable};

use super::{
    conn, path,
    space::{data, handshake, initial},
};

/// 发送一个数据包，
#[derive(Deref, DerefMut)]
pub struct PacketMemory<'b, 's, F> {
    #[deref]
    writer: PacketWriter<'b>,
    // 不同空间的send guard类型不一样
    guard: journal::NewPacketGuard<'s, F>,
}

impl<'b, 's, F> PacketMemory<'b, 's, F> {
    pub fn new<H>(
        header: H,
        buf: &'b mut [u8],
        tag_len: usize,
        journal: &'s journal::ArcSentJournal<F>,
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

impl<'b> MarshalPathFrame<PathChallengeFrame> for PacketMemory<'b, '_, reliable::GuaranteedFrame>
where
    PacketWriter<'b>: WriteFrame<PathChallengeFrame>,
{
    fn dump_path_frame(&mut self, frame: PathChallengeFrame) {
        self.writer.dump_frame(frame);
        self.guard.record_trivial();
    }
}

impl<'b> MarshalPathFrame<PathResponseFrame> for PacketMemory<'b, '_, reliable::GuaranteedFrame>
where
    PacketWriter<'b>: WriteFrame<PathResponseFrame>,
{
    fn dump_path_frame(&mut self, frame: PathResponseFrame) {
        self.writer.dump_frame(frame);
        self.guard.record_trivial();
    }
}

impl<'b, F> MarshalFrame<F> for PacketMemory<'b, '_, reliable::GuaranteedFrame>
where
    F: BeFrame + Into<ReliableFrame>,
    PacketWriter<'b>: WriteFrame<F>,
{
    fn dump_frame(&mut self, frame: F) -> Option<F> {
        self.writer.dump_frame(frame).and_then(|frame| {
            self.guard
                .record_frame(reliable::GuaranteedFrame::Reliable(frame.into()));
            None
        })
    }
}

impl<'b, D> MarshalDataFrame<CryptoFrame, D> for PacketMemory<'b, '_, reliable::GuaranteedFrame>
where
    D: DescribeData,
    PacketWriter<'b>: WriteData<D> + WriteDataFrame<CryptoFrame, D>,
{
    fn dump_frame_with_data(&mut self, frame: CryptoFrame, data: D) -> Option<CryptoFrame> {
        self.writer
            .dump_frame_with_data(frame, data)
            .and_then(|frame| {
                self.guard
                    .record_frame(reliable::GuaranteedFrame::Crypto(frame));
                None
            })
    }
}

impl<'b, D> MarshalDataFrame<StreamFrame, D> for PacketMemory<'b, '_, reliable::GuaranteedFrame>
where
    D: DescribeData,
    PacketWriter<'b>: WriteData<D> + WriteDataFrame<StreamFrame, D>,
{
    fn dump_frame_with_data(&mut self, frame: StreamFrame, data: D) -> Option<StreamFrame> {
        self.writer
            .dump_frame_with_data(frame, data)
            .and_then(|frame| {
                self.guard
                    .record_frame(reliable::GuaranteedFrame::Stream(frame));
                None
            })
    }
}

impl<'b, D> MarshalDataFrame<DatagramFrame, D> for PacketMemory<'b, '_, reliable::GuaranteedFrame>
where
    D: DescribeData,
    PacketWriter<'b>: WriteData<D> + WriteDataFrame<DatagramFrame, D>,
{
    fn dump_frame_with_data(&mut self, frame: DatagramFrame, data: D) -> Option<DatagramFrame> {
        self.writer
            .dump_frame_with_data(frame, data)
            .and_then(|_frame| {
                self.guard.record_trivial();
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

pub type DcidCell = cid::ArcCidCell<reliable::ArcReliableFrameDeque>;

pub struct Transaction<'a> {
    scid: cid::ConnectionId,
    dcid: cid::BorrowedCid<'a, reliable::ArcReliableFrameDeque>,
    cc: &'a qcongestion::ArcCC,
    flow_limit: conn::Credit<'a>,
    constraints: path::Constraints,
}

impl<'a> Transaction<'a> {
    pub fn prepare(
        scid: cid::ConnectionId,
        dcid: &'a DcidCell,
        cc: &'a qcongestion::ArcCC,
        anti_amplifier: &'a path::AntiAmplifier,
        flow_ctrl: &'a conn::FlowController,
    ) -> PrepareTransaction<'a> {
        PrepareTransaction {
            scid,
            dcid,
            cc,
            anti_amplifier,
            flow_ctrl,
        }
    }

    pub fn scid(&self) -> cid::ConnectionId {
        self.scid
    }

    pub fn dcid(&self) -> cid::ConnectionId {
        *self.dcid
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
        initial_space: &initial::Space,
        fill: bool,
    ) -> Option<(AssembledPacket<'b>, Option<u64>)> {
        initial_space.try_assemble(self, self.constraints.constrain(buf), fill)
    }

    pub fn load_0rtt_data<'b>(
        &mut self,
        buf: &'b mut [u8],
        path_challenge_frames: &path::SendBuffer<PathChallengeFrame>,
        data_space: &data::Space,
        fill: bool,
    ) -> Option<(AssembledPacket<'b>, usize)> {
        data_space.try_assemble_0rtt(
            self,
            path_challenge_frames,
            self.constraints.constrain(buf),
            fill,
        )
    }

    pub fn load_handshake_space<'b>(
        &mut self,
        buf: &'b mut [u8],
        hs_space: &handshake::Space,
        fill: bool,
    ) -> Option<(AssembledPacket<'b>, Option<u64>)> {
        hs_space.try_assemble(self, self.constraints.constrain(buf), fill)
    }

    pub fn load_1rtt_data<'b>(
        &mut self,
        buf: &'b mut [u8],
        spin: &Arc<AtomicBool>,
        path_challenge_frames: &path::SendBuffer<PathChallengeFrame>,
        path_response_frames: &path::SendBuffer<PathResponseFrame>,
        data_space: &data::Space,
        fill: bool,
    ) -> Option<(AssembledPacket<'b>, Option<u64>, usize)> {
        let spin = SpinBit::from(spin.load(Ordering::Relaxed));
        data_space.try_assemble_1rtt(
            self,
            spin,
            path_challenge_frames,
            path_response_frames,
            self.constraints.constrain(buf),
            fill,
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
    scid: cid::ConnectionId,
    dcid: &'a DcidCell,
    cc: &'a qcongestion::ArcCC,
    anti_amplifier: &'a path::AntiAmplifier,
    flow_ctrl: &'a conn::FlowController,
}

impl<'a> Future for PrepareTransaction<'a> {
    type Output = Option<Transaction<'a>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        use core::task::ready;

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
        let constraints = path::Constraints::new(credit_limit, send_quota);

        Poll::Ready(Some(Transaction {
            scid: self.scid,
            dcid: borrowed_dcid,
            cc: self.cc,
            flow_limit,
            constraints,
        }))
    }
}
