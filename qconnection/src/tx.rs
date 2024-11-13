use std::{
    future::Future,
    pin::Pin,
    task::{ready, Context, Poll},
    time::Instant,
};

use deref_derive::{Deref, DerefMut};
use qbase::{
    cid::{ArcCidCell, BorrowedCid, ConnectionId},
    flow::{Credit, FlowController},
    frame::{
        io::{WriteDataFrame, WriteFrame},
        AckFrame, BeFrame, CryptoFrame, PingFrame, ReliableFrame, StreamFrame,
    },
    packet::{
        header::{io::WriteHeader, EncodeHeader},
        MarshalDataFrame, MarshalFrame, PacketWriter,
    },
    util::{DescribeData, WriteData},
    Epoch,
};
use qcongestion::{ArcCC, CongestionControl};
use qrecovery::{
    journal::{ArcSentJournal, SendGuard},
    reliable::{ArcReliableFrameDeque, GuaranteedFrame},
};

use crate::{
    conn::space::InitialSpace,
    path::{ArcAntiAmplifier, Constraints, DEFAULT_ANTI_FACTOR},
};

/// 发送一个数据包，
#[derive(Deref, DerefMut)]
pub struct JournalAssembly<'b, F> {
    #[deref]
    writer: PacketWriter<'b>,
    // 不同空间的send guard类型不一样
    guard: SendGuard<'b, F>,
}

impl<'b, F> JournalAssembly<'b, F> {
    pub fn new<H>(
        header: H,
        buf: &'b mut [u8],
        tag_len: usize,
        journal: &'b ArcSentJournal<F>,
    ) -> Option<Self>
    where
        H: EncodeHeader,
        for<'a> &'a mut [u8]: WriteHeader<H>,
    {
        let guard = journal.send();
        let pn = guard.next_pn();
        let writer = PacketWriter::new(&header, buf, pn, tag_len)?;
        Some(Self { writer, guard })
    }
}

impl<F> JournalAssembly<'_, F> {
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
impl<'b, D> MarshalDataFrame<CryptoFrame, D> for JournalAssembly<'b, CryptoFrame>
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

impl<'b, F> MarshalFrame<F> for JournalAssembly<'b, GuaranteedFrame>
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

impl<'b, D> MarshalDataFrame<CryptoFrame, D> for JournalAssembly<'b, GuaranteedFrame>
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

impl<'b, D> MarshalDataFrame<StreamFrame, D> for JournalAssembly<'b, GuaranteedFrame>
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

type DcidCell = ArcCidCell<ArcReliableFrameDeque>;

pub struct Transaction<'a> {
    borrowed_dcid: BorrowedCid<'a, ArcReliableFrameDeque>,
    cc: &'a ArcCC,
    flow_limit: Credit<'a>,
    _constraints: Constraints,
}

impl<'a> Transaction<'a> {
    pub fn prepare(
        dcid: &'a DcidCell,
        cc: &'a ArcCC,
        anti_amplifier: &'a ArcAntiAmplifier<DEFAULT_ANTI_FACTOR>,
        flow_ctrl: &'a FlowController,
    ) -> PrepareTransaction<'a> {
        PrepareTransaction {
            dcid,
            cc,
            anti_amplifier,
            flow_ctrl,
        }
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

    pub fn load_initial_space(&mut self, buf: &mut [u8], initial_space: &InitialSpace) -> usize {
        initial_space.try_assemble(self, buf);
        0
    }

    /*
    pub fn load_0rtt_data_space(&mut self, buf: &mut [u8], data_space: &DataSpace) -> usize {
        data_space.try_collect_0rtt(&mut self, buf);
        0
    }

    pub fn load_handshake_space(&mut self, buf: &mut [u8], hs_space: &HandshakeSpace) -> usize {
        hs_space.try_collect(&mut self, buf);
        0
    }

    pub fn load_1rtt_data_space(&mut self, buf: &mut [u8], data_space: &DataSpace) -> usize {
        data_space.try_collect_1rtt(&mut self, buf);
        0
    }
    */

    pub fn commit(&mut self, _packet: PacketWriter<'a>) {
        // commit
    }
}

pub struct PrepareTransaction<'a> {
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
        // TODO: self.flow_ctrl.send_limit() 这样更易读一些
        let Ok(flow_limit) = self.flow_ctrl.sender_ref().credit() else {
            return Poll::Ready(None);
        };
        let Some(borrowed_dcid) = ready!(self.dcid.poll_borrow_cid(cx)) else {
            return Poll::Ready(None);
        };

        Poll::Ready(Some(Transaction {
            borrowed_dcid,
            cc: self.cc,
            flow_limit,
            _constraints: Constraints::new(send_quota, credit_limit),
        }))
    }
}
