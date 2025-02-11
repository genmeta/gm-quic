use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};

use bytes::BufMut;
use deref_derive::{Deref, DerefMut};
use qbase::{
    cid::{BorrowedCid, ConnectionId},
    frame::{
        io::{WriteDataFrame, WriteFrame},
        AckFrame, BeFrame, CryptoFrame, DatagramFrame, PathChallengeFrame, PathResponseFrame,
        PingFrame, ReliableFrame, StreamFrame,
    },
    packet::{
        header::{io::WriteHeader, long::LongHeader, short::OneRttHeader, EncodeHeader},
        signal::{KeyPhaseBit, SpinBit},
        AssembledPacket, MarshalDataFrame, MarshalFrame, MarshalPathFrame, MiddleAssembledPacket,
        PacketWriter,
    },
    util::{DescribeData, WriteData},
    Epoch,
};
use qcongestion::{ArcCC, CongestionControl};
use qrecovery::{
    journal::{ArcSentJournal, NewPacketGuard},
    reliable::GuaranteedFrame,
};

use crate::{
    path::{AntiAmplifier, Constraints, SendBuffer},
    space::{data::DataSpace, handshake::HandshakeSpace, initial::InitialSpace, Spaces},
    ArcDcidCell, ArcReliableFrameDeque, Credit, FlowController,
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
    pub fn new_long<S>(
        header: LongHeader<S>,
        buffer: &'b mut [u8],
        keys: Arc<rustls::quic::Keys>,
        journal: &'s ArcSentJournal<F>,
    ) -> Option<Self>
    where
        S: EncodeHeader,
        for<'a> &'a mut [u8]: WriteHeader<LongHeader<S>>,
    {
        let guard = journal.new_packet();
        let pn = guard.pn();
        let writer = PacketWriter::new_long(&header, buffer, pn, keys)?;
        Some(Self { writer, guard })
    }

    pub fn new_short(
        header: OneRttHeader,
        buffer: &'b mut [u8],
        hpk: Arc<dyn rustls::quic::HeaderProtectionKey>,
        pk: Arc<dyn rustls::quic::PacketKey>,
        key_phase: KeyPhaseBit,
        journal: &'s ArcSentJournal<F>,
    ) -> Option<Self> {
        let guard = journal.new_packet();
        let pn = guard.pn();
        let writer = PacketWriter::new_short(&header, buffer, pn, hpk, pk, key_phase)?;
        Some(Self { writer, guard })
    }
}

impl<F> PacketMemory<'_, '_, F> {
    pub fn dump_ack_frame(&mut self, frame: AckFrame) {
        tracing::trace!(?frame, pn = self.guard.pn().0, "dump frame");
        self.writer.dump_frame(frame);
        self.guard.record_trivial();
    }

    pub fn dump_ping_frame(&mut self, frame: PingFrame) {
        tracing::trace!(?frame, pn = self.guard.pn().0, "dump frame");
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
                tracing::trace!(?frame, pn = self.guard.pn().0, "dump frame");
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
        tracing::trace!(?frame, pn = self.guard.pn().0, "dump frame");
        self.writer.dump_frame(frame);
        self.guard.record_trivial();
    }
}

impl<'b> MarshalPathFrame<PathResponseFrame> for PacketMemory<'b, '_, GuaranteedFrame>
where
    PacketWriter<'b>: WriteFrame<PathResponseFrame>,
{
    fn dump_path_frame(&mut self, frame: PathResponseFrame) {
        tracing::trace!(?frame, pn = self.guard.pn().0, "dump frame");
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
            tracing::trace!(?frame, pn = self.guard.pn().0, "dump frame");
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
                tracing::trace!(?frame, pn = self.guard.pn().0, "dump frame");
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
                tracing::trace!(?frame, pn = self.guard.pn().0, "dump frame");
                self.guard.record_frame(GuaranteedFrame::Stream(frame));
                None
            })
    }
}

impl<'b, D> MarshalDataFrame<DatagramFrame, D> for PacketMemory<'b, '_, GuaranteedFrame>
where
    D: DescribeData,
    PacketWriter<'b>: WriteData<D> + WriteDataFrame<DatagramFrame, D>,
{
    fn dump_frame_with_data(&mut self, frame: DatagramFrame, data: D) -> Option<DatagramFrame> {
        self.writer
            .dump_frame_with_data(frame, data)
            .and_then(|_frame| {
                tracing::trace!(?frame, pn = self.guard.pn().0, "dump frame");
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

pub struct Transaction<'a> {
    scid: ConnectionId,
    dcid: BorrowedCid<'a, ArcReliableFrameDeque>,
    cc: &'a ArcCC,
    flow_limit: Credit<'a>,
    constraints: Constraints,
}

impl<'a> Transaction<'a> {
    pub fn prepare(
        scid: ConnectionId,
        dcid: &'a ArcDcidCell,
        cc: &'a ArcCC,
        anti_amplifier: &'a AntiAmplifier,
        flow_ctrl: &'a crate::FlowController,
        expect_quota: usize,
    ) -> PrepareTransaction<'a> {
        PrepareTransaction {
            scid,
            dcid,
            cc,
            anti_amplifier,
            flow_ctrl,
            expect_quota,
        }
    }

    pub fn scid(&self) -> ConnectionId {
        self.scid
    }

    pub fn dcid(&self) -> ConnectionId {
        *self.dcid
    }

    pub fn need_ack(&self, epoch: Epoch) -> Option<(u64, Instant)> {
        self.cc.need_ack(epoch)
    }

    pub fn flow_limit(&self) -> usize {
        self.flow_limit.available()
    }

    pub fn load_initial_space(
        &mut self,
        buf: &mut [u8],
        initial_space: &InitialSpace,
    ) -> Option<(MiddleAssembledPacket, Option<u64>)> {
        initial_space.try_assemble(self, self.constraints.constrain(buf))
    }

    pub fn load_0rtt_data(
        &mut self,
        buf: &mut [u8],
        path_challenge_frames: &SendBuffer<PathChallengeFrame>,
        data_space: &DataSpace,
    ) -> Option<(MiddleAssembledPacket, usize)> {
        data_space.try_assemble_0rtt(self, path_challenge_frames, self.constraints.constrain(buf))
    }

    pub fn load_handshake_space(
        &mut self,
        buf: &mut [u8],
        hs_space: &HandshakeSpace,
    ) -> Option<(MiddleAssembledPacket, Option<u64>)> {
        hs_space.try_assemble(self, self.constraints.constrain(buf))
    }

    pub fn load_1rtt_data(
        &mut self,
        buf: &mut [u8],
        spin: SpinBit,
        path_challenge_frames: &SendBuffer<PathChallengeFrame>,
        path_response_frames: &SendBuffer<PathResponseFrame>,
        data_space: &DataSpace,
    ) -> Option<(MiddleAssembledPacket, Option<u64>, usize)> {
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
        packet: AssembledPacket,
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
    dcid: &'a ArcDcidCell,
    cc: &'a ArcCC,
    anti_amplifier: &'a AntiAmplifier,
    flow_ctrl: &'a FlowController,
    expect_quota: usize,
}

impl<'a> Future for PrepareTransaction<'a> {
    type Output = Option<Transaction<'a>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let send_quota = match self.cc.poll_send(cx, self.expect_quota) {
            Poll::Ready(send_quota) => send_quota,
            Poll::Pending => {
                tracing::trace!(reason = "send quota to small", "sending blocked");
                return Poll::Pending;
            }
        };
        let credit_limit = match self.anti_amplifier.poll_balance(cx) {
            Poll::Ready(Some(credit_limit)) => credit_limit,
            Poll::Ready(None) => return Poll::Ready(None),
            Poll::Pending => {
                tracing::trace!(reason = "credit limit", "sending blocked");
                return Poll::Pending;
            }
        };

        let flow_limit = match self.flow_ctrl.send_limit() {
            Ok(flow_limit) => flow_limit,
            Err(_error) => return Poll::Ready(None),
        };

        let borrowed_dcid = match self.dcid.poll_borrow_cid(cx) {
            Poll::Ready(Some(borrowed_dcid)) => borrowed_dcid,
            Poll::Ready(None) => return Poll::Ready(None),
            Poll::Pending => {
                tracing::trace!(reason = "borrow dcid", "sending blocked");
                return Poll::Pending;
            }
        };
        let constraints = Constraints::new(credit_limit, send_quota);
        tracing::trace!(
            credit_limit,
            send_quota,
            borrowed_dcid = ?*borrowed_dcid,
            flow_limit = flow_limit.available(),
            "transaction ready"
        );

        Poll::Ready(Some(Transaction {
            scid: self.scid,
            dcid: borrowed_dcid,
            cc: self.cc,
            flow_limit,
            constraints,
        }))
    }
}

struct LevelState {
    epoch: Epoch,
    mid_pkt: MiddleAssembledPacket,
    ack: Option<u64>,
}

impl Transaction<'_> {
    pub fn load_spaces(
        &mut self,
        datagram: &mut [u8],
        spaces: &Spaces,
        spin: SpinBit,
        path_challenge_frames: &SendBuffer<PathChallengeFrame>,
        path_response_frames: &SendBuffer<PathResponseFrame>,
    ) -> usize {
        let mut written = 0;
        let mut last_level: Option<LevelState> = None;
        let mut last_level_size = 0;

        if let Some((mid_pkt, ack)) =
            self.load_initial_space(&mut datagram[written..], spaces.initial())
        {
            self.constraints.commit(mid_pkt.size(), mid_pkt.in_flight());
            last_level_size = mid_pkt.size();
            last_level = Some(LevelState {
                epoch: Epoch::Initial,
                mid_pkt,
                ack,
            });
        }

        let is_one_rtt_ready = spaces.data().is_one_rtt_ready();
        if !is_one_rtt_ready {
            if let Some((mid_pkt, fresh_data)) = self.load_0rtt_data(
                &mut datagram[written + last_level_size..],
                path_challenge_frames,
                spaces.data(),
            ) {
                if let Some(last_level) = last_level.take() {
                    let packet = last_level
                        .mid_pkt
                        .resume(&mut datagram[written..])
                        .encrypt_and_protect();
                    written += packet.size();
                    self.cc.on_pkt_sent(
                        last_level.epoch,
                        packet.pn(),
                        packet.is_ack_eliciting(),
                        packet.size(),
                        packet.in_flight(),
                        last_level.ack,
                    );
                }

                self.constraints.commit(mid_pkt.size(), mid_pkt.in_flight());
                self.flow_limit.post_sent(fresh_data);
                last_level_size = mid_pkt.size();
                last_level = Some(LevelState {
                    epoch: Epoch::Data,
                    mid_pkt,
                    ack: None,
                });
            }
        }

        if let Some((mid_pkt, ack)) = self.load_handshake_space(
            &mut datagram[written + last_level_size..],
            spaces.handshake(),
        ) {
            if let Some(last_level) = last_level.take() {
                let packet = last_level
                    .mid_pkt
                    .resume(&mut datagram[written..])
                    .encrypt_and_protect();
                written += packet.size();
                self.cc.on_pkt_sent(
                    last_level.epoch,
                    packet.pn(),
                    packet.is_ack_eliciting(),
                    packet.size(),
                    packet.in_flight(),
                    last_level.ack,
                );
            }

            self.constraints.commit(mid_pkt.size(), mid_pkt.in_flight());
            last_level_size = mid_pkt.size();
            last_level = Some(LevelState {
                epoch: Epoch::Handshake,
                mid_pkt,
                ack,
            });
        }

        if is_one_rtt_ready {
            if let Some((mid_pkt, ack, fresh_data)) = self.load_1rtt_data(
                &mut datagram[written + last_level_size..],
                spin,
                path_challenge_frames,
                path_response_frames,
                spaces.data(),
            ) {
                if let Some(last_level) = last_level.take() {
                    let packet = last_level
                        .mid_pkt
                        .resume(&mut datagram[written..])
                        .encrypt_and_protect();
                    written += packet.size();
                    self.cc.on_pkt_sent(
                        last_level.epoch,
                        packet.pn(),
                        packet.is_ack_eliciting(),
                        packet.size(),
                        packet.in_flight(),
                        last_level.ack,
                    );
                }

                self.constraints.commit(mid_pkt.size(), mid_pkt.in_flight());
                self.flow_limit.post_sent(fresh_data);
                last_level = Some(LevelState {
                    epoch: Epoch::Data,
                    mid_pkt,
                    ack,
                });
            }
        }

        if let Some(final_level) = last_level {
            let mut packet = final_level.mid_pkt.resume(&mut datagram[written..]);

            let padding = packet.remaining_mut().min(self.constraints.available());
            packet.pad(padding);
            self.constraints.commit(padding, packet.in_flight());

            let packet = packet.encrypt_and_protect();
            written += packet.size();
            self.cc.on_pkt_sent(
                final_level.epoch,
                packet.pn(),
                packet.is_ack_eliciting(),
                packet.size(),
                packet.in_flight(),
                final_level.ack,
            );
        }

        written
    }

    pub fn load_validation(
        &mut self,
        buf: &mut [u8],
        spin: SpinBit,
        path_challenge_frames: &SendBuffer<PathChallengeFrame>,
        path_response_frames: &SendBuffer<PathResponseFrame>,
        data_space: &DataSpace,
    ) -> Option<AssembledPacket> {
        data_space.try_assemble_validation(
            self,
            spin,
            path_challenge_frames,
            path_response_frames,
            self.constraints.constrain(buf),
        )
    }
}
