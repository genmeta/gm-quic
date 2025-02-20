use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};

use bytes::{BufMut, Bytes};
use deref_derive::Deref;
use qbase::{
    cid::{BorrowedCid, ConnectionId},
    frame::{
        io::{WriteDataFrame, WriteFrame},
        AckFrame, BeFrame, CryptoFrame, DatagramFrame, PathChallengeFrame, PathResponseFrame,
        ReliableFrame, StreamFrame,
    },
    packet::{
        header::{
            io::WriteHeader, long::LongHeader, short::OneRttHeader, EncodeHeader, GetDcid, GetScid,
            GetType,
        },
        signal::{KeyPhaseBit, SpinBit},
        EncryptedPacket, MarshalDataFrame, MarshalFrame, MarshalPathFrame, PacketWriter,
        UnencryptedPacket,
    },
    util::{DescribeData, WriteData},
    Epoch,
};
use qcongestion::{ArcCC, CongestionControl};
use qlog::quic::{transport::PacketSent, QuicFrame};
use qrecovery::{
    journal::{ArcSentJournal, NewPacketGuard},
    reliable::GuaranteedFrame,
};

use crate::{
    path::{AntiAmplifier, Constraints, SendBuffer},
    space::{data::DataSpace, Spaces},
    ArcDcidCell, ArcReliableFrameDeque, Credit, FlowController,
};

pub struct PacketLogger {
    header: qlog::quic::PacketHeaderBuilder,
    frames: Vec<QuicFrame>,
}

impl PacketLogger {
    pub fn record_frame(&mut self, frame: QuicFrame) {
        self.frames.push(frame);
    }

    pub fn emit_sent(mut self, packet: &PacketWriter) {
        // TODO: 如果以后涉及到组装VN，Retry，这里的逻辑得改
        if !packet.is_short_header() {
            self.header
                .length((packet.payload_len() + packet.tag_len()) as u16);
        }

        qlog::event!(qlog::build!(PacketSent {
            header: self.header.build(),
            frames: self.frames,
            raw: qlog::RawInfo {
                length: packet.packet_len() as u64,
                payload_length: { packet.packet_len() + packet.tag_len() } as u64,
                data: { Bytes::from(packet.buffer().to_vec()) },
            },
            // TODO: trigger
        }))
    }
}

pub struct PacketMemory<'b, 's, F> {
    writer: PacketWriter<'b>,
    // 不同空间的send guard类型不一样
    guard: NewPacketGuard<'s, F>,
    logger: PacketLogger,
}

impl<'b, 's, F> PacketMemory<'b, 's, F> {
    pub fn new_long<S>(
        header: LongHeader<S>,
        buffer: &'b mut [u8],
        keys: Arc<rustls::quic::Keys>,
        journal: &'s ArcSentJournal<F>,
    ) -> Option<Self>
    where
        S: EncodeHeader + 'static,
        LongHeader<S>: GetType,
        for<'a> &'a mut [u8]: WriteHeader<LongHeader<S>>,
    {
        let guard = journal.new_packet();
        let pn = guard.pn();
        Some(Self {
            guard,
            writer: PacketWriter::new_long(&header, buffer, pn, keys)?,
            logger: PacketLogger {
                header: {
                    let mut builder = qlog::quic::PacketHeader::builder();
                    builder.packet_type(header.get_type());
                    builder.packet_number(pn.0);
                    builder.scil(header.scid().len() as u8);
                    builder.scid(*header.scid());
                    builder.dcil(header.dcid().len() as u8);
                    builder.dcid(*header.dcid());
                    builder
                },
                frames: vec![],
            },
        })
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
        Some(Self {
            guard,
            writer: PacketWriter::new_short(&header, buffer, pn, hpk, pk, key_phase)?,
            logger: PacketLogger {
                header: {
                    let mut builder = qlog::quic::PacketHeader::builder();
                    builder.packet_type(header.get_type());
                    builder.packet_number(pn.0);
                    builder.dcil(header.dcid().len() as u8);
                    builder.dcid(*header.dcid());
                    builder
                },
                frames: vec![],
            },
        })
    }
}

#[derive(Deref)]
pub struct MiddleAssembledPacket {
    #[deref]
    packet: UnencryptedPacket,
    logger: PacketLogger,
}

impl MiddleAssembledPacket {
    pub fn fill_and_complete(mut self, buffer: &mut [u8]) -> EncryptedPacket {
        let mut writer = self.packet.resume(buffer);

        let padding_len = writer.remaining_mut();
        if padding_len > 0 {
            writer.pad(padding_len);
            self.logger.record_frame(QuicFrame::Padding {
                length: Some(padding_len as u32),
                payload_length: padding_len as u32,
            });
        }

        self.logger.emit_sent(&writer);
        writer.encrypt_and_protect()
    }

    pub fn complete(mut self, buffer: &mut [u8]) -> EncryptedPacket {
        let mut writer = self.packet.resume(buffer);
        let packet_len = writer.packet_len();
        if packet_len < 20 {
            let padding_len = 20 - packet_len;
            writer.pad(padding_len);
            self.logger.record_frame(QuicFrame::Padding {
                length: Some(padding_len as u32),
                payload_length: padding_len as u32,
            });
        }

        self.logger.emit_sent(&writer);
        writer.encrypt_and_protect()
    }
}

unsafe impl<F> BufMut for PacketMemory<'_, '_, F> {
    #[inline]
    fn remaining_mut(&self) -> usize {
        self.writer.remaining_mut()
    }

    #[inline]
    unsafe fn advance_mut(&mut self, cnt: usize) {
        self.writer.advance_mut(cnt);
    }

    #[inline]
    fn chunk_mut(&mut self) -> &mut bytes::buf::UninitSlice {
        self.writer.chunk_mut()
    }

    // steam/datagram可能会手动padding，padding也要被记录，所以这里不能用默认实现
    #[inline]
    fn put_bytes(&mut self, val: u8, cnt: usize) {
        if val == 0 {
            self.pad(cnt);
        } else {
            self.writer.put_bytes(val, cnt);
        }
    }
}

impl<F> PacketMemory<'_, '_, F> {
    pub fn dump_ack_frame(&mut self, frame: AckFrame) {
        self.logger.record_frame((&frame).into());
        self.writer.dump_frame(frame);
        self.guard.record_trivial();
    }

    pub fn pad(&mut self, len: usize) {
        if len == 0 {
            return;
        }
        self.writer.pad(len);
        self.logger.record_frame(QuicFrame::Padding {
            length: Some(len as u32),
            payload_length: len as u32,
        });
    }

    pub fn interrupt(self) -> Option<MiddleAssembledPacket> {
        if self.writer.is_empty() {
            return None;
        }
        Some(MiddleAssembledPacket {
            packet: self.writer.interrupt().0,
            logger: self.logger,
        })
    }

    // 其实never used，但是还是给它留一个位置
    pub fn complete(mut self) -> Option<EncryptedPacket> {
        let packet_len = self.writer.packet_len();
        if packet_len == 0 {
            return None;
        }
        if packet_len < 20 {
            self.pad(20 - packet_len);
        }

        self.logger.emit_sent(&self.writer);
        Some(self.writer.encrypt_and_protect())
    }
}

/// 对IH空间有效
impl<'b, D> MarshalDataFrame<CryptoFrame, D> for PacketMemory<'b, '_, CryptoFrame>
where
    D: DescribeData,
    PacketWriter<'b>: WriteData<Bytes> + WriteDataFrame<CryptoFrame, Bytes>,
{
    fn dump_frame_with_data(&mut self, frame: CryptoFrame, data: D) -> Option<CryptoFrame> {
        let data = data.to_bytes();
        self.writer
            .dump_frame_with_data(frame, data.clone())
            .and_then(|frame| {
                self.logger.record_frame((&frame, &data).into());
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
        self.logger.record_frame((&frame).into());
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
        self.logger.record_frame((&frame).into());
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
            let reliable_frame = frame.into();
            self.logger.record_frame((&reliable_frame).into());
            self.guard
                .record_frame(GuaranteedFrame::Reliable(reliable_frame));
            None
        })
    }
}

impl<'b, D> MarshalDataFrame<CryptoFrame, D> for PacketMemory<'b, '_, GuaranteedFrame>
where
    D: DescribeData,
    PacketWriter<'b>: WriteData<Bytes> + WriteDataFrame<CryptoFrame, Bytes>,
{
    fn dump_frame_with_data(&mut self, frame: CryptoFrame, data: D) -> Option<CryptoFrame> {
        let data = data.to_bytes();
        self.writer
            .dump_frame_with_data(frame, data.clone())
            .and_then(|frame| {
                self.logger.record_frame((&frame, &data).into());
                self.guard.record_frame(GuaranteedFrame::Crypto(frame));
                None
            })
    }
}

impl<'b, D> MarshalDataFrame<StreamFrame, D> for PacketMemory<'b, '_, GuaranteedFrame>
where
    D: DescribeData,
    PacketWriter<'b>: WriteData<Bytes> + WriteDataFrame<StreamFrame, Bytes>,
{
    fn dump_frame_with_data(&mut self, frame: StreamFrame, data: D) -> Option<StreamFrame> {
        let data = data.to_bytes();
        self.writer
            .dump_frame_with_data(frame, data.clone())
            .and_then(|frame| {
                self.logger.record_frame((&frame, &data).into());
                self.guard.record_frame(GuaranteedFrame::Stream(frame));
                None
            })
    }
}

impl<'b, D> MarshalDataFrame<DatagramFrame, D> for PacketMemory<'b, '_, GuaranteedFrame>
where
    D: DescribeData,
    PacketWriter<'b>: WriteData<Bytes> + WriteDataFrame<DatagramFrame, Bytes>,
{
    fn dump_frame_with_data(&mut self, frame: DatagramFrame, data: D) -> Option<DatagramFrame> {
        let data = data.to_bytes();
        self.writer
            .dump_frame_with_data(frame, data.clone())
            .and_then(|frame| {
                self.logger.record_frame((&frame, &data).into());
                self.guard.record_trivial();
                None
            })
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

    pub fn commit(
        &mut self,
        epoch: Epoch,
        packet: EncryptedPacket,
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
    pkt: MiddleAssembledPacket,
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

        if let Some((mid_pkt, ack)) = spaces
            .initial()
            .try_assemble(self, &mut datagram[written..])
        {
            self.constraints
                .commit(mid_pkt.packet_len(), mid_pkt.in_flight());
            last_level_size = mid_pkt.packet_len();
            last_level = Some(LevelState {
                epoch: Epoch::Initial,
                pkt: mid_pkt,
                ack,
            });
        }

        let is_one_rtt_ready = spaces.data().is_one_rtt_ready();
        if !is_one_rtt_ready {
            if let Some((mid_pkt, fresh_data)) = spaces.data().try_assemble_0rtt(
                self,
                path_challenge_frames,
                &mut datagram[written + last_level_size..],
            ) {
                if let Some(last_level) = last_level.take() {
                    let packet = last_level.pkt.complete(&mut datagram[written..]);
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

                self.constraints
                    .commit(mid_pkt.packet_len(), mid_pkt.in_flight());
                self.flow_limit.post_sent(fresh_data);
                last_level_size = mid_pkt.packet_len();
                last_level = Some(LevelState {
                    epoch: Epoch::Data,
                    pkt: mid_pkt,
                    ack: None,
                });
            }
        }

        if let Some((mid_pkt, ack)) = spaces
            .handshake()
            .try_assemble(self, &mut datagram[written + last_level_size..])
        {
            if let Some(last_level) = last_level.take() {
                let packet = last_level.pkt.complete(&mut datagram[written..]);
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

            self.constraints
                .commit(mid_pkt.packet_len(), mid_pkt.in_flight());
            last_level_size = mid_pkt.packet_len();
            last_level = Some(LevelState {
                epoch: Epoch::Handshake,
                pkt: mid_pkt,
                ack,
            });
        }

        if is_one_rtt_ready {
            if let Some((mid_pkt, ack, fresh_data)) = spaces.data().try_assemble_1rtt(
                self,
                spin,
                path_challenge_frames,
                path_response_frames,
                &mut datagram[written + last_level_size..],
            ) {
                if let Some(last_level) = last_level.take() {
                    let packet = last_level.pkt.complete(&mut datagram[written..]);
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

                self.constraints
                    .commit(mid_pkt.packet_len(), mid_pkt.in_flight());
                self.flow_limit.post_sent(fresh_data);
                last_level = Some(LevelState {
                    epoch: Epoch::Data,
                    pkt: mid_pkt,
                    ack,
                });
            }
        }

        if let Some(final_level) = last_level {
            let packet = final_level.pkt.fill_and_complete(&mut datagram[written..]);

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

    pub fn load_one_rtt(
        &mut self,
        buf: &mut [u8],
        spin: SpinBit,
        path_challenge_frames: &SendBuffer<PathChallengeFrame>,
        path_response_frames: &SendBuffer<PathResponseFrame>,
        data_space: &DataSpace,
    ) -> usize {
        let buffer = self.constraints.constrain(buf);
        data_space
            .try_assemble_1rtt(
                self,
                spin,
                path_challenge_frames,
                path_response_frames,
                buffer,
            )
            .map_or(0, |(packet, ack, fresh_bytes)| {
                let packet = packet.fill_and_complete(buffer);
                self.constraints.commit(packet.size(), packet.in_flight());
                self.flow_limit.post_sent(fresh_bytes);
                self.cc.on_pkt_sent(
                    Epoch::Data,
                    packet.pn(),
                    packet.is_ack_eliciting(),
                    packet.size(),
                    packet.in_flight(),
                    ack,
                );
                packet.size()
            })
    }

    pub fn load_validation(
        &mut self,
        buf: &mut [u8],
        spin: SpinBit,
        path_challenge_frames: &SendBuffer<PathChallengeFrame>,
        path_response_frames: &SendBuffer<PathResponseFrame>,
        data_space: &DataSpace,
    ) -> usize {
        let buffer = self.constraints.constrain(buf);
        data_space
            .try_assemble_validation(
                self,
                spin,
                path_challenge_frames,
                path_response_frames,
                buffer,
            )
            .map_or(0, |packet| {
                let packet = packet.fill_and_complete(buffer);
                self.cc.on_pkt_sent(
                    Epoch::Data,
                    packet.pn(),
                    packet.is_ack_eliciting(),
                    packet.size(),
                    packet.in_flight(),
                    None,
                );
                packet.size()
            })
    }
}
