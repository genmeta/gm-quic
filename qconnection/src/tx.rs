use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::BufMut;
use deref_derive::Deref;
use qbase::{
    Epoch,
    cid::{BorrowedCid, ConnectionId},
    frame::{
        AckFrame, BeFrame, CryptoFrame, DatagramFrame, PathChallengeFrame, PathResponseFrame,
        ReliableFrame, StreamFrame,
        io::{WriteDataFrame, WriteFrame},
    },
    net::tx::{ArcSendWaker, Signals},
    packet::{
        CipherPacket, MarshalDataFrame, MarshalFrame, MarshalPathFrame, PacketWriter, PlainPacket,
        header::{
            EncodeHeader, GetDcid, GetScid, GetType, io::WriteHeader, long::LongHeader,
            short::OneRttHeader,
        },
        signal::{KeyPhaseBit, SpinBit},
    },
    util::{DescribeData, WriteData},
};
use qcongestion::{ArcCC, Transport};
use qlog::quic::{QuicFrame, QuicFramesCollector, transport::PacketSent};
use qrecovery::{
    journal::{ArcSentJournal, NewPacketGuard},
    reliable::GuaranteedFrame,
};

use crate::{
    ArcDcidCell, ArcReliableFrameDeque, Credit,
    path::{AntiAmplifier, Constraints, SendBuffer},
    space::{Spaces, data::DataSpace},
};

pub struct PacketLogger {
    header: qlog::quic::PacketHeaderBuilder,
    frames: QuicFramesCollector<PacketSent>,
}

impl PacketLogger {
    pub fn record_frame(&mut self, frame: impl Into<QuicFrame>) {
        self.frames.extend([frame]);
    }

    pub fn log_sent(mut self, packet: &PacketWriter) {
        // TODO: 如果以后涉及到组装VN，Retry，这里的逻辑得改
        if !packet.is_short_header() {
            self.header
                .length((packet.payload_len() + packet.tag_len()) as u16);
        }

        qlog::event!(PacketSent {
            header: self.header.build(),
            frames: self.frames,
            raw: qlog::RawInfo {
                length: packet.packet_len() as u64,
                payload_length: { packet.packet_len() + packet.tag_len() } as u64,
                data: packet.buffer(),
            },
            // TODO: trigger
        })
    }
}

pub struct PacketBuffer<'b, 's, F> {
    writer: PacketWriter<'b>,
    // 不同空间的send guard类型不一样
    clerk: NewPacketGuard<'s, F>,
    logger: PacketLogger,
}

impl<'b, 's, F> PacketBuffer<'b, 's, F> {
    pub fn new_long<S>(
        header: LongHeader<S>,
        buffer: &'b mut [u8],
        keys: Arc<rustls::quic::Keys>,
        journal: &'s ArcSentJournal<F>,
    ) -> Result<Self, Signals>
    where
        S: EncodeHeader + 'static,
        LongHeader<S>: GetType,
        for<'a> &'a mut [u8]: WriteHeader<LongHeader<S>>,
    {
        let guard = journal.new_packet();
        let pn = guard.pn();
        Ok(Self {
            clerk: guard,
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
                frames: QuicFramesCollector::new(),
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
    ) -> Result<Self, Signals> {
        let guard = journal.new_packet();
        let pn = guard.pn();
        Ok(Self {
            clerk: guard,
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
                frames: QuicFramesCollector::new(),
            },
        })
    }
}

#[derive(Deref)]
pub struct PaddablePacket {
    #[deref]
    packet: PlainPacket,
    logger: PacketLogger,
}

impl PaddablePacket {
    pub fn fill_and_complete(mut self, buffer: &mut [u8]) -> CipherPacket {
        let mut writer = self.packet.writer(buffer);

        let padding_len = writer.remaining_mut();
        if padding_len > 0 {
            writer.pad(padding_len);
            self.logger.record_frame(QuicFrame::Padding {
                length: Some(padding_len as u32),
                payload_length: padding_len as u32,
            });
        }

        self.logger.log_sent(&writer);
        writer.encrypt_and_protect()
    }

    pub fn complete(mut self, buffer: &mut [u8]) -> CipherPacket {
        let mut writer = self.packet.writer(buffer);
        if writer.payload_len() + writer.tag_len() < 20 {
            let padding_len = 20 - writer.payload_len() - writer.tag_len();
            writer.pad(padding_len);
            self.logger.record_frame(QuicFrame::Padding {
                length: Some(padding_len as u32),
                payload_length: padding_len as u32,
            });
        }

        self.logger.log_sent(&writer);
        writer.encrypt_and_protect()
    }
}

unsafe impl<F> BufMut for PacketBuffer<'_, '_, F> {
    #[inline]
    fn remaining_mut(&self) -> usize {
        self.writer.remaining_mut()
    }

    #[inline]
    unsafe fn advance_mut(&mut self, cnt: usize) {
        unsafe { self.writer.advance_mut(cnt) };
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

impl<F> PacketBuffer<'_, '_, F> {
    pub fn dump_ack_frame(&mut self, frame: AckFrame) {
        self.logger.record_frame(&frame);
        self.writer.dump_frame(frame);
        self.clerk.record_trivial();
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

    pub fn prepare_with_time(
        self,
        retran_timeout: Duration,
        expire_timeout: Duration,
    ) -> Result<PaddablePacket, Signals> {
        if self.writer.is_empty() {
            return Err(Signals::TRANSPORT);
        }
        self.clerk.build_with_time(retran_timeout, expire_timeout);
        Ok(PaddablePacket {
            packet: self.writer.interrupt().0,
            logger: self.logger,
        })
    }

    // 其实never used，但是还是给它留一个位置
    pub fn ready_with_send_time(
        mut self,
        retran_timeout: Duration,
        expire_timeout: Duration,
    ) -> Option<CipherPacket> {
        let packet_len = self.writer.packet_len();
        if packet_len == 0 {
            return None;
        }
        if packet_len < 20 {
            self.pad(20 - packet_len);
        }
        self.clerk.build_with_time(retran_timeout, expire_timeout);

        self.logger.log_sent(&self.writer);
        Some(self.writer.encrypt_and_protect())
    }
}

/// 对IH空间有效
impl<'b, D> MarshalDataFrame<CryptoFrame, D> for PacketBuffer<'b, '_, CryptoFrame>
where
    D: DescribeData + Clone,
    PacketWriter<'b>: WriteData<D> + WriteDataFrame<CryptoFrame, D>,
{
    fn dump_frame_with_data(&mut self, frame: CryptoFrame, data: D) -> Option<CryptoFrame> {
        // no matter to clone, currently, except for datagrams, all other `D`s impl Copy
        self.writer
            .dump_frame_with_data(frame, data.clone())
            .and_then(|frame| {
                self.logger.record_frame((&frame, &data));
                self.clerk.record_frame(frame);
                None
            })
    }
}

impl<'b> MarshalPathFrame<PathChallengeFrame> for PacketBuffer<'b, '_, GuaranteedFrame>
where
    PacketWriter<'b>: WriteFrame<PathChallengeFrame>,
{
    fn dump_path_frame(&mut self, frame: PathChallengeFrame) {
        self.writer.dump_frame(frame);
        self.logger.record_frame(&frame);
        self.clerk.record_trivial();
    }
}

impl<'b> MarshalPathFrame<PathResponseFrame> for PacketBuffer<'b, '_, GuaranteedFrame>
where
    PacketWriter<'b>: WriteFrame<PathResponseFrame>,
{
    fn dump_path_frame(&mut self, frame: PathResponseFrame) {
        self.writer.dump_frame(frame);
        self.logger.record_frame(&frame);
        self.clerk.record_trivial();
    }
}

impl<'b, F> MarshalFrame<F> for PacketBuffer<'b, '_, GuaranteedFrame>
where
    F: BeFrame + Into<ReliableFrame>,
    PacketWriter<'b>: WriteFrame<F>,
{
    fn dump_frame(&mut self, frame: F) -> Option<F> {
        self.writer.dump_frame(frame).and_then(|frame| {
            let reliable_frame = frame.into();
            self.logger.record_frame(&reliable_frame);
            self.clerk
                .record_frame(GuaranteedFrame::Reliable(reliable_frame));
            None
        })
    }
}

impl<'b, D> MarshalDataFrame<CryptoFrame, D> for PacketBuffer<'b, '_, GuaranteedFrame>
where
    D: DescribeData + Clone,
    PacketWriter<'b>: WriteData<D> + WriteDataFrame<CryptoFrame, D>,
{
    fn dump_frame_with_data(&mut self, frame: CryptoFrame, data: D) -> Option<CryptoFrame> {
        self.writer
            .dump_frame_with_data(frame, data.clone())
            .and_then(|frame| {
                self.logger.record_frame((&frame, &data));
                self.clerk.record_frame(GuaranteedFrame::Crypto(frame));
                None
            })
    }
}

impl<'b, D> MarshalDataFrame<StreamFrame, D> for PacketBuffer<'b, '_, GuaranteedFrame>
where
    D: DescribeData + Clone,
    PacketWriter<'b>: WriteData<D> + WriteDataFrame<StreamFrame, D>,
{
    fn dump_frame_with_data(&mut self, frame: StreamFrame, data: D) -> Option<StreamFrame> {
        self.writer
            .dump_frame_with_data(frame, data.clone())
            .and_then(|frame| {
                self.logger.record_frame((&frame, &data));
                self.clerk.record_frame(GuaranteedFrame::Stream(frame));
                None
            })
    }
}

impl<'b, D> MarshalDataFrame<DatagramFrame, D> for PacketBuffer<'b, '_, GuaranteedFrame>
where
    D: DescribeData + Clone,
    PacketWriter<'b>: WriteData<D> + WriteDataFrame<DatagramFrame, D>,
{
    fn dump_frame_with_data(&mut self, frame: DatagramFrame, data: D) -> Option<DatagramFrame> {
        self.writer
            .dump_frame_with_data(frame, data.clone())
            .and_then(|frame| {
                self.logger.record_frame((&frame, &data));
                self.clerk.record_trivial();
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
        tx_waker: ArcSendWaker,
    ) -> Result<Option<Self>, Signals> {
        let send_quota = cc.send_quota(expect_quota)?;
        let credit_limit = anti_amplifier.balance()?;
        if credit_limit.is_none() {
            return Ok(None);
        }
        let flow_limit = match flow_ctrl.send_limit(send_quota) {
            Ok(flow_limit) => flow_limit,
            Err(_error) => return Ok(None),
        };
        let borriwed_dcid = match dcid.borrow_cid(tx_waker)? {
            Some(borriwed_dcid) => borriwed_dcid,
            None => return Ok(None),
        };
        let constraints = Constraints::new(credit_limit.unwrap(), send_quota);
        Ok(Some(Self {
            scid,
            dcid: borriwed_dcid,
            cc,
            flow_limit,
            constraints,
        }))
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

    pub fn retransmit_and_expire_time(&self, epoch: Epoch) -> (Duration, Duration) {
        self.cc.retransmit_and_expire_time(epoch)
    }

    pub fn flow_limit(&self) -> usize {
        self.flow_limit.available()
    }

    pub fn commit(
        &mut self,
        epoch: Epoch,
        packet: CipherPacket,
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

struct LevelState {
    epoch: Epoch,
    pkt: PaddablePacket,
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
    ) -> Result<usize, Signals> {
        let mut written = 0;
        let mut last_level: Option<LevelState> = None;
        let mut last_level_size = 0;
        let mut containing_initial = false;
        let mut limiter = Signals::empty();

        if let Ok((mid_pkt, ack)) = spaces
            .initial()
            .try_assemble_packet(self, &mut datagram[written..])
            .inspect_err(|l| limiter |= *l)
        {
            self.constraints
                .commit(mid_pkt.packet_len(), mid_pkt.in_flight());
            last_level_size = mid_pkt.packet_len();
            containing_initial = true;
            last_level = Some(LevelState {
                epoch: Epoch::Initial,
                pkt: mid_pkt,
                ack,
            });
        }

        let is_one_rtt_ready = spaces.data().is_one_rtt_ready();
        if !is_one_rtt_ready {
            if let Ok((mid_pkt, fresh_data)) = spaces
                .data()
                .try_assemble_0rtt_packet(
                    self,
                    path_challenge_frames,
                    &mut datagram[written + last_level_size..],
                )
                .inspect_err(|l| limiter |= *l)
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
                self.flow_limit.post_sent(fresh_data);
                last_level_size = mid_pkt.packet_len();
                last_level = Some(LevelState {
                    epoch: Epoch::Data,
                    pkt: mid_pkt,
                    ack: None,
                });
            }
        }

        if let Ok((mid_pkt, ack)) = spaces
            .handshake()
            .try_assemble_packet(self, &mut datagram[written + last_level_size..])
            .inspect_err(|l| limiter |= *l)
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
            if let Ok((mid_pkt, ack, fresh_data)) = spaces
                .data()
                .try_assemble_1rtt_packet(
                    self,
                    spin,
                    path_challenge_frames,
                    path_response_frames,
                    &mut datagram[written + last_level_size..],
                )
                .inspect_err(|l| limiter |= *l)
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
                self.flow_limit.post_sent(fresh_data);
                last_level = Some(LevelState {
                    epoch: Epoch::Data,
                    pkt: mid_pkt,
                    ack,
                });
            }
        }

        if let Some(final_level) = last_level {
            let packet = if containing_initial || final_level.pkt.probe_new_path() {
                final_level.pkt.fill_and_complete(&mut datagram[written..])
            } else {
                final_level.pkt.complete(&mut datagram[written..])
            };

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

        if written != 0 {
            Ok(written)
        } else {
            Err(limiter)
        }
    }

    pub fn load_one_rtt(
        &mut self,
        buf: &mut [u8],
        spin: SpinBit,
        path_challenge_frames: &SendBuffer<PathChallengeFrame>,
        path_response_frames: &SendBuffer<PathResponseFrame>,
        data_space: &DataSpace,
    ) -> Result<usize, Signals> {
        let buffer = self.constraints.constrain(buf);
        data_space
            .try_assemble_1rtt_packet(
                self,
                spin,
                path_challenge_frames,
                path_response_frames,
                buffer,
            )
            .map(|(packet, ack, fresh_bytes)| {
                let packet = if packet.probe_new_path() {
                    packet.complete(buffer)
                } else {
                    packet.fill_and_complete(buffer)
                };
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
    ) -> Result<usize, Signals> {
        let buffer = self.constraints.constrain(buf);
        data_space
            .try_assemble_probe_packet(
                self,
                spin,
                path_challenge_frames,
                path_response_frames,
                buffer,
            )
            .map(|packet| {
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
