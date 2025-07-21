use std::ops::Range;

use bytes::BufMut;
use derive_more::Deref;
use qbase::{
    Epoch,
    cid::{BorrowedCid, ConnectionId},
    frame::{
        AckFrame, CryptoFrame, DatagramFrame, EncodeSize, FrameFeture, PathChallengeFrame,
        PathResponseFrame, PingFrame, ReliableFrame, StreamFrame,
        io::{WriteDataFrame, WriteFrame},
    },
    net::tx::{ArcSendWaker, Signals},
    packet::{
        FinalPacketLayout, MarshalDataFrame, MarshalFrame, MarshalPathFrame, PacketLayout,
        PacketWriter,
        header::{
            EncodeHeader, GetDcid, GetScid, GetType, io::WriteHeader, long::LongHeader,
            short::OneRttHeader,
        },
        keys::DirectionalKeys,
        signal::{KeyPhaseBit, SpinBit},
    },
    role::Role,
    util::{ContinuousData, WriteData},
};
use qcongestion::{ArcCC, Transport};
use qevent::quic::{QuicFrame, QuicFramesCollector, transport::PacketSent};
use qrecovery::journal::{ArcSentJournal, NewPacketGuard};
use tokio::time::{Duration, Instant};

use crate::{
    ArcDcidCell, ArcReliableFrameDeque, CidRegistry, GuaranteedFrame,
    path::{AntiAmplifier, Constraints, SendBuffer},
    space::Spaces,
};

pub struct PacketLogger {
    header: qevent::quic::PacketHeaderBuilder,
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

        qevent::event!(PacketSent {
            header: self.header.build(),
            frames: self.frames,
            raw: qevent::RawInfo {
                length: packet.packet_len() as u64,
                payload_length: { packet.payload_len() + packet.tag_len() } as u64,
                data: packet.buffer(),
            },
            // TODO: trigger
        })
    }
}

pub struct PacketBuffer<'b, 's, F> {
    pn: u64,
    writer: PacketWriter<'b>,
    // 不同空间的send guard类型不一样
    clerk: NewPacketGuard<'s, F>,
    logger: PacketLogger,
}

impl<'b, 's, F> PacketBuffer<'b, 's, F> {
    pub fn new_long<S>(
        header: LongHeader<S>,
        buffer: &'b mut [u8],
        keys: DirectionalKeys,
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
            pn: pn.0,
            clerk: guard,
            writer: PacketWriter::new_long(&header, buffer, pn, keys)?,
            logger: PacketLogger {
                header: {
                    let mut builder = qevent::quic::PacketHeader::builder();
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
        keys: DirectionalKeys,
        key_phase: KeyPhaseBit,
        journal: &'s ArcSentJournal<F>,
    ) -> Result<Self, Signals> {
        let guard = journal.new_packet();
        let pn = guard.pn();
        Ok(Self {
            pn: pn.0,
            clerk: guard,
            writer: PacketWriter::new_short(&header, buffer, pn, keys, key_phase)?,
            logger: PacketLogger {
                header: {
                    let mut builder = qevent::quic::PacketHeader::builder();
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

    pub fn payload_len(&self) -> usize {
        self.writer.payload_len()
    }
}

#[derive(Deref)]
pub struct PaddablePacket {
    #[deref]
    layout: PacketLayout,
    logger: PacketLogger,
}

impl PaddablePacket {
    pub fn fill_and_complete(mut self, buffer: &mut [u8]) -> FinalPacketLayout {
        let mut writer = self.layout.writer(buffer);

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

    pub fn complete(mut self, buffer: &mut [u8]) -> FinalPacketLayout {
        let mut writer = self.layout.writer(buffer);
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

    pub fn dump_ping_frame(&mut self) {
        self.logger.record_frame(QuicFrame::Ping {
            length: Some(1),
            payload_length: Some(1),
        });
        self.writer.dump_frame(PingFrame);
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
            layout: self.writer.interrupt().0,
            logger: self.logger,
        })
    }

    // 其实never used，但是还是给它留一个位置
    pub fn ready_with_send_time(
        mut self,
        retran_timeout: Duration,
        expire_timeout: Duration,
    ) -> Option<FinalPacketLayout> {
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

    pub fn pn(&self) -> u64 {
        self.pn
    }
}

/// 对IH空间有效
impl<'b, D> MarshalDataFrame<CryptoFrame, D> for PacketBuffer<'b, '_, CryptoFrame>
where
    D: ContinuousData + Clone,
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
    F: EncodeSize + FrameFeture + Into<ReliableFrame>,
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
    D: ContinuousData + Clone,
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
    D: ContinuousData + Clone,
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
    D: ContinuousData + Clone,
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
    cid_registry: &'a CidRegistry,
    borrowed_dcid: Result<BorrowedCid<'a, ArcReliableFrameDeque>, Signals>,
    tls_handshake_finished: bool,
    path_validated: bool,
    path_first_load: bool,
    cc: &'a ArcCC,
    constraints: Constraints,
}

impl<'a> Transaction<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        cid_registry: &'a CidRegistry,
        dcid_cell: &'a ArcDcidCell,
        tls_handshake_finished: bool,
        path_validated: bool,
        path_first_load: bool,
        cc: &'a ArcCC,
        anti_amplifier: &'a AntiAmplifier,
        tx_waker: ArcSendWaker,
    ) -> Result<Option<Self>, Signals> {
        let send_quota = cc.send_quota()?;
        let Some(credit_limit) = anti_amplifier.balance()? else {
            return Ok(None);
        };

        let Some(borrowed_dcid) = dcid_cell.borrow_cid(tx_waker).transpose() else {
            return Ok(None);
        };

        let constraints = Constraints::new(credit_limit, send_quota);
        Ok(Some(Self {
            cid_registry,
            borrowed_dcid,
            tls_handshake_finished,
            path_validated,
            path_first_load,
            cc,
            constraints,
        }))
    }

    pub fn initial_scid(&self) -> Option<ConnectionId> {
        self.cid_registry.local.initial_scid()
    }

    /// Return the connection ID that used to send the initial and zero rtt packets.
    ///
    /// gm-quic implements multi-path handshake feature, the client creates many paths and sends initial packets.
    ///
    /// Client will only use origin_dcid to send initial and zero rtt packets.
    ///
    /// The client and server must negotiate a handshake path and assign the initial dcid to this path
    /// to prevent the unique connection ID from being obtained by an invalid path, causing the connection to fail.
    ///
    /// The client and server choose the path where they receive the first initial packet as the handshake path.
    /// The server will only return the initial packet on the handshake path to negotiate the handshake path.
    ///
    /// Therefore, for the server, it can only send the initial packet with the connection ID assigned to the path.
    /// This manifests itself during the handshake as sending the initial packet only on the first path.
    pub fn initial_dcid(&self) -> Result<ConnectionId, Signals> {
        match self.cid_registry.role() {
            Role::Client => Ok(self.cid_registry.origin_dcid()),
            Role::Server => self.applied_dcid(),
        }
    }

    pub fn path_first_load(&mut self) -> bool {
        std::mem::replace(&mut self.path_first_load, false)
    }

    pub fn applied_dcid(&self) -> Result<ConnectionId, Signals> {
        self.borrowed_dcid.as_deref().copied().map_err(|e| *e)
    }

    pub fn need_ack(&self, epoch: Epoch) -> Option<(u64, Instant)> {
        self.cc.need_ack(epoch)
    }

    pub fn retransmit_and_expire_time(&self, epoch: Epoch) -> (Duration, Duration) {
        self.cc.retransmit_and_expire_time(epoch)
    }

    pub fn commit(&mut self, epoch: Epoch, final_layout: FinalPacketLayout, ack: Option<u64>) {
        self.constraints
            .commit(final_layout.sent_bytes(), final_layout.in_flight());
        self.cc.on_pkt_sent(
            epoch,
            final_layout.pn(),
            final_layout.is_ack_eliciting(),
            final_layout.sent_bytes(),
            final_layout.in_flight(),
            ack,
        );
    }
}

struct LevelState {
    epoch: Epoch,
    packet: PaddablePacket,
    ack: Option<u64>,
    buf_range: Range<usize>,
}

impl Transaction<'_> {
    pub fn load_spaces(
        &mut self,
        buf: &mut [u8],
        spaces: &Spaces,
        spin: SpinBit,
        path_challenge_frames: &SendBuffer<PathChallengeFrame>,
        path_response_frames: &SendBuffer<PathResponseFrame>,
    ) -> Result<usize, Signals> {
        // how many bytes are used (constrains packets that encrypted and protected)
        let mut written = 0;
        // last written but unencrypted packet, may be pad before encrypt and protect
        let mut last_level: Option<LevelState> = None;
        let mut containing_initial = false;
        let mut signals = Signals::empty();

        let load_initial = &|tx: &mut Self, buf: &mut [u8], buf_range: Range<usize>| {
            spaces
                .initial()
                .try_assemble_initial_packet(tx, &mut buf[buf_range.clone()])
                .map(|(packet, ack)| LevelState {
                    epoch: Epoch::Initial,
                    packet,
                    ack,
                    buf_range,
                })
        };

        let load_0rtt = &|tx: &mut Self, buf: &mut [u8], buf_range: Range<usize>| {
            spaces
                .data()
                .try_assemble_0rtt_packet(tx, path_challenge_frames, &mut buf[buf_range.clone()])
                .map(|packet| LevelState {
                    epoch: Epoch::Data,
                    packet,
                    ack: None,
                    buf_range,
                })
        };

        let load_handshake = &|tx: &mut Self, buf: &mut [u8], buf_range: Range<usize>| {
            spaces
                .handshake()
                .try_assemble_packet(tx, &mut buf[buf_range.clone()])
                .map(|(packet, ack)| LevelState {
                    epoch: Epoch::Handshake,
                    packet,
                    ack,
                    buf_range,
                })
        };

        let load_1rtt_data = &|tx: &mut Self, buf: &mut [u8], buf_range: Range<usize>| {
            spaces
                .data()
                .try_assemble_1rtt_packet(
                    tx,
                    spin,
                    path_challenge_frames,
                    path_response_frames,
                    &mut buf[buf_range.clone()],
                )
                .map(|(packet, ack)| LevelState {
                    epoch: Epoch::Data,
                    packet,
                    ack,
                    buf_range,
                })
        };

        let load_validate = &|tx: &mut Self, buf: &mut [u8], buf_range: Range<usize>| {
            spaces
                .data()
                .try_assemble_probe_packet(
                    tx,
                    spin,
                    path_challenge_frames,
                    path_response_frames,
                    &mut buf[buf_range.clone()],
                )
                .map(|packet| LevelState {
                    epoch: Epoch::Data,
                    packet,
                    ack: None,
                    buf_range,
                })
        };

        #[allow(clippy::complexity)]
        let mut loads: Vec<&dyn Fn(&mut Self, &mut [u8], Range<usize>) -> _> = vec![];

        loads.push(load_initial);
        if !self.tls_handshake_finished {
            loads.push(load_0rtt);
            signals |= Signals::TLS_FIN;
        }
        loads.push(load_handshake);

        if self.tls_handshake_finished {
            if self.path_validated {
                loads.push(load_1rtt_data)
            } else {
                loads.push(load_validate);
                signals |= Signals::PATH_VALIDATE;
            }
        }

        for load in loads {
            // calculate the buffer size of this data packet
            let last_level_size = last_level
                .as_ref()
                .map(|last_level| last_level.packet.packet_len())
                .unwrap_or_default();
            let this_level_start = written + last_level_size;
            let this_level_end = (this_level_start + self.constraints.available()).min(buf.len());
            match (load)(self, buf, this_level_start..this_level_end) {
                Ok(this_level) => {
                    if this_level.epoch == Epoch::Initial {
                        containing_initial = true;
                    }
                    // commit constraints and flow_limit
                    self.constraints.commit(
                        this_level.packet.packet_len(),
                        this_level.packet.in_flight(),
                    );
                    // replace last level, complete and commit last level to cc
                    if let Some(last_level) = last_level.replace(this_level) {
                        let final_layout =
                            last_level.packet.complete(&mut buf[last_level.buf_range]);
                        written += final_layout.sent_bytes();
                        self.cc.on_pkt_sent(
                            last_level.epoch,
                            final_layout.pn(),
                            final_layout.is_ack_eliciting(),
                            final_layout.sent_bytes(),
                            final_layout.in_flight(),
                            last_level.ack,
                        );
                    }
                }
                Err(s) => signals |= s,
            }
        }

        if let Some(final_level) = last_level {
            // if the datagram contains initial packet or probe new path frames, it should be padded
            let final_layout = if containing_initial || final_level.packet.probe_new_path() {
                let origin_len = final_level.packet.packet_len();
                let final_layout = final_level
                    .packet
                    .fill_and_complete(&mut buf[final_level.buf_range]);
                self.constraints.commit(
                    final_layout.sent_bytes() - origin_len,
                    final_layout.in_flight(),
                );
                final_layout
            } else {
                final_level.packet.complete(&mut buf[final_level.buf_range])
            };

            written += final_layout.sent_bytes();
            self.cc.on_pkt_sent(
                final_level.epoch,
                final_layout.pn(),
                final_layout.is_ack_eliciting(),
                final_layout.sent_bytes(),
                final_layout.in_flight(),
                final_level.ack,
            );
        }

        if written != 0 {
            Ok(written)
        } else {
            Err(signals)
        }
    }

    pub fn load_one_ping(
        &mut self,
        buf: &mut [u8],
        spin: SpinBit,
        spaces: &Spaces,
    ) -> Result<usize, Signals> {
        let buf = self.constraints.constrain(buf);
        for epoch in [Epoch::Data, Epoch::Handshake, Epoch::Initial] {
            if self.cc.need_send_ack_eliciting(epoch) == 0 {
                continue;
            }
            if epoch != Epoch::Data && self.initial_scid().is_none() {
                continue;
            }
            let middle_assembled_packet = match epoch {
                Epoch::Initial => spaces.initial().try_assemble_ping_packet(self, buf),
                Epoch::Handshake => spaces.handshake().try_assemble_ping_packet(self, buf),
                Epoch::Data => spaces.data().try_assemble_ping_packet(self, spin, buf),
            };
            return middle_assembled_packet.map(|packet| {
                let final_layout = if epoch == Epoch::Initial {
                    packet.fill_and_complete(buf)
                } else {
                    packet.complete(buf)
                };
                self.constraints
                    .commit(final_layout.sent_bytes(), final_layout.in_flight());
                self.cc.on_pkt_sent(
                    epoch,
                    final_layout.pn(),
                    final_layout.is_ack_eliciting(),
                    final_layout.sent_bytes(),
                    final_layout.in_flight(),
                    None,
                );
                final_layout.sent_bytes()
            });
        }
        Err(Signals::PING)
    }
}
