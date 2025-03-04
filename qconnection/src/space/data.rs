use std::sync::Arc;

use bytes::BufMut;
use futures::{Stream, StreamExt};
use qbase::{
    Epoch,
    cid::ConnectionId,
    error::Error,
    frame::{
        ConnectionCloseFrame, Frame, FrameReader, PathChallengeFrame, PathResponseFrame,
        ReceiveFrame, SendFrame,
    },
    net::{Link, Pathway},
    packet,
    packet::{
        CipherPacket, MarshalFrame, PacketWriter,
        header::{
            GetType, OneRttHeader,
            long::{ZeroRttHeader, io::LongHeaderBuilder},
        },
        keys::{ArcKeys, ArcOneRttKeys, ArcOneRttPacketKeys, HeaderProtectionKeys},
        number::PacketNumber,
        signal::SpinBit,
        r#type::Type,
    },
    param::CommonParameters,
    sid::{ControlConcurrency, Role},
};
use qcongestion::{CongestionControl, TrackPackets};
use qlog::{
    quic::{
        PacketHeader, PacketType, QuicFrames,
        recovery::{PacketLost, PacketLostTrigger},
    },
    telemetry::Instrument,
};
use qrecovery::{
    crypto::CryptoStream,
    journal::{ArcRcvdJournal, DataJournal},
    reliable::GuaranteedFrame,
};
#[cfg(feature = "unreliable")]
use qunreliable::DatagramFlow;
use tokio::sync::{Notify, mpsc};
use tracing::Instrument as _;

use super::{PlainPacket, ReceivedCipherPacket};
use crate::{
    ArcReliableFrameDeque, Components, DataStreams,
    events::{ArcEventBroker, EmitEvent, Event},
    path::{Path, SendBuffer},
    space::{AckData, FlowControlledDataStreams, pipe},
    termination::ClosingState,
    tx::{MiddleAssembledPacket, PacketMemory, Transaction},
};

pub type ReceivedZeroRttBundle = ((ZeroRttHeader, bytes::BytesMut, usize), Pathway, Link);
pub type ReceivedZeroRttPacket = ReceivedCipherPacket<ZeroRttHeader>;
pub type PlainZeroRttPacket = PlainPacket<ZeroRttHeader>;
pub type ReceivedOneRttBundle = ((OneRttHeader, bytes::BytesMut, usize), Pathway, Link);
pub type ReceivedOneRttPacket = ReceivedCipherPacket<OneRttHeader>;
pub type PlainOneRttPacket = PlainPacket<OneRttHeader>;

pub struct DataSpace {
    zero_rtt_keys: ArcKeys,
    one_rtt_keys: ArcOneRttKeys,
    crypto_stream: CryptoStream,
    streams: DataStreams,
    #[cfg(feature = "unreliable")]
    datagrams: DatagramFlow,
    journal: DataJournal,
    reliable_frames: ArcReliableFrameDeque,
    sendable: Arc<Notify>,
}

impl DataSpace {
    pub fn new(
        role: Role,
        reliable_frames: ArcReliableFrameDeque,
        local_params: &CommonParameters,
        streams_ctrl: Box<dyn ControlConcurrency>,
        sendable: Arc<Notify>,
    ) -> Self {
        let streams = DataStreams::new(role, local_params, streams_ctrl, reliable_frames.clone());
        Self {
            zero_rtt_keys: ArcKeys::new_pending(),
            one_rtt_keys: ArcOneRttKeys::new_pending(),
            journal: DataJournal::with_capacity(16),
            crypto_stream: CryptoStream::new(4096, 4096),
            reliable_frames,
            streams,
            #[cfg(feature = "unreliable")]
            datagrams: DatagramFlow::new(1024),
            sendable,
        }
    }

    pub async fn decrypt_0rtt_packet(
        &self,
        packet: ReceivedZeroRttPacket,
    ) -> Option<Result<PlainZeroRttPacket, Error>> {
        match self.zero_rtt_keys.get_remote_keys().await {
            Some(keys) => packet.decrypt_as_long(
                keys.remote.header.as_ref(),
                keys.remote.packet.as_ref(),
                |pn| self.journal.of_rcvd_packets().decode_pn(pn),
            ),
            None => {
                packet.drop_on_key_unavailable();
                None
            }
        }
    }

    pub async fn decrypt_1rtt_packet(
        &self,
        packet: ReceivedOneRttPacket,
    ) -> Option<Result<PlainOneRttPacket, Error>> {
        match self.one_rtt_keys.get_remote_keys().await {
            Some((hpk, pk)) => packet.decrypt_as_short(hpk.as_ref(), &pk, |pn| {
                self.journal.of_rcvd_packets().decode_pn(pn)
            }),
            None => {
                packet.drop_on_key_unavailable();
                None
            }
        }
    }

    pub fn try_assemble_0rtt(
        &self,
        tx: &mut Transaction<'_>,
        path_challenge_frames: &SendBuffer<PathChallengeFrame>,
        buf: &mut [u8],
    ) -> Option<(MiddleAssembledPacket, usize)> {
        if self.one_rtt_keys.get_local_keys().is_some() {
            return None;
        }

        let keys = self.zero_rtt_keys.get_local_keys()?;
        let sent_journal = self.journal.of_sent_packets();
        let mut packet = PacketMemory::new_long(
            LongHeaderBuilder::with_cid(tx.dcid(), tx.scid()).zero_rtt(),
            buf,
            keys,
            &sent_journal,
        )?;

        path_challenge_frames.try_load_frames_into(&mut packet);
        // TODO: 可以封装在CryptoStream中，当成一个函数
        //      crypto_stream.try_load_data_into(&mut packet);
        let crypto_stream_outgoing = self.crypto_stream.outgoing();
        crypto_stream_outgoing.try_load_data_into(&mut packet);
        // try to load reliable frames into this 0RTT packet to send
        self.reliable_frames.try_load_frames_into(&mut packet);
        // try to load stream frames into this 0RTT packet to send
        let fresh_data = self
            .streams
            .try_load_data_into(&mut packet, tx.flow_limit());
        #[cfg(feature = "unreliable")]
        self.datagrams.try_load_data_into(&mut packet);

        Some((packet.interrupt()?, fresh_data))
    }

    pub fn try_assemble_1rtt(
        &self,
        tx: &mut Transaction<'_>,
        spin: SpinBit,
        path_challenge_frames: &SendBuffer<PathChallengeFrame>,
        path_response_frames: &SendBuffer<PathResponseFrame>,
        buf: &mut [u8],
    ) -> Option<(MiddleAssembledPacket, Option<u64>, usize)> {
        let (hpk, pk) = self.one_rtt_keys.get_local_keys()?;
        let (key_phase, pk) = pk.lock_guard().get_local();
        let sent_journal = self.journal.of_sent_packets();
        // (1) may_loss被调用时cc已经被锁定，may_loss会尝试锁定sent_journal
        // (2) PacketMemory会持有sent_journal的guard，而need_ack会尝试锁定cc
        // 在PacketMemory存在时尝试锁定cc，可能会和 (1) 冲突:
        //   (1)持有cc，要锁定sent_journal；(2)持有sent_journal要锁定cc
        // 在多线程的情况下，可能会发生死锁。所以提前调用need_ack，避免交叉导致死锁
        let need_ack = tx.need_ack(Epoch::Data);
        let mut packet = PacketMemory::new_short(
            OneRttHeader::new(spin, tx.dcid()),
            buf,
            hpk,
            pk,
            key_phase,
            &sent_journal,
        )?;

        let mut ack = None;
        if let Some((largest, rcvd_time)) = need_ack {
            let rcvd_journal = self.journal.of_rcvd_packets();
            if let Some(ack_frame) =
                rcvd_journal.gen_ack_frame_util(largest, rcvd_time, packet.remaining_mut())
            {
                packet.dump_ack_frame(ack_frame);
                ack = Some(largest);
            }
        }

        path_challenge_frames.try_load_frames_into(&mut packet);
        path_response_frames.try_load_frames_into(&mut packet);
        // TODO: 可以封装在CryptoStream中，当成一个函数
        //      crypto_stream.try_load_data_into(&mut packet);
        let crypto_stream_outgoing = self.crypto_stream.outgoing();
        crypto_stream_outgoing.try_load_data_into(&mut packet);
        // try to load reliable frames into this 1RTT packet to send
        self.reliable_frames.try_load_frames_into(&mut packet);
        // try to load stream frames into this 1RTT packet to send
        let fresh_data = self
            .streams
            .try_load_data_into(&mut packet, tx.flow_limit());
        #[cfg(feature = "unreliable")]
        self.datagrams.try_load_data_into(&mut packet);

        Some((packet.interrupt()?, ack, fresh_data))
    }

    pub fn try_assemble_validation(
        &self,
        tx: &mut Transaction<'_>,
        spin: SpinBit,
        path_challenge_frames: &SendBuffer<PathChallengeFrame>,
        path_response_frames: &SendBuffer<PathResponseFrame>,
        buf: &mut [u8],
    ) -> Option<MiddleAssembledPacket> {
        let (hpk, pk) = self.one_rtt_keys.get_local_keys()?;
        let (key_phase, pk) = pk.lock_guard().get_local();
        let sent_journal = self.journal.of_sent_packets();
        let mut packet = PacketMemory::new_short(
            OneRttHeader::new(spin, tx.dcid()),
            buf,
            hpk,
            pk,
            key_phase,
            &sent_journal,
        )?;

        path_challenge_frames.try_load_frames_into(&mut packet);
        path_response_frames.try_load_frames_into(&mut packet);
        // 其实还应该加上NCID，但是从ReliableFrameDeque分拣太复杂了

        packet.interrupt()
    }

    pub fn is_one_rtt_ready(&self) -> bool {
        self.one_rtt_keys.get_local_keys().is_some()
    }

    pub fn one_rtt_keys(&self) -> ArcOneRttKeys {
        self.one_rtt_keys.clone()
    }

    pub fn on_conn_error(&self, error: &Error) {
        self.streams.on_conn_error(error);
        #[cfg(feature = "unreliable")]
        self.datagrams.on_conn_error(error);
    }

    pub fn crypto_stream(&self) -> &CryptoStream {
        &self.crypto_stream
    }

    pub fn streams(&self) -> &DataStreams {
        &self.streams
    }

    #[cfg(feature = "unreliable")]
    pub fn datagrams(&self) -> &DatagramFlow {
        &self.datagrams
    }
}

pub fn spawn_deliver_and_parse(
    mut zeor_rtt_packets: impl Stream<Item = ReceivedZeroRttBundle> + Unpin + Send + 'static,
    mut one_rtt_packets: impl Stream<Item = ReceivedOneRttBundle> + Unpin + Send + 'static,
    space: Arc<DataSpace>,
    components: &Components,
    event_broker: ArcEventBroker,
) {
    let (ack_frames_entry, rcvd_ack_frames) = mpsc::unbounded_channel();
    // 连接级的
    let (max_data_frames_entry, rcvd_max_data_frames) = mpsc::unbounded_channel();
    let (data_blocked_frames_entry, rcvd_data_blocked_frames) = mpsc::unbounded_channel();
    let (new_cid_frames_entry, rcvd_new_cid_frames) = mpsc::unbounded_channel();
    let (retire_cid_frames_entry, rcvd_retire_cid_frames) = mpsc::unbounded_channel();
    let (handshake_done_frames_entry, rcvd_handshake_done_frames) = mpsc::unbounded_channel();
    let (new_token_frames_entry, rcvd_new_token_frames) = mpsc::unbounded_channel();
    // 数据级的
    let (crypto_frames_entry, rcvd_crypto_frames) = mpsc::unbounded_channel();
    let (stream_ctrl_frames_entry, rcvd_stream_ctrl_frames) = mpsc::unbounded_channel();
    let (stream_frames_entry, rcvd_stream_frames) = mpsc::unbounded_channel();
    #[cfg(feature = "unreliable")]
    let (datagram_frames_entry, rcvd_datagram_frames) = mpsc::unbounded_channel();

    let flow_controlled_data_streams =
        FlowControlledDataStreams::new(space.streams.clone(), components.flow_ctrl.clone());

    // Assemble the pipelines of frame processing
    // TODO: pipe rcvd_new_token_frames
    pipe(
        rcvd_retire_cid_frames,
        components.cid_registry.local.clone(),
        event_broker.clone(),
    );
    pipe(
        rcvd_new_cid_frames,
        components.cid_registry.remote.clone(),
        event_broker.clone(),
    );
    pipe(
        rcvd_max_data_frames,
        components.flow_ctrl.sender.clone(),
        event_broker.clone(),
    );
    pipe(
        rcvd_data_blocked_frames,
        components.flow_ctrl.recver.clone(),
        event_broker.clone(),
    );
    pipe(
        rcvd_handshake_done_frames,
        components.handshake.clone(),
        event_broker.clone(),
    );
    pipe(
        rcvd_crypto_frames,
        space.crypto_stream.incoming(),
        event_broker.clone(),
    );
    pipe(
        rcvd_stream_ctrl_frames,
        flow_controlled_data_streams.clone(),
        event_broker.clone(),
    );
    pipe(
        rcvd_stream_frames,
        flow_controlled_data_streams,
        event_broker.clone(),
    );
    #[cfg(feature = "unreliable")]
    pipe(
        rcvd_datagram_frames,
        space.datagrams.clone(),
        event_broker.clone(),
    );
    pipe(
        rcvd_ack_frames,
        AckData::new(&space.journal, &space.streams, &space.crypto_stream),
        event_broker.clone(),
    );
    pipe(
        rcvd_new_token_frames,
        components.token_registry.clone(),
        event_broker.clone(),
    );

    let dispatch_data_frame = {
        let event_broker = event_broker.clone();
        move |frame: Frame, pty: packet::Type, path: &Path| match frame {
            Frame::Ack(f) => {
                path.cc().on_ack(Epoch::Data, &f);
                _ = ack_frames_entry.send(f)
            }
            Frame::NewToken(f) => _ = new_token_frames_entry.send(f),
            Frame::MaxData(f) => _ = max_data_frames_entry.send(f),
            Frame::NewConnectionId(f) => _ = new_cid_frames_entry.send(f),
            Frame::RetireConnectionId(f) => _ = retire_cid_frames_entry.send(f),
            Frame::HandshakeDone(f) => _ = handshake_done_frames_entry.send(f),
            Frame::DataBlocked(f) => _ = data_blocked_frames_entry.send(f),
            Frame::Challenge(f) => _ = path.recv_frame(&f),
            Frame::Response(f) => _ = path.recv_frame(&f),
            Frame::StreamCtl(f) => _ = stream_ctrl_frames_entry.send(f),
            Frame::Stream(f, data) => _ = stream_frames_entry.send((f, data)),
            Frame::Crypto(f, bytes) => _ = crypto_frames_entry.send((f, bytes)),
            #[cfg(feature = "unreliable")]
            Frame::Datagram(f, data) => _ = datagram_frames_entry.send((f, data)),
            Frame::Close(f) if matches!(pty, Type::Short(_)) => event_broker.emit(Event::Closed(f)),
            _ => {}
        }
    };

    let parse_zero_rtt = {
        let components = components.clone();
        let space = space.clone();
        let event_broker = event_broker.clone();
        let dispatch_data_frame = dispatch_data_frame.clone();
        async move |packet: ReceivedZeroRttPacket, pathway, socket| match space
            .decrypt_0rtt_packet(packet)
            .await
        {
            Some(Ok(packet)) => {
                let path = match components.get_or_create_path(socket, pathway, true) {
                    Some(path) => path,
                    None => {
                        packet.drop_on_conenction_closed();
                        return;
                    }
                };
                path.on_rcvd(packet.plain.len());

                let mut frames = QuicFrames::new();
                match FrameReader::new(packet.body(), packet.header.get_type()).try_fold(
                    false,
                    |is_ack_packet, frame| {
                        let (frame, is_ack_eliciting) = frame?;
                        frames.extend(Some(&frame));
                        dispatch_data_frame(frame, packet.header.get_type(), &path);
                        Result::<bool, Error>::Ok(is_ack_packet || is_ack_eliciting)
                    },
                ) {
                    Ok(is_ack_packet) => {
                        space
                            .journal
                            .of_rcvd_packets()
                            .register_pn(packet.decoded_pn);
                        path.cc()
                            .on_pkt_rcvd(Epoch::Data, packet.decoded_pn, is_ack_packet);
                        packet.emit_received(frames);
                    }
                    Err(error) => event_broker.emit(Event::Failed(error)),
                }
            }
            Some(Err(error)) => event_broker.emit(Event::Failed(error)),
            None => {}
        }
    };

    let parse_one_rtt = {
        let components = components.clone();
        async move |packet: ReceivedOneRttPacket, pathway, socket| match space
            .decrypt_1rtt_packet(packet)
            .await
        {
            Some(Ok(packet)) => {
                let path = match components.get_or_create_path(socket, pathway, true) {
                    Some(path) => path,
                    None => {
                        packet.drop_on_conenction_closed();
                        return;
                    }
                };
                path.on_rcvd(packet.plain.len());

                let mut frames = QuicFrames::new();
                match FrameReader::new(packet.body(), packet.header.get_type()).try_fold(
                    false,
                    |is_ack_packet, frame| {
                        let (frame, is_ack_eliciting) = frame?;
                        frames.extend(Some(&frame));
                        dispatch_data_frame(frame, packet.header.get_type(), &path);
                        Result::<bool, Error>::Ok(is_ack_packet || is_ack_eliciting)
                    },
                ) {
                    Ok(is_ack_packet) => {
                        space
                            .journal
                            .of_rcvd_packets()
                            .register_pn(packet.decoded_pn);
                        path.cc()
                            .on_pkt_rcvd(Epoch::Data, packet.decoded_pn, is_ack_packet);
                        packet.emit_received(frames);
                    }
                    Err(error) => event_broker.emit(Event::Failed(error)),
                }
            }
            Some(Err(error)) => event_broker.emit(Event::Failed(error)),
            None => {}
        }
    };

    tokio::spawn(
        async move {
            while let Some((packet, pathway, socket)) = zeor_rtt_packets.next().await {
                parse_zero_rtt(packet.into(), pathway, socket).await;
            }
        }
        .instrument_in_current()
        .in_current_span(),
    );
    tokio::spawn(
        async move {
            while let Some((packet, pathway, socket)) = one_rtt_packets.next().await {
                parse_one_rtt(packet.into(), pathway, socket).await;
            }
        }
        .instrument_in_current()
        .in_current_span(),
    );
}

impl TrackPackets for DataSpace {
    fn may_loss(&self, trigger: PacketLostTrigger, pns: &mut dyn Iterator<Item = u64>) {
        let sent_jornal = self.journal.of_sent_packets();
        let crypto_outgoing = self.crypto_stream.outgoing();
        let mut rotate = sent_jornal.rotate();
        for pn in pns {
            let mut may_lost_frames = QuicFrames::new();
            for frame in rotate.may_loss_pkt(pn) {
                match frame {
                    GuaranteedFrame::Crypto(frame) => {
                        may_lost_frames.extend(Some(&Frame::Crypto(frame, bytes::Bytes::new())));
                        crypto_outgoing.may_loss_data(&frame);
                        self.sendable.notify_waiters();
                    }
                    GuaranteedFrame::Stream(frame) => {
                        may_lost_frames.extend(Some(&Frame::Stream(frame, bytes::Bytes::new())));
                        self.streams.may_loss_data(&frame);
                        self.sendable.notify_waiters();
                    }
                    GuaranteedFrame::Reliable(frame) => {
                        may_lost_frames.extend(Some(&frame.clone().into()));
                        self.reliable_frames.send_frame([frame]);
                        // self.sendable.notify_waiters();
                    }
                };
            }
            qlog::event!(PacketLost {
                header: PacketHeader {
                    // TOOD: 如果只有支持0rtt，这里就不一定是1rtt了
                    packet_type: PacketType::OneRTT,
                    packet_number: pn
                },
                frames: may_lost_frames,
                trigger
            });
        }
    }

    fn rotate_to(&self, pathway: Pathway, pn: u64) {
        self.journal.of_rcvd_packets().rotate_to(pathway, pn);
    }
}

#[derive(Clone)]
pub struct ClosingDataSpace {
    keys: (HeaderProtectionKeys, ArcOneRttPacketKeys),
    ccf_packet_pn: (u64, PacketNumber),
    rcvd_journal: ArcRcvdJournal,
}

impl DataSpace {
    pub fn close(&self) -> Option<ClosingDataSpace> {
        let keys = self.one_rtt_keys.invalid()?;
        let sent_journal = self.journal.of_sent_packets();
        let new_packet_guard = sent_journal.new_packet();
        let ccf_packet_pn = new_packet_guard.pn();
        let rcvd_journal = self.journal.of_rcvd_packets();
        Some(ClosingDataSpace {
            rcvd_journal,
            ccf_packet_pn,
            keys,
        })
    }
}

impl ClosingDataSpace {
    pub fn recv_packet(&self, packet: ReceivedOneRttPacket) -> Option<ConnectionCloseFrame> {
        let packet = packet
            .decrypt_as_short(self.keys.0.remote.as_ref(), &self.keys.1, |pn| {
                self.rcvd_journal.decode_pn(pn)
            })
            .and_then(Result::ok)?;

        let mut farmes = QuicFrames::new();
        FrameReader::new(packet.body(), packet.header.get_type())
            .filter_map(Result::ok)
            .inspect(|(f, _ack)| farmes.extend(Some(f)))
            .fold(None, |ccf, (frame, _)| match (ccf, frame) {
                (ccf @ Some(..), _) => ccf,
                (None, Frame::Close(ccf)) => Some(ccf),
                (None, _) => None,
            })
    }

    pub fn try_assemble_ccf_packet(
        &self,
        dcid: ConnectionId,
        ccf: &ConnectionCloseFrame,
        buf: &mut [u8],
    ) -> Option<CipherPacket> {
        let (hpk, pk) = &self.keys;
        let (key_phase, pk) = pk.lock_guard().get_local();
        let header = OneRttHeader::new(Default::default(), dcid);
        let pn = self.ccf_packet_pn;
        let mut packet_writer =
            PacketWriter::new_short(&header, buf, pn, hpk.local.clone(), pk, key_phase)?;

        packet_writer.dump_frame(ccf.clone());

        Some(packet_writer.encrypt_and_protect())
    }
}

pub fn spawn_deliver_and_parse_closing(
    mut packets: impl Stream<Item = ReceivedOneRttBundle> + Unpin + Send + 'static,
    space: ClosingDataSpace,
    closing_state: Arc<ClosingState>,
    event_broker: ArcEventBroker,
) {
    tokio::spawn(async move {
        while let Some((packet, pathway, _socket)) = packets.next().await {
            if let Some(ccf) = space.recv_packet(packet.into()) {
                event_broker.emit(Event::Closed(ccf.clone()));
                return;
            }
            if closing_state.should_send() {
                _ = closing_state
                    .try_send_with(pathway, |buf, _scid, dcid, ccf| {
                        space
                            .try_assemble_ccf_packet(dcid?, ccf, buf)
                            .map(|packet| packet.size())
                    })
                    .await;
            }
        }
    });
}
