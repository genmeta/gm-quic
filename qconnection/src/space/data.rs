use std::sync::Arc;

use bytes::BufMut;
use futures::{Stream, StreamExt};
use qbase::{
    cid::ConnectionId,
    error::Error,
    frame::{
        ConnectionCloseFrame, Frame, FrameReader, PathChallengeFrame, PathResponseFrame,
        ReceiveFrame, SendFrame,
    },
    packet::{
        self,
        decrypt::{
            decrypt_packet, remove_protection_of_long_packet, remove_protection_of_short_packet,
        },
        header::{
            long::{io::LongHeaderBuilder, ZeroRttHeader},
            GetType, OneRttHeader,
        },
        keys::{ArcKeys, ArcOneRttKeys, ArcOneRttPacketKeys, HeaderProtectionKeys},
        number::PacketNumber,
        r#type::Type,
        signal::SpinBit,
        AssembledPacket, MarshalFrame, MiddleAssembledPacket, PacketWriter,
    },
    param::CommonParameters,
    sid::{ControlConcurrency, Role},
    Epoch,
};
use qcongestion::{CongestionControl, TrackPackets};
use qinterface::path::{Pathway, Socket};
use qrecovery::{
    crypto::CryptoStream,
    journal::{ArcRcvdJournal, DataJournal},
    reliable::GuaranteedFrame,
};
use qunreliable::DatagramFlow;
use tokio::sync::{mpsc, Notify};
use tracing::{trace_span, Instrument};

use super::DecryptedPacket;
use crate::{
    events::{ArcEventBroker, EmitEvent, Event},
    path::{Path, SendBuffer},
    space::{pipe, AckData, FlowControlledDataStreams},
    termination::ClosingState,
    tx::{PacketMemory, Transaction},
    ArcReliableFrameDeque, Components, DataStreams,
};

pub type ZeroRttPacket = (ZeroRttHeader, bytes::BytesMut, usize);
pub type DecryptedZeroRttPacket = DecryptedPacket<ZeroRttHeader>;
pub type OneRttPacket = (OneRttHeader, bytes::BytesMut, usize);
pub type DecryptedOneRttPacket = DecryptedPacket<OneRttHeader>;

pub struct DataSpace {
    zero_rtt_keys: ArcKeys,
    one_rtt_keys: ArcOneRttKeys,
    crypto_stream: CryptoStream,
    streams: DataStreams,
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
            datagrams: DatagramFlow::new(1024),
            sendable,
        }
    }

    pub async fn decrypt_0rtt_packet(
        &self,
        (header, mut payload, offset): ZeroRttPacket,
    ) -> Option<Result<DecryptedZeroRttPacket, Error>> {
        let keys = self.zero_rtt_keys.get_remote_keys().await?;
        let (hpk, pk) = (keys.remote.header.as_ref(), keys.remote.packet.as_ref());

        let undecoded_pn =
            match remove_protection_of_long_packet(hpk, payload.as_mut(), offset).transpose()? {
                Ok(undecoded_pn) => undecoded_pn,
                Err(invalid_reversed_bits) => return Some(Err(invalid_reversed_bits.into())),
            };
        let rcvd_journal = self.journal.of_rcvd_packets();
        let pn = rcvd_journal.decode_pn(undecoded_pn).ok()?;
        let body_offset = offset + undecoded_pn.size();
        let pkt_len = decrypt_packet(pk, pn, payload.as_mut(), body_offset).ok()?;

        let _header = payload.split_to(body_offset);
        payload.truncate(pkt_len);
        Some(Ok(DecryptedPacket {
            header,
            pn,
            payload: payload.freeze(),
        }))
    }

    pub async fn decrypt_1rtt_packet(
        &self,
        (header, mut payload, offset): OneRttPacket,
    ) -> Option<Result<DecryptedOneRttPacket, Error>> {
        let (hpk, pk) = self.one_rtt_keys.get_remote_keys().await?;
        let (undecoded_pn, key_phase) =
            match remove_protection_of_short_packet(hpk.as_ref(), payload.as_mut(), offset)
                .transpose()?
            {
                Ok(ok) => ok,
                Err(invalid_reversed_bits) => return Some(Err(invalid_reversed_bits.into())),
            };

        let rcvd_journal = self.journal.of_rcvd_packets();
        let pn = rcvd_journal.decode_pn(undecoded_pn).ok()?;
        let pk = pk.lock_guard().get_remote(key_phase, pn);
        let body_offset = offset + undecoded_pn.size();
        let pkt_len = decrypt_packet(pk.as_ref(), pn, payload.as_mut(), body_offset).ok()?;

        let _header = payload.split_to(body_offset);
        payload.truncate(pkt_len);
        Some(Ok(DecryptedPacket {
            header,
            pn,
            payload: payload.freeze(),
        }))
    }

    pub fn try_assemble_0rtt<'b>(
        &self,
        tx: &mut Transaction<'_>,
        path_challenge_frames: &SendBuffer<PathChallengeFrame>,
        buf: &'b mut [u8],
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
        self.datagrams.try_load_data_into(&mut packet);

        let packet: PacketWriter<'b> = packet.try_into().ok()?;
        Some((packet.abandon(), fresh_data))
    }

    pub fn try_assemble_1rtt<'b>(
        &self,
        tx: &mut Transaction<'_>,
        spin: SpinBit,
        path_challenge_frames: &SendBuffer<PathChallengeFrame>,
        path_response_frames: &SendBuffer<PathResponseFrame>,
        buf: &'b mut [u8],
    ) -> Option<(MiddleAssembledPacket, Option<u64>, usize)> {
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

        let mut ack = None;
        if let Some((largest, rcvd_time)) = tx.need_ack(Epoch::Data) {
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
        self.datagrams.try_load_data_into(&mut packet);

        let packet: PacketWriter<'b> = packet.try_into().ok()?;
        Some((packet.abandon(), ack, fresh_data))
    }

    pub fn try_assemble_validation<'b>(
        &self,
        tx: &mut Transaction<'_>,
        spin: SpinBit,
        path_challenge_frames: &SendBuffer<PathChallengeFrame>,
        path_response_frames: &SendBuffer<PathResponseFrame>,
        buf: &'b mut [u8],
    ) -> Option<AssembledPacket> {
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

        let remaining = packet.remaining_mut();
        packet.pad(remaining);

        let mut packet: PacketWriter<'b> = packet.try_into().ok()?;
        Some(packet.encrypt_and_protect())
    }

    pub fn is_one_rtt_ready(&self) -> bool {
        self.one_rtt_keys.get_local_keys().is_some()
    }

    pub fn one_rtt_keys(&self) -> ArcOneRttKeys {
        self.one_rtt_keys.clone()
    }

    pub fn on_conn_error(&self, error: &Error) {
        self.streams.on_conn_error(error);
        self.datagrams.on_conn_error(error);
    }

    pub fn crypto_stream(&self) -> &CryptoStream {
        &self.crypto_stream
    }

    pub fn streams(&self) -> &DataStreams {
        &self.streams
    }

    pub fn datagrams(&self) -> &DatagramFlow {
        &self.datagrams
    }
}

#[tracing::instrument(level = "trace", name = "data_space_packet_handler", skip_all)]
pub fn spawn_deliver_and_parse(
    mut zeor_rtt_packets: impl Stream<Item = (ZeroRttPacket, Pathway, Socket)> + Unpin + Send + 'static,
    mut one_rtt_packets: impl Stream<Item = (OneRttPacket, Pathway, Socket)> + Unpin + Send + 'static,
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
            Frame::Datagram(f, data) => _ = datagram_frames_entry.send((f, data)),
            Frame::Close(f) if matches!(pty, Type::Short(_)) => event_broker.emit(Event::Closed(f)),
            _ => {}
        }
    };

    tokio::spawn(
        {
            let components = components.clone();
            let space = space.clone();
            let event_broker = event_broker.clone();
            let dispatch_data_frame = dispatch_data_frame.clone();
            async move {
                while let Some((packet, pathway, socket)) = zeor_rtt_packets.next().await {
                    let packet_size = packet.1.len();
                    match space.decrypt_0rtt_packet(packet).await {
                        Some(Ok(packet)) => {
                            tracing::trace!(
                                pn = packet.pn,
                                payload_size = packet.payload.len(),
                                "decrypted packet"
                            );
                            let path = match components.get_or_create_path(socket, pathway, true) {
                                Some(path) => path,
                                None => return,
                            };
                            path.on_rcvd(packet_size);
                            match FrameReader::new(packet.payload, packet.header.get_type())
                                .try_fold(false, |is_ack_packet, frame| {
                                    let (frame, is_ack_eliciting) = frame?;
                                    dispatch_data_frame(frame, packet.header.get_type(), &path);
                                    Result::<bool, Error>::Ok(is_ack_packet || is_ack_eliciting)
                                }) {
                                Ok(is_ack_packet) => {
                                    space.journal.of_rcvd_packets().register_pn(packet.pn);
                                    path.cc().on_pkt_rcvd(Epoch::Data, packet.pn, is_ack_packet);
                                }
                                Err(error) => event_broker.emit(Event::Failed(error)),
                            }
                        }
                        Some(Err(error)) => event_broker.emit(Event::Failed(error)),
                        None => continue,
                    }
                }
            }
        }
        .instrument(trace_span!("zeor_rtt_task")),
    );
    tokio::spawn(
        {
            let components = components.clone();
            let dispatch_data_frame = dispatch_data_frame.clone();
            async move {
                while let Some((packet, pathway, socket)) = one_rtt_packets.next().await {
                    let packet_size = packet.1.len();
                    match space.decrypt_1rtt_packet(packet).await {
                        Some(Ok(packet)) => {
                            tracing::trace!(
                                pn = packet.pn,
                                payload_size = packet.payload.len(),
                                "decrypted packet"
                            );
                            let path = match components.get_or_create_path(socket, pathway, true) {
                                Some(path) => path,
                                None => return,
                            };
                            path.on_rcvd(packet_size);
                            match FrameReader::new(packet.payload, packet.header.get_type())
                                .try_fold(false, |is_ack_packet, frame| {
                                    let (frame, is_ack_eliciting) = frame?;
                                    dispatch_data_frame(frame, packet.header.get_type(), &path);
                                    Result::<bool, Error>::Ok(is_ack_packet || is_ack_eliciting)
                                }) {
                                Ok(is_ack_packet) => {
                                    space.journal.of_rcvd_packets().register_pn(packet.pn);
                                    path.cc().on_pkt_rcvd(Epoch::Data, packet.pn, is_ack_packet);
                                }
                                Err(error) => event_broker.emit(Event::Failed(error)),
                            }
                        }
                        Some(Err(error)) => event_broker.emit(Event::Failed(error)),
                        None => continue,
                    }
                }
            }
        }
        .instrument(trace_span!("one_rtt_task")),
    );
}

impl TrackPackets for DataSpace {
    fn may_loss(&self, pns: &mut dyn Iterator<Item = u64>) {
        let sent_jornal = self.journal.of_sent_packets();
        let crypto_outgoing = self.crypto_stream.outgoing();
        let mut rotate = sent_jornal.rotate();
        for pn in pns {
            for frame in rotate.may_loss_pkt(pn) {
                match frame {
                    GuaranteedFrame::Stream(f) => {
                        self.streams.may_loss_data(&f);
                        self.sendable.notify_waiters();
                    }
                    GuaranteedFrame::Reliable(f) => {
                        self.reliable_frames.send_frame([f]);
                        // self.sendable.notify_waiters();
                    }
                    GuaranteedFrame::Crypto(f) => {
                        crypto_outgoing.may_loss_data(&f);
                        self.sendable.notify_waiters();
                    }
                }
            }
        }
    }

    fn retire(&self, pns: &mut dyn Iterator<Item = u64>) {
        let rcvd_journal = self.journal.of_rcvd_packets();
        let mut write_guard = rcvd_journal.write();
        for pn in pns {
            write_guard.retire(pn);
        }
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
    pub fn recv_packet(
        &self,
        (header, mut bytes, offset): OneRttPacket,
    ) -> Option<ConnectionCloseFrame> {
        let (hpk, pk) = &self.keys;
        let hpk = &hpk.local;
        let (undecoded_pn, key_phase) =
            remove_protection_of_short_packet(hpk.as_ref(), bytes.as_mut(), offset).ok()??;
        let pn = self.rcvd_journal.decode_pn(undecoded_pn).ok()?;
        let body_offset = offset + undecoded_pn.size();
        let pk = pk.lock_guard().get_remote(key_phase, pn);
        let _pkt_len = decrypt_packet(pk.as_ref(), pn, bytes.as_mut(), body_offset).ok()?;

        FrameReader::new(bytes.freeze(), header.get_type())
            .filter_map(Result::ok)
            .find_map(|(f, _ack)| match f {
                Frame::Close(ccf) => Some(ccf),
                _ => None,
            })
    }

    pub fn try_assemble_ccf_packet(
        &self,
        dcid: ConnectionId,
        ccf: &ConnectionCloseFrame,
        buf: &mut [u8],
    ) -> Option<AssembledPacket> {
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
    mut packets: impl Stream<Item = (OneRttPacket, Pathway, Socket)> + Unpin + Send + 'static,
    space: ClosingDataSpace,
    closing_state: Arc<ClosingState>,
    event_broker: ArcEventBroker,
) {
    tokio::spawn(async move {
        while let Some((packet, pathway, _socket)) = packets.next().await {
            if let Some(ccf) = space.recv_packet(packet) {
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
