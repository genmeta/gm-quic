use std::sync::Arc;

use bytes::BufMut;
use futures::{channel::mpsc, Stream, StreamExt};
use qbase::{
    cid::ConnectionId,
    error::Error,
    frame::{
        io::WriteFrame, ConnectionCloseFrame, Frame, FrameReader, PathChallengeFrame,
        PathResponseFrame, ReceiveFrame, SendFrame,
    },
    packet::{
        self,
        decrypt::{
            decrypt_packet, remove_protection_of_long_packet, remove_protection_of_short_packet,
        },
        encrypt::{encode_short_first_byte, encrypt_packet, protect_header},
        header::{
            io::WriteHeader,
            long::{io::LongHeaderBuilder, ZeroRttHeader},
            EncodeHeader, GetType, OneRttHeader,
        },
        keys::{ArcKeys, ArcOneRttKeys, ArcOneRttPacketKeys, HeaderProtectionKeys},
        number::WritePacketNumber,
        r#type::Type,
        signal::SpinBit,
        DataPacket, MiddleAssembledPacket, PacketNumber, PacketWriter,
    },
    param::CommonParameters,
    sid::{ControlConcurrency, Role},
    Epoch,
};
use qcongestion::{CongestionControl, TrackPackets, MSS};
use qrecovery::{
    crypto::{CryptoStream, CryptoStreamOutgoing},
    journal::{ArcRcvdJournal, DataJournal},
    reliable::{ArcReliableFrameDeque, GuaranteedFrame},
};
use qunreliable::DatagramFlow;
use tokio::task::JoinHandle;

use super::try_join2;
use crate::{
    events::{EmitEvent, Event},
    path::{Path, Paths, Pathway, SendBuffer},
    space::{pipe, AckData, FlowControlledDataStreams},
    tx::{PacketMemory, Transaction},
    Components, DataStreams,
};

pub type ZeroRttPacket = (ZeroRttHeader, bytes::BytesMut, usize);
pub type OneRttPacket = (OneRttHeader, bytes::BytesMut, usize);

#[derive(Clone)]
pub struct DataSpace {
    pub zero_rtt_keys: ArcKeys,
    pub one_rtt_keys: ArcOneRttKeys,
    pub journal: DataJournal,
    pub crypto_stream: CryptoStream,
    pub reliable_frames: ArcReliableFrameDeque,
    pub streams: DataStreams,
    pub datagrams: DatagramFlow,
}

impl DataSpace {
    pub fn new(
        role: Role,
        local_params: &CommonParameters,
        streams_ctrl: Box<dyn ControlConcurrency>,
    ) -> Self {
        let reliable_frames = ArcReliableFrameDeque::with_capacity(8);
        let streams = DataStreams::new(role, local_params, streams_ctrl, reliable_frames.clone());
        Self {
            zero_rtt_keys: ArcKeys::new_pending(),
            one_rtt_keys: ArcOneRttKeys::new_pending(),
            journal: DataJournal::with_capacity(16),
            crypto_stream: CryptoStream::new(4096, 4096),
            reliable_frames,
            streams,
            datagrams: DatagramFlow::new(1024),
        }
    }

    pub fn build(
        &self,
        pathes: &Arc<Paths>,
        components: &Components,
        rcvd_0rtt_packets: impl Stream<Item = (ZeroRttPacket, Pathway)> + Send + Unpin + 'static,
        rcvd_1rtt_packets: impl Stream<Item = (OneRttPacket, Pathway)> + Send + Unpin + 'static,
        broker: impl EmitEvent + Clone + Send + 'static,
    ) -> (JoinHandle<()>, JoinHandle<()>) {
        let (ack_frames_entry, rcvd_ack_frames) = mpsc::unbounded();
        // 连接级的
        let (max_data_frames_entry, rcvd_max_data_frames) = mpsc::unbounded();
        let (data_blocked_frames_entry, rcvd_data_blocked_frames) = mpsc::unbounded();
        let (new_cid_frames_entry, rcvd_new_cid_frames) = mpsc::unbounded();
        let (retire_cid_frames_entry, rcvd_retire_cid_frames) = mpsc::unbounded();
        let (handshake_done_frames_entry, rcvd_handshake_done_frames) = mpsc::unbounded();
        let (new_token_frames_entry, rcvd_new_token_frames) = mpsc::unbounded();
        // 数据级的
        let (crypto_frames_entry, rcvd_crypto_frames) = mpsc::unbounded();
        let (stream_ctrl_frames_entry, rcvd_stream_ctrl_frames) = mpsc::unbounded();
        let (stream_frames_entry, rcvd_stream_frames) = mpsc::unbounded();
        let (datagram_frames_entry, rcvd_datagram_frames) = mpsc::unbounded();

        let flow_controlled_data_streams =
            FlowControlledDataStreams::new(self.streams.clone(), components.flow_ctrl.clone());
        let dispatch_data_frame = {
            let broker = broker.clone();
            move |frame: Frame, pty: packet::Type, path: &Path| match frame {
                Frame::Ack(f) => {
                    path.cc().on_ack(Epoch::Data, &f);
                    _ = ack_frames_entry.unbounded_send(f)
                }
                Frame::NewToken(f) => _ = new_token_frames_entry.unbounded_send(f),
                Frame::MaxData(f) => _ = max_data_frames_entry.unbounded_send(f),
                Frame::NewConnectionId(f) => _ = new_cid_frames_entry.unbounded_send(f),
                Frame::RetireConnectionId(f) => _ = retire_cid_frames_entry.unbounded_send(f),
                Frame::HandshakeDone(f) => _ = handshake_done_frames_entry.unbounded_send(f),
                Frame::DataBlocked(f) => _ = data_blocked_frames_entry.unbounded_send(f),
                Frame::Challenge(f) => _ = path.recv_frame(&f),
                Frame::Response(f) => _ = path.recv_frame(&f),
                Frame::StreamCtl(f) => _ = stream_ctrl_frames_entry.unbounded_send(f),
                Frame::Stream(f, data) => _ = stream_frames_entry.unbounded_send((f, data)),
                Frame::Crypto(f, bytes) => _ = crypto_frames_entry.unbounded_send((f, bytes)),
                Frame::Datagram(f, data) => _ = datagram_frames_entry.unbounded_send((f, data)),
                Frame::Close(f) if matches!(pty, Type::Short(_)) => broker.emit(Event::Closed(f)),
                _ => {}
            }
        };

        // Assemble the pipelines of frame processing
        // TODO: pipe rcvd_new_token_frames
        pipe(
            rcvd_retire_cid_frames,
            components.cid_registry.local.clone(),
            broker.clone(),
        );
        pipe(
            rcvd_new_cid_frames,
            components.cid_registry.remote.clone(),
            broker.clone(),
        );
        pipe(
            rcvd_max_data_frames,
            components.flow_ctrl.sender.clone(),
            broker.clone(),
        );
        pipe(
            rcvd_data_blocked_frames,
            components.flow_ctrl.recver.clone(),
            broker.clone(),
        );
        pipe(
            rcvd_handshake_done_frames,
            components.handshake.clone(),
            broker.clone(),
        );
        pipe(
            rcvd_crypto_frames,
            self.crypto_stream.incoming(),
            broker.clone(),
        );
        pipe(
            rcvd_stream_ctrl_frames,
            flow_controlled_data_streams.clone(),
            broker.clone(),
        );
        pipe(
            rcvd_stream_frames,
            flow_controlled_data_streams,
            broker.clone(),
        );
        pipe(rcvd_datagram_frames, self.datagrams.clone(), broker.clone());
        pipe(
            rcvd_ack_frames,
            AckData::new(&self.journal, &self.streams, &self.crypto_stream),
            broker.clone(),
        );
        pipe(
            rcvd_new_token_frames,
            components.token_registry.clone(),
            broker.clone(),
        );

        let join_handler0 = self.parse_rcvd_0rtt_packet_and_dispatch_frames(
            rcvd_0rtt_packets,
            pathes.clone(),
            dispatch_data_frame.clone(),
            broker.clone(),
        );
        let join_handler1 = self.parse_rcvd_1rtt_packet_and_dispatch_frames(
            rcvd_1rtt_packets,
            pathes.clone(),
            dispatch_data_frame,
            broker.clone(),
        );
        (join_handler0, join_handler1)
    }

    fn parse_rcvd_0rtt_packet_and_dispatch_frames(
        &self,
        mut rcvd_packets: impl Stream<Item = (ZeroRttPacket, Pathway)> + Send + Unpin + 'static,
        pathes: Arc<Paths>,
        dispatch_frame: impl Fn(Frame, packet::Type, &Path) + Send + 'static,
        broker: impl EmitEvent + Clone + Send + 'static,
    ) -> JoinHandle<()> {
        tokio::spawn({
            let rcvd_journal = self.journal.of_rcvd_packets();
            let keys = self.zero_rtt_keys.clone();
            async move {
                while let Some((((header, mut bytes, offset), pathway), keys)) =
                    try_join2(rcvd_packets.next(), keys.get_remote_keys()).await
                {
                    let Some(path) = pathes.get(&pathway) else {
                        continue;
                    };
                    let undecoded_pn = match remove_protection_of_long_packet(
                        keys.remote.header.as_ref(),
                        bytes.as_mut(),
                        offset,
                    ) {
                        Ok(Some(pn)) => pn,
                        Ok(None) => continue,
                        Err(invalid_reserved_bits) => {
                            broker.emit(Event::Failed(invalid_reserved_bits.into()));
                            break;
                        }
                    };

                    let pn = match rcvd_journal.decode_pn(undecoded_pn) {
                        Ok(pn) => pn,
                        // TooOld/TooLarge/HasRcvd
                        Err(_e) => continue,
                    };
                    let body_offset = offset + undecoded_pn.size();
                    let decrypted = decrypt_packet(
                        keys.remote.packet.as_ref(),
                        pn,
                        bytes.as_mut(),
                        body_offset,
                    );
                    let Ok(pkt_len) = decrypted else { continue };

                    path.on_rcvd(bytes.len());

                    let _header = bytes.split_to(body_offset);
                    bytes.truncate(pkt_len);

                    match FrameReader::new(bytes.freeze(), header.get_type()).try_fold(
                        false,
                        |is_ack_packet, frame| {
                            let (frame, is_ack_eliciting) = frame?;
                            dispatch_frame(frame, header.get_type(), &path);
                            Ok(is_ack_packet || is_ack_eliciting)
                        },
                    ) {
                        Ok(is_ack_packet) => {
                            rcvd_journal.register_pn(pn);
                            path.cc().on_pkt_rcvd(Epoch::Data, pn, is_ack_packet);
                        }
                        Err(e) => broker.emit(Event::Failed(e)),
                    }
                }
            }
        })
    }

    fn parse_rcvd_1rtt_packet_and_dispatch_frames(
        &self,
        mut rcvd_packets: impl Stream<Item = (OneRttPacket, Pathway)> + Send + Unpin + 'static,
        pathes: Arc<Paths>,
        dispatch_frame: impl Fn(Frame, packet::Type, &Path) + Send + 'static,
        broker: impl EmitEvent + Clone + Send + 'static,
    ) -> JoinHandle<()> {
        tokio::spawn({
            let rcvd_journal = self.journal.of_rcvd_packets();
            let keys = self.one_rtt_keys.clone();
            async move {
                while let Some((((header, mut bytes, offset), pathway), (hpk, pk))) =
                    try_join2(rcvd_packets.next(), keys.get_remote_keys()).await
                {
                    let Some(path) = pathes.get(&pathway) else {
                        continue;
                    };
                    let (undecoded_pn, key_phase) = match remove_protection_of_short_packet(
                        hpk.as_ref(),
                        bytes.as_mut(),
                        offset,
                    ) {
                        Ok(Some(pn)) => pn,
                        Ok(None) => continue,
                        Err(invalid_reserved_bits) => {
                            broker.emit(Event::Failed(invalid_reserved_bits.into()));
                            break;
                        }
                    };

                    let pn = match rcvd_journal.decode_pn(undecoded_pn) {
                        Ok(pn) => pn,
                        // TooOld/TooLarge/HasRcvd
                        Err(_e) => continue,
                    };
                    let body_offset = offset + undecoded_pn.size();
                    let pk = pk.lock_guard().get_remote(key_phase, pn);
                    let decrypted = decrypt_packet(pk.as_ref(), pn, bytes.as_mut(), body_offset);
                    let Ok(pkt_len) = decrypted else { continue };

                    path.on_rcvd(bytes.len());

                    let _header = bytes.split_to(body_offset);
                    bytes.truncate(pkt_len);

                    match FrameReader::new(bytes.freeze(), header.get_type()).try_fold(
                        false,
                        |is_ack_packet, frame| {
                            let (frame, is_ack_eliciting) = frame?;
                            dispatch_frame(frame, header.get_type(), &path);
                            Ok(is_ack_packet || is_ack_eliciting)
                        },
                    ) {
                        Ok(is_ack_packet) => {
                            rcvd_journal.register_pn(pn);
                            path.cc().on_pkt_rcvd(Epoch::Data, pn, is_ack_packet);
                        }
                        Err(e) => broker.emit(Event::Failed(e)),
                    }
                }
            }
        })
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
        if let Some((largest, rcvd_time)) = tx.need_ack(Epoch::Handshake) {
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
        // try to load reliable frames into this 0RTT packet to send
        self.reliable_frames.try_load_frames_into(&mut packet);
        // try to load stream frames into this 0RTT packet to send
        let fresh_data = self
            .streams
            .try_load_data_into(&mut packet, tx.flow_limit());
        self.datagrams.try_load_data_into(&mut packet);

        let packet: PacketWriter<'b> = packet.try_into().ok()?;
        Some((packet.abandon(), ack, fresh_data))
    }

    pub fn is_one_rtt_ready(&self) -> bool {
        self.one_rtt_keys.get_local_keys().is_some()
    }

    pub fn on_conn_error(&self, error: &Error) {
        self.streams.on_conn_error(error);
        self.datagrams.on_conn_error(error);
    }
}

#[derive(Clone)]
pub struct DataTracker {
    journal: DataJournal,
    reliable_frames: ArcReliableFrameDeque,
    streams: DataStreams,
    outgoing: CryptoStreamOutgoing,
}

impl DataTracker {
    pub fn new(
        journal: DataJournal,
        reliable_frames: ArcReliableFrameDeque,
        streams: DataStreams,
        outgoing: CryptoStreamOutgoing,
    ) -> Self {
        Self {
            journal,
            reliable_frames,
            streams,
            outgoing,
        }
    }
}

impl TrackPackets for DataTracker {
    fn may_loss(&self, pn: u64) {
        for frame in self.journal.of_sent_packets().rotate().may_loss_pkt(pn) {
            match frame {
                GuaranteedFrame::Stream(f) => self.streams.may_loss_data(&f),
                GuaranteedFrame::Reliable(f) => self.reliable_frames.send_frame([f]),
                GuaranteedFrame::Crypto(f) => self.outgoing.may_loss_data(&f),
            }
        }
    }

    fn retire(&self, pn: u64) {
        self.journal.of_rcvd_packets().write().retire(pn);
    }
}

#[derive(Clone)]
pub struct ClosingOneRttScope {
    keys: (HeaderProtectionKeys, ArcOneRttPacketKeys),
    rcvd_journal: ArcRcvdJournal,
    // 发包时用得着
    next_sending_pn: (u64, PacketNumber),
}

impl ClosingOneRttScope {
    pub fn assemble_ccf_packet(
        &self,
        buf: &mut [u8; MSS],
        ccf: &ConnectionCloseFrame,
        dcid: ConnectionId,
    ) -> usize {
        let (hpk, pk) = &self.keys;
        let hpk = &hpk.local;

        let spin = Default::default();
        let hdr = OneRttHeader::new(spin, dcid);
        let (mut hdr_buf, payload_tag) = buf.split_at_mut(hdr.size());
        let payload_tag_len = payload_tag.len();
        let tag_len = pk.tag_len();
        let payload_buf = &mut payload_tag[..payload_tag_len - tag_len];

        let (pn, encoded_pn) = self.next_sending_pn;
        let (mut pn_buf, mut body_buf) = payload_buf.split_at_mut(encoded_pn.size());

        let body_size = body_buf.remaining_mut();

        body_buf.put_frame(ccf);

        let hdr_len = hdr_buf.len();
        let pn_len = pn_buf.len();
        let mut body_len = body_size - body_buf.remaining_mut();
        if pn_len + body_len + tag_len < 20 {
            let padding_len = 20 - pn_len - body_len - tag_len;
            body_buf.put_bytes(0, padding_len);
            body_len += padding_len;
        }
        let sent_size = hdr_len + pn_len + body_len + tag_len;

        hdr_buf.put_header(&hdr);
        pn_buf.put_packet_number(encoded_pn);

        let (key_phase, pk) = pk.lock_guard().get_local();
        encode_short_first_byte(&mut buf[0], pn_len, key_phase);
        encrypt_packet(pk.as_ref(), pn, &mut buf[..sent_size], hdr_len + pn_len);
        protect_header(hpk.as_ref(), &mut buf[..sent_size], hdr_len, pn_len);

        sent_size
    }
}

impl TryFrom<DataSpace> for ClosingOneRttScope {
    type Error = ();

    fn try_from(data: DataSpace) -> Result<Self, Self::Error> {
        let Some(keys) = data.one_rtt_keys.invalid() else {
            return Err(());
        };
        let rcvd_journal = data.journal.of_rcvd_packets();
        let next_sending_pn = data.journal.of_sent_packets().new_packet().pn();

        Ok(Self {
            keys,
            rcvd_journal,
            next_sending_pn,
        })
    }
}

impl super::RecvPacket for ClosingOneRttScope {
    fn has_rcvd_ccf(&self, mut packet: DataPacket) -> bool {
        let (undecoded_pn, key_phase) = match remove_protection_of_short_packet(
            self.keys.0.remote.as_ref(),
            packet.bytes.as_mut(),
            packet.offset,
        ) {
            Ok(Some(pn)) => pn,
            _ => return false,
        };

        let pn = match self.rcvd_journal.decode_pn(undecoded_pn) {
            Ok(pn) => pn,
            // TooOld/TooLarge/HasRcvd
            Err(_e) => return false,
        };
        let body_offset = packet.offset + undecoded_pn.size();
        let pk = self.keys.1.lock_guard().get_remote(key_phase, pn);
        Self::decrypt_and_parse(pk.as_ref(), pn, packet, body_offset)
    }
}