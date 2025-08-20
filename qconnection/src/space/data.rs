use std::sync::{Arc, atomic::Ordering::SeqCst};

use qbase::{
    Epoch, GetEpoch,
    error::{Error, QuicError},
    frame::{ConnectionCloseFrame, Frame, FrameReader, ReceiveFrame, SendFrame},
    net::{
        addr::BindUri,
        route::{Link, Pathway},
        tx::Signals,
    },
    packet::{
        self, PacketContains,
        header::{GetDcid, GetType, OneRttHeader, long::ZeroRttHeader},
        io::PacketSpace,
        keys::{ArcOneRttKeys, ArcZeroRttKeys, DirectionalKeys},
        r#type::Type,
    },
    util::BoundQueue,
};
use qcongestion::{ArcCC, Feedback, Transport};
use qevent::{
    quic::{
        PacketHeader, PacketType, QuicFramesCollector,
        recovery::{PacketLost, PacketLostTrigger},
        transport::PacketReceived,
    },
    telemetry::Instrument,
};
use qinterface::packet::{CipherPacket, PlainPacket};
use qrecovery::crypto::CryptoStream;
use tokio::sync::mpsc;
use tracing::Instrument as _;

use crate::{
    ArcReliableFrameDeque, Components, DataJournal, DataStreams, GuaranteedFrame,
    SpecificComponents,
    events::{ArcEventBroker, EmitEvent, Event},
    path::{self, Path, error::CreatePathFailure},
    space::{AckDataSpace, FlowControlledDataStreams, assemble_closing_packet, pipe},
    termination::Terminator,
    tx::{PacketWriter, TrivialPacketWriter},
};

pub type CipherZeroRttPacket = CipherPacket<ZeroRttHeader>;
pub type PlainZeroRttPacket = PlainPacket<ZeroRttHeader>;
pub type ReceivedZeroRttFrom = (CipherZeroRttPacket, (BindUri, Pathway, Link));

pub type CipherOneRttPacket = CipherPacket<OneRttHeader>;
pub type PlainOneRttPacket = PlainPacket<OneRttHeader>;
pub type ReceivedOneRttFrom = (CipherOneRttPacket, (BindUri, Pathway, Link));

pub struct DataSpace {
    zero_rtt_keys: ArcZeroRttKeys,
    one_rtt_keys: ArcOneRttKeys,
    journal: DataJournal,
}

impl AsRef<DataJournal> for DataSpace {
    fn as_ref(&self) -> &DataJournal {
        &self.journal
    }
}

impl DataSpace {
    pub fn new(zero_rtt_keys: ArcZeroRttKeys) -> Self {
        Self {
            zero_rtt_keys,
            one_rtt_keys: ArcOneRttKeys::new_pending(),
            journal: DataJournal::with_capacity(16, None),
        }
    }

    pub async fn decrypt_0rtt_packet(
        &self,
        packet: CipherZeroRttPacket,
    ) -> Option<Result<PlainZeroRttPacket, QuicError>> {
        // TODO: client should never received 0rtt packet...
        match self.zero_rtt_keys.get_decrypt_keys()?.await {
            Some(keys) => {
                packet.decrypt_long_packet(keys.header.as_ref(), keys.packet.as_ref(), |pn| {
                    self.journal.of_rcvd_packets().decode_pn(pn)
                })
            }
            None => {
                packet.drop_on_key_unavailable();
                None
            }
        }
    }

    pub async fn decrypt_1rtt_packet(
        &self,
        packet: CipherOneRttPacket,
    ) -> Option<Result<PlainOneRttPacket, QuicError>> {
        match self.one_rtt_keys.get_remote_keys().await {
            Some((hpk, pk)) => packet.decrypt_short_packet(hpk.as_ref(), &pk, |pn| {
                self.journal.of_rcvd_packets().decode_pn(pn)
            }),
            None => {
                packet.drop_on_key_unavailable();
                None
            }
        }
    }

    pub fn new_0rtt_packet<'b, 's>(
        &'s self,
        header: ZeroRttHeader,
        cc: &ArcCC,
        buffer: &'b mut [u8],
    ) -> Result<PacketWriter<'b, 's, GuaranteedFrame>, Signals> {
        if self.one_rtt_keys.get_local_keys().is_some() {
            return Err(Signals::TLS_FIN); // should 1rtt
        }

        let Some(keys) = self.zero_rtt_keys.get_encrypt_keys() else {
            return Err(Signals::empty()); // no 0rtt keys, just skip 0rtt
        };

        let (retran_timeout, expire_timeout) = cc.retransmit_and_expire_time(Epoch::Data);
        PacketWriter::new_long(
            header,
            buffer,
            keys,
            self.journal.as_ref(),
            retran_timeout,
            expire_timeout,
        )
    }

    pub fn new_1rtt_packet<'b, 's>(
        &'s self,
        header: OneRttHeader,
        cc: &ArcCC,
        buffer: &'b mut [u8],
    ) -> Result<PacketWriter<'b, 's, GuaranteedFrame>, Signals> {
        let (hpk, pk) = self.one_rtt_keys.get_local_keys().ok_or(Signals::KEYS)?;
        let (key_phase, pk) = pk.lock_guard().get_local();
        let (retran_timeout, expire_timeout) = cc.retransmit_and_expire_time(Epoch::Data);
        PacketWriter::new_short(
            header,
            buffer,
            DirectionalKeys {
                header: hpk,
                packet: pk,
            },
            key_phase,
            self.journal.as_ref(),
            retran_timeout,
            expire_timeout,
        )
    }

    pub fn is_one_rtt_keys_ready(&self) -> bool {
        self.one_rtt_keys.get_local_keys().is_some()
    }

    pub fn is_zero_rtt_avaliable(&self) -> bool {
        self.zero_rtt_keys.get_encrypt_keys().is_some()
    }

    pub fn one_rtt_keys(&self) -> ArcOneRttKeys {
        self.one_rtt_keys.clone()
    }

    pub fn zero_rtt_keys(&self) -> ArcZeroRttKeys {
        self.zero_rtt_keys.clone()
    }

    pub(crate) fn journal(&self) -> &DataJournal {
        &self.journal
    }

    pub fn tracker(
        &self,
        crypto_stream: CryptoStream,
        streams: DataStreams,
        reliable_frames: ArcReliableFrameDeque,
    ) -> DataTracker {
        DataTracker {
            journal: self.journal.clone(),
            crypto_stream,
            streams,
            reliable_frames,
        }
    }
}

impl GetEpoch for DataSpace {
    fn epoch(&self) -> Epoch {
        Epoch::Data
    }
}

impl path::PacketSpace<ZeroRttHeader> for DataSpace {
    type JournalFrame = GuaranteedFrame;

    fn new_packet<'b, 's>(
        &'s self,
        header: ZeroRttHeader,
        cc: &ArcCC,
        buffer: &'b mut [u8],
    ) -> Result<PacketWriter<'b, 's, GuaranteedFrame>, Signals> {
        if self.one_rtt_keys.get_local_keys().is_some() {
            return Err(Signals::TLS_FIN); // should 1rtt
        }

        let Some(keys) = self.zero_rtt_keys.get_encrypt_keys() else {
            return Err(Signals::empty()); // no 0rtt keys, just skip 0rtt
        };

        let (retran_timeout, expire_timeout) = cc.retransmit_and_expire_time(Epoch::Data);
        PacketWriter::new_long(
            header,
            buffer,
            keys,
            self.journal.as_ref(),
            retran_timeout,
            expire_timeout,
        )
    }
}

impl path::PacketSpace<OneRttHeader> for DataSpace {
    type JournalFrame = GuaranteedFrame;

    fn new_packet<'b, 's>(
        &'s self,
        header: OneRttHeader,
        cc: &ArcCC,
        buffer: &'b mut [u8],
    ) -> Result<PacketWriter<'b, 's, GuaranteedFrame>, Signals> {
        let (hpk, pk) = self.one_rtt_keys.get_local_keys().ok_or(Signals::KEYS)?;
        let (key_phase, pk) = pk.lock_guard().get_local();
        let (retran_timeout, expire_timeout) = cc.retransmit_and_expire_time(Epoch::Data);
        PacketWriter::new_short(
            header,
            buffer,
            DirectionalKeys {
                header: hpk,
                packet: pk,
            },
            key_phase,
            self.journal.as_ref(),
            retran_timeout,
            expire_timeout,
        )
    }
}

pub fn spawn_deliver_and_parse(
    zeor_rtt_packets: BoundQueue<ReceivedZeroRttFrom>,
    one_rtt_packets: BoundQueue<ReceivedOneRttFrom>,
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

    let flow_controlled_data_streams = FlowControlledDataStreams::new(
        components.data_streams.clone(),
        components.flow_ctrl.clone(),
    );

    // Assemble the pipelines of frame processing
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
        components
            .quic_handshake
            .discard_spaces_on_client_handshake_done(components.paths.clone()),
        event_broker.clone(),
    );
    pipe(
        rcvd_crypto_frames,
        components.crypto_streams[space.epoch()].incoming(),
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
        components.datagram_flow.clone(),
        event_broker.clone(),
    );
    pipe(
        rcvd_ack_frames,
        AckDataSpace::new(
            &space.journal,
            &components.data_streams,
            &components.crypto_streams[space.epoch()],
        ),
        event_broker.clone(),
    );
    pipe(
        rcvd_new_token_frames,
        components.token_registry.clone(),
        event_broker.clone(),
    );

    let dispatch_data_frame = {
        let event_broker = event_broker.clone();
        let rcvd_joural = space.journal.of_rcvd_packets();
        move |frame: Frame, pty: packet::Type, path: &Path| match frame {
            Frame::Ack(f) => {
                path.cc().on_ack_rcvd(Epoch::Data, &f);
                rcvd_joural.on_rcvd_ack(&f);
                _ = ack_frames_entry.send(f)
            }
            Frame::NewToken(f) => _ = new_token_frames_entry.send(f),
            Frame::MaxData(f) => _ = max_data_frames_entry.send(f),
            Frame::NewConnectionId(f) => _ = new_cid_frames_entry.send(f),
            Frame::RetireConnectionId(f) => _ = retire_cid_frames_entry.send(f),
            Frame::HandshakeDone(f) => {
                // See [Section 4.1.2](https://datatracker.ietf.org/doc/html/rfc9001#handshake-confirmed)
                _ = handshake_done_frames_entry.send(f)
            }
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

    let deliver_and_parse_0rtt = {
        let tls_handshake = components.tls_handshake.clone();
        let components = components.clone();
        let space = space.clone();
        let dispatch_data_frame = dispatch_data_frame.clone();
        let event_broker = event_broker.clone();
        async move {
            // wait for the 1RTT to be ready, then start receiving packets
            tls_handshake.finished().await;
            while let Some((packet, (bind_uri, pathway, link))) = zeor_rtt_packets.recv().await {
                let parse = async {
                    let Some(packet) = space.decrypt_0rtt_packet(packet).await.transpose()? else {
                        return Ok(());
                    };

                    let path =
                        match components.get_or_try_create_path(bind_uri, link, pathway, true) {
                            Ok(path) => path,
                            Err(CreatePathFailure::ConnectionClosed(..)) => {
                                packet.drop_on_conenction_closed();
                                return Ok(());
                            }
                            Err(CreatePathFailure::NoInterface(..)) => {
                                packet.drop_on_interface_not_found();
                                return Ok(());
                            }
                        };

                    // the origin dcid doesnot own a sequences number, once we received a packet which dcid != odcid,
                    // we should stop using the odcid, and drop the subsequent packets with odcid.
                    //
                    // We do not remove the route to odcid, otherwise the server may establish multiple connections.
                    //
                    // https://www.rfc-editor.org/rfc/rfc9000.html#name-negotiating-connection-ids
                    if let SpecificComponents::Server {
                        odcid_router_entry,
                        using_odcid,
                    } = &components.specific
                    {
                        if odcid_router_entry.signpost() == (*packet.dcid()).into()
                            && !using_odcid.load(SeqCst)
                        {
                            drop(packet); // just drop the packet, It's like we never received this packet.
                            return Ok(());
                        }

                        if odcid_router_entry.signpost() != (*packet.dcid()).into() {
                            using_odcid.store(false, SeqCst);
                        }
                    }

                    let mut frames = QuicFramesCollector::<PacketReceived>::new();
                    let packet_contains = FrameReader::new(packet.body(), packet.get_type())
                        .try_fold(PacketContains::default(), |packet_contains, frame| {
                            let (frame, frame_type) = frame?;
                            frames.extend(Some(&frame));
                            dispatch_data_frame(frame, packet.get_type(), &path);
                            Result::<_, QuicError>::Ok(packet_contains.include(frame_type))
                        })?;
                    packet.log_received(frames);

                    space.journal.of_rcvd_packets().on_rcvd_pn(
                        packet.pn(),
                        packet_contains.ack_eliciting(),
                        path.cc().get_pto(Epoch::Data),
                    );
                    path.on_packet_rcvd(Epoch::Data, packet.pn(), packet.size(), packet_contains);

                    Result::<(), Error>::Ok(())
                };

                if let Err(Error::Quic(error)) =
                    Instrument::instrument(parse, qevent::span!(@current, path=pathway.to_string()))
                        .await
                {
                    event_broker.emit(Event::Failed(error));
                };
            }
        }
    };

    let deliver_and_parse_1rtt = {
        let tls_handshake = components.tls_handshake.clone();
        let components = components.clone();
        let space = space.clone();
        let dispatch_data_frame = dispatch_data_frame.clone();
        let event_broker = event_broker.clone();
        async move {
            // wait for the 1RTT to be ready, then start receiving packets
            tls_handshake.finished().await;
            while let Some((packet, (bind_uri, pathway, link))) = one_rtt_packets.recv().await {
                let parse = async {
                    let Some(packet) = space.decrypt_1rtt_packet(packet).await.transpose()? else {
                        return Ok(());
                    };

                    let path =
                        match components.get_or_try_create_path(bind_uri, link, pathway, true) {
                            Ok(path) => path,
                            Err(CreatePathFailure::ConnectionClosed(..)) => {
                                packet.drop_on_conenction_closed();
                                return Ok(());
                            }
                            Err(CreatePathFailure::NoInterface(..)) => {
                                packet.drop_on_interface_not_found();
                                return Ok(());
                            }
                        };

                    // the origin dcid doesnot own a sequences number, once we received a packet which dcid != odcid,
                    // we should stop using the odcid, and drop the subsequent packets with odcid.
                    //
                    // We do not remove the route to odcid, otherwise the server may establish multiple connections.
                    //
                    // https://www.rfc-editor.org/rfc/rfc9000.html#name-negotiating-connection-ids
                    if let SpecificComponents::Server {
                        odcid_router_entry,
                        using_odcid,
                    } = &components.specific
                    {
                        if odcid_router_entry.signpost() == (*packet.dcid()).into()
                            && !using_odcid.load(SeqCst)
                        {
                            drop(packet); // just drop the packet, It's like we never received this packet.
                            return Ok(());
                        }

                        if odcid_router_entry.signpost() != (*packet.dcid()).into() {
                            using_odcid.store(false, SeqCst);
                        }
                    }

                    components
                        .quic_handshake
                        .discard_spaces_on_server_handshake_done(&components.paths);

                    let mut frames = QuicFramesCollector::<PacketReceived>::new();
                    let packet_contains = FrameReader::new(packet.body(), packet.get_type())
                        .try_fold(PacketContains::default(), |packet_contains, frame| {
                            let (frame, frame_type) = frame?;
                            frames.extend(Some(&frame));
                            dispatch_data_frame(frame, packet.get_type(), &path);
                            Result::<_, QuicError>::Ok(packet_contains.include(frame_type))
                        })?;
                    packet.log_received(frames);

                    space.journal.of_rcvd_packets().on_rcvd_pn(
                        packet.pn(),
                        packet_contains.ack_eliciting(),
                        path.cc().get_pto(Epoch::Data),
                    );
                    path.on_packet_rcvd(Epoch::Data, packet.pn(), packet.size(), packet_contains);

                    Result::<(), Error>::Ok(())
                };

                if let Err(Error::Quic(error)) =
                    Instrument::instrument(parse, qevent::span!(@current, path=pathway.to_string()))
                        .await
                {
                    event_broker.emit(Event::Failed(error));
                };
            }
        }
    };

    tokio::spawn({
        let conn_state = components.conn_state.clone();
        async move {
            tokio::select! {
                _ = deliver_and_parse_0rtt => {},
                _ = conn_state.terminated() => {}
            };
        }
        .instrument_in_current()
        .in_current_span()
    });
    tokio::spawn({
        let conn_state = components.conn_state.clone();
        async move {
            tokio::select! {
                _ = deliver_and_parse_1rtt => {},
                _ = conn_state.terminated() => {}
            };
        }
        .instrument_in_current()
        .in_current_span()
    });
}

pub struct DataTracker {
    journal: DataJournal,
    crypto_stream: CryptoStream,
    streams: DataStreams,
    reliable_frames: ArcReliableFrameDeque,
}

impl Feedback for DataTracker {
    fn may_loss(&self, trigger: PacketLostTrigger, pns: &mut dyn Iterator<Item = u64>) {
        let sent_jornal = self.journal.of_sent_packets();
        let crypto_outgoing = self.crypto_stream.outgoing();
        let mut sent_packets = sent_jornal.rotate();
        for pn in pns {
            let mut may_lost_frames = QuicFramesCollector::<PacketLost>::new();
            for frame in sent_packets.may_loss_packet(pn) {
                match frame {
                    GuaranteedFrame::Crypto(frame) => {
                        may_lost_frames.extend([&frame]);
                        crypto_outgoing.may_loss_data(&frame);
                    }
                    GuaranteedFrame::Stream(frame) => {
                        may_lost_frames.extend([&frame]);
                        self.streams.may_loss_data(&frame);
                    }
                    GuaranteedFrame::Reliable(frame) => {
                        may_lost_frames.extend([&frame]);
                        self.reliable_frames.send_frame([frame]);
                    }
                };
            }
            qevent::event!(PacketLost {
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
}

impl PacketSpace<ZeroRttHeader> for DataSpace {
    type PacketAssembler<'a> = TrivialPacketWriter<'a, 'a, GuaranteedFrame>;

    #[inline]
    fn new_packet<'a>(
        &'a self,
        header: ZeroRttHeader,
        buffer: &'a mut [u8],
    ) -> Result<Self::PacketAssembler<'a>, Signals> {
        if self.one_rtt_keys.get_local_keys().is_some() {
            return Err(Signals::TLS_FIN); // should 1rtt
        }

        let Some(keys) = self.zero_rtt_keys.get_encrypt_keys() else {
            return Err(Signals::empty()); // no 0rtt keys, just skip 0rtt
        };

        TrivialPacketWriter::new_long(header, buffer, keys, self.journal.as_ref())
    }
}

impl PacketSpace<OneRttHeader> for DataSpace {
    type PacketAssembler<'a> = TrivialPacketWriter<'a, 'a, GuaranteedFrame>;

    #[inline]
    fn new_packet<'a>(
        &'a self,
        header: OneRttHeader,
        buffer: &'a mut [u8],
    ) -> Result<Self::PacketAssembler<'a>, Signals> {
        let (hpk, pk) = self.one_rtt_keys.get_local_keys().ok_or(Signals::KEYS)?;
        let (key_phase, pk) = pk.lock_guard().get_local();
        TrivialPacketWriter::new_short(
            header,
            buffer,
            DirectionalKeys {
                header: hpk,
                packet: pk,
            },
            key_phase,
            self.journal.as_ref(),
        )
    }
}

impl DataSpace {
    pub fn recv_packet(&self, packet: CipherOneRttPacket) -> Option<ConnectionCloseFrame> {
        let (hpk, pk) = self.one_rtt_keys.remote_keys()?;
        let packet = packet
            .decrypt_short_packet(hpk.as_ref(), &pk, |pn| {
                self.journal.of_rcvd_packets().decode_pn(pn)
            })
            .and_then(Result::ok)?;

        let mut frames = QuicFramesCollector::<PacketReceived>::new();
        let ccf = FrameReader::new(packet.body(), packet.get_type())
            .filter_map(Result::ok)
            .inspect(|(f, _ack)| frames.extend(Some(f)))
            .fold(None, |ccf, (frame, _)| match (ccf, frame) {
                (ccf @ Some(..), _) => ccf,
                (None, Frame::Close(ccf)) => Some(ccf),
                (None, _) => None,
            });
        packet.log_received(frames);
        ccf
    }
}

pub fn spawn_deliver_and_parse_closing(
    packets: BoundQueue<ReceivedOneRttFrom>,
    space: Arc<DataSpace>,
    terminator: Arc<Terminator>,
    event_broker: ArcEventBroker,
) {
    tokio::spawn(
        async move {
            while let Some((packet, (_, pathway, _socket))) = packets.recv().await {
                if let Some(ccf) = space.recv_packet(packet) {
                    event_broker.emit(Event::Closed(ccf.clone()));
                    return;
                }
                if terminator.should_send() {
                    _ = terminator
                        .try_send_on(pathway, |buffer, ccf| {
                            assemble_closing_packet::<OneRttHeader, _>(
                                space.as_ref(),
                                terminator.as_ref(),
                                buffer,
                                ccf,
                            )
                        })
                        .await;
                }
            }
        }
        .instrument_in_current()
        .in_current_span(),
    );
}
