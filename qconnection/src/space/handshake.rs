use std::sync::{Arc, atomic::Ordering::SeqCst};

use qbase::{
    Epoch, GetEpoch,
    error::{Error, QuicError},
    frame::{ConnectionCloseFrame, CryptoFrame, Frame, FrameReader},
    net::tx::Signals,
    packet::{
        PacketContains,
        header::{GetDcid, GetType, long::HandshakeHeader},
        io::PacketSpace,
        keys::ArcKeys,
    },
    util::BoundQueue,
};
use qcongestion::{Feedback, Transport};
use qevent::{
    quic::{
        PacketHeader, PacketType, QuicFramesCollector,
        recovery::{PacketLost, PacketLostTrigger},
        transport::PacketReceived,
    },
    telemetry::Instrument,
};
use qinterface::{
    packet::{CipherPacket, PlainPacket},
    route::Way,
};
use qrecovery::crypto::CryptoStream;
use tokio::sync::mpsc;
use tracing::Instrument as _;

use crate::{
    Components, HandshakeJournal, SpecificComponents,
    events::{ArcEventBroker, EmitEvent, Event},
    path::{self, Path, error::CreatePathFailure},
    space::{AckHandshakeSpace, assemble_closing_packet, pipe},
    termination::Terminator,
    tx::{PacketWriter, TrivialPacketWriter},
};

pub type CipherHanshakePacket = CipherPacket<HandshakeHeader>;
pub type PlainHandshakePacket = PlainPacket<HandshakeHeader>;
pub type ReceivedFrom = (CipherHanshakePacket, Way);

pub struct HandshakeSpace {
    keys: ArcKeys,
    journal: HandshakeJournal,
}

impl AsRef<HandshakeJournal> for HandshakeSpace {
    fn as_ref(&self) -> &HandshakeJournal {
        &self.journal
    }
}

impl HandshakeSpace {
    pub fn new() -> Self {
        Self {
            keys: ArcKeys::new_pending(),
            journal: HandshakeJournal::with_capacity(16, None),
        }
    }

    pub fn keys(&self) -> ArcKeys {
        self.keys.clone()
    }

    pub async fn decrypt_packet(
        &self,
        packet: CipherHanshakePacket,
    ) -> Option<Result<PlainHandshakePacket, QuicError>> {
        match self.keys.get_remote_keys().await {
            Some(keys) => packet.decrypt_long_packet(
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

    pub fn tracker(&self, crypto_stream: CryptoStream) -> HandshakeTracker {
        HandshakeTracker {
            journal: self.journal.clone(),
            crypto_stream,
        }
    }
}

impl Default for HandshakeSpace {
    fn default() -> Self {
        Self::new()
    }
}

impl GetEpoch for HandshakeSpace {
    fn epoch(&self) -> Epoch {
        Epoch::Handshake
    }
}

impl path::PacketSpace<HandshakeHeader> for HandshakeSpace {
    type JournalFrame = CryptoFrame;

    fn new_packet<'b, 's>(
        &'s self,
        header: HandshakeHeader,
        cc: &qcongestion::ArcCC,
        buffer: &'b mut [u8],
    ) -> Result<PacketWriter<'b, 's, CryptoFrame>, Signals> {
        let keys = self.keys.get_local_keys().ok_or(Signals::KEYS)?;
        let (retran_timeout, expire_timeout) = cc.retransmit_and_expire_time(Epoch::Handshake);
        PacketWriter::new_long(
            header,
            buffer,
            keys.local.clone(),
            self.journal.as_ref(),
            retran_timeout,
            expire_timeout,
        )
    }
}

pub fn spawn_deliver_and_parse(
    packets: BoundQueue<ReceivedFrom>,
    space: Arc<HandshakeSpace>,
    components: &Components,
    event_broker: ArcEventBroker,
) {
    let (crypto_frames_entry, rcvd_crypto_frames) = mpsc::unbounded_channel();
    let (ack_frames_entry, rcvd_ack_frames) = mpsc::unbounded_channel();

    pipe(
        rcvd_crypto_frames,
        components.crypto_streams[space.epoch()].incoming(),
        event_broker.clone(),
    );
    pipe(
        rcvd_ack_frames,
        AckHandshakeSpace::new(&space.journal, &components.crypto_streams[space.epoch()]),
        event_broker.clone(),
    );

    let inform_cc = components.quic_handshake.status();
    let dispatch_frame = {
        let event_broker = event_broker.clone();
        let rcvd_joural = space.journal.of_rcvd_packets();
        move |frame: Frame, path: &Path| match frame {
            Frame::Ack(f) => {
                path.cc().on_ack_rcvd(Epoch::Handshake, &f);
                rcvd_joural.on_rcvd_ack(&f);
                _ = ack_frames_entry.send(f);
                inform_cc.received_handshake_ack();
            }
            Frame::Close(f) => event_broker.emit(Event::Closed(f)),
            Frame::Crypto(f, bytes) => _ = crypto_frames_entry.send((f, bytes)),
            Frame::Padding(_) | Frame::Ping(_) => {}
            _ => unreachable!("unexpected frame: {:?} in handshake packet", frame),
        }
    };

    let components = components.clone();
    let conn_state = components.conn_state.clone();
    let deliver_and_parse = async move {
        while let Some((packet, (bind_uri, pathway, link))) = packets.recv().await {
            let parse = async {
                let Some(packet) = space.decrypt_packet(packet).await.transpose()? else {
                    return Ok(());
                };

                let path = match components.get_or_try_create_path(bind_uri, link, pathway, true) {
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

                // See [RFC 9000 section 8.1](https://www.rfc-editor.org/rfc/rfc9000.html#name-address-validation-during-c)
                // Once an endpoint has successfully processed a Handshake packet from the peer, it can consider the peer
                // address to have been validated.
                // It may have already been verified using tokens in the Handshake space
                path.grant_anti_amplification();

                let mut frames = QuicFramesCollector::<PacketReceived>::new();
                let packet_contains = FrameReader::new(packet.body(), packet.get_type()).try_fold(
                    PacketContains::default(),
                    |packet_contains, frame| {
                        let (frame, frame_type) = frame?;
                        frames.extend(Some(&frame));
                        dispatch_frame(frame, &path);
                        Result::<_, QuicError>::Ok(packet_contains.include(frame_type))
                    },
                )?;
                packet.log_received(frames);

                space.journal.of_rcvd_packets().on_rcvd_pn(
                    packet.pn(),
                    packet_contains != PacketContains::NonAckEliciting,
                    path.cc().get_pto(Epoch::Handshake),
                );
                path.on_packet_rcvd(
                    Epoch::Handshake,
                    packet.pn(),
                    packet.size(),
                    packet_contains,
                );

                Result::<(), Error>::Ok(())
            };

            if let Err(Error::Quic(error)) =
                Instrument::instrument(parse, qevent::span!(@current, path=pathway.to_string()))
                    .await
            {
                event_broker.emit(Event::Failed(error));
            };
        }
    };

    tokio::spawn(
        async move {
            tokio::select! {
                _ = deliver_and_parse => {},
                _ = conn_state.terminated() => {}
            };
        }
        .instrument_in_current()
        .in_current_span(),
    );
}

pub struct HandshakeTracker {
    journal: HandshakeJournal,
    crypto_stream: CryptoStream,
}

impl Feedback for HandshakeTracker {
    fn may_loss(&self, trigger: PacketLostTrigger, pns: &mut dyn Iterator<Item = u64>) {
        let sent_jornal = self.journal.of_sent_packets();
        let outgoing = self.crypto_stream.outgoing();
        let mut sent_packets = sent_jornal.rotate();
        for pn in pns {
            let mut may_lost_frames = QuicFramesCollector::<PacketLost>::new();
            for frame in sent_packets.may_loss_packet(pn) {
                may_lost_frames.extend([&frame]);
                outgoing.may_loss_data(&frame);
            }
            qevent::event!(PacketLost {
                header: PacketHeader {
                    packet_type: PacketType::Handshake,
                    packet_number: pn
                },
                frames: may_lost_frames,
                trigger
            });
        }
    }
}

impl HandshakeSpace {
    pub fn recv_packet(&self, packet: CipherHanshakePacket) -> Option<ConnectionCloseFrame> {
        let remote_keys = self.keys.get_local_keys()?.remote;
        let packet = packet
            .decrypt_long_packet(
                remote_keys.header.as_ref(),
                remote_keys.packet.as_ref(),
                |pn| self.journal.of_rcvd_packets().decode_pn(pn),
            )
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

    // pub fn try_assemble_ccf_packet(
    //     &self,
    //     scid: ConnectionId,
    //     dcid: ConnectionId,
    //     ccf: &ConnectionCloseFrame,
    //     buf: &mut [u8],
    // ) -> Option<FinalPacketLayout> {
    //     let header = LongHeaderBuilder::with_cid(dcid, scid).handshake();
    //     let pn = self.ccf_packet_pn;
    //     let mut packet_writer =
    //         PacketWriter::new_long(&header, buf, pn, self.keys.local.clone()).ok()?;

    //     let ccf = match ccf.clone() {
    //         ConnectionCloseFrame::App(mut app_close_frame) => {
    //             app_close_frame.conceal();
    //             ConnectionCloseFrame::App(app_close_frame)
    //         }
    //         ccf @ ConnectionCloseFrame::Quic(_) => ccf,
    //     };

    //     packet_writer.dump_frame(ccf);

    //     Some(packet_writer.encrypt_and_protect())
    // }
}

impl PacketSpace<HandshakeHeader> for HandshakeSpace {
    type PacketAssembler<'a> = TrivialPacketWriter<'a, 'a, CryptoFrame>;

    #[inline]
    fn new_packet<'a>(
        &'a self,
        header: HandshakeHeader,
        buffer: &'a mut [u8],
    ) -> Result<Self::PacketAssembler<'a>, Signals> {
        let keys = self.keys.get_local_keys().ok_or(Signals::KEYS)?;
        TrivialPacketWriter::new_long(header, buffer, keys.local, self.journal.as_ref())
    }
}

pub fn spawn_deliver_and_parse_closing(
    bundles: BoundQueue<ReceivedFrom>,
    space: Arc<HandshakeSpace>,
    terminator: Arc<Terminator>,
    event_broker: ArcEventBroker,
) {
    tokio::spawn(
        async move {
            while let Some((packet, (_, pathway, _socket))) = bundles.recv().await {
                if let Some(ccf) = space.recv_packet(packet) {
                    event_broker.emit(Event::Closed(ccf.clone()));
                    return;
                }
                if terminator.should_send() {
                    _ = terminator
                        .try_send_on(pathway, |buffer, ccf| {
                            assemble_closing_packet(
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
