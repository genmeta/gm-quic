use std::{
    ops::Deref,
    sync::{Arc, atomic::Ordering::SeqCst},
};

use qbase::{
    Epoch, GetEpoch,
    error::{Error, QuicError},
    frame::{ConnectionCloseFrame, CryptoFrame, Frame, FrameReader},
    net::tx::Signals,
    packet::{
        PacketContains,
        header::{GetDcid, GetScid, GetType, long::InitialHeader},
        io::PacketSpace,
        keys::{ArcKeys, Keys},
    },
    token::TokenRegistry,
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
    Components, InitialJournal, SpecificComponents,
    events::{ArcEventBroker, EmitEvent, Event},
    path::{self, Path, error::CreatePathFailure},
    space::{AckInitialSpace, assemble_closing_packet, pipe},
    termination::Terminator,
    tx::{PacketWriter, TrivialPacketWriter},
};

pub type CipherInitialPacket = CipherPacket<InitialHeader>;
pub type PlainInitialPacket = PlainPacket<InitialHeader>;
pub type ReceivedFrom = (CipherInitialPacket, Way);

pub struct InitialSpace {
    keys: ArcKeys,
    journal: InitialJournal,
}

impl AsRef<InitialJournal> for InitialSpace {
    fn as_ref(&self) -> &InitialJournal {
        &self.journal
    }
}

impl InitialSpace {
    // Initial keys应该是预先知道的，或者传入dcid，可以构造出来
    pub fn new(keys: Keys) -> Self {
        let journal = InitialJournal::with_capacity(16, None);
        Self {
            keys: ArcKeys::with_keys(keys),
            journal,
        }
    }

    pub fn keys(&self) -> ArcKeys {
        self.keys.clone()
    }

    pub async fn decrypt_packet(
        &self,
        packet: CipherInitialPacket,
    ) -> Option<Result<PlainInitialPacket, QuicError>> {
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

    pub fn tracker(&self, crypto_stream: CryptoStream) -> InitialTracker {
        InitialTracker {
            journal: self.journal.clone(),
            crypto_stream,
        }
    }
}

impl GetEpoch for InitialSpace {
    fn epoch(&self) -> Epoch {
        Epoch::Initial
    }
}

impl path::PacketSpace<InitialHeader> for InitialSpace {
    type JournalFrame = CryptoFrame;

    fn new_packet<'b, 's>(
        &'s self,
        header: InitialHeader,
        cc: &qcongestion::ArcCC,
        buffer: &'b mut [u8],
    ) -> Result<PacketWriter<'b, 's, CryptoFrame>, Signals> {
        let keys = self.keys.get_local_keys().ok_or(Signals::KEYS)?;
        let (retran_timeout, expire_timeout) = cc.retransmit_and_expire_time(Epoch::Handshake);
        PacketWriter::new_long(
            header,
            buffer,
            keys.local,
            self.journal.as_ref(),
            retran_timeout,
            expire_timeout,
        )
    }
}

pub fn spawn_deliver_and_parse(
    packets: BoundQueue<ReceivedFrom>,
    space: Arc<InitialSpace>,
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
        AckInitialSpace::new(&space.journal, &components.crypto_streams[space.epoch()]),
        event_broker.clone(),
    );

    let dispatch_frame = {
        let event_broker = event_broker.clone();
        let rcvd_joural = space.journal.of_rcvd_packets();
        move |frame: Frame, path: &Path| match frame {
            Frame::Ack(f) => {
                path.cc().on_ack_rcvd(Epoch::Initial, &f);
                rcvd_joural.on_rcvd_ack(&f);
                _ = ack_frames_entry.send(f);
            }
            Frame::Close(f) => event_broker.emit(Event::Closed(f)),
            Frame::Crypto(f, bytes) => _ = crypto_frames_entry.send((f, bytes)),
            Frame::Padding(_) | Frame::Ping(_) => {}
            _ => unreachable!("unexpected frame: {:?} in handshake packet", frame),
        }
    };

    let validate = {
        let tls_handshake = components.tls_handshake.clone();
        let token_registry = components.token_registry.clone();
        move |initial_token: &[u8], path: &Path| {
            if let TokenRegistry::Server(provider) = token_registry.deref() {
                if let Ok(Some(server_name)) = tls_handshake.server_name() {
                    if provider.verify_token(server_name, initial_token) {
                        path.grant_anti_amplification();
                    }
                }
            }
        }
    };

    let components = components.clone();
    let conn_state = components.conn_state.clone();
    let remote_cids = components.cid_registry.remote.clone();
    let deliver_and_parse = async move {
        while let Some((packet, (bind_uri, pathway, link))) = packets.recv().await {
            let parse = async {
                // rfc9000 7.2:
                // if subsequent Initial packets include a different Source Connection ID, they MUST be discarded. This avoids
                // unpredictable outcomes that might otherwise result from stateless processing of multiple Initial packets
                // with different Source Connection IDs.
                if matches!(components.parameters.lock_guard()?.initial_scid_from_peer(), Some(scid) if scid != *packet.scid())
                {
                    packet.drop_on_scid_unmatch();
                    return Ok(());
                }

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
                    path.cc().get_pto(Epoch::Initial),
                );
                path.on_packet_rcvd(Epoch::Initial, packet.pn(), packet.size(), packet_contains);

                if components
                    .paths
                    .assign_handshake_path(&path, &remote_cids, *packet.scid())
                {
                    components
                        .parameters
                        .lock_guard()?
                        .initial_scid_from_peer_need_equal(*packet.scid())?;
                }

                // See [RFC 9000 section 8.1](https://www.rfc-editor.org/rfc/rfc9000.html#name-address-validation-during-c)
                // A server might wish to validate the client address before starting the cryptographic handshake.
                // QUIC uses a token in the Initial packet to provide address validation prior to completing the handshake.
                // This token is delivered to the client during connection establishment with a Retry packet (see Section 8.1.2)
                // or in a previous connection using the NEW_TOKEN frame (see Section 8.1.3).
                if !packet.token().is_empty() {
                    validate(packet.token(), &path);
                }
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

pub struct InitialTracker {
    journal: InitialJournal,
    crypto_stream: CryptoStream,
}

impl Feedback for InitialTracker {
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
                    packet_type: PacketType::Initial,
                    packet_number: pn
                },
                frames: may_lost_frames,
                trigger
            });
        }
    }
}

impl PacketSpace<InitialHeader> for InitialSpace {
    type PacketAssembler<'a> = TrivialPacketWriter<'a, 'a, CryptoFrame>;

    #[inline]
    fn new_packet<'a>(
        &'a self,
        header: InitialHeader,
        buffer: &'a mut [u8],
    ) -> Result<Self::PacketAssembler<'a>, Signals> {
        let keys = self.keys.get_local_keys().ok_or(Signals::KEYS)?;
        TrivialPacketWriter::new_long(header, buffer, keys.local, self.journal.as_ref())
    }
}

impl InitialSpace {
    pub fn recv_packet(&self, packet: CipherInitialPacket) -> Option<ConnectionCloseFrame> {
        // TOOD: improve Keys
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
}

pub fn spawn_deliver_and_parse_closing(
    packets: BoundQueue<ReceivedFrom>,
    space: Arc<InitialSpace>,
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
