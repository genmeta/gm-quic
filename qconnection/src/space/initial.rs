use std::{
    ops::Deref,
    sync::{Arc, Mutex},
};

use bytes::BufMut;
use qbase::{
    Epoch,
    cid::ConnectionId,
    error::{Error, QuicError},
    frame::{ConnectionCloseFrame, Frame, FrameReader},
    net::{
        address::BindAddr,
        route::{Link, Pathway},
        tx::{ArcSendWakers, Signals},
    },
    packet::{
        FinalPacketLayout, MarshalFrame, PacketContains, PacketWriter,
        header::{
            GetDcid, GetScid, GetType,
            long::{InitialHeader, io::LongHeaderBuilder},
        },
        keys::ArcKeys,
        number::PacketNumber,
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
use qinterface::packet::{CipherPacket, PlainPacket};
use qrecovery::{crypto::CryptoStream, journal::ArcRcvdJournal};
use rustls::quic::Keys;
use tokio::sync::mpsc;
use tracing::Instrument as _;

use super::{AckInitialSpace, pipe};
use crate::{
    Components, InitialJournal,
    events::{ArcEventBroker, EmitEvent, Event},
    path::Path,
    termination::Terminator,
    tx::{PacketBuffer, PaddablePacket, Transaction},
};

pub type CipherInitialPacket = CipherPacket<InitialHeader>;
pub type PlainInitialPacket = PlainPacket<InitialHeader>;
pub type ReceivedFrom = (BindAddr, CipherInitialPacket, Pathway, Link);

pub struct InitialSpace {
    keys: ArcKeys,
    crypto_stream: CryptoStream,
    token: Mutex<Vec<u8>>,
    journal: InitialJournal,
}

impl InitialSpace {
    // Initial keys应该是预先知道的，或者传入dcid，可以构造出来
    pub fn new(keys: rustls::quic::Keys, token: Vec<u8>, tx_wakers: ArcSendWakers) -> Self {
        let journal = InitialJournal::with_capacity(16, None);
        let crypto_stream = CryptoStream::new(4096, 4096, tx_wakers);

        Self {
            token: Mutex::new(token),
            keys: ArcKeys::with_keys(keys),
            journal,
            crypto_stream,
        }
    }

    pub fn keys(&self) -> ArcKeys {
        self.keys.clone()
    }

    pub fn crypto_stream(&self) -> &CryptoStream {
        &self.crypto_stream
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

    pub fn try_assemble_initial_packet(
        &self,
        tx: &mut Transaction<'_>,
        buf: &mut [u8],
    ) -> Result<(PaddablePacket, Option<u64>), Signals> {
        let keys = self.keys.get_local_keys().ok_or(Signals::KEYS)?;
        let sent_journal = self.journal.of_sent_packets();
        let need_ack = tx.need_ack(Epoch::Initial);
        let (retran_timeout, expire_timeout) = tx.retransmit_and_expire_time(Epoch::Initial);
        let mut packet = PacketBuffer::new_long(
            LongHeaderBuilder::with_cid(tx.dcid(), tx.scid())
                .initial(self.token.lock().unwrap().clone()),
            buf,
            keys,
            &sent_journal,
        )?;

        let mut signals = Signals::empty();

        let ack = need_ack
            .or_else(|| {
                let rcvd_journal = self.journal.of_rcvd_packets();
                rcvd_journal.trigger_ack_frame()
            })
            .ok_or(Signals::TRANSPORT)
            .and_then(|(largest, rcvd_time)| {
                let rcvd_journal = self.journal.of_rcvd_packets();
                let ack_frame = rcvd_journal.gen_ack_frame_util(
                    packet.pn(),
                    largest,
                    rcvd_time,
                    packet.remaining_mut(),
                )?;
                packet.dump_ack_frame(ack_frame);
                Ok(largest)
            })
            .map_err(|s| signals |= s)
            .ok();

        _ = self
            .crypto_stream
            .outgoing()
            .try_load_data_into(&mut packet)
            .map_err(|s| signals |= s);

        Ok((
            packet
                .prepare_with_time(retran_timeout, expire_timeout)
                .map_err(|_| signals)?,
            ack,
        ))
    }

    pub fn try_assemble_ping_packet(
        &self,
        tx: &mut Transaction<'_>,
        buf: &mut [u8],
    ) -> Result<PaddablePacket, Signals> {
        let keys = self.keys.get_local_keys().ok_or(Signals::KEYS)?;
        let (retran_timeout, expire_timeout) = tx.retransmit_and_expire_time(Epoch::Handshake);
        let sent_journal = self.journal.of_sent_packets();
        let mut packet = PacketBuffer::new_long(
            LongHeaderBuilder::with_cid(tx.dcid(), tx.scid())
                .initial(self.token.lock().unwrap().clone()),
            buf,
            keys,
            &sent_journal,
        )?;

        packet.dump_ping_frame();

        packet
            .prepare_with_time(retran_timeout, expire_timeout)
            .map_err(|_| unreachable!("packet is not empty"))
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
        space.crypto_stream.incoming(),
        event_broker.clone(),
    );
    pipe(
        rcvd_ack_frames,
        AckInitialSpace::new(&space.journal, &space.crypto_stream),
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
        let tls_session = components.tls_session.clone();
        let token_registry = components.token_registry.clone();
        move |initial_token: &[u8], path: &Path| {
            if let TokenRegistry::Server(provider) = token_registry.deref() {
                if let Some(server_name) = tls_session.server_name() {
                    if provider.verify_token(server_name, initial_token) {
                        path.grant_anti_amplification();
                    }
                }
            }
        }
    };

    let components = components.clone();
    let role = components.handshake.role();
    let conn_state = components.conn_state.clone();
    let remote_cids = components.cid_registry.remote.clone();
    let deliver_and_parse = async move {
        while let Some((bind_addr, packet, pathway, link)) = packets.recv().await {
            let parse = async {
                let _qlog_span = qevent::span!(@current, path=pathway.to_string()).enter();
                // rfc9000 7.2:
                // if subsequent Initial packets include a different Source Connection ID, they MUST be discarded. This avoids
                // unpredictable outcomes that might otherwise result from stateless processing of multiple Initial packets
                // with different Source Connection IDs.
                if components
                    .parameters
                    .initial_scid_from_peer()?
                    .is_some_and(|scid| scid != *packet.scid())
                {
                    packet.drop_on_scid_unmatch();
                    return Ok(());
                }

                if let Some(packet) = space.decrypt_packet(packet).await.transpose()? {
                    let path =
                        match components.get_or_try_create_path(bind_addr, link, pathway, true) {
                            Ok(path) => path,
                            Err(_) => {
                                packet.drop_on_conenction_closed();
                                return Ok(());
                            }
                        };

                    let mut frames = QuicFramesCollector::<PacketReceived>::new();
                    let packet_contains = FrameReader::new(packet.body(), packet.get_type())
                        .try_fold(PacketContains::default(), |packet_contains, frame| {
                            let (frame, frame_type) = frame?;
                            frames.extend(Some(&frame));
                            dispatch_frame(frame, &path);
                            Result::<_, QuicError>::Ok(packet_contains.include(frame_type))
                        })?;
                    packet.log_received(frames);

                    space.journal.of_rcvd_packets().register_pn(
                        packet.pn(),
                        packet_contains != PacketContains::NonAckEliciting,
                        path.cc().get_pto(Epoch::Initial),
                    );
                    path.on_packet_rcvd(
                        Epoch::Initial,
                        packet.pn(),
                        packet.size(),
                        packet_contains,
                    );
                    if components.parameters.initial_scid_from_peer()?.is_none() {
                        remote_cids.revise_initial_dcid(*packet.scid());
                        components
                            .parameters
                            .initial_scid_from_peer_need_equal(*packet.scid());
                    }
                    // See [RFC 9000 section 8.1](https://www.rfc-editor.org/rfc/rfc9000.html#name-address-validation-during-c)
                    // A server might wish to validate the client address before starting the cryptographic handshake.
                    // QUIC uses a token in the Initial packet to provide address validation prior to completing the handshake.
                    // This token is delivered to the client during connection establishment with a Retry packet (see Section 8.1.2)
                    // or in a previous connection using the NEW_TOKEN frame (see Section 8.1.3).
                    if !packet.token().is_empty() {
                        validate(packet.token(), &path);
                    }

                    // the origin dcid doesnot own a sequences number, so remove its router entry after the connection id
                    // negotiating done.
                    // https://www.rfc-editor.org/rfc/rfc9000.html#name-negotiating-connection-ids
                    if role == qbase::sid::Role::Server {
                        let origin_dcid = components.parameters.get_origin_dcid()?;
                        if origin_dcid != *packet.dcid() {
                            components.router.remove(&origin_dcid.into());
                        }
                    }
                }
                Result::<(), Error>::Ok(())
            };

            if let Err(Error::Quic(error)) = parse.await {
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

impl Feedback for InitialSpace {
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

#[derive(Clone)]
pub struct ClosingInitialSpace {
    rcvd_journal: ArcRcvdJournal,
    ccf_packet_pn: (u64, PacketNumber),
    keys: Arc<Keys>,
}

impl InitialSpace {
    pub fn close(&self) -> Option<ClosingInitialSpace> {
        let keys = self.keys.invalid()?;
        let sent_journal = self.journal.of_sent_packets();
        let new_packet_guard = sent_journal.new_packet();
        let ccf_packet_pn = new_packet_guard.pn();
        let rcvd_journal = self.journal.of_rcvd_packets();
        Some(ClosingInitialSpace {
            rcvd_journal,
            ccf_packet_pn,
            keys,
        })
    }
}

impl ClosingInitialSpace {
    pub fn recv_packet(&self, packet: CipherInitialPacket) -> Option<ConnectionCloseFrame> {
        let packet = packet
            .decrypt_long_packet(
                self.keys.remote.header.as_ref(),
                self.keys.remote.packet.as_ref(),
                |pn| self.rcvd_journal.decode_pn(pn),
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

    pub fn try_assemble_ccf_packet(
        &self,
        scid: ConnectionId,
        dcid: ConnectionId,
        ccf: &ConnectionCloseFrame,
        buf: &mut [u8],
    ) -> Option<FinalPacketLayout> {
        let header = LongHeaderBuilder::with_cid(dcid, scid).initial(vec![]);
        let pn = self.ccf_packet_pn;
        let mut packet_writer = PacketWriter::new_long(&header, buf, pn, self.keys.clone()).ok()?;

        let ccf = match ccf.clone() {
            ConnectionCloseFrame::App(mut app_close_frame) => {
                app_close_frame.conceal();
                ConnectionCloseFrame::App(app_close_frame)
            }
            ccf @ ConnectionCloseFrame::Quic(_) => ccf,
        };

        packet_writer.dump_frame(ccf);

        Some(packet_writer.encrypt_and_protect())
    }
}

pub fn spawn_deliver_and_parse_closing(
    packets: BoundQueue<ReceivedFrom>,
    space: ClosingInitialSpace,
    terminator: Arc<Terminator>,
    event_broker: ArcEventBroker,
) {
    tokio::spawn(
        async move {
            while let Some((_, packet, pathway, _socket)) = packets.recv().await {
                if let Some(ccf) = space.recv_packet(packet) {
                    event_broker.emit(Event::Closed(ccf.clone()));
                    return;
                }
                if terminator.should_send() {
                    _ = terminator
                        .try_send_with(pathway, |buf, scid, dcid, ccf| {
                            space
                                .try_assemble_ccf_packet(scid?, dcid?, ccf, buf)
                                .map(|layout| layout.sent_bytes())
                        })
                        .await;
                }
            }
        }
        .instrument_in_current()
        .in_current_span(),
    );
}
