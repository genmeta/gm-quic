use std::{
    ops::Deref,
    sync::{Arc, Mutex},
};

use bytes::{BufMut, BytesMut};
use futures::{Stream, StreamExt};
use qbase::{
    Epoch,
    cid::ConnectionId,
    error::Error,
    frame::{ConnectionCloseFrame, Frame, FrameReader},
    packet::{
        CipherPacket, MarshalFrame, PacketWriter,
        header::{
            GetDcid, GetScid, GetType,
            long::{InitialHeader, io::LongHeaderBuilder},
        },
        keys::ArcKeys,
        number::PacketNumber,
    },
    token::TokenRegistry,
};
use qcongestion::{CongestionControl, TrackPackets};
use qinterface::path::{Netway, Pathway};
use qlog::{
    quic::{
        PacketHeader, PacketType, QuicFrames,
        recovery::{PacketLost, PacketLostTrigger},
    },
    telemetry::Instrument,
};
use qrecovery::{
    crypto::CryptoStream,
    journal::{ArcRcvdJournal, InitialJournal},
};
use rustls::quic::Keys;
use tokio::sync::{Notify, mpsc};
use tracing::Instrument as _;

use super::{AckInitial, PlainPacket, ReceivedCipherPacket, pipe};
use crate::{
    Components,
    events::{ArcEventBroker, EmitEvent, Event},
    path::Path,
    termination::ClosingState,
    tx::{MiddleAssembledPacket, PacketMemory, Transaction},
};

pub type ReceivedBundle = ((InitialHeader, BytesMut, usize), Pathway, Netway);
pub type ReceivedInitialPacket = ReceivedCipherPacket<InitialHeader>;
pub type PlainInitialPacket = PlainPacket<InitialHeader>;

pub struct InitialSpace {
    keys: ArcKeys,
    crypto_stream: CryptoStream,
    token: Mutex<Vec<u8>>,
    journal: InitialJournal,
    sendable: Arc<Notify>,
}

impl InitialSpace {
    // Initial keys应该是预先知道的，或者传入dcid，可以构造出来
    pub fn new(keys: rustls::quic::Keys, token: Vec<u8>, sendable: Arc<Notify>) -> Self {
        let journal = InitialJournal::with_capacity(16);
        let crypto_stream = CryptoStream::new(4096, 4096);

        Self {
            token: Mutex::new(token),
            keys: ArcKeys::with_keys(keys),
            journal,
            crypto_stream,
            sendable,
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
        packet: ReceivedInitialPacket,
    ) -> Option<Result<PlainInitialPacket, Error>> {
        match self.keys.get_remote_keys().await {
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

    pub fn try_assemble(
        &self,
        tx: &mut Transaction<'_>,
        buf: &mut [u8],
    ) -> Option<(MiddleAssembledPacket, Option<u64>)> {
        let keys = self.keys.get_local_keys()?;
        let sent_journal = self.journal.of_sent_packets();
        let need_ack = tx.need_ack(Epoch::Initial);
        let mut packet = PacketMemory::new_long(
            LongHeaderBuilder::with_cid(tx.dcid(), tx.scid())
                .initial(self.token.lock().unwrap().clone()),
            buf,
            keys,
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

        let crypto_stream_outgoing = self.crypto_stream.outgoing();
        crypto_stream_outgoing.try_load_data_into(&mut packet);

        Some((packet.interrupt()?, ack))
    }
}

pub fn spawn_deliver_and_parse(
    mut packets: impl Stream<Item = ReceivedBundle> + Unpin + Send + 'static,
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
        AckInitial::new(&space.journal, &space.crypto_stream),
        event_broker.clone(),
    );

    let dispatch_frame = {
        let event_broker = event_broker.clone();
        move |frame: Frame, path: &Path| match frame {
            Frame::Ack(f) => {
                path.cc().on_ack(Epoch::Initial, &f);
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
                        path.grant_anti_amplifier();
                    }
                }
            }
        }
    };

    let components = components.clone();
    let role = components.handshake.role();
    let parameters = components.parameters.clone();
    let remote_cids = components.cid_registry.remote.clone();
    let parse = async move |packet: ReceivedInitialPacket, pathway, socket| {
        // rfc9000 7.2:
        // if subsequent Initial packets include a different Source Connection ID, they MUST be discarded. This avoids
        // unpredictable outcomes that might otherwise result from stateless processing of multiple Initial packets
        // with different Source Connection IDs.
        if parameters
            .initial_scid_from_peer()
            .is_some_and(|scid| scid != *packet.header.scid())
        {
            packet.drop_on_scid_unmatch();
            return;
        }
        let packet_size = packet.payload.len();
        match space.decrypt_packet(packet).await {
            Some(Ok(packet)) => {
                let path = match components.get_or_create_path(socket, pathway, true) {
                    Some(path) => path,
                    None => {
                        packet.drop_on_conenction_closed();
                        return;
                    }
                };
                path.on_rcvd(packet_size);

                let mut frames = QuicFrames::new();
                match FrameReader::new(packet.body(), packet.header.get_type()).try_fold(
                    false,
                    |is_ack_packet, frame| {
                        let (frame, is_ack_eliciting) = frame?;
                        frames.extend(Some(&frame));
                        dispatch_frame(frame, &path);
                        Result::<bool, Error>::Ok(is_ack_packet || is_ack_eliciting)
                    },
                ) {
                    Ok(is_ack_packet) => {
                        space
                            .journal
                            .of_rcvd_packets()
                            .register_pn(packet.decoded_pn);
                        path.cc()
                            .on_pkt_rcvd(Epoch::Initial, packet.decoded_pn, is_ack_packet);
                        if parameters.initial_scid_from_peer().is_none() {
                            remote_cids.revise_initial_dcid(*packet.header.scid());
                            parameters.initial_scid_from_peer_need_equal(*packet.header.scid());
                        }
                        // See [RFC 9000 section 8.1](https://www.rfc-editor.org/rfc/rfc9000.html#name-address-validation-during-c)
                        // A server might wish to validate the client address before starting the cryptographic handshake.
                        // QUIC uses a token in the Initial packet to provide address validation prior to completing the handshake.
                        // This token is delivered to the client during connection establishment with a Retry packet (see Section 8.1.2)
                        // or in a previous connection using the NEW_TOKEN frame (see Section 8.1.3).
                        if !packet.header.token().is_empty() {
                            validate(packet.header.token(), &path);
                        }

                        // the origin dcid doesnot own a sequences number, so remove its router entry after the connection id
                        // negotiating done.
                        // https://www.rfc-editor.org/rfc/rfc9000.html#name-negotiating-connection-ids
                        if role == qbase::sid::Role::Server {
                            if let Some(origin_dcid) = parameters.server().map(|local_params| {
                                local_params.original_destination_connection_id()
                            }) {
                                if origin_dcid != *packet.header.dcid() {
                                    components.proto.del_router_entry(&origin_dcid.into());
                                }
                            }
                        }

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
            while let Some((packet, pathway, socket)) = packets.next().await {
                parse(packet.into(), pathway, socket).await;
            }
        }
        .instrument_in_current()
        .in_current_span(),
    );
}

impl TrackPackets for InitialSpace {
    fn may_loss(&self, trigger: PacketLostTrigger, pns: &mut dyn Iterator<Item = u64>) {
        let sent_jornal = self.journal.of_sent_packets();
        let outgoing = self.crypto_stream.outgoing();
        let mut rotate = sent_jornal.rotate();
        for pn in pns {
            let mut may_lost_frames = QuicFrames::new();
            for frame in rotate.may_loss_pkt(pn) {
                // for this convert, empty bytes indicates the raw info is not available
                may_lost_frames.extend(Some(&Frame::Crypto(frame, bytes::Bytes::new())));
                outgoing.may_loss_data(&frame);
                self.sendable.notify_waiters();
            }
            qlog::event!(PacketLost {
                header: PacketHeader {
                    packet_type: PacketType::Initial,
                    packet_number: pn
                },
                frames: may_lost_frames,
                trigger
            });
        }
    }

    fn rotate(&self, pns: &mut dyn Iterator<Item = u64>) {
        self.journal.of_rcvd_packets().rotate(pns);
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
    pub fn recv_packet(&self, packet: ReceivedInitialPacket) -> Option<ConnectionCloseFrame> {
        let packet = packet
            .decrypt_as_long(
                self.keys.remote.header.as_ref(),
                self.keys.remote.packet.as_ref(),
                |pn| self.rcvd_journal.decode_pn(pn),
            )
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
        scid: ConnectionId,
        dcid: ConnectionId,
        ccf: &ConnectionCloseFrame,
        buf: &mut [u8],
    ) -> Option<CipherPacket> {
        let header = LongHeaderBuilder::with_cid(scid, dcid).handshake();
        let pn = self.ccf_packet_pn;
        let mut packet_writer = PacketWriter::new_long(&header, buf, pn, self.keys.clone())?;

        packet_writer.dump_frame(ccf.clone());

        Some(packet_writer.encrypt_and_protect())
    }
}

pub fn spawn_deliver_and_parse_closing(
    mut packets: impl Stream<Item = ReceivedBundle> + Unpin + Send + 'static,
    space: ClosingInitialSpace,
    closing_state: Arc<ClosingState>,
    event_broker: ArcEventBroker,
) {
    tokio::spawn(
        async move {
            while let Some((packet, pathway, _socket)) = packets.next().await {
                if let Some(ccf) = space.recv_packet(packet.into()) {
                    event_broker.emit(Event::Closed(ccf.clone()));
                    return;
                }
                if closing_state.should_send() {
                    _ = closing_state
                        .try_send_with(pathway, |buf, scid, dcid, ccf| {
                            space
                                .try_assemble_ccf_packet(scid?, dcid?, ccf, buf)
                                .map(|packet| packet.size())
                        })
                        .await;
                }
            }
        }
        .instrument_in_current(),
    );
}
