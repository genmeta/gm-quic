use std::sync::Arc;

use bytes::BufMut;
use futures::{Stream, StreamExt};
use qbase::{
    Epoch,
    cid::ConnectionId,
    error::Error,
    frame::{ConnectionCloseFrame, Frame, FrameReader},
    net::{Link, Pathway},
    packet::{
        CipherPacket, MarshalFrame, PacketWriter,
        header::{
            GetDcid, GetType,
            long::{HandshakeHeader, io::LongHeaderBuilder},
        },
        keys::ArcKeys,
        number::PacketNumber,
    },
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
    journal::{ArcRcvdJournal, HandshakeJournal},
};
use rustls::quic::Keys;
use tokio::sync::{Notify, mpsc};
use tracing::Instrument as _;

use super::{AckHandshake, PlainPacket, ReceivedCipherPacket};
use crate::{
    Components,
    events::{ArcEventBroker, EmitEvent, Event},
    path::Path,
    space::pipe,
    termination::ClosingState,
    tx::{MiddleAssembledPacket, PacketMemory, Transaction},
};

pub type ReceivedBundle = ((HandshakeHeader, bytes::BytesMut, usize), Pathway, Link);
pub type ReceiveHanshakePacket = ReceivedCipherPacket<HandshakeHeader>;
pub type PlainHandshakePacket = PlainPacket<HandshakeHeader>;

pub struct HandshakeSpace {
    keys: ArcKeys,
    crypto_stream: CryptoStream,
    journal: HandshakeJournal,
    sendable: Arc<Notify>,
}

impl HandshakeSpace {
    pub fn new(sendable: Arc<Notify>) -> Self {
        Self {
            keys: ArcKeys::new_pending(),
            crypto_stream: CryptoStream::new(4096, 4096),
            journal: HandshakeJournal::with_capacity(16),
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
        packet: ReceiveHanshakePacket,
    ) -> Option<Result<PlainHandshakePacket, Error>> {
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
        let header = LongHeaderBuilder::with_cid(tx.dcid(), tx.scid()).handshake();
        let need_ack = tx.need_ack(Epoch::Handshake);
        let mut packet = PacketMemory::new_long(header, buf, keys, &sent_journal)?;

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

        // TODO: 可以封装在CryptoStream中，当成一个函数
        //      crypto_stream.try_load_data_into(&mut packet);
        let crypto_stream_outgoing = self.crypto_stream.outgoing();
        crypto_stream_outgoing.try_load_data_into(&mut packet);

        Some((packet.interrupt()?, ack))
    }
}

pub fn spawn_deliver_and_parse(
    mut bundles: impl Stream<Item = ReceivedBundle> + Unpin + Send + 'static,
    space: Arc<HandshakeSpace>,
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
        AckHandshake::new(&space.journal, &space.crypto_stream),
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

    let components = components.clone();
    let role = components.handshake.role();
    let parameters = components.parameters.clone();
    let parse = async move |packet: ReceiveHanshakePacket, pathway, socket| {
        match space.decrypt_packet(packet).await {
            Some(Ok(packet)) => {
                let path = match components.get_or_create_path(socket, pathway, true) {
                    Some(path) => path,
                    None => {
                        packet.drop_on_conenction_closed();
                        return;
                    }
                };
                // See [RFC 9000 section 8.1](https://www.rfc-editor.org/rfc/rfc9000.html#name-address-validation-during-c)
                // Once an endpoint has successfully processed a Handshake packet from the peer, it can consider the peer
                // address to have been validated.
                // It may have already been verified using tokens in the Handshake space
                path.grant_anti_amplifier();
                path.on_rcvd(packet.plain.len());

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
                            .on_pkt_rcvd(Epoch::Handshake, packet.decoded_pn, is_ack_packet);

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
            while let Some((packet, pathway, socket)) = bundles.next().await {
                parse(packet.into(), pathway, socket).await;
            }
        }
        .instrument_in_current()
        .in_current_span(),
    );
}

impl TrackPackets for HandshakeSpace {
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
                    packet_type: PacketType::Handshake,
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
pub struct ClosingHandshakeSpace {
    rcvd_journal: ArcRcvdJournal,
    ccf_packet_pn: (u64, PacketNumber),
    keys: Arc<Keys>,
}

impl HandshakeSpace {
    pub fn close(&self) -> Option<ClosingHandshakeSpace> {
        let keys = self.keys.invalid()?;
        let sent_journal = self.journal.of_sent_packets();
        let new_packet_guard = sent_journal.new_packet();
        let ccf_packet_pn = new_packet_guard.pn();
        let rcvd_journal = self.journal.of_rcvd_packets();
        Some(ClosingHandshakeSpace {
            rcvd_journal,
            ccf_packet_pn,
            keys,
        })
    }
}

impl ClosingHandshakeSpace {
    pub fn recv_packet(&self, packet: ReceiveHanshakePacket) -> Option<ConnectionCloseFrame> {
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
    mut bundles: impl Stream<Item = ReceivedBundle> + Unpin + Send + 'static,
    space: ClosingHandshakeSpace,
    closing_state: Arc<ClosingState>,
    event_broker: ArcEventBroker,
) {
    tokio::spawn(
        async move {
            while let Some((packet, pathway, _socket)) = bundles.next().await {
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
