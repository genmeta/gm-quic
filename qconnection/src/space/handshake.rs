use std::sync::Arc;

use bytes::BufMut;
use futures::{Stream, StreamExt};
use qbase::{
    Epoch,
    cid::ConnectionId,
    error::Error,
    frame::{ConnectionCloseFrame, Frame, FrameReader},
    net::{
        route::{Link, Pathway},
        tx::{ArcSendWakers, Signals},
    },
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
        PacketHeader, PacketType, QuicFramesCollector,
        recovery::{PacketLost, PacketLostTrigger},
        transport::PacketReceived,
    },
    telemetry::Instrument,
};
use qrecovery::{
    crypto::CryptoStream,
    journal::{ArcRcvdJournal, HandshakeJournal},
};
use rustls::quic::Keys;
use tokio::sync::mpsc;
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
}

impl HandshakeSpace {
    pub fn new(tx_wakers: ArcSendWakers) -> Self {
        Self {
            keys: ArcKeys::new_pending(),
            crypto_stream: CryptoStream::new(4096, 4096, tx_wakers),
            journal: HandshakeJournal::with_capacity(16),
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
    ) -> Result<(MiddleAssembledPacket, Option<u64>), Signals> {
        let keys = self.keys.get_local_keys().ok_or(Signals::KEYS)?;
        let sent_journal = self.journal.of_sent_packets();
        let header = LongHeaderBuilder::with_cid(tx.dcid(), tx.scid()).handshake();
        let need_ack = tx.need_ack(Epoch::Handshake);
        let mut packet = PacketMemory::new_long(header, buf, keys, &sent_journal)?;

        let mut signals = Signals::empty();

        let ack = need_ack
            .ok_or(Signals::TRANSPORT)
            .and_then(|(largest, rcvd_time)| {
                let rcvd_journal = self.journal.of_rcvd_packets();
                let ack_frame =
                    rcvd_journal.gen_ack_frame_util(largest, rcvd_time, packet.remaining_mut())?;
                packet.dump_ack_frame(ack_frame);
                Ok(largest)
            })
            .inspect_err(|s| signals |= *s)
            .ok();

        _ = self
            .crypto_stream
            .outgoing()
            .try_load_data_into(&mut packet)
            .inspect_err(|s| signals |= *s);

        Ok((packet.interrupt().map_err(|_| signals)?, ack))
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
                path.cc().on_ack(Epoch::Handshake, &f);
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
        if let Some(packet) = space.decrypt_packet(packet).await.transpose()? {
            let path = match components.get_or_try_create_path(socket, pathway, true) {
                Some(path) => path,
                None => {
                    packet.drop_on_conenction_closed();
                    return Ok(());
                }
            };
            // See [RFC 9000 section 8.1](https://www.rfc-editor.org/rfc/rfc9000.html#name-address-validation-during-c)
            // Once an endpoint has successfully processed a Handshake packet from the peer, it can consider the peer
            // address to have been validated.
            // It may have already been verified using tokens in the Handshake space
            path.grant_anti_amplifier();
            path.on_rcvd(packet.plain.len());

            let mut frames = QuicFramesCollector::<PacketReceived>::new();

            let is_ack_packet = FrameReader::new(packet.body(), packet.header.get_type())
                .try_fold(false, |is_ack_packet, frame| {
                    let (frame, is_ack_eliciting) = frame?;
                    frames.extend(Some(&frame));
                    dispatch_frame(frame, &path);
                    Result::<bool, Error>::Ok(is_ack_packet || is_ack_eliciting)
                })?;

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
                if let Some(origin_dcid) = parameters
                    .server()
                    .map(|local_params| local_params.original_destination_connection_id())
                {
                    if origin_dcid != *packet.header.dcid() {
                        components.proto.del_router_entry(&origin_dcid.into());
                    }
                }
            }
            packet.emit_received(frames);
        }

        Result::<(), Error>::Ok(())
    };

    tokio::spawn(
        async move {
            while let Some((packet, pathway, socket)) = bundles.next().await {
                if let Err(error) = parse(packet.into(), pathway, socket).await {
                    event_broker.emit(Event::Failed(error));
                };
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
            let mut may_lost_frames = QuicFramesCollector::<PacketLost>::new();
            for frame in rotate.may_loss_pkt(pn) {
                // for this convert, empty bytes indicates the raw info is not available
                may_lost_frames.extend(Some(&Frame::Crypto(frame, bytes::Bytes::new())));
                outgoing.may_loss_data(&frame);
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

    fn drain_to(&self, pn: u64) {
        self.journal.of_rcvd_packets().drain_to(pn);
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

        let mut frames = QuicFramesCollector::<PacketReceived>::new();
        let ccf = FrameReader::new(packet.body(), packet.header.get_type())
            .filter_map(Result::ok)
            .inspect(|(f, _ack)| frames.extend(Some(f)))
            .fold(None, |ccf, (frame, _)| match (ccf, frame) {
                (ccf @ Some(..), _) => ccf,
                (None, Frame::Close(ccf)) => Some(ccf),
                (None, _) => None,
            });
        packet.emit_received(frames);
        ccf
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
        let mut packet_writer = PacketWriter::new_long(&header, buf, pn, self.keys.clone()).ok()?;

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
        .instrument_in_current()
        .in_current_span(),
    );
}
