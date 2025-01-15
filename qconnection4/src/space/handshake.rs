use std::{ops::Deref, sync::Arc};

use bytes::BufMut;
use futures::{Stream, StreamExt};
use qbase::{
    cid::ConnectionId,
    error::Error,
    frame::{ConnectionCloseFrame, Frame, FrameReader},
    packet::{
        decrypt::{decrypt_packet, remove_protection_of_long_packet},
        header::{
            long::{io::LongHeaderBuilder, HandshakeHeader},
            GetType,
        },
        keys::ArcKeys,
        number::PacketNumber,
        AssembledPacket, MarshalFrame, MiddleAssembledPacket, PacketWriter,
    },
    Epoch,
};
use qcongestion::{CongestionControl, TrackPackets};
use qinterface::{closing::ClosingInterface, path::Pathway};
use qrecovery::{
    crypto::{CryptoStream, CryptoStreamOutgoing},
    journal::{ArcRcvdJournal, HandshakeJournal},
};
use rustls::quic::Keys;
use tokio::sync::mpsc;

use super::{AckHandshake, DecryptedPacket};
use crate::{
    events::{EmitEvent, Event},
    path::Path,
    space::pipe,
    tx::{PacketMemory, Transaction},
    Components,
};

pub type HandshakePacket = (HandshakeHeader, bytes::BytesMut, usize);
pub type DecryptedHandshakePacket = DecryptedPacket<HandshakeHeader>;

pub struct HandshakeSpace {
    keys: ArcKeys,
    crypto_stream: CryptoStream,
    journal: HandshakeJournal,
}

impl Default for HandshakeSpace {
    fn default() -> Self {
        Self {
            keys: ArcKeys::new_pending(),
            journal: HandshakeJournal::with_capacity(16),
            crypto_stream: CryptoStream::new(4096, 4096),
        }
    }
}

impl HandshakeSpace {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn keys(&self) -> ArcKeys {
        self.keys.clone()
    }

    pub fn crypto_stream(&self) -> &CryptoStream {
        &self.crypto_stream
    }

    pub async fn decrypt_packet(
        &self,
        (header, mut payload, offset): HandshakePacket,
    ) -> Option<Result<DecryptedHandshakePacket, Error>> {
        let keys = self.keys.get_remote_keys().await?;
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

    pub fn try_assemble<'b>(
        &self,
        tx: &mut Transaction<'_>,
        buf: &'b mut [u8],
    ) -> Option<(MiddleAssembledPacket, Option<u64>)> {
        let keys = self.keys.get_local_keys()?;
        let sent_journal = self.journal.of_sent_packets();
        let header = LongHeaderBuilder::with_cid(tx.dcid(), tx.scid()).handshake();
        let mut packet = PacketMemory::new_long(header, buf, keys, &sent_journal)?;

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

        // TODO: 可以封装在CryptoStream中，当成一个函数
        //      crypto_stream.try_load_data_into(&mut packet);
        let crypto_stream_outgoing = self.crypto_stream.outgoing();
        crypto_stream_outgoing.try_load_data_into(&mut packet);

        let packet: PacketWriter<'b> = packet.try_into().ok()?;
        Some((packet.abandon(), ack))
    }
}

pub fn launch_deliver_and_parse(
    mut packets: impl Stream<Item = (HandshakePacket, Pathway)> + Unpin + Send + 'static,
    space: Arc<HandshakeSpace>,
    components: &Components,
    event_broker: impl EmitEvent + Clone + Send + Sync + 'static,
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

    let components = components.clone();
    let role = components.handshake.role();
    let parameters = components.parameters.clone();
    let conn_iface = components.conn_iface.clone();
    tokio::spawn(async move {
        while let Some((packet, pathway)) = packets.next().await {
            let dispatch_frame = |frame: Frame, path: &Path| match frame {
                Frame::Ack(f) => {
                    path.cc().on_ack(Epoch::Handshake, &f);
                    _ = ack_frames_entry.send(f);
                }
                Frame::Close(f) => event_broker.emit(Event::Closed(f)),
                Frame::Crypto(f, bytes) => _ = crypto_frames_entry.send((f, bytes)),
                Frame::Padding(_) | Frame::Ping(_) => {}
                _ => unreachable!("unexpected frame: {:?} in handshake packet", frame),
            };
            let packet_size = packet.1.len();
            match space.decrypt_packet(packet).await {
                Some(Ok(packet)) => {
                    let path = match conn_iface.paths().entry(pathway) {
                        dashmap::Entry::Occupied(path) => path.get().deref().clone(),
                        dashmap::Entry::Vacant(vacant_entry) => {
                            match components.try_create_path(pathway, true) {
                                Some(new_path) => vacant_entry.insert(new_path).clone(),
                                // connection already entered closing or draining state
                                None => continue,
                            }
                        }
                    };
                    // See [RFC 9000 section 8.1](https://www.rfc-editor.org/rfc/rfc9000.html#name-address-validation-during-c)
                    // Once an endpoint has successfully processed a Handshake packet from the peer, it can consider the peer
                    // address to have been validated.
                    // It may have already been verified using tokens in the Handshake space
                    path.grant_anti_amplifier();
                    path.on_rcvd(packet_size);

                    match FrameReader::new(packet.payload, packet.header.get_type()).try_fold(
                        false,
                        |is_ack_packet, frame| {
                            let (frame, is_ack_eliciting) = frame?;
                            dispatch_frame(frame, &path);
                            Result::<bool, Error>::Ok(is_ack_packet || is_ack_eliciting)
                        },
                    ) {
                        Ok(is_ack_packet) => {
                            space.journal.of_rcvd_packets().register_pn(packet.pn);
                            path.cc()
                                .on_pkt_rcvd(Epoch::Handshake, packet.pn, is_ack_packet);

                            // the origin dcid doesnot own a sequences number, so remove its router entry after the connection id
                            // negotiating done.
                            // https://www.rfc-editor.org/rfc/rfc9000.html#name-negotiating-connection-ids
                            if role == qbase::sid::Role::Server {
                                if let Some(origin_dcid) = parameters.server().map(|local_params| {
                                    local_params.original_destination_connection_id()
                                }) {
                                    if origin_dcid != packet.header.dcid {
                                        conn_iface.router_if().unregister(&origin_dcid.into());
                                    }
                                }
                            }
                        }
                        Err(error) => event_broker.emit(Event::Failed(error)),
                    }
                }
                Some(Err(error)) => event_broker.emit(Event::Failed(error)),
                None => continue,
            }
        }
    });
}

#[derive(Clone)]
pub struct HandshakeTracker {
    journal: HandshakeJournal,
    outgoing: CryptoStreamOutgoing,
}

impl TrackPackets for HandshakeSpace {
    fn may_loss(&self, pn: u64) {
        for frame in self.journal.of_sent_packets().rotate().may_loss_pkt(pn) {
            self.crypto_stream.outgoing().may_loss_data(&frame);
        }
    }

    fn retire(&self, pn: u64) {
        self.journal.of_rcvd_packets().write().retire(pn);
    }
}

impl TrackPackets for HandshakeTracker {
    fn may_loss(&self, pn: u64) {
        for frame in self.journal.of_sent_packets().rotate().may_loss_pkt(pn) {
            self.outgoing.may_loss_data(&frame);
        }
    }

    fn retire(&self, pn: u64) {
        self.journal.of_rcvd_packets().write().retire(pn);
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
    pub fn recv_packet(
        &self,
        (header, mut bytes, offset): HandshakePacket,
    ) -> Option<ConnectionCloseFrame> {
        let (hpk, pk) = (
            self.keys.remote.header.as_ref(),
            self.keys.remote.packet.as_ref(),
        );
        let undecoded_pn = remove_protection_of_long_packet(hpk, bytes.as_mut(), offset).ok()??;

        let pn = self.rcvd_journal.decode_pn(undecoded_pn).ok()?;
        let body_offset = offset + undecoded_pn.size();
        let _pkt_len = decrypt_packet(pk, pn, bytes.as_mut(), body_offset).ok()?;

        FrameReader::new(bytes.freeze(), header.get_type())
            .filter_map(Result::ok)
            .find_map(|(f, _ack)| match f {
                Frame::Close(ccf) => Some(ccf),
                _ => None,
            })
    }

    pub fn try_assemble_ccf_packet(
        &self,
        scid: ConnectionId,
        dcid: ConnectionId,
        ccf: &ConnectionCloseFrame,
        buf: &mut [u8],
    ) -> Option<AssembledPacket> {
        let header = LongHeaderBuilder::with_cid(scid, dcid).handshake();
        let pn = self.ccf_packet_pn;
        let mut packet_writer = PacketWriter::new_long(&header, buf, pn, self.keys.clone())?;

        packet_writer.dump_frame(ccf.clone());

        Some(packet_writer.encrypt_and_protect())
    }
}

pub fn launch_deliver_and_parse_closing(
    mut packets: impl Stream<Item = (HandshakePacket, Pathway)> + Unpin + Send + 'static,
    space: ClosingHandshakeSpace,
    closing_iface: Arc<ClosingInterface>,
    event_broker: impl EmitEvent + Clone + Send + 'static,
) {
    tokio::spawn(async move {
        while let Some((packet, pathway)) = packets.next().await {
            if let Some(ccf) = space.recv_packet(packet) {
                event_broker.emit(Event::Closed(ccf.clone()));
                return;
            }
            if closing_iface.should_send() {
                _ = closing_iface
                    .try_send_with(pathway, pathway.dst(), |buf, scid, dcid, ccf| {
                        space
                            .try_assemble_ccf_packet(scid?, dcid?, ccf, buf)
                            .map(|packet| packet.size())
                    })
                    .await;
            }
        }
    });
}
