use std::sync::Arc;

use bytes::BufMut;
use futures::{channel::mpsc, Stream, StreamExt};
use qbase::{
    cid::ConnectionId,
    frame::{io::WriteFrame, ConnectionCloseFrame, Frame, FrameReader},
    packet::{
        decrypt::{decrypt_packet, remove_protection_of_long_packet},
        encrypt::{encode_long_first_byte, encrypt_packet, protect_header},
        header::{
            io::WriteHeader,
            long::{io::LongHeaderBuilder, HandshakeHeader},
            EncodeHeader, GetType,
        },
        keys::ArcKeys,
        number::WritePacketNumber,
        DataPacket, MiddleAssembledPacket, PacketNumber, PacketWriter,
    },
    varint::{EncodeBytes, VarInt, WriteVarInt},
    Epoch,
};
use qcongestion::{CongestionControl, TrackPackets, MSS};
use qrecovery::{
    crypto::{CryptoStream, CryptoStreamOutgoing},
    journal::{ArcRcvdJournal, HandshakeJournal},
};
use tokio::task::JoinHandle;

use super::try_join2;
use crate::{
    events::{EmitEvent, Event},
    path::{Path, Paths, Pathway},
    space::{pipe, AckHandshake},
    tx::{PacketMemory, Transaction},
};

pub type HandshakePacket = (HandshakeHeader, bytes::BytesMut, usize);

#[derive(Clone)]
pub struct HandshakeSpace {
    pub keys: ArcKeys,
    pub journal: HandshakeJournal,
    pub crypto_stream: CryptoStream,
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
    pub fn build(
        &self,
        rcvd_packets: impl Stream<Item = (HandshakePacket, Pathway)> + Unpin + Send + 'static,
        pathes: &Arc<Paths>,
        broker: impl EmitEvent + Clone + Send + 'static,
    ) -> JoinHandle<()> {
        let (crypto_frames_entry, rcvd_crypto_frames) = mpsc::unbounded();
        let (ack_frames_entry, rcvd_ack_frames) = mpsc::unbounded();

        let dispatch_frame = {
            let broker = broker.clone();
            move |frame: Frame, path: &Path| match frame {
                Frame::Ack(f) => {
                    path.cc().on_ack(Epoch::Initial, &f);
                    _ = ack_frames_entry.unbounded_send(f);
                }
                Frame::Close(f) => broker.emit(Event::Closed(f)),
                Frame::Crypto(f, bytes) => _ = crypto_frames_entry.unbounded_send((f, bytes)),
                Frame::Padding(_) | Frame::Ping(_) => {}
                _ => unreachable!("unexpected frame: {:?} in handshake packet", frame),
            }
        };

        pipe(
            rcvd_crypto_frames,
            self.crypto_stream.incoming(),
            broker.clone(),
        );
        pipe(
            rcvd_ack_frames,
            AckHandshake::new(&self.journal, &self.crypto_stream),
            broker.clone(),
        );

        self.parse_rcvd_packets_and_dispatch_frames(rcvd_packets, pathes, dispatch_frame, broker)
    }

    fn parse_rcvd_packets_and_dispatch_frames(
        &self,
        mut rcvd_packets: impl Stream<Item = (HandshakePacket, Pathway)> + Unpin + Send + 'static,
        pathes: &Arc<Paths>,
        dispatch_frame: impl Fn(Frame, &Path) + Send + 'static,
        broker: impl EmitEvent + Clone + Send + 'static,
    ) -> JoinHandle<()> {
        let pathes = pathes.clone();
        tokio::spawn({
            let rcvd_journal = self.journal.of_rcvd_packets();
            let keys = self.keys.clone();
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

                    // See [RFC 9000 section 8.1](https://www.rfc-editor.org/rfc/rfc9000.html#name-address-validation-during-c)
                    // Once an endpoint has successfully processed a Handshake packet from the peer, it can consider the peer
                    // address to have been validated.
                    // It may have already been verified using tokens in the Initial space
                    path.grant_anti_amplifier();

                    match FrameReader::new(bytes.freeze(), header.get_type()).try_fold(
                        false,
                        |is_ack_packet, frame| {
                            let (frame, is_ack_eliciting) = frame?;
                            dispatch_frame(frame, &path);
                            Ok(is_ack_packet || is_ack_eliciting)
                        },
                    ) {
                        Ok(is_ack_packet) => {
                            rcvd_journal.register_pn(pn);
                            path.cc().on_pkt_rcvd(Epoch::Handshake, pn, is_ack_packet);
                        }
                        Err(e) => broker.emit(Event::Failed(e)),
                    }
                }
            }
        })
    }

    pub fn try_assemble<'b>(
        &self,
        tx: &mut Transaction<'_>,
        buf: &'b mut [u8],
    ) -> Option<(MiddleAssembledPacket, Option<u64>)> {
        let keys = self.keys.get_local_keys()?;
        let sent_journal = self.journal.of_sent_packets();
        let mut packet = PacketMemory::new_long(
            LongHeaderBuilder::with_cid(tx.dcid(), tx.scid()).handshake(),
            buf,
            keys,
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

        // TODO: 可以封装在CryptoStream中，当成一个函数
        //      crypto_stream.try_load_data_into(&mut packet);
        let crypto_stream_outgoing = self.crypto_stream.outgoing();
        crypto_stream_outgoing.try_load_data_into(&mut packet);

        let packet: PacketWriter<'b> = packet.try_into().ok()?;
        Some((packet.abandon(), ack))
    }
}

#[derive(Clone)]
pub struct ClosingHandshakeScope {
    keys: Arc<rustls::quic::Keys>,
    rcvd_journal: ArcRcvdJournal,
    // 发包时用得着
    next_sending_pn: (u64, PacketNumber),
}

impl ClosingHandshakeScope {
    pub fn assemble_ccf_packet(
        &self,
        buf: &mut [u8; MSS],
        ccf: &ConnectionCloseFrame,
        scid: ConnectionId,
        dcid: ConnectionId,
    ) -> usize {
        let (pk, hk) = (
            self.keys.local.packet.as_ref(),
            self.keys.local.header.as_ref(),
        );

        let hdr = LongHeaderBuilder::with_cid(dcid, scid).handshake();
        let (mut hdr_buf, payload_tag) = buf.split_at_mut(hdr.size() + 2);
        let payload_tag_len = payload_tag.len();
        let tag_len = pk.tag_len();
        let payload_buf = &mut payload_tag[..payload_tag_len - tag_len];

        let (pn, encoded_pn) = self.next_sending_pn;
        let (mut pn_buf, mut body_buf) = payload_buf.split_at_mut(encoded_pn.size());

        let body_size = body_buf.remaining_mut();
        body_buf.put_frame(ccf);
        let mut body_len = body_size - body_buf.remaining_mut();

        let hdr_len = hdr_buf.len();
        let pn_len = pn_buf.len();
        if pn_len + body_len + tag_len < 20 {
            let padding_len = 20 - pn_len - body_len - tag_len;
            body_buf.put_bytes(0, padding_len);
            body_len += padding_len;
        }
        let pkt_size = hdr_len + pn_len + body_len + tag_len;

        hdr_buf.put_header(&hdr);
        hdr_buf.encode_varint(
            &VarInt::try_from(pn_len + body_len + tag_len).unwrap(),
            EncodeBytes::Two,
        );
        pn_buf.put_packet_number(encoded_pn);

        encode_long_first_byte(&mut buf[0], pn_len);
        encrypt_packet(pk, pn, &mut buf[..pkt_size], hdr_len + pn_len);
        protect_header(hk, &mut buf[..pkt_size], hdr_len, pn_len);

        pkt_size
    }
}

impl TryFrom<HandshakeSpace> for ClosingHandshakeScope {
    type Error = ();

    fn try_from(hs: HandshakeSpace) -> Result<Self, Self::Error> {
        let Some(keys) = hs.keys.invalid() else {
            return Err(());
        };
        let rcvd_journal = hs.journal.of_rcvd_packets();
        let next_sending_pn = hs.journal.of_sent_packets().new_packet().pn();

        Ok(Self {
            keys,
            rcvd_journal,
            next_sending_pn,
        })
    }
}

impl super::RecvPacket for ClosingHandshakeScope {
    fn has_rcvd_ccf(&self, mut packet: DataPacket) -> bool {
        let undecoded_pn = match remove_protection_of_long_packet(
            self.keys.remote.header.as_ref(),
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
        Self::decrypt_and_parse(self.keys.remote.packet.as_ref(), pn, packet, body_offset)
    }
}

#[derive(Clone)]
pub struct HandshakeTracker {
    journal: HandshakeJournal,
    outgoing: CryptoStreamOutgoing,
}

impl HandshakeTracker {
    pub fn new(journal: HandshakeJournal, outgoing: CryptoStreamOutgoing) -> Self {
        Self { journal, outgoing }
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