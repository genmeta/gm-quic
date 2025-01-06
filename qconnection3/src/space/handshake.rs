use std::sync::Arc;

use bytes::BufMut;
use futures::{channel::mpsc, Stream, StreamExt};
use qbase::{
    cid::ConnectionId,
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
use qrecovery::{
    crypto::{CryptoStream, CryptoStreamOutgoing},
    journal::{ArcRcvdJournal, HandshakeJournal},
};
use rustls::quic::Keys;
use tokio::task::JoinHandle;

use super::try_join2;
use crate::{
    events::{EmitEvent, Event},
    path::{ArcPaths, Path, Pathway},
    space::{pipe, AckHandshake},
    tx::{PacketMemory, Transaction},
};

pub type HandshakePacket = (HandshakeHeader, bytes::BytesMut, usize);

#[derive(Clone)]
pub struct HandshakeSpace {
    pub keys: ArcKeys,
    pub crypto_stream: CryptoStream,
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

    pub fn build(
        &self,
        rcvd_packets: impl Stream<Item = (HandshakePacket, Pathway)> + Unpin + Send + 'static,
        paths: &ArcPaths,
        broker: impl EmitEvent + Clone + Send + 'static,
    ) -> JoinHandle<()> {
        let (crypto_frames_entry, rcvd_crypto_frames) = mpsc::unbounded();
        let (ack_frames_entry, rcvd_ack_frames) = mpsc::unbounded();

        let dispatch_frame = {
            let broker = broker.clone();
            move |frame: Frame, path: &Path| match frame {
                Frame::Ack(f) => {
                    path.cc().on_ack(Epoch::Handshake, &f);
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

        self.parse_rcvd_packets_and_dispatch_frames(rcvd_packets, paths, dispatch_frame, broker)
    }

    fn parse_rcvd_packets_and_dispatch_frames(
        &self,
        mut rcvd_packets: impl Stream<Item = (HandshakePacket, Pathway)> + Unpin + Send + 'static,
        paths: &ArcPaths,
        dispatch_frame: impl Fn(Frame, &Path) + Send + 'static,
        broker: impl EmitEvent + Clone + Send + 'static,
    ) -> JoinHandle<()> {
        let paths = paths.clone();
        tokio::spawn({
            let rcvd_journal = self.journal.of_rcvd_packets();
            let keys = self.keys.clone();
            async move {
                while let Some((((header, mut bytes, offset), pathway), keys)) =
                    try_join2(rcvd_packets.next(), keys.get_remote_keys()).await
                {
                    let Some(path) = paths.get(&pathway) else {
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
                    // It may have already been verified using tokens in the Handshake space
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

    pub fn tracker(&self) -> HandshakeTracker {
        HandshakeTracker {
            journal: self.journal.clone(),
            outgoing: self.crypto_stream.outgoing().clone(),
        }
    }
}

#[derive(Clone)]
pub struct HandshakeTracker {
    journal: HandshakeJournal,
    outgoing: CryptoStreamOutgoing,
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
    pub fn close(self) -> Option<ClosingHandshakeSpace> {
        let keys = self.keys.get_local_keys()?;
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
    pub fn deliver(
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
