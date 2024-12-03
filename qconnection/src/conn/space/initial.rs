use std::sync::{Arc, Mutex};

use bytes::BufMut;
use futures::{channel::mpsc, StreamExt};
use qbase::{
    frame::{AckFrame, Frame, FrameReader, ReceiveFrame},
    packet::{
        decrypt::{decrypt_packet, remove_protection_of_long_packet},
        header::{long::io::LongHeaderBuilder, GetScid, GetType},
        keys::ArcKeys,
        long, AssembledPacket, DataHeader, PacketWriter,
    },
    Epoch,
};
use qcongestion::{CongestionControl, TrackPackets};
use qrecovery::{
    crypto::{CryptoStream, CryptoStreamOutgoing},
    journal::InitialJournal,
};
use tokio::{sync::Notify, task::JoinHandle};

use super::any;
use crate::{
    conn::{transmit::InitialSpaceReader, ArcRemoteCids, RcvdPackets},
    error::ConnError,
    path::{ArcPath, ArcPaths, Path},
    pipe,
    tx::{PacketMemory, Transaction},
};

#[derive(Clone)]
pub struct InitialSpace {
    pub keys: ArcKeys,
    pub journal: InitialJournal,
    pub crypto_stream: CryptoStream,
}

impl InitialSpace {
    // Initial keys应该是预先知道的，或者传入dcid，可以构造出来
    pub fn new(keys: ArcKeys) -> Self {
        let journal = InitialJournal::with_capacity(16);
        let crypto_stream = CryptoStream::new(4096, 4096);

        Self {
            keys,
            journal,
            crypto_stream,
        }
    }

    pub fn build(
        &self,
        rcvd_packets: RcvdPackets,
        pathes: &ArcPaths,
        remote_cids: &ArcRemoteCids,
        notify: &Arc<Notify>,
        conn_error: &ConnError,
        validate: impl Fn(&[u8], ArcPath) + Send + 'static,
    ) -> JoinHandle<RcvdPackets> {
        let (crypto_frames_entry, rcvd_crypto_frames) = mpsc::unbounded();
        let (ack_frames_entry, rcvd_ack_frames) = mpsc::unbounded();

        let dispatch_frame = move |frame: Frame, path: &Path| {
            match frame {
                Frame::Ack(f) => {
                    path.cc().on_ack(Epoch::Initial, &f);
                    _ = ack_frames_entry.unbounded_send(f)
                }
                Frame::Crypto(f, bytes) => _ = crypto_frames_entry.unbounded_send((f, bytes)),
                Frame::Close(_) => { /* trustless */ }
                Frame::Padding(_) | Frame::Ping(_) => {}
                _ => unreachable!("unexpected frame: {:?} in initial packet", frame),
            }
        };
        let on_data_acked = {
            let crypto_stream_outgoing = self.crypto_stream.outgoing();
            let sent_journal = self.journal.of_sent_packets();
            move |ack_frame: &AckFrame| {
                let mut rotate_guard = sent_journal.rotate();
                rotate_guard.update_largest(ack_frame.largest.into_inner());

                for pn in ack_frame.iter().flat_map(|r| r.rev()) {
                    for frame in rotate_guard.on_pkt_acked(pn) {
                        crypto_stream_outgoing.on_data_acked(&frame);
                    }
                }
            }
        };

        pipe!(@error(conn_error) rcvd_crypto_frames |> self.crypto_stream.incoming(), recv_frame);
        pipe!(rcvd_ack_frames |> on_data_acked);

        self.parse_rcvd_packets_and_dispatch_frames(
            rcvd_packets,
            pathes,
            remote_cids,
            dispatch_frame,
            notify,
            conn_error,
            validate,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn parse_rcvd_packets_and_dispatch_frames(
        &self,
        mut rcvd_packets: RcvdPackets,
        pathes: &ArcPaths,
        remote_cids: &ArcRemoteCids,
        dispatch_frame: impl Fn(Frame, &Path) + Send + 'static,
        notify: &Arc<Notify>,
        conn_error: &ConnError,
        validate: impl Fn(&[u8], ArcPath) + Send + 'static,
    ) -> JoinHandle<RcvdPackets> {
        let pathes = pathes.clone();
        let conn_error = conn_error.clone();
        tokio::spawn({
            let rcvd_journal = self.journal.of_rcvd_packets();
            let keys = self.keys.clone();
            let remote_cids = remote_cids.clone();
            let notify = notify.clone();

            async move {
                while let Some((mut packet, pathway, usc)) = any(rcvd_packets.next(), &notify).await
                {
                    let pty = packet.header.get_type();
                    let Some(keys) = any(keys.get_remote_keys(), &notify).await else {
                        break;
                    };
                    let undecoded_pn = match remove_protection_of_long_packet(
                        keys.remote.header.as_ref(),
                        packet.bytes.as_mut(),
                        packet.offset,
                    ) {
                        Ok(Some(pn)) => pn,
                        Ok(None) => continue,
                        Err(invalid_reserved_bits) => {
                            conn_error.on_error(invalid_reserved_bits.into());
                            break;
                        }
                    };

                    let pn = match rcvd_journal.decode_pn(undecoded_pn) {
                        Ok(pn) => pn,
                        // TooOld/TooLarge/HasRcvd
                        Err(_e) => continue,
                    };
                    let body_offset = packet.offset + undecoded_pn.size();
                    let decrypted = decrypt_packet(
                        keys.remote.packet.as_ref(),
                        pn,
                        packet.bytes.as_mut(),
                        body_offset,
                    );
                    let Ok(pkt_len) = decrypted else { continue };

                    let path = pathes.get_or_create(pathway, usc);
                    path.on_rcvd(packet.bytes.len());

                    let _header = packet.bytes.split_to(body_offset);
                    packet.bytes.truncate(pkt_len);

                    let remote_scid = match packet.header {
                        DataHeader::Long(ref long_header) => long_header.get_scid(),
                        _ => unreachable!(),
                    };
                    // When receiving the initial packet, change the DCID of the
                    // path to the SCID carried in the received packet.
                    remote_cids.revise_initial_dcid(*remote_scid);

                    match FrameReader::new(packet.bytes.freeze(), pty).try_fold(
                        false,
                        |is_ack_packet, frame| {
                            let (frame, is_ack_eliciting) = frame?;
                            dispatch_frame(frame, &path);
                            Ok(is_ack_packet || is_ack_eliciting)
                        },
                    ) {
                        Ok(is_ack_packet) => {
                            rcvd_journal.register_pn(pn);
                            path.cc().on_pkt_rcvd(Epoch::Initial, pn, is_ack_packet);
                        }
                        Err(e) => {
                            conn_error.on_error(e);
                            break;
                        }
                    }
                    // See [RFC 9000 section 8.1](https://www.rfc-editor.org/rfc/rfc9000.html#name-address-validation-during-c)
                    // A server might wish to validate the client address before starting the cryptographic handshake.
                    // QUIC uses a token in the Initial packet to provide address validation prior to completing the handshake.
                    // This token is delivered to the client during connection establishment with a Retry packet (see Section 8.1.2)
                    // or in a previous connection using the NEW_TOKEN frame (see Section 8.1.3).
                    if let DataHeader::Long(long::DataHeader::Initial(initial)) = &packet.header {
                        if !initial.token.is_empty() {
                            validate(&initial.token, path);
                        }
                    }
                }
                rcvd_packets
            }
        })
    }

    /// TODO: 还要padding、加密等功能，理应返回一个PacketWriter+密钥，以防后续还要padding
    ///     或者提供一个不需外部计算padding的接口，比如先填充Initial之外的包，最后再填充Initial，提供最小长度
    pub fn try_assemble<'b>(
        &self,
        tx: &mut Transaction<'_>,
        token: Vec<u8>,
        buf: &'b mut [u8],
    ) -> Option<(AssembledPacket<'b>, Option<u64>)> {
        let keys = self.keys.get_local_keys()?;
        let sent_journal = self.journal.of_sent_packets();
        let mut packet = PacketMemory::new(
            LongHeaderBuilder::with_cid(tx.dcid(), tx.scid()).initial(token),
            buf,
            keys.local.packet.tag_len(),
            &sent_journal,
        )?;

        let mut ack = None;
        if let Some((largest, rcvd_time)) = tx.need_ack(Epoch::Initial) {
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

        let packet: PacketWriter<'b> = packet.try_into().ok()?;
        Some((
            packet.encrypt_long_packet(keys.local.header.as_ref(), keys.local.packet.as_ref()),
            ack,
        ))
    }

    pub fn reader(&self, token: Arc<Mutex<Vec<u8>>>) -> InitialSpaceReader {
        InitialSpaceReader {
            token,
            keys: self.keys.clone(),
            journal: self.journal.clone(),
            crypto_stream_outgoing: self.crypto_stream.outgoing(),
        }
    }
}

#[derive(Clone)]
pub struct InitialTracker {
    journal: InitialJournal,
    outgoing: CryptoStreamOutgoing,
}

impl InitialTracker {
    pub fn new(journal: InitialJournal, outgoing: CryptoStreamOutgoing) -> Self {
        Self { journal, outgoing }
    }
}

impl TrackPackets for InitialTracker {
    fn may_loss(&self, pn: u64) {
        for frame in self.journal.of_sent_packets().rotate().may_loss_pkt(pn) {
            self.outgoing.may_loss_data(&frame);
        }
    }

    fn retire(&self, pn: u64) {
        self.journal.of_rcvd_packets().write().retire(pn);
    }
}
