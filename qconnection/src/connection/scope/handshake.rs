use std::sync::Arc;

use futures::{channel::mpsc, StreamExt};
use qbase::{
    frame::{AckFrame, Frame, FrameReader, ReceiveFrame},
    packet::{
        decrypt::{decrypt_packet, remove_protection_of_long_packet},
        header::GetType,
        keys::ArcKeys,
        DataPacket, PacketNumber,
    },
};
use qrecovery::{
    reliable::rcvdpkt::ArcRcvdPktRecords,
    space::{Epoch, HandshakeSpace},
    streams::crypto::CryptoStream,
};
use tokio::{sync::Notify, task::JoinHandle};

use super::any;
use crate::{
    connection::{transmit::handshake::HandshakeSpaceReader, RcvdPackets},
    error::ConnError,
    path::{ArcPathes, RawPath},
    pipe,
};

#[derive(Clone)]
pub struct HandshakeScope {
    pub keys: ArcKeys,
    pub space: HandshakeSpace,
    pub crypto_stream: CryptoStream,
}

impl Default for HandshakeScope {
    fn default() -> Self {
        Self {
            keys: ArcKeys::new_pending(),
            space: HandshakeSpace::with_capacity(16),
            crypto_stream: CryptoStream::new(4096, 4096),
        }
    }
}

impl HandshakeScope {
    pub fn build(
        &self,
        rcvd_packets: RcvdPackets,
        pathes: &ArcPathes,
        notify: &Arc<Notify>,
        conn_error: &ConnError,
    ) -> JoinHandle<RcvdPackets> {
        let (crypto_frames_entry, rcvd_crypto_frames) = mpsc::unbounded();
        let (ack_frames_entry, rcvd_ack_frames) = mpsc::unbounded();

        let dispatch_frame = {
            let conn_error = conn_error.clone();
            move |frame: Frame, path: &RawPath| match frame {
                Frame::Ack(f) => {
                    path.on_ack(Epoch::Initial, &f);
                    _ = ack_frames_entry.unbounded_send(f);
                }
                Frame::Close(f) => conn_error.on_ccf_rcvd(&f),
                Frame::Crypto(f, bytes) => _ = crypto_frames_entry.unbounded_send((f, bytes)),
                Frame::Padding(_) | Frame::Ping(_) => {}
                _ => unreachable!("unexpected frame: {:?} in handshake packet", frame),
            }
        };
        let on_data_acked = {
            let crypto_stream_outgoing = self.crypto_stream.outgoing();
            let sent_pkt_records = self.space.sent_packets();
            move |ack_frame: &AckFrame| {
                let mut recv_guard = sent_pkt_records.receive();
                recv_guard.update_largest(ack_frame.largest.into_inner());

                for pn in ack_frame.iter().flat_map(|r| r.rev()) {
                    for frame in recv_guard.on_pkt_acked(pn) {
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
            dispatch_frame,
            notify,
            conn_error,
        )
    }

    fn parse_rcvd_packets_and_dispatch_frames(
        &self,
        mut rcvd_packets: RcvdPackets,
        pathes: &ArcPathes,
        dispatch_frame: impl Fn(Frame, &RawPath) + Send + 'static,
        notify: &Arc<Notify>,
        conn_error: &ConnError,
    ) -> JoinHandle<RcvdPackets> {
        let pathes = pathes.clone();
        let conn_error = conn_error.clone();
        let notify = notify.clone();
        tokio::spawn({
            let rcvd_pkt_records = self.space.rcvd_packets();
            let keys = self.keys.clone();
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
                        Err(_e) => {
                            // conn_error.on_error(e);
                            break;
                        }
                    };

                    let pn = match rcvd_pkt_records.decode_pn(undecoded_pn) {
                        Ok(pn) => pn,
                        // TooOld/TooLarge/HasRcvd
                        Err(_e) => continue,
                    };
                    let body_offset = packet.offset + undecoded_pn.size();
                    let pkt_len = decrypt_packet(
                        keys.remote.packet.as_ref(),
                        pn,
                        packet.bytes.as_mut(),
                        body_offset,
                    )
                    .unwrap();
                    packet.bytes.truncate(pkt_len);

                    let path = pathes.get(pathway, usc);

                    // See [RFC 9000 section 8.1](https://www.rfc-editor.org/rfc/rfc9000.html#name-address-validation-during-c)
                    // Once an endpoint has successfully processed a Handshake packet from the peer, it can consider the peer
                    // address to have been validated.
                    // It may have already been verified using tokens in the Initial space
                    path.anti_amplifier.grant();

                    let body = packet.bytes.split_off(body_offset);
                    match FrameReader::new(body.freeze(), pty).try_fold(
                        false,
                        |is_ack_packet, frame| {
                            let (frame, is_ack_eliciting) = frame?;
                            dispatch_frame(frame, &path);
                            Ok(is_ack_packet || is_ack_eliciting)
                        },
                    ) {
                        Ok(is_ack_packet) => {
                            rcvd_pkt_records.register_pn(pn);
                            path.on_recv_pkt(Epoch::Handshake, pn, is_ack_packet);
                        }
                        Err(e) => conn_error.on_error(e),
                    }
                }
                rcvd_packets
            }
        })
    }

    pub fn reader(&self) -> HandshakeSpaceReader {
        HandshakeSpaceReader {
            keys: self.keys.clone(),
            space: self.space.clone(),
            crypto_stream_outgoing: self.crypto_stream.outgoing(),
        }
    }
}

#[derive(Clone)]
pub struct ClosingHandshakeScope {
    keys: Arc<rustls::quic::Keys>,
    rcvd_pkt_records: ArcRcvdPktRecords,
    // 发包时用得着
    _next_sending_pn: (u64, PacketNumber),
}

impl TryFrom<HandshakeScope> for ClosingHandshakeScope {
    type Error = ();

    fn try_from(hs: HandshakeScope) -> Result<Self, Self::Error> {
        let Some(keys) = hs.keys.invalid() else {
            return Err(());
        };
        let rcvd_pkt_records = hs.space.rcvd_packets();
        let next_sending_pn = hs.space.sent_packets().send().next_pn();

        Ok(Self {
            keys,
            rcvd_pkt_records,
            _next_sending_pn: next_sending_pn,
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

        let pn = match self.rcvd_pkt_records.decode_pn(undecoded_pn) {
            Ok(pn) => pn,
            // TooOld/TooLarge/HasRcvd
            Err(_e) => return false,
        };
        let body_offset = packet.offset + undecoded_pn.size();
        Self::decrypt_and_parse(self.keys.remote.packet.as_ref(), pn, packet, body_offset)
    }
}
