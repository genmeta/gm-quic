use futures::{channel::mpsc, StreamExt};
use qbase::{
    frame::{AckFrame, DataFrame, Frame, FrameReader},
    packet::{
        decrypt::{decrypt_packet, remove_protection_of_long_packet},
        header::GetType,
        keys::ArcKeys,
    },
};
use qrecovery::{
    space::{Epoch, HandshakeSpace},
    streams::crypto::CryptoStream,
};
use tokio::task::JoinHandle;

use crate::{
    connection::{transmit::handshake::HandshakeSpaceReader, PacketEntry, RcvdPackets},
    error::ConnError,
    path::{ArcPathes, RawPath},
    pipe,
};

#[derive(Clone)]
pub struct HandshakeScope {
    pub keys: ArcKeys,
    pub space: HandshakeSpace,
    pub crypto_stream: CryptoStream,
    pub packets_entry: PacketEntry,
}

impl HandshakeScope {
    // Initial keys应该是预先知道的，或者传入dcid，可以构造出来
    pub fn new(packets_entry: PacketEntry) -> Self {
        Self {
            keys: ArcKeys::new_pending(),
            space: HandshakeSpace::with_capacity(16),
            crypto_stream: CryptoStream::new(4096, 4096),
            packets_entry,
        }
    }

    pub fn build(
        &self,
        rcvd_packets: RcvdPackets,
        pathes: &ArcPathes,
        conn_error: &ConnError,
    ) -> JoinHandle<RcvdPackets> {
        let (crypto_frames_entry, rcvd_crypto_frames) = mpsc::unbounded();
        let (ack_frames_entry, rcvd_ack_frames) = mpsc::unbounded();

        let dispatch_frame = {
            let conn_error = conn_error.clone();
            move |frame: Frame, path: &RawPath| match frame {
                Frame::Ack(ack_frame) => {
                    path.on_ack(Epoch::Initial, &ack_frame);
                    _ = ack_frames_entry.unbounded_send(ack_frame);
                }
                Frame::Data(DataFrame::Crypto(crypto), bytes) => {
                    _ = crypto_frames_entry.unbounded_send((crypto, bytes));
                }
                Frame::Close(ccf) => conn_error.on_ccf_rcvd(&ccf),
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

        pipe!(rcvd_crypto_frames |> self.crypto_stream.incoming(), recv_crypto_frame);
        pipe!(rcvd_ack_frames |> on_data_acked);
        self.parse_rcvd_packets_and_dispatch_frames(
            rcvd_packets,
            pathes,
            dispatch_frame,
            conn_error,
        )
    }

    fn parse_rcvd_packets_and_dispatch_frames(
        &self,
        mut rcvd_packets: RcvdPackets,
        pathes: &ArcPathes,
        dispatch_frame: impl Fn(Frame, &RawPath) + Send + 'static,
        conn_error: &ConnError,
    ) -> JoinHandle<RcvdPackets> {
        let pathes = pathes.clone();
        let conn_error = conn_error.clone();
        tokio::spawn({
            let rcvd_pkt_records = self.space.rcvd_packets();
            let keys = self.keys.clone();
            async move {
                while let Some((mut packet, pathway, usc)) = rcvd_packets.next().await {
                    let pty = packet.header.get_type();
                    let Some(keys) = keys.get_remote_keys().await else {
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
                    decrypt_packet(
                        keys.remote.packet.as_ref(),
                        pn,
                        &mut packet.bytes.as_mut(),
                        body_offset,
                    )
                    .unwrap();
                    let path = pathes.get(pathway, usc);
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
