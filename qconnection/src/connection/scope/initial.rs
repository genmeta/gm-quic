use std::sync::{Arc, Mutex};

use futures::{channel::mpsc, StreamExt};
use qbase::{
    frame::{AckFrame, Frame, FrameReader, ReceiveFrame},
    packet::{
        decrypt::{decrypt_packet, remove_protection_of_long_packet},
        header::{GetScid, GetType},
        keys::ArcKeys,
        long, DataHeader,
    },
};
use qcongestion::{CongestionControl, MayLoss, RetirePktRecord};
use qrecovery::{
    crypto::CryptoStream,
    space::{Epoch, InitialSpace},
};
use tokio::{sync::Notify, task::JoinHandle};

use super::any;
use crate::{
    connection::{transmit::initial::InitialSpaceReader, ArcRemoteCids, RcvdPackets},
    error::ConnError,
    path::{ArcPath, ArcPathes, RawPath},
    pipe,
};

#[derive(Clone)]
pub struct InitialScope {
    pub keys: ArcKeys,
    pub space: InitialSpace,
    pub crypto_stream: CryptoStream,
}

impl InitialScope {
    // Initial keys应该是预先知道的，或者传入dcid，可以构造出来
    pub fn new(keys: ArcKeys) -> Self {
        let space = InitialSpace::with_capacity(16);
        let crypto_stream = CryptoStream::new(4096, 4096);

        Self {
            keys,
            space,
            crypto_stream,
        }
    }

    pub fn build(
        &self,
        rcvd_packets: RcvdPackets,
        pathes: &ArcPathes,
        remote_cids: &ArcRemoteCids,
        notify: &Arc<Notify>,
        conn_error: &ConnError,
        validate: impl Fn(&[u8], ArcPath) + Send + 'static,
    ) -> JoinHandle<RcvdPackets> {
        let (crypto_frames_entry, rcvd_crypto_frames) = mpsc::unbounded();
        let (ack_frames_entry, rcvd_ack_frames) = mpsc::unbounded();

        let dispatch_frame = move |frame: Frame, path: &RawPath| {
            match frame {
                Frame::Ack(f) => {
                    path.cc.on_ack(Epoch::Initial, &f);
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
            let sent_pkt_records = self.space.sent_packets();
            move |ack_frame: &AckFrame| {
                let mut recv_guard = sent_pkt_records.recv();
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
        pathes: &ArcPathes,
        remote_cids: &ArcRemoteCids,
        dispatch_frame: impl Fn(Frame, &RawPath) + Send + 'static,
        notify: &Arc<Notify>,
        conn_error: &ConnError,
        validate: impl Fn(&[u8], ArcPath) + Send + 'static,
    ) -> JoinHandle<RcvdPackets> {
        let pathes = pathes.clone();
        let conn_error = conn_error.clone();
        tokio::spawn({
            let rcvd_pkt_records = self.space.rcvd_packets();
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
                    let _header = packet.bytes.split_to(body_offset);
                    packet.bytes.truncate(pkt_len);

                    let path = pathes.get_or_create(pathway, usc);
                    path.update_recv_time();

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
                            rcvd_pkt_records.register_pn(pn);
                            path.cc.on_pkt_rcvd(Epoch::Initial, pn, is_ack_packet);
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

    pub fn reader(&self, token: Arc<Mutex<Vec<u8>>>) -> InitialSpaceReader {
        InitialSpaceReader {
            token,
            keys: self.keys.clone(),
            space: self.space.clone(),
            crypto_stream_outgoing: self.crypto_stream.outgoing(),
        }
    }
}

impl MayLoss for InitialScope {
    fn may_loss(&self, pn: u64) {
        for frame in self.space.sent_packets().recv().may_loss_pkt(pn) {
            self.crypto_stream.outgoing().may_loss_data(&frame);
        }
    }
}

impl RetirePktRecord for InitialScope {
    fn retire(&self, pn: u64) {
        self.space.rcvd_packets().write().retire(pn);
    }
}
