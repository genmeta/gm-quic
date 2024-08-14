use std::{
    fmt::Debug,
    sync::{Arc, Mutex},
};

use futures::{channel::mpsc, StreamExt};
use qbase::{
    frame::{AckFrame, Frame, FrameReader, ReceiveFrame},
    packet::{
        decrypt::{decrypt_packet, remove_protection_of_long_packet},
        header::GetType,
        keys::ArcKeys,
        long::{self},
        DataHeader,
    },
    token::RetryInitial,
};
use qrecovery::{
    space::{Epoch, InitialSpace},
    streams::crypto::CryptoStream,
};
use tokio::{sync::Notify, task::JoinHandle};

use super::any;
use crate::{
    connection::{
        transmit::initial::InitialSpaceReader, validator::ArcAddrValidator, RcvdPackets,
        TokenRegistry,
    },
    error::ConnError,
    path::{ArcPathes, RawPath},
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
        let crypto_stream = CryptoStream::new(0, 0);

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
        notify: &Arc<Notify>,
        conn_error: &ConnError,
        addr_validator: ArcAddrValidator,
        token_registry: TokenRegistry,
    ) -> JoinHandle<RcvdPackets> {
        let (crypto_frames_entry, rcvd_crypto_frames) = mpsc::unbounded();
        let (ack_frames_entry, rcvd_ack_frames) = mpsc::unbounded();

        let dispatch_frame = move |frame: Frame, path: &RawPath| {
            match frame {
                Frame::Ack(f) => {
                    path.on_ack(Epoch::Initial, &f);
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
            addr_validator,
            token_registry,
        )
    }

    fn parse_rcvd_packets_and_dispatch_frames(
        &self,
        mut rcvd_packets: RcvdPackets,
        pathes: &ArcPathes,
        dispatch_frame: impl Fn(Frame, &RawPath) + Send + 'static,
        notify: &Arc<Notify>,
        conn_error: &ConnError,
        addr_validator: ArcAddrValidator,
        token_registry: TokenRegistry,
    ) -> JoinHandle<RcvdPackets> {
        let pathes = pathes.clone();
        let conn_error = conn_error.clone();
        tokio::spawn({
            let rcvd_pkt_records = self.space.rcvd_packets();
            let keys = self.keys.clone();
            let notify = notify.clone();
            let addr_validator = addr_validator.clone();
            let mut token_registry = token_registry.clone();
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
                    decrypt_packet(
                        keys.remote.packet.as_ref(),
                        pn,
                        packet.bytes.as_mut(),
                        body_offset,
                    )
                    .unwrap();

                    match &mut token_registry {
                        TokenRegistry::Server(server) => {
                            let token =
                                if let DataHeader::Long(long::DataHeader::Initial(initial)) =
                                    packet.header
                                {
                                    initial.token.clone()
                                } else {
                                    unreachable!("Must be initial packet")
                                };
                            server.issue_new_token();
                            if server.validate(&token) {
                                addr_validator.0.validate();
                            }
                        }
                        TokenRegistry::Client(_) => {
                            addr_validator.0.validate();
                        }
                    }

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
                            path.on_recv_pkt(Epoch::Initial, pn, is_ack_packet);
                        }
                        Err(e) => {
                            conn_error.on_error(e);
                            break;
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

impl RetryInitial for InitialScope {
    fn retry_initial(&mut self) {
        let largest_pn = self.space.sent_packets().receive().largest_pn();
        // Packet numbers in each space start at packet number 0.
        // All packets in the initial space are considered lost.
        for pn in 0..largest_pn {
            let _ = self.space.sent_packets().receive().may_loss_pkt(pn);
        }
    }
}

impl Debug for InitialScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitialScope")
            .field("space", &self.space)
            .field("crypto_stream", &self.crypto_stream)
            .finish()
    }
}
