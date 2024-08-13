use std::sync::Arc;

use futures::{channel::mpsc, StreamExt};
use qbase::{
    frame::{AckFrame, Frame, FrameReader},
    new_token::{Client, Server, TokenRegistry},
    packet::{
        decrypt::{decrypt_packet, remove_protection_of_long_packet},
        header::GetType,
        keys::ArcKeys,
        long::{self, Initial},
        DataHeader,
    },
    token,
};
use qrecovery::{
    reliable::ArcReliableFrameDeque,
    space::{Epoch, InitialSpace},
    streams::crypto::CryptoStream,
};
use tokio::{select, sync::Notify, task::JoinHandle};

use crate::{
    any,
    connection::{transmit::initial::InitialSpaceReader, RcvdPackets},
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

        self.recv_retry(rcvd_retry);
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
        tokio::spawn({
            let rcvd_pkt_records = self.space.rcvd_packets();
            let keys = self.keys.clone();
            let notify = notify.clone();
            async move {
                while let Some((mut packet, pathway, usc)) =
                    any!(rcvd_packets.next(), notify.notified())
                {
                    let pty = packet.header.get_type();
                    let Some(keys) = any!(keys.get_remote_keys(), notify.notified()) else {
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

                    if let TokenRegistry::Server(server) = &mut token_registry {
                        let token = if let DataHeader::Long(long::DataHeader::Initial(initial)) =
                            packet.header
                        {
                            initial.token.clone()
                        } else {
                            unreachable!("Must be initial packet")
                        };

                        if server.validate(&token) {
                            server.issue_new_token();
                            // todo: validate wakeup
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

    pub fn reader(&self) -> InitialSpaceReader {
        let token = match &self.token_registry {
            TokenRegistry::Client(client) => client.pop_token().unwrap_or_else(Vec::new),
            _ => Vec::new(),
        };
        InitialSpaceReader {
            token: Arc::new(Mutex::new(token)),
            keys: self.keys.clone(),
            space: self.space.clone(),
            crypto_stream_outgoing: self.crypto_stream.outgoing(),
        }
    }

    pub fn recv_retry(&self, mut rcvd_retry: RcvdRetry) {
        tokio::spawn({
            let token = self.retry_token.clone();
            async move {
                if let Some(retry) = rcvd_retry.next().await {
                    *token.lock().unwrap() = retry.token.to_vec();
                    // 客户端只会接受一次 Retry 包，如果是服务端应该报错
                    rcvd_retry.close();
                }
            }
        });
    }
}
