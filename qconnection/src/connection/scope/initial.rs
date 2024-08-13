use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
};

use futures::{channel::mpsc, task::AtomicWaker, StreamExt};
use qbase::{
    frame::{AckFrame, Frame, FrameReader},
    packet::{
        decrypt::{decrypt_packet, remove_protection_of_long_packet},
        header::GetType,
        keys::ArcKeys,
        long::{self},
        DataHeader,
    },
    token_registry::TokenRegistry,
};
use qrecovery::{
    reliable::ArcReliableFrameDeque,
    space::{Epoch, InitialSpace},
    streams::crypto::CryptoStream,
};
use tokio::{sync::Notify, task::JoinHandle};

use crate::{
    any,
    connection::{transmit::initial::InitialSpaceReader, RcvdPackets, RcvdRetry},
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
        rcvd_retry: RcvdRetry,
        pathes: &ArcPathes,
        notify: &Arc<Notify>,
        conn_error: &ConnError,
        addr_validator: ArcAddrValidator,
        token_registry: TokenRegistry<ArcReliableFrameDeque>,
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

        self.recv_retry(rcvd_retry, token_registry.clone());

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
        token_registry: TokenRegistry<ArcReliableFrameDeque>,
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

                            if server.validate(&token) {
                                server.issue_new_token();
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

    pub fn reader(
        &self,
        token_registry: TokenRegistry<ArcReliableFrameDeque>,
    ) -> InitialSpaceReader {
        let token = match token_registry {
            TokenRegistry::Client(client) => client.initial_token.clone(),
            _ => Arc::new(Mutex::new(Vec::new())),
        };

        InitialSpaceReader {
            token,
            keys: self.keys.clone(),
            space: self.space.clone(),
            crypto_stream_outgoing: self.crypto_stream.outgoing(),
        }
    }

    pub fn recv_retry(
        &self,
        mut rcvd_retry: RcvdRetry,
        mut token_registry: TokenRegistry<ArcReliableFrameDeque>,
    ) {
        tokio::spawn({
            async move {
                if let Some(retry) = rcvd_retry.next().await {
                    match &mut token_registry {
                        TokenRegistry::Client(client) => {
                            client.recv_retry_token(retry.token.clone())
                        }
                        TokenRegistry::Server(_) => {
                            unreachable!("Server should not receive retry")
                        }
                    }
                    rcvd_retry.close();
                }
            }
        });
    }
}

#[derive(Default)]
pub struct AddrValidator {
    waker: AtomicWaker,
    state: AtomicU8,
}

impl AddrValidator {
    const NORMAL: u8 = 0;
    const VALIDATED: u8 = 1;
    const ABORTED: u8 = 2;

    pub fn validate(&self) {
        if self
            .state
            .compare_exchange(
                Self::NORMAL,
                Self::ABORTED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            self.waker.wake();
        }
    }

    pub fn abort(&self) {
        if self
            .state
            .compare_exchange(
                Self::NORMAL,
                Self::ABORTED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            self.waker.wake();
        }
    }
}

#[derive(Clone, Default)]
pub struct ArcAddrValidator(pub Arc<AddrValidator>);

impl Future for ArcAddrValidator {
    type Output = bool;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let state = self.0.state.load(Ordering::Acquire);
        match state {
            AddrValidator::NORMAL => {
                self.0.waker.register(cx.waker());
                Poll::Pending
            }
            AddrValidator::VALIDATED => Poll::Ready(true),
            AddrValidator::ABORTED => Poll::Ready(false),
            _ => unreachable!("invalid state"),
        }
    }
}
