use std::{
    net::SocketAddr,
    ops::Deref,
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use dashmap::DashMap;
use futures::{channel::mpsc, StreamExt};
use qbase::{
    cid::Registry,
    error::{Error, ErrorKind},
    flow::FlowController,
    frame::{AckFrame, BeFrame, DataFrame, Frame, FrameReader},
    handshake::Handshake,
    packet::{
        self,
        decrypt::{DecodeHeader, DecryptPacket, RemoteProtection},
        header::GetType,
        keys::{ArcKeys, ArcOneRttKeys},
        HandshakePacket, InitialPacket, OneRttPacket, PacketNumber, SpacePacket, SpinBit,
        ZeroRttPacket,
    },
};
use qrecovery::{
    reliable::{ArcReliableFrameDeque, ReliableFrame},
    space::{DataSpace, Epoch, HandshakeSpace, InitialSpace},
    streams::{crypto::CryptoStream, DataStreams},
};
use qudp::ArcUsc;
use qunreliable::DatagramFlow;

use crate::{error::ConnError, path::ArcPath, pipe, tls::ArcTlsSession};

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct RelayAddr {
    pub agent: SocketAddr, // 代理人
    pub addr: SocketAddr,
}

/// 无论哪种Pathway，socket都必须绑定local地址
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Pathway {
    Direct {
        local: SocketAddr,
        remote: SocketAddr,
    },
    Relay {
        local: RelayAddr,
        remote: RelayAddr,
    },
}

type PacketQueue<P> = mpsc::UnboundedSender<(P, ArcPath)>;

pub type InitialPacketQueue = PacketQueue<InitialPacket>;
pub type HandshakePacketQueue = PacketQueue<HandshakePacket>;
pub type ZeroRttPacketQueue = PacketQueue<ZeroRttPacket>;
pub type OneRttPacketQueue = PacketQueue<OneRttPacket>;

pub struct RawConnection {
    pathes: DashMap<Pathway, ArcPath>,
    cid_registry: Registry,
    // handshake done的信号
    handshake: Handshake,
    flow_control: FlowController,
    spin: Arc<Mutex<SpinBit>>,
    error: ConnError,

    initial_space: InitialSpace,
    initial_crypto_stream: CryptoStream,
    initial_packet_queue: InitialPacketQueue,
    initial_keys: ArcKeys,

    handshake_space: HandshakeSpace,
    handshake_crypto_stream: CryptoStream,
    handshake_packet_queue: HandshakePacketQueue,
    handshake_keys: ArcKeys,

    data_space: DataSpace,
    data_crypto_stream: CryptoStream,
    data_streams: DataStreams,
    data_reliable_frames_deque: ArcReliableFrameDeque,

    zero_rtt_packet_queue: ZeroRttPacketQueue,
    zero_rtt_keys: ArcKeys,
    one_rtt_packet_queue: OneRttPacketQueue,
    one_rtt_keys: ArcOneRttKeys,

    datagram_flow: DatagramFlow,
}

type PacketType = packet::r#type::Type;

impl RawConnection {
    pub fn new(role: Role, tls_session: ArcTlsSession) -> Self {
        let pathes = DashMap::new();
        let cid_registry = Registry::new(2);
        let handshake = Handshake::with_role(role);
        let flow_control = FlowController::with_initial(0, 0);
        let spin = Arc::new(Mutex::new(SpinBit::Off));
        let conn_error = ConnError::default();

        let initial_space = InitialSpace::with_capacity(0);
        let initial_crypto_stream = CryptoStream::new(0, 0);
        let initial_keys = ArcKeys::new_pending();

        let handshake_space = HandshakeSpace::with_capacity(0);
        let handshake_crypto_stream = CryptoStream::new(0, 0);
        let handshake_keys = ArcKeys::new_pending();

        let data_space = DataSpace::with_capacity(0);
        let data_crypto_stream = CryptoStream::new(0, 0);
        let data_reliable_frames_deque = ArcReliableFrameDeque::with_capacity(0);
        let data_streams =
            DataStreams::with_role_and_limit(role, 0, 0, data_reliable_frames_deque.clone());
        let zero_rtt_keys = ArcKeys::new_pending();
        let one_rtt_keys = ArcOneRttKeys::new_pending();

        let datagram_flow = DatagramFlow::new(0, 0);

        let (initial_packet_queue, initial_packets) = mpsc::unbounded();
        let (handshake_packet_queue, handshake_packets) = mpsc::unbounded();
        let (zero_rtt_packet_queue, zero_rtt_packets) = mpsc::unbounded();
        let (one_rtt_packet_queue, one_rtt_packets) = mpsc::unbounded();

        tokio::spawn({
            const EPOCH: Epoch = Epoch::Initial;
            const PACKET_TYPE: packet::r#type::Type = packet::r#type::Type::Long(
                packet::r#type::long::Type::V1(packet::r#type::long::Version::INITIAL),
            );
            let mut packets = initial_packets;

            let space = initial_space.clone();
            let crypto_stream_outgoing = initial_crypto_stream.outgoing();
            let on_ack = move |ack_frame: &AckFrame| {
                let record = space.sent_packets();
                let mut recv_guard = record.receive();
                recv_guard.update_largest(ack_frame.largest.into_inner());

                for pn in ack_frame.iter().flat_map(|r| r.rev()) {
                    for frame in recv_guard.on_pkt_acked(pn) {
                        crypto_stream_outgoing.on_data_acked(&frame);
                    }
                }
            };

            let space = initial_space.clone();
            let crypto_stream = initial_crypto_stream.clone();
            let keys = initial_keys.clone();

            let conn_error = conn_error.clone();

            let (crypto_frames_entry, rcvd_crypto_frames) = mpsc::unbounded();
            pipe!(rcvd_crypto_frames |> crypto_stream.incoming(), recv_crypto_frame);

            let (ack_frames_entry, rcvd_ack_frames) = mpsc::unbounded();
            pipe!(rcvd_ack_frames |> on_ack);

            async move {
                let dispatch_frames_of_initial_packet = |frame: Frame, path: &ArcPath| {
                    let is_ack_eliciting = frame.is_ack_eliciting();
                    match frame {
                        Frame::Ack(ack_frame) => {
                            path.on_ack(EPOCH, &ack_frame);
                            _ = ack_frames_entry.unbounded_send(ack_frame);
                        }
                        Frame::Data(DataFrame::Crypto(crypto), bytes) => {
                            _ = crypto_frames_entry.unbounded_send((crypto, bytes));
                        }
                        _ => {}
                    }
                    is_ack_eliciting
                };

                let rcvd_packets = space.rcvd_packets();
                while let Some((packet, path)) = packets.next().await {
                    let decode_pn = |pn| rcvd_packets.decode_pn(pn).ok();
                    let payload_opt = decode_long_header_packet(packet, &keys, decode_pn).await;

                    let Some(payload) = payload_opt else {
                        return;
                    };

                    let dispath_result = FrameReader::new(payload.payload, PACKET_TYPE).try_fold(
                        false,
                        |is_ack_packet, frame| {
                            Ok(is_ack_packet || dispatch_frames_of_initial_packet(frame?, &path))
                        },
                    );

                    match dispath_result {
                        Ok(is_ack_packet) => {
                            space.rcvd_packets().register_pn(payload.pn);
                            path.on_recv_pkt(EPOCH, payload.pn, is_ack_packet);
                        }
                        Err(e) => conn_error.on_error(e),
                    }
                }
            }
        });

        tokio::spawn({
            const EPOCH: Epoch = Epoch::Initial;
            const PACKET_TYPE: packet::r#type::Type = packet::r#type::Type::Long(
                packet::r#type::long::Type::V1(packet::r#type::long::Version::HANDSHAKE),
            );
            let mut packets = handshake_packets;

            let space = handshake_space.clone();
            let crypto_stream_outgoing = handshake_crypto_stream.outgoing();
            let on_ack = move |ack_frame: &AckFrame| {
                let record = space.sent_packets();
                let mut recv_guard = record.receive();
                recv_guard.update_largest(ack_frame.largest.into_inner());

                for pn in ack_frame.iter().flat_map(|r| r.rev()) {
                    for frame in recv_guard.on_pkt_acked(pn) {
                        crypto_stream_outgoing.on_data_acked(&frame);
                    }
                }
            };

            let space = handshake_space.clone();
            let crypto_stream = handshake_crypto_stream.clone();
            let keys = handshake_keys.clone();

            let conn_error = conn_error.clone();

            let (crypto_frames_entry, rcvd_crypto_frames) = mpsc::unbounded();
            pipe!(rcvd_crypto_frames |> crypto_stream.incoming(), recv_crypto_frame);

            let (ack_frames_entry, rcvd_ack_frames) = mpsc::unbounded();
            pipe!(rcvd_ack_frames |> on_ack);

            async move {
                let dispatch_frames_of_handshake_packet = |frame: Frame, path: &ArcPath| {
                    let is_ack_eliciting = frame.is_ack_eliciting();
                    match frame {
                        Frame::Ack(ack_frame) => {
                            path.on_ack(EPOCH, &ack_frame);
                            _ = ack_frames_entry.unbounded_send(ack_frame);
                        }
                        Frame::Data(DataFrame::Crypto(crypto), bytes) => {
                            _ = crypto_frames_entry.unbounded_send((crypto, bytes));
                        }
                        _ => {}
                    }
                    is_ack_eliciting
                };

                let rcvd_packets = space.rcvd_packets();
                while let Some((packet, path)) = packets.next().await {
                    let decode_pn = |pn| rcvd_packets.decode_pn(pn).ok();
                    let payload_opt = decode_long_header_packet(packet, &keys, decode_pn).await;

                    let Some(payload) = payload_opt else {
                        return;
                    };

                    let dispath_result = FrameReader::new(payload.payload, PACKET_TYPE).try_fold(
                        false,
                        |is_ack_packet, frame| {
                            Ok(is_ack_packet || dispatch_frames_of_handshake_packet(frame?, &path))
                        },
                    );

                    match dispath_result {
                        Ok(is_ack_packet) => {
                            space.rcvd_packets().register_pn(payload.pn);
                            path.on_recv_pkt(Epoch::Handshake, payload.pn, is_ack_packet);
                        }
                        Err(e) => conn_error.on_error(e),
                    }
                }
            }
        });

        tokio::spawn({
            const EPOCH: Epoch = Epoch::Data;
            const PACKET_TYPE: packet::r#type::Type = packet::r#type::Type::Long(
                packet::r#type::long::Type::V1(packet::r#type::long::Version::ZERO_RTT),
            );
            let mut packets = zero_rtt_packets;

            let space = data_space.clone();
            let keys = zero_rtt_keys.clone();

            let conn_error = conn_error.clone();

            let (max_data_frames_entry, rcvd_max_data_frames) = mpsc::unbounded();
            pipe!(rcvd_max_data_frames |> *flow_control.sender(),recv_max_data_frame);
            // let (data_blocked_frames_entry, rcvd_data_blocked_frames) = mpsc::unbounded(); ignore
            let (stream_ctrl_frames_entry, rcvd_stream_ctrl_frames) = mpsc::unbounded();
            pipe!(@error(conn_error)  rcvd_stream_ctrl_frames |> data_streams,recv_stream_control);
            let (stream_frames_entry, rcvd_stream_frames) = mpsc::unbounded();
            pipe!(@error(conn_error)  rcvd_stream_frames |> data_streams,recv_data);
            let (datagram_frames_entry, rcvd_datagram_frames) = mpsc::unbounded();
            pipe!(@error(conn_error)  rcvd_datagram_frames |> datagram_flow,recv_datagram);

            async move {
                let dispatch_frames_of_0rtt_packet = |frame: Frame, _path: &ArcPath| {
                    let is_ack_eliciting = frame.is_ack_eliciting();
                    match frame {
                        Frame::MaxData(max_data) => {
                            _ = max_data_frames_entry.unbounded_send(max_data);
                        }
                        Frame::Stream(stream_ctrl) => {
                            _ = stream_ctrl_frames_entry.unbounded_send(stream_ctrl);
                        }
                        Frame::Data(DataFrame::Stream(stream), data) => {
                            _ = stream_frames_entry.unbounded_send((stream, data));
                        }
                        Frame::Datagram(datagram, data) => {
                            _ = datagram_frames_entry.unbounded_send((datagram, data));
                        }
                        _ => {}
                    }
                    is_ack_eliciting
                };

                let rcvd_packets = space.rcvd_packets();
                while let Some((packet, path)) = packets.next().await {
                    let decode_pn = |pn| rcvd_packets.decode_pn(pn).ok();
                    let payload_opt = decode_long_header_packet(packet, &keys, decode_pn).await;

                    let Some(payload) = payload_opt else {
                        return;
                    };

                    let dispath_result = FrameReader::new(payload.payload, PACKET_TYPE).try_fold(
                        false,
                        |is_ack_packet, frame| {
                            Ok(is_ack_packet || dispatch_frames_of_0rtt_packet(frame?, &path))
                        },
                    );

                    match dispath_result {
                        Ok(is_ack_packet) => {
                            space.rcvd_packets().register_pn(payload.pn);
                            path.on_recv_pkt(EPOCH, payload.pn, is_ack_packet);
                        }
                        Err(e) => conn_error.on_error(e),
                    }
                }
            }
        });

        tokio::spawn({
            const EPOCH: Epoch = Epoch::Data;

            let mut packets: mpsc::UnboundedReceiver<(OneRttPacket, ArcPath)> = one_rtt_packets;

            let keys = one_rtt_keys.clone();
            let space = data_space.clone();
            let data_streams = data_streams.clone();
            let conn_error = conn_error.clone();

            let (max_data_frames_entry, rcvd_max_data_frames) = mpsc::unbounded();
            pipe!(rcvd_max_data_frames |> *flow_control.sender(),recv_max_data_frame);
            // let (data_blocked_frames_entry, rcvd_data_blocked_frames) = mpsc::unbounded(); ignore

            // TODO: impl endpoint router
            let (new_cid_frames_entry, rcvd_new_cid_frames) = mpsc::unbounded();
            pipe!(@error(conn_error) rcvd_new_cid_frames |> cid_registry.remote,recv_new_cid_frame);
            let (retire_cid_frames_entry, rcvd_retire_cid_frames) = mpsc::unbounded();
            pipe!(@error(conn_error) rcvd_retire_cid_frames |> cid_registry.local,recv_retire_cid_frame);

            let (handshake_done_frames_entry, rcvd_handshake_done_frames) = mpsc::unbounded();
            pipe!(@error(conn_error) rcvd_handshake_done_frames |> handshake,recv_handshake_done_frame);
            let (new_token_frames_entry, rcvd_new_token_frames) = mpsc::unbounded();

            let (data_crypto_frames_entry, rcvd_data_crypto_frames) = mpsc::unbounded();
            pipe!(rcvd_data_crypto_frames |> data_crypto_stream.incoming(), recv_crypto_frame);
            let (stream_ctrl_frames_entry, rcvd_stream_ctrl_frames) = mpsc::unbounded();
            pipe!(@error(conn_error) rcvd_stream_ctrl_frames |> data_streams, recv_stream_control);
            let (stream_frames_entry, rcvd_stream_frames) = mpsc::unbounded();
            pipe!(@error(conn_error) rcvd_stream_frames |> data_streams, recv_data);
            let (datagram_frames_entry, rcvd_datagram_frames) = mpsc::unbounded();
            pipe!(@error(conn_error) rcvd_datagram_frames |> datagram_flow,recv_datagram);

            let crypto_stream_outgoing = data_crypto_stream.outgoing();
            let on_ack = move |ack_frame: &AckFrame| {
                let record = space.sent_packets();
                let mut recv_guard = record.receive();
                recv_guard.update_largest(ack_frame.largest.into_inner());

                for pn in ack_frame.iter().flat_map(|r| r.rev()) {
                    for frame in recv_guard.on_pkt_acked(pn) {
                        match frame {
                            ReliableFrame::Data(DataFrame::Stream(stream_frame)) => {
                                data_streams.on_data_acked(stream_frame)
                            }
                            ReliableFrame::Data(DataFrame::Crypto(crypto)) => {
                                crypto_stream_outgoing.on_data_acked(&crypto)
                            }
                            // qrecovery::reliable::ReliableFrame::NewToken(_) => todo!(),
                            // qrecovery::reliable::ReliableFrame::MaxData(_) => todo!(),
                            // qrecovery::reliable::ReliableFrame::DataBlocked(_) => todo!(),
                            // qrecovery::reliable::ReliableFrame::NewConnectionId(_) => todo!(),
                            // qrecovery::reliable::ReliableFrame::RetireConnectionId(_) => todo!(),
                            // qrecovery::reliable::ReliableFrame::HandshakeDone(_) => todo!(),
                            // qrecovery::reliable::ReliableFrame::Stream(_) => todo!(),
                            _ => {}
                        }
                    }
                }
            };
            let (ack_frames_entry, rcvd_ack_frames) = mpsc::unbounded();

            pipe!(rcvd_ack_frames |> on_ack);
            let (ccf_entry, rcvd_ccf) = mpsc::unbounded();

            pipe!(rcvd_ccf |> conn_error, on_ccf_rcvd);
            let space = data_space.clone();

            async move {
                let dispatch_frames_of_1rtt_packet = |frame: Frame, path: &ArcPath| {
                    let is_ack_eliciting = frame.is_ack_eliciting();
                    match frame {
                        Frame::Close(ccf) => {
                            _ = ccf_entry.unbounded_send(ccf);
                        }
                        Frame::NewToken(new_token) => {
                            _ = new_token_frames_entry.unbounded_send(new_token);
                        }
                        Frame::MaxData(max_data) => {
                            _ = max_data_frames_entry.unbounded_send(max_data);
                        }
                        Frame::NewConnectionId(new_cid) => {
                            _ = new_cid_frames_entry.unbounded_send(new_cid);
                        }
                        Frame::RetireConnectionId(retire_cid) => {
                            _ = retire_cid_frames_entry.unbounded_send(retire_cid);
                        }
                        Frame::HandshakeDone(hs_done) => {
                            _ = handshake_done_frames_entry.unbounded_send(hs_done);
                        }
                        Frame::DataBlocked(_) => { /* ignore */ }
                        Frame::Ack(ack_frame) => {
                            path.on_ack(EPOCH, &ack_frame);
                            _ = ack_frames_entry.unbounded_send(ack_frame);
                        }
                        Frame::Challenge(challenge) => {
                            path.recv_challenge(challenge);
                        }
                        Frame::Response(response) => {
                            path.recv_response(response);
                        }
                        Frame::Stream(stream_ctrl) => {
                            _ = stream_ctrl_frames_entry.unbounded_send(stream_ctrl);
                        }
                        Frame::Data(DataFrame::Stream(stream), data) => {
                            _ = stream_frames_entry.unbounded_send((stream, data));
                        }
                        Frame::Data(DataFrame::Crypto(crypto), data) => {
                            _ = data_crypto_frames_entry.unbounded_send((crypto, data));
                        }
                        Frame::Datagram(datagram, data) => {
                            _ = datagram_frames_entry.unbounded_send((datagram, data));
                        }
                        _ => {}
                    }
                    is_ack_eliciting
                };

                let rcvd_packets = space.rcvd_packets();
                while let Some((packet, path)) = packets.next().await {
                    let pty = packet.header.get_type();
                    let decode_pn = |pn| rcvd_packets.decode_pn(pn).ok();
                    let payload_opt = decode_short_header_packet(packet, &keys, decode_pn).await;

                    let Some(payload) = payload_opt else {
                        return;
                    };

                    let dispath_result = FrameReader::new(payload.payload, pty).try_fold(
                        false,
                        |is_ack_packet, frame| {
                            Ok(is_ack_packet || dispatch_frames_of_1rtt_packet(frame?, &path))
                        },
                    );

                    match dispath_result {
                        // TODO：到底有什么用？
                        Ok(is_ack_packet) => {
                            space.rcvd_packets().register_pn(payload.pn);
                            path.on_recv_pkt(EPOCH, payload.pn, is_ack_packet);
                        }
                        Err(e) => conn_error.on_error(e),
                    }
                }
            }
        });

        // tokio::spawn({
        //     let conn_error = conn_error.clone();
        //     let data_streams = data_streams.clone();
        //     let datagram_flow = datagram_flow.clone();
        //     async move {
        //         let (error, is_active) = conn_error.did_error_occur().await;
        //         data_streams.on_conn_error(&error);
        //         datagram_flow.on_conn_error(&error);

        //         let countdown = tokio::spawn(async {
        //             tokio::time::sleep(Duration::from_secs(3 /* * PTO */)).await;
        //             // final cleanup
        //         });

        //         if is_active {
        //             let recv_ccf = async {
        //                 loop {
        //                     if let (e, false) = conn_error.did_error_occur().await {
        //                         return e;
        //                     }
        //                 }
        //             };

        //             tokio::select! {
        //                 _ = countdown => {}
        //                 _ = recv_ccf => {
        //                     // enter draining
        //                 }
        //             }
        //             // enter closing
        //         } else {
        //             // enter draining
        //         }
        //     }
        // });

        Self {
            pathes,
            cid_registry,
            handshake,
            flow_control,
            initial_space,
            initial_crypto_stream,
            initial_packet_queue,
            initial_keys,
            handshake_space,
            handshake_crypto_stream,
            handshake_packet_queue,
            handshake_keys,
            data_space,
            data_crypto_stream,
            data_streams,
            data_reliable_frames_deque,
            zero_rtt_packet_queue,
            zero_rtt_keys,
            one_rtt_packet_queue,
            one_rtt_keys,
            datagram_flow,
            spin,
            error: conn_error,
        }
    }

    pub fn recv_packet_via_path(&self, packet: SpacePacket, path: ArcPath) {
        match packet {
            SpacePacket::Initial(packet) => {
                _ = self.initial_packet_queue.unbounded_send((packet, path))
            }
            SpacePacket::Handshake(packet) => {
                _ = self.handshake_packet_queue.unbounded_send((packet, path))
            }
            SpacePacket::ZeroRtt(packet) => {
                _ = self.zero_rtt_packet_queue.unbounded_send((packet, path))
            }
            SpacePacket::OneRtt(packet) => {
                _ = self.one_rtt_packet_queue.unbounded_send((packet, path))
            }
        }
    }

    pub fn get_path(&self, pathway: Pathway, usc: &ArcUsc) -> ArcPath {
        self.pathes
            .entry(pathway)
            .or_insert_with(|| {
                let _ = (pathway, usc);
                unimplemented!()
            })
            .value()
            .clone()
    }
}

pub(crate) struct PacketPayload {
    pub pn: u64,
    pub payload: Bytes,
}

async fn decode_long_header_packet<P>(
    mut packet: P,
    keys: &ArcKeys,
    decode_pn: impl FnOnce(PacketNumber) -> Option<u64>,
) -> Option<PacketPayload>
where
    P: DecodeHeader<Output = PacketNumber> + DecryptPacket + RemoteProtection,
{
    let k = keys.get_remote_keys().await?;

    if !packet.remove_protection(k.remote.header.deref()) {
        return None;
    }

    let encoded_pn = packet.decode_header().ok()?;
    let pn = decode_pn(encoded_pn)?;
    let payload = packet
        .decrypt_packet(pn, encoded_pn.size(), k.remote.packet.deref())
        .ok()?;

    Some(PacketPayload { pn, payload })
}

pub(crate) async fn decode_short_header_packet(
    mut packet: OneRttPacket,
    keys: &ArcOneRttKeys,
    decode_pn: impl FnOnce(PacketNumber) -> Option<u64>,
) -> Option<PacketPayload> {
    let (hk, pk) = keys.get_remote_keys().await?;

    if !packet.remove_protection(hk.deref()) {
        return None;
    }

    let (encoded_pn, key_phase) = packet.decode_header().ok()?;
    let pn = decode_pn(encoded_pn)?;
    let packet_key = pk.lock().unwrap().get_remote(key_phase, pn);
    let payload = packet
        .decrypt_packet(pn, encoded_pn.size(), packet_key.deref())
        .ok()?;

    Some(PacketPayload { pn, payload })
}
