use std::{
    net::SocketAddr,
    ops::Deref,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::Bytes;
use dashmap::DashMap;
use futures::{channel::mpsc, StreamExt};
use qbase::{
    cid::Registry,
    error::{Error, ErrorKind},
    flow::FlowController,
    frame::{
        AckFrame, BeFrame, DataFrame, Frame, FrameReader, PathChallengeFrame, PathResponseFrame,
    },
    packet::{
        self,
        decrypt::{DecodeHeader, DecryptPacket, RemoteProtection},
        header::GetType,
        keys::{ArcKeys, ArcOneRttKeys},
        HandshakePacket, InitialPacket, OneRttPacket, PacketNumber, SpacePacket, SpinBit,
        ZeroRttPacket,
    },
    streamid::Role,
};
use qrecovery::{
    crypto::{ArcCryptoFrameDeque, CryptoStream},
    reliable::{ArcReliableFrameDeque, ReliableFrame},
    space::{DataSpace, Epoch, HandshakeSpace, InitialSpace},
    streams::DataStreams,
};
use qudp::ArcUsc;
use qunreliable::DatagramFlow;

use crate::{crypto::TlsSession, error::ConnError, pipe};

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

/// unimplemented
#[derive(Clone)]
pub struct ArcPath;

impl ArcPath {
    pub fn on_ack(&self, ack: &AckFrame) {
        _ = ack;
    }

    pub fn on_recv_pkt(&self, epoch: Epoch, pn: u64) {
        _ = (epoch, pn);
    }

    pub fn recv_path_challenge_frame(&self, frame: PathChallengeFrame) -> Result<(), Error> {
        _ = frame;
        Ok(())
    }

    pub fn recv_path_response_frame(&self, frame: PathResponseFrame) -> Result<(), Error> {
        _ = frame;
        Ok(())
    }
}

type PacketQueue<P> = mpsc::UnboundedSender<(P, ArcPath)>;

pub type InitialPacketQueue = PacketQueue<InitialPacket>;
pub type HandshakePacketQueue = PacketQueue<HandshakePacket>;
pub type ZeroRttPacketQueue = PacketQueue<ZeroRttPacket>;
pub type OneRttPacketQueue = PacketQueue<OneRttPacket>;

pub struct RawConnection {
    pathes: DashMap<Pathway, ArcPath>,
    cid_registry: Registry,
    spin: Arc<Mutex<SpinBit>>,
    error: ConnError,

    initial_space: InitialSpace,
    initial_crypto_stream: CryptoStream,
    initial_crypto_frames_deque: ArcCryptoFrameDeque,
    initial_packet_queue: InitialPacketQueue,
    initial_keys: ArcKeys,

    handshake_space: HandshakeSpace,
    handshake_crypto_stream: CryptoStream,
    handshake_crypto_frames_deque: ArcCryptoFrameDeque,
    handshake_packet_queue: HandshakePacketQueue,
    handshake_keys: ArcKeys,

    data_space: DataSpace,
    data_crypto_stream: CryptoStream,
    data_streams: DataStreams,
    data_reliable_frames_deque: ArcReliableFrameDeque,
    flow_control: FlowController,

    zero_rtt_packet_queue: ZeroRttPacketQueue,
    zero_rtt_keys: ArcKeys,
    one_rtt_packet_queue: OneRttPacketQueue,
    one_rtt_keys: ArcOneRttKeys,

    datagram_flow: DatagramFlow,
}

type PacketType = packet::r#type::Type;

impl RawConnection {
    pub fn new(role: Role, tls_session: TlsSession) -> Self {
        let pathes = DashMap::new();
        let cid_registry = Registry::new(2);
        let spin = Arc::new(Mutex::new(SpinBit::Off));
        let conn_error = ConnError::default();

        let initial_space = InitialSpace::with_capacity(0);
        let initial_crypto_stream = CryptoStream::new(0, 0);
        let initial_crypto_frames_deque = ArcCryptoFrameDeque::with_capacity(0);
        let initial_keys = ArcKeys::new_pending();

        let handshake_space = HandshakeSpace::with_capacity(0);
        let handshake_crypto_stream = CryptoStream::new(0, 0);
        let handshake_crypto_frames_deque = ArcCryptoFrameDeque::with_capacity(0);
        let handshake_keys = ArcKeys::new_pending();

        let data_space = DataSpace::with_capacity(0);
        let data_crypto_stream = CryptoStream::new(0, 0);
        let data_reliable_frames_deque = ArcReliableFrameDeque::with_capacity(0);
        let data_streams =
            DataStreams::with_role_and_limit(role, 0, 0, data_reliable_frames_deque.clone());
        let flow_control = FlowController::with_initial(0, 0);
        let zero_rtt_keys = ArcKeys::new_pending();
        let one_rtt_keys = ArcOneRttKeys::new_pending();

        let datagram_flow = DatagramFlow::new(0, 0);

        let (initial_packet_queue, initial_packets) = mpsc::unbounded();
        let (handshake_packet_queue, handshake_packets) = mpsc::unbounded();
        let (zero_rtt_packet_queue, zero_rtt_packets) = mpsc::unbounded();
        let (one_rtt_packet_queue, one_rtt_packets) = mpsc::unbounded();

        tokio::spawn({
            let mut packets = initial_packets;

            let space = initial_space.clone();
            let crypto_stream = initial_crypto_stream.clone();
            let on_ack = move |ack_frame: AckFrame| {
                let record = space.sent_packets();
                let mut recv_guard = record.receive();
                recv_guard.update_largest(ack_frame.largest.into_inner());

                for pn in ack_frame.iter().flat_map(|r| r.rev()) {
                    for frame in recv_guard.on_pkt_acked(pn) {
                        crypto_stream.on_data_acked(frame);
                    }
                }
            };

            let space = initial_space.clone();
            let crypto_stream = initial_crypto_stream.clone();
            let keys = initial_keys.clone();

            let conn_error = conn_error.clone();

            let (ack_frames_entry, rcvd_ack_frames) = mpsc::unbounded();
            pipe!(rcvd_ack_frames |> on_ack);
            let (crypto_frames_entry, rcvd_crypto_frames) = mpsc::unbounded();
            pipe!(@error(conn_error) rcvd_crypto_frames |> crypto_stream, recv_data);

            async move {
                let dispatch_frames_of_initial_packet = |frame: Frame, path: &ArcPath| {
                    let initial_packet_type = packet::r#type::Type::Long(
                        packet::r#type::long::Type::V1(packet::r#type::long::Version::INITIAL),
                    );
                    if !frame.belongs_to(initial_packet_type) {
                        return Err(Error::new(
                            ErrorKind::ProtocolViolation,
                            frame.frame_type(),
                            format!("cann't exist in {:?}", initial_packet_type),
                        ));
                    }
                    match frame {
                        Frame::Ack(ack_frame) => {
                            path.on_ack(&ack_frame);
                            _ = ack_frames_entry.unbounded_send(ack_frame);
                            Ok(false)
                        }
                        Frame::Data(DataFrame::Crypto(crypto), bytes) => {
                            _ = crypto_frames_entry.unbounded_send((crypto, bytes));
                            Ok(true)
                        }
                        _ => Ok(false),
                    }
                };

                let rcvd_packets = space.rcvd_packets();
                while let Some((packet, path)) = packets.next().await {
                    let decode_pn = |pn| rcvd_packets.decode_pn(pn).ok();
                    let payload_opt = decode_long_header_packet(packet, &keys, decode_pn).await;

                    let Some(payload) = payload_opt else {
                        return;
                    };

                    let dispath_result = FrameReader::new(payload.payload).try_fold(
                        false,
                        |is_ack_packet, frame| {
                            let frame = frame.map_err(Error::from)?;
                            dispatch_frames_of_initial_packet(frame, &path)
                                .map(|is_ack_frmae| is_ack_packet | is_ack_frmae)
                        },
                    );

                    match dispath_result {
                        // TODO：到底有什么用？
                        Ok(_is_ack_packet) => {
                            space.rcvd_packets().register_pn(payload.pn);
                            path.on_recv_pkt(Epoch::Initial, payload.pn);
                        }
                        Err(e) => conn_error.on_error(e),
                    }
                }
            }
        });

        tokio::spawn({
            let mut packets = handshake_packets;

            let space = handshake_space.clone();
            let crypto_stream = handshake_crypto_stream.clone();
            let on_ack = move |ack_frame: AckFrame| {
                let record = space.sent_packets();
                let mut recv_guard = record.receive();
                recv_guard.update_largest(ack_frame.largest.into_inner());

                for pn in ack_frame.iter().flat_map(|r| r.rev()) {
                    for frame in recv_guard.on_pkt_acked(pn) {
                        crypto_stream.on_data_acked(frame);
                    }
                }
            };

            let space = handshake_space.clone();
            let crypto_stream = handshake_crypto_stream.clone();
            let keys = handshake_keys.clone();

            let conn_error = conn_error.clone();

            let (ack_frames_entry, rcvd_ack_frames) = mpsc::unbounded();
            let (crypto_frames_entry, rcvd_crypto_frames) = mpsc::unbounded();

            pipe!(rcvd_ack_frames |> on_ack);
            pipe!(@error(conn_error) rcvd_crypto_frames |> crypto_stream, recv_data);

            async move {
                let dispatch_frames_of_handshake_packet = |frame: Frame, path: &ArcPath| {
                    let handshake_packet_type = packet::r#type::Type::Long(
                        packet::r#type::long::Type::V1(packet::r#type::long::Version::HANDSHAKE),
                    );
                    if !frame.belongs_to(handshake_packet_type) {
                        return Err(Error::new(
                            ErrorKind::ProtocolViolation,
                            frame.frame_type(),
                            format!("cann't exist in {:?}", handshake_packet_type),
                        ));
                    }
                    match frame {
                        Frame::Ack(ack_frame) => {
                            path.on_ack(&ack_frame);
                            _ = ack_frames_entry.unbounded_send(ack_frame);
                            Ok(false)
                        }
                        Frame::Data(DataFrame::Crypto(crypto), bytes) => {
                            _ = crypto_frames_entry.unbounded_send((crypto, bytes));
                            Ok(true)
                        }
                        _ => Ok(false),
                    }
                };

                let rcvd_packets = space.rcvd_packets();
                while let Some((packet, path)) = packets.next().await {
                    let decode_pn = |pn| rcvd_packets.decode_pn(pn).ok();
                    let payload_opt = decode_long_header_packet(packet, &keys, decode_pn).await;

                    let Some(payload) = payload_opt else {
                        return;
                    };

                    let dispath_result = FrameReader::new(payload.payload).try_fold(
                        false,
                        |is_ack_packet, frame| {
                            let frame = frame.map_err(Error::from)?;
                            dispatch_frames_of_handshake_packet(frame, &path)
                                .map(|is_ack_frmae| is_ack_packet | is_ack_frmae)
                        },
                    );

                    match dispath_result {
                        // TODO：到底有什么用？
                        Ok(_is_ack_packet) => {
                            space.rcvd_packets().register_pn(payload.pn);
                            path.on_recv_pkt(Epoch::Handshake, payload.pn);
                        }
                        Err(e) => conn_error.on_error(e),
                    }
                }
            }
        });

        tokio::spawn({
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
                    let handshake_packet_type = packet::r#type::Type::Long(
                        packet::r#type::long::Type::V1(packet::r#type::long::Version::HANDSHAKE),
                    );
                    if !frame.belongs_to(handshake_packet_type) {
                        return Err(Error::new(
                            ErrorKind::ProtocolViolation,
                            frame.frame_type(),
                            format!("cann't exist in {:?}", handshake_packet_type),
                        ));
                    }
                    match frame {
                        Frame::MaxData(max_data) => {
                            _ = max_data_frames_entry.unbounded_send(max_data);
                            Ok(true)
                        }
                        Frame::Stream(stream_ctrl) => {
                            _ = stream_ctrl_frames_entry.unbounded_send(stream_ctrl);
                            Ok(true)
                        }
                        Frame::Data(DataFrame::Stream(stream), data) => {
                            _ = stream_frames_entry.unbounded_send((stream, data));
                            Ok(true)
                        }
                        Frame::Datagram(datagram, data) => {
                            _ = datagram_frames_entry.unbounded_send((datagram, data));
                            Ok(false)
                        }
                        _ => Ok(false),
                    }
                };

                let rcvd_packets = space.rcvd_packets();
                while let Some((packet, path)) = packets.next().await {
                    let decode_pn = |pn| rcvd_packets.decode_pn(pn).ok();
                    let payload_opt = decode_long_header_packet(packet, &keys, decode_pn).await;

                    let Some(payload) = payload_opt else {
                        return;
                    };

                    let dispath_result = FrameReader::new(payload.payload).try_fold(
                        false,
                        |is_ack_packet, frame| {
                            let frame = frame.map_err(Error::from)?;
                            dispatch_frames_of_0rtt_packet(frame, &path)
                                .map(|is_ack_frmae| is_ack_packet | is_ack_frmae)
                        },
                    );

                    match dispath_result {
                        // TODO：到底有什么用？
                        Ok(_is_ack_packet) => {
                            space.rcvd_packets().register_pn(payload.pn);
                            path.on_recv_pkt(Epoch::Data, payload.pn);
                        }
                        Err(e) => conn_error.on_error(e),
                    }
                }
            }
        });

        tokio::spawn({
            let mut packets: mpsc::UnboundedReceiver<(OneRttPacket, ArcPath)> = one_rtt_packets;

            let keys = one_rtt_keys.clone();
            let space = data_space.clone();
            let data_streams = data_streams.clone();
            let crypto_stream = data_crypto_stream.clone();
            let conn_error = conn_error.clone();

            let (max_data_frames_entry, rcvd_max_data_frames) = mpsc::unbounded();
            pipe!(rcvd_max_data_frames |> *flow_control.sender(),recv_max_data_frame);
            // let (data_blocked_frames_entry, rcvd_data_blocked_frames) = mpsc::unbounded(); ignore

            // TODO: impl endpoint router
            let (new_cid_frames_entry, rcvd_new_cid_frames) = mpsc::unbounded();
            pipe!(@error(conn_error)  rcvd_new_cid_frames |> cid_registry.remote,recv_new_cid_frame);
            let (retire_cid_frames_entry, rcvd_retire_cid_frames) = mpsc::unbounded();
            pipe!(@error(conn_error)  rcvd_retire_cid_frames |> cid_registry.local,recv_retire_cid_frame);

            let (handshake_done_frames_entry, rcvd_handshake_done_frames) = mpsc::unbounded();
            let (new_token_frames_entry, rcvd_new_token_frames) = mpsc::unbounded();

            let (data_crypto_frames_entry, rcvd_data_crypto_frames) = mpsc::unbounded();
            pipe!(@error(conn_error) rcvd_data_crypto_frames |> crypto_stream, recv_data);
            let (stream_ctrl_frames_entry, rcvd_stream_ctrl_frames) = mpsc::unbounded();
            pipe!(@error(conn_error) rcvd_stream_ctrl_frames |> data_streams, recv_stream_control);
            let (stream_frames_entry, rcvd_stream_frames) = mpsc::unbounded();
            pipe!(@error(conn_error) rcvd_stream_frames |> data_streams, recv_data);
            let (datagram_frames_entry, rcvd_datagram_frames) = mpsc::unbounded();
            pipe!(@error(conn_error) rcvd_datagram_frames |> datagram_flow,recv_datagram);

            let on_ack = move |ack_frame: AckFrame| {
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
                                crypto_stream.on_data_acked(crypto)
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

            pipe!(rcvd_ccf |> conn_error, recv_ccf);
            let space = data_space.clone();

            async move {
                // 除了分发的错误之外，路径帧带来的错误也会在这里被返回（TODO: 路径帧会不会触发错误？）
                let dispatch_frames_of_1rtt_packet =
                    |frame: Frame, pty: PacketType, path: &ArcPath| {
                        if !frame.belongs_to(pty) {
                            return Err(Error::new(
                                ErrorKind::ProtocolViolation,
                                frame.frame_type(),
                                format!("cann't exist in {:?}", pty),
                            ));
                        }
                        match frame {
                            Frame::Close(ccf) => {
                                _ = ccf_entry.unbounded_send(ccf);
                                Ok(true)
                            }
                            Frame::NewToken(new_token) => {
                                _ = new_token_frames_entry.unbounded_send(new_token);
                                Ok(true)
                            }
                            Frame::MaxData(max_data) => {
                                _ = max_data_frames_entry.unbounded_send(max_data);
                                Ok(true)
                            }
                            Frame::NewConnectionId(new_cid) => {
                                _ = new_cid_frames_entry.unbounded_send(new_cid);
                                Ok(true)
                            }
                            Frame::RetireConnectionId(retire_cid) => {
                                _ = retire_cid_frames_entry.unbounded_send(retire_cid);
                                Ok(true)
                            }
                            Frame::HandshakeDone(hs_done) => {
                                _ = handshake_done_frames_entry.unbounded_send(hs_done);
                                Ok(true)
                            }
                            Frame::DataBlocked(_) => Ok(true),
                            Frame::Ack(ack_frame) => {
                                _ = ack_frames_entry.unbounded_send(ack_frame);
                                Ok(true)
                            }
                            Frame::Challenge(challenge) => {
                                path.recv_path_challenge_frame(challenge)?;
                                Ok(true)
                            }
                            Frame::Response(response) => {
                                path.recv_path_response_frame(response)?;
                                Ok(true)
                            }
                            Frame::Stream(stream_ctrl) => {
                                _ = stream_ctrl_frames_entry.unbounded_send(stream_ctrl);
                                Ok(true)
                            }
                            Frame::Data(DataFrame::Stream(stream), data) => {
                                _ = stream_frames_entry.unbounded_send((stream, data));
                                Ok(true)
                            }
                            Frame::Data(DataFrame::Crypto(crypto), data) => {
                                _ = data_crypto_frames_entry.unbounded_send((crypto, data));
                                Ok(true)
                            }
                            Frame::Datagram(datagram, data) => {
                                _ = datagram_frames_entry.unbounded_send((datagram, data));
                                Ok(false)
                            }
                            _ => Ok(false),
                        }
                    };

                let rcvd_packets = space.rcvd_packets();
                while let Some((packet, path)) = packets.next().await {
                    let pty = packet.header.get_type();
                    let decode_pn = |pn| rcvd_packets.decode_pn(pn).ok();
                    let payload_opt = decode_short_header_packet(packet, &keys, decode_pn).await;

                    let Some(payload) = payload_opt else {
                        return;
                    };

                    let dispath_result = FrameReader::new(payload.payload).try_fold(
                        false,
                        |is_ack_packet, frame| {
                            let frame = frame.map_err(Error::from)?;
                            dispatch_frames_of_1rtt_packet(frame, pty, &path)
                                .map(|is_ack_frmae| is_ack_packet | is_ack_frmae)
                        },
                    );

                    match dispath_result {
                        // TODO：到底有什么用？
                        Ok(_is_ack_packet) => {
                            space.rcvd_packets().register_pn(payload.pn);
                            path.on_recv_pkt(Epoch::Data, payload.pn);
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
            initial_space,
            initial_crypto_stream,
            initial_crypto_frames_deque,
            initial_packet_queue,
            initial_keys,
            handshake_space,
            handshake_crypto_stream,
            handshake_crypto_frames_deque,
            handshake_packet_queue,
            handshake_keys,
            data_space,
            data_crypto_stream,
            data_streams,
            data_reliable_frames_deque,
            flow_control,
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

async fn decode_short_header_packet(
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
