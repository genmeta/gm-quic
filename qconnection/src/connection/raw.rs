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
    frame::{AckFrame, BeFrame, ConnFrame, DataFrame, Frame, FrameReader, PureFrame},
    packet::{
        self,
        decrypt::{DecodeHeader, DecryptPacket, RemoteProtection},
        keys::{ArcKeys, ArcOneRttKeys},
        HandshakePacket, InitialPacket, OneRttPacket, PacketNumber, SpacePacket, SpinBit,
        ZeroRttPacket,
    },
    streamid::Role,
};
use qrecovery::{
    crypto::CryptoStream,
    reliable::ArcReliableFrameDeque,
    space::{DataSpace, HandshakeSpace, InitialSpace},
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
    initial_packet_queue: InitialPacketQueue,
    initial_keys: ArcKeys,

    handshake_space: HandshakeSpace,
    handshake_crypto_stream: CryptoStream,
    handshake_packet_queue: HandshakePacketQueue,
    handshake_keys: ArcKeys,

    data_space: DataSpace,
    data_crypto_stream: CryptoStream,
    data_streams: DataStreams,
    flow_control: FlowController,

    zero_rtt_packet_queue: ZeroRttPacketQueue,
    zero_rtt_keys: ArcKeys,
    one_rtt_packet_queue: OneRttPacketQueue,
    one_rtt_keys: ArcOneRttKeys,

    datagram_flow: DatagramFlow,
}

impl RawConnection {
    pub fn new(role: Role, tls_session: TlsSession) -> Self {
        let pathes = DashMap::new();
        let cid_registry = Registry::new(2);
        let spin = Arc::new(Mutex::new(SpinBit::Off));
        let conn_error = ConnError::new();

        let initial_space = InitialSpace::with_capacity(0);
        let initial_crypto_stream = CryptoStream::new(0, 0);
        let initial_keys = ArcKeys::new_pending();

        let handshake_space = HandshakeSpace::with_capacity(0);
        let handshake_crypto_stream = CryptoStream::new(0, 0);
        let handshake_keys = ArcKeys::new_pending();

        let data_space = DataSpace::with_capacity(0);
        let data_crypto_stream = CryptoStream::new(0, 0);
        let data_streams =
            DataStreams::with_role_and_limit(role, 0, 0, ArcReliableFrameDeque::clone(&data_space));
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
                    for record in recv_guard.on_pkt_acked(pn) {
                        crypto_stream.on_data_acked(record);
                    }
                }
            };

            let space = initial_space.clone();
            let crypto_stream = initial_crypto_stream.clone();
            let keys = initial_keys.clone();

            let conn_error = conn_error.clone();

            let (ack_frames_entry, rcvd_ack_frames) = mpsc::unbounded();
            let (crypto_frames_entry, rcvd_crypto_frames) = mpsc::unbounded();

            pipe!(rcvd_ack_frames |> on_ack);
            pipe!(rcvd_crypto_frames |> crypto_stream, recv_data);

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
                        Frame::Pure(PureFrame::Ack(ack_frame)) => {
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
                    let payload_opt =
                        decode_long_header_packet(packet, keys.clone(), decode_pn).await;

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
                        Ok(_) => {}
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
                    for record in recv_guard.on_pkt_acked(pn) {
                        crypto_stream.on_data_acked(record);
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
            pipe!(rcvd_crypto_frames |> crypto_stream, recv_data);

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
                        Frame::Pure(PureFrame::Ack(ack_frame)) => {
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
                    let payload_opt =
                        decode_long_header_packet(packet, keys.clone(), decode_pn).await;

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
                        Ok(_) => {}
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
            // let (data_blocked_frames_entry, rcvd_data_blocked_frames) = mpsc::unbounded(); ignore
            let (stream_ctrl_frames_entry, rcvd_stream_ctrl_frames) = mpsc::unbounded();
            let (stream_frames_entry, rcvd_stream_frames) = mpsc::unbounded();
            let (datagram_frames_entry, rcvd_datagram_frames) = mpsc::unbounded();

            pipe!(rcvd_max_data_frames |> *flow_control.sender(),recv_max_data_frame);
            pipe!(rcvd_stream_ctrl_frames |> data_streams,recv_stream_control);
            pipe!(rcvd_stream_frames |> data_streams,recv_data);
            pipe!(rcvd_datagram_frames |> datagram_flow,recv_datagram);

            // data_streams.recv_stream_control()
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
                        Frame::Pure(PureFrame::Conn(ConnFrame::MaxData(max_data))) => {
                            _ = max_data_frames_entry.unbounded_send(max_data);
                            Ok(true)
                        }
                        Frame::Pure(PureFrame::Stream(stream_ctrl)) => {
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
                    let payload_opt =
                        decode_long_header_packet(packet, keys.clone(), decode_pn).await;

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
                        Ok(_) => {}
                        Err(e) => conn_error.on_error(e),
                    }
                }
            }
        });

        Self {
            pathes,
            cid_registry,
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
    keys: ArcKeys,
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
    keys: ArcOneRttKeys,
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
