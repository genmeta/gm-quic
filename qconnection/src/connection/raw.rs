use std::net::SocketAddr;

use dashmap::DashMap;
use futures::channel::mpsc;
use qbase::{
    cid::Registry,
    flow::FlowController,
    packet::{
        header,
        keys::{ArcKeys, ArcOneRttKeys},
        PacketWrapper, SpinBit,
    },
};
use qrecovery::{
    crypto::CryptoStream,
    space::{DataSpace, HandshakeSpace, InitialSpace},
    streams::DataStreams,
};

use crate::{crypto::TlsSession, error::ConnError};

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

pub struct ArcPath;

type PacketQueue<H> = mpsc::UnboundedSender<(PacketWrapper<H>, ArcPath)>;

pub type InitialPacketQueue = PacketQueue<header::InitialHeader>;
pub type HandshakePacketQueue = PacketQueue<header::HandshakeHeader>;
pub type ZeroRttPacketQueue = PacketQueue<header::ZeroRttHeader>;
pub type OneRttPacketQueue = PacketQueue<header::OneRttHeader>;

/// unimplemented

pub struct RawConnection {
    pathes: DashMap<Pathway, ArcPath>,
    cid_registry: Registry,

    initial_space: InitialSpace,
    initial_crypto_stream: CryptoStream,
    initial_packet_queue: InitialPacketQueue,
    initial_keys: ArcKeys,

    handshake_space: HandshakeSpace,
    handshake_crypto_stream: CryptoStream,
    handshake_packet_queue: InitialPacketQueue,
    handshake_keys: ArcKeys,

    data_space: DataSpace,
    data_crypto_stream: CryptoStream,
    data_streams: DataStreams,
    flow_control: FlowController,

    zero_rtt_packet_queue: ZeroRttPacketQueue,
    zero_rtt_keys: ArcKeys,
    one_rtt_packet_queue: OneRttPacketQueue,
    one_rtt_keys: ArcOneRttKeys,

    spin: SpinBit,
    error: ConnError,
}

impl RawConnection {
    pub fn new(tls_session: TlsSession) -> Self {
        todo!()
    }
}
