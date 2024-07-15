use std::sync::Arc;

use dashmap::DashMap;
use qbase::{
    cid::ConnectionId,
    packet::{header::GetDcid, SpacePacket},
    token::ResetToken,
};
use qudp::ArcUsc;

use crate::{connection::ArcConnectionHandle, path::Pathway, ReceiveProtectedPacket};

pub struct Endpoint {
    connections: Arc<DashMap<ConnectionId, ArcConnectionHandle>>,
    // 某条连接的对端的无状态重置令牌
    reset_tokens: Arc<DashMap<ResetToken, ArcConnectionHandle>>,
    // TODO: 管理多个 usc
    /// `UdpSocketController` manages a UDP socket with additional configurations,
    /// providing asynchronous I/O operations, TTL management, and support for GSO and GRO.
    usc: ArcUsc,
    // 新连接的监听器
    // listener: Listener,
}

impl Endpoint {
    pub fn new(usc: ArcUsc) -> Self {
        Self {
            connections: Arc::new(DashMap::new()),
            reset_tokens: Arc::new(DashMap::new()),
            usc,
        }
    }
}

impl ReceiveProtectedPacket for Endpoint {
    fn receive_protected_packet(&self, protected_packet: SpacePacket, pathway: Pathway) {
        let dcid = protected_packet.get_dcid();
        if let Some(conn) = self.connections.get(dcid) {
            conn.recv_protected_pkt_via(protected_packet, &self.usc, pathway);
        } else if let SpacePacket::Initial(_packet) = protected_packet {
            // TODO: 创建新连接，并塞给Listener
        }

        // In other cases, discard it directly
    }
}
