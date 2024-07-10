use std::sync::Arc;

use dashmap::DashMap;
use qbase::{
    cid::ConnectionId,
    packet::{header::GetDcid, SpacePacket},
    token::ResetToken,
};

use crate::{connection::ArcConnectionHandle, ReceiveProtectedPacket};

#[derive(Default)]
pub struct Endpoint {
    connections: Arc<DashMap<ConnectionId, ArcConnectionHandle>>,
    // 某条连接的对端的无状态重置令牌
    reset_tokens: Arc<DashMap<ResetToken, ArcConnectionHandle>>,
    // 新连接的监听器
    // listener: Listener,
}

impl Endpoint {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ReceiveProtectedPacket for Endpoint {
    fn receive_protected_packet(&mut self, protected_packet: SpacePacket) {
        let dcid = protected_packet.get_dcid();
        if let Some(_conn) = self.connections.get_mut(dcid) {
            // let _ = conn.receive_protected_packet(protected_packet);
        } else {
            match protected_packet {
                SpacePacket::Initial(_packet) => {
                    // TODO: 创建新连接，并塞给Listener
                }
                _other => {
                    // just ignore
                }
            }
        }
    }
}
