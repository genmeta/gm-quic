use std::collections::HashMap;

use qbase::{
    cid::ConnectionId,
    packet::{header::GetDcid, SpacePacket},
};

use crate::{connection::ArcConnection, ReceiveProtectedPacket};

pub struct Endpoint {
    // 尚未实现连接迁移
    connections: HashMap<ConnectionId, ArcConnection>,
    // 新连接的监听器
    // listener: Listener,
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
