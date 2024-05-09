use crate::connection::Connection;
use bytes::BytesMut;
use qbase::{
    cid::ConnectionId,
    packet::{ext::decrypt_packet, ProtectedInitialHeader},
};
use rustls::{
    quic::{Keys, Version},
    Side,
};
use std::collections::HashMap;

pub struct Endpiont {
    // 尚未实现连接迁移，多个连接id对应一个连接的功能尚未实现
    connections: HashMap<ConnectionId, Connection>,
    // 新连接的监听器
    // listener: Listener,
}

impl Endpiont {
    pub fn receive_initial_packet(
        &mut self,
        mut header: ProtectedInitialHeader,
        mut packet: BytesMut,
        pn_offset: usize,
    ) {
        // only support RFC9000 version 1
        assert_eq!(header.version, 1);
        let dcid = &header.dcid;
        if let Some(conn) = self.connections.get_mut(dcid) {
            conn.receive_initial_packet(header, packet);
        } else {
            // new connection
            let keys = Keys::initial(Version::V1, dcid, Side::Server);
            // 下面这一步，应该在connection内部处理了
            let (pn, body) = decrypt_packet(header, packet, pn_offset, 0, &keys.remote).unwrap();
        }
        // todo
    }
}
