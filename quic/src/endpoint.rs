use crate::connection::Connection;
use bytes::BytesMut;
use qbase::{
    cid::ConnectionId,
    packet::{BeProtected, ProtectedInitialHeader},
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
            let first_bytes = header.first_byte_mut();
            // let packet = &mut packet;
            let (pn_offset, sample) = packet.split_at_mut(4);
            let result = keys
                .remote
                .header
                .decrypt_in_place(sample, first_bytes, pn_offset);
            // 1.获取pn_length
            // 2.读取pn
            // 3.解密packet
        }
        // todo
    }
}
