use qbase::cid::ConnectionId;
use qrecovery::rtt::Rtt;
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

#[derive(Debug)]
pub struct Path {
    // 以下4个字段，唯一标识一个Path。
    // 理论上，一个Path当前只能使用一个对方连接id，即便历史上有多个对方连接id应用在该Path上；
    // 一个Path可能有多个自己的连接id，收到一个目标连接id为任意自己的连接的，都要转到此Path上。
    // 根据quic规定，一个连接可能没有连接id，而仅使用地址4元组来唯一标识。
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    // local_cid: ConnectionId,
    peer_cid: ConnectionId, // peer_cid.len == 0 表示没有使用连接id

    rtt: Arc<Mutex<Rtt>>,
}

impl Path {
    pub fn new(local_addr: SocketAddr, peer_addr: SocketAddr, peer_cid: ConnectionId) -> Self {
        Self {
            local_addr,
            peer_addr,
            peer_cid,
            rtt: Arc::new(Mutex::new(Rtt::default())),
        }
    }
}

#[cfg(test)]
mod tests {
    use qbase::cid::ConnectionId;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[tokio::test]
    async fn read_initial_packet() {
        // 构造一个Path结构
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081);
        let peer_cid = ConnectionId::from_slice(b"peer cid");
        let path = super::Path::new(local_addr, peer_addr, peer_cid);

        // let _packet = path.read_1rtt_packet().await;
    }
}
