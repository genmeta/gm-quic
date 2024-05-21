use super::ArcFrameQueue;
use qbase::{cid::ConnectionId, frame::PathFrame};
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
    scid: ConnectionId, // scid.len == 0 表示没有使用连接id
    dcid: ConnectionId, // dcid.len == 0 表示没有使用连接id

    // 待发包队列
    frames: ArcFrameQueue<PathFrame>,
    rtt: Arc<Mutex<Rtt>>,
}

pub struct ArcPath(Arc<Path>);

impl ArcPath {
    pub fn new(
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        scid: ConnectionId,
        dcid: ConnectionId,
    ) -> Self {
        Self(Arc::new(Path {
            local_addr,
            peer_addr,
            scid,
            dcid,
            frames: ArcFrameQueue::new(),
            rtt: Arc::new(Mutex::new(Rtt::default())),
        }))
    }

    pub fn rtt(&self) -> Arc<Mutex<Rtt>> {
        self.0.as_ref().rtt.clone()
    }

    pub fn frames(&self) -> &ArcFrameQueue<PathFrame> {
        &(self.0.as_ref().frames)
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
        // let path = super::Path::new(local_addr, peer_addr, peer_cid);

        // let _packet = path.read_1rtt_packet().await;
    }
}
