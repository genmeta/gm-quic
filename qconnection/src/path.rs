use qbase::{cid::ConnectionId, frame::PathFrame};
use qrecovery::{frame_queue::ArcFrameQueue, rtt::Rtt};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

#[derive(Debug, PartialEq, Eq)]
pub struct RelayAddr {
    agent: SocketAddr,
    target: SocketAddr,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PathId {
    Direct {
        local: SocketAddr,
        remote: SocketAddr,
    },
    Relay {
        local: RelayAddr,
        remote: RelayAddr,
    },
}

#[derive(Debug)]
pub struct Path {
    path_id: PathId,
    scid: ConnectionId, // scid.len == 0 表示没有使用连接id
    dcid: ConnectionId, // dcid.len == 0 表示没有使用连接id

    // 待发包队列
    frames: ArcFrameQueue<PathFrame>,
    rtt: Arc<Mutex<Rtt>>,
    // TODO: 维护PTO、路径是否丢失等状态，还有BBR控制器
    // 可重传的帧队列，因为判定了该path的包，要重传。但也可反馈给SentPacketManager，让其决定是否重传
}

pub struct ArcPath(Arc<Path>);

impl ArcPath {
    pub fn new(path_id: PathId, scid: ConnectionId, dcid: ConnectionId) -> Self {
        Self(Arc::new(Path {
            path_id,
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
