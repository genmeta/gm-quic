use qbase::cid::ConnectionId;
use qcongestion::congestion::CongestionController;
use std::{net::SocketAddr, sync::Arc};

pub mod validate;
pub use validate::{ResponseState, ValidateState};

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

/// Path代表一个连接的路径，一个路径就相当于一个子传输控制，它主要有2个功能
/// - 收包：将收到的包，包括Initial/Handshake/0RTT/1RTT的，放进各自队列里即可，
///   后续有专门的任务处理这些包，包括解包、解密等。
/// - 发包：发包受拥塞控制、流量控制，从异步角度看是一个无限循环，循环体：
///   - 异步地获取积攒的发送信用
///   - 扫描有效space，从中读取待发数据，以及是否发送Ack，Path帧，装包、记录
pub struct RawPath<OA, OL> {
    id: PathId,
    scid: ConnectionId, // scid.len == 0 表示没有使用连接id
    dcid: ConnectionId, // dcid.len == 0 表示没有使用连接id。发包时填充

    // PathState，包括新建待验证（有抗放大攻击响应限制），已发挑战验证中，验证通过，再挑战，再挑战验证中，后三者无抗放大攻击响应限制
    validator: ValidateState,
    // 不包括被动收到PathRequest，响应Response，这是另外一个单独的控制，分为无挑战/有挑战未响应/响应中，响应被确认
    transponder: ResponseState,

    // 拥塞控制器。另外还有连接级的流量控制、流级别的流量控制，以及抗放大攻击
    // 但这只是正常情况下。当连接处于Closing状态时，庞大的拥塞控制器便不再适用，而是简单的回应ConnectionCloseFrame。
    cc: CongestionController<OA, OL>,
}

pub struct ArcPath<OA, OL>(Arc<RawPath<OA, OL>>);

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn read_initial_packet() {
        // 构造一个Path结构
        // let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        // let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081);
        // let peer_cid = ConnectionId::from_slice(b"peer cid");
        // let path = super::Path::new(local_addr, peer_addr, peer_cid);

        // let _packet = path.read_1rtt_packet().await;
    }
}
