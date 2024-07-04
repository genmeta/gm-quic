use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use anti_amplifier::ANTI_FACTOR;
use observer::{ConnectionObserver, PathObserver};
use qbase::cid::ConnectionId;
use qcongestion::congestion::ArcCC;
use qudp::ArcUsc;

pub mod anti_amplifier;
pub use anti_amplifier::ArcAntiAmplifier;

pub mod validate;
pub use validate::{Transponder, Validator};

pub mod observer;
pub use observer::{AckObserver, LossObserver};

use crate::Sendmsg;

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct RelayAddr {
    agent: SocketAddr, // 代理人
    addr: SocketAddr,
}

/// 无论哪种Pathway，socket都必须绑定local地址
#[derive(Debug, PartialEq, Eq, Hash)]
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

/// 通过一个路径发送报文，前提是该路径的本地地址，必须是路径的local地址一致
pub trait ViaPathway {
    fn sendmsg_via_pathway(&mut self, msg: &[u8], pathway: Pathway) -> std::io::Result<usize>;
}

impl<T> ViaPathway for T
where
    T: Sendmsg,
{
    fn sendmsg_via_pathway(&mut self, _msg: &[u8], _pathway: Pathway) -> std::io::Result<usize> {
        // 1. (optional)验证local bind address == pathway.local.addr
        // 2. 直发就是sendmsg to pathway.remote；转发就是封一个包头，发给pathway.remote.agent

        todo!()
    }
}

/// Path代表一个连接的路径，一个路径就相当于一个子传输控制，它主要有2个功能
/// - 收包：将收到的包，包括Initial/Handshake/0RTT/1RTT的，放进各自队列里即可，
///   后续有专门的任务处理这些包，包括解包、解密等。
/// - 发包：发包受拥塞控制、流量控制，从异步角度看是一个无限循环，循环体：
///   - 异步地获取积攒的发送信用
///   - 扫描有效space，从中读取待发数据，以及是否发送Ack，Path帧，装包、记录
pub struct RawPath {
    // udp socket controller, impl Sendmsg + ViaPathway
    usc: ArcUsc,

    // 连接id信息，当长度为0时，表示不使用连接id
    // 我方的连接id，发长包时需要，后期发短包不再需要。而收包的时候，只要是任何我方的连接id，都可以。
    // 发长包的时候，获取当前连接我方有效的一个连接id即可，因此我方的连接id并不在此管理。
    // TODO: 这里应该是个共享的我方连接id，随时获取最新的我方连接id即可
    //       但这个信息，在发送任务里维护即可。

    // 对方的连接id，发包时需要。它在创建的时候，代表着一个新路径，新路径需要使用新的连接id向对方发包。
    // Ref RFC9000 9.3 If the recipient has no unused connection IDs from the peer, it
    // will not be able to send anything on the new path until the peer provides one
    // 所以，这里应是一个对方的连接id管理器，可以异步地获取一个连接id，旧的连接id也会被废弃重新分配，
    // 是动态变化的。(暂时用Option<ConnectionId>来表示)
    peer_cid: Option<ConnectionId>,

    // 拥塞控制器。另外还有连接级的流量控制、流级别的流量控制，以及抗放大攻击
    // 但这只是正常情况下。当连接处于Closing状态时，庞大的拥塞控制器便不再适用，而是简单的回应ConnectionCloseFrame。
    cc: ArcCC<ConnectionObserver, PathObserver>,

    // 抗放大攻击控制器, 服务端地址验证之前有效
    // 连接建立隐式提供了地址验证
    // 1. 服务端收到对方的 handshake 包即代表验证了对方地址
    // 2. 服务端发送 Retry 包, 收到对方的 Initial包后，其中携带了包含在Retry包中提供的令牌
    // 3. 0-RTT 连接中，收到客户端携带服务端使用 NEW_TOKEN 颁发的令牌
    anti_amplifier: Option<ArcAntiAmplifier<ANTI_FACTOR>>,

    // PathState，包括新建待验证（有抗放大攻击响应限制），已发挑战验证中，验证通过，再挑战，再挑战验证中，后三者无抗放大攻击响应限制
    validator: Validator,
    // 不包括被动收到PathRequest，响应Response，这是另外一个单独的控制，分为无挑战/有挑战未响应/响应中，响应被确认
    transponder: Transponder,
}

impl RawPath {
    fn new(usc: ArcUsc, max_ack_delay: Duration, connection_observer: ConnectionObserver) -> Self {
        use qcongestion::congestion::CongestionAlgorithm;

        let anti_amplifier = ArcAntiAmplifier::default();
        let path_observer = PathObserver::new(anti_amplifier.clone());
        Self {
            usc,
            peer_cid: None,
            validator: Validator::default(),
            transponder: Transponder::default(),
            anti_amplifier: Some(anti_amplifier),
            cc: ArcCC::new(
                CongestionAlgorithm::Bbr,
                max_ack_delay,
                connection_observer,
                path_observer,
            ),
        }
    }
}

#[derive(Clone)]
pub struct ArcPath(Arc<Mutex<RawPath>>);

impl ArcPath {
    pub fn new(
        usc: ArcUsc,
        max_ack_delay: Duration,
        connection_observer: ConnectionObserver,
    ) -> Self {
        Self(Arc::new(Mutex::new(RawPath::new(
            usc,
            max_ack_delay,
            connection_observer,
        ))))
    }
}

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
