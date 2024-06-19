use qbase::{
    cid::ConnectionId,
    packet::{HandshakePacket, InitialPacket, OneRttPacket, ZeroRttPacket},
};
use qcongestion::congestion::ArcCongestionController;
use qudp::ArcUsc;
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::sync::mpsc::UnboundedSender;

pub mod anti_amplifier;
pub use anti_amplifier::ArcAntiAmplifier;

pub mod validate;
pub use validate::{Transponder, Validator};

pub mod observer;
pub use observer::{AckObserver, LossObserver};

use crate::Sendmsg;

#[derive(Debug, PartialEq, Eq)]
pub struct RelayAddr {
    agent: SocketAddr, // 代理人
    addr: SocketAddr,
}

/// 无论哪种Pathway，socket都必须绑定local地址
#[derive(Debug, PartialEq, Eq)]
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
    way: Pathway,
    scid: ConnectionId, // scid.len == 0 表示没有使用连接id
    dcid: ConnectionId, // dcid.len == 0 表示没有使用连接id。发包时填充

    // PathState，包括新建待验证（有抗放大攻击响应限制），已发挑战验证中，验证通过，再挑战，再挑战验证中，后三者无抗放大攻击响应限制
    validator: Validator,
    // 不包括被动收到PathRequest，响应Response，这是另外一个单独的控制，分为无挑战/有挑战未响应/响应中，响应被确认
    transponder: Transponder,

    // 拥塞控制器。另外还有连接级的流量控制、流级别的流量控制，以及抗放大攻击
    // 但这只是正常情况下。当连接处于Closing状态时，庞大的拥塞控制器便不再适用，而是简单的回应ConnectionCloseFrame。
    cc: ArcCongestionController<AckObserver, LossObserver>,
    // udp socket controller, impl Sendmsg + ViaPathway
    usc: ArcUsc,
}

pub struct ArcPath(Arc<Mutex<RawPath>>);

/// 可能用不着。虽然想要QUIC连接的收发分离，在连接ID => Connection的hash表里，找到Connection，
/// Connection只需要一个类似如下收包器即可。然而，新路径创建，下面的信息是不够的。
/// 因此，只好将ArcConnection放在 Cid => Connection的hash表里，让连接先收到包，
/// 连接在找到Path，没有则创建，然后塞进对应的收包队列里。所以，下面这个结构用不着
pub struct PathPacketReceiver {
    path: ArcPath,
    // 以下几个队列，不应在这样一个结构里，而是在Pathway => {[queue...]}这样一个hash表里
    // 根据连接id，找到Connection，再根据Pathway找到Path的收包队列，但是扔进收包队列时，需要标记那个path接收的
    // 为什么呢？因为，Path收到数据了，还要反馈给Path的controller，包括验证器、响应器、发送控制器
    // Path发送需要带上[scid, dcid]，
    initial_pkt_tx: UnboundedSender<(InitialPacket, ArcPath)>,
    handshake_pkt_tx: UnboundedSender<(HandshakePacket, ArcPath)>,
    zero_rtt_pkt_tx: UnboundedSender<(ZeroRttPacket, ArcPath)>,
    one_rtt_pkt_tx: UnboundedSender<(OneRttPacket, ArcPath)>,
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
