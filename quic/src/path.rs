use qbase::{
    cid::ConnectionId,
    packet::{
        ProtectedHandshakePacket, ProtectedInitialPacket, ProtectedOneRttPacket,
        ProtectedZeroRTTPacket,
    },
};
use qrecovery::rtt::Rtt;
use std::{
    collections::VecDeque,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

#[derive(Debug, Default)]
struct RcvdPackets<T> {
    packets: VecDeque<T>,
    read_waker: Option<Waker>,
}

impl<T> RcvdPackets<T> {
    fn new() -> Self {
        Self {
            packets: VecDeque::with_capacity(4),
            read_waker: None,
        }
    }

    fn push(&mut self, value: T) {
        self.packets.push_back(value);
        if let Some(waker) = self.read_waker.take() {
            waker.wake();
        }
    }

    fn poll_read(&mut self, cx: &mut Context<'_>) -> Poll<T> {
        if let Some(packet) = self.packets.pop_front() {
            Poll::Ready(packet)
        } else {
            assert!(self.read_waker.is_none());
            self.read_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

type ArcRcvdPackets<T> = Arc<Mutex<RcvdPackets<T>>>;

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
    initial_packets: ArcRcvdPackets<ProtectedInitialPacket>,
    handshake_packets: ArcRcvdPackets<ProtectedHandshakePacket>,
    zero_rtt_packets: ArcRcvdPackets<ProtectedZeroRTTPacket>,
    one_rtt_packets: ArcRcvdPackets<ProtectedOneRttPacket>,
}

impl Path {
    pub fn new(local_addr: SocketAddr, peer_addr: SocketAddr, peer_cid: ConnectionId) -> Self {
        Self {
            local_addr,
            peer_addr,
            peer_cid,
            rtt: Arc::new(Mutex::new(Rtt::default())),
            initial_packets: Arc::new(Mutex::new(RcvdPackets::new())),
            handshake_packets: Arc::new(Mutex::new(RcvdPackets::new())),
            zero_rtt_packets: Arc::new(Mutex::new(RcvdPackets::new())),
            one_rtt_packets: Arc::new(Mutex::new(RcvdPackets::new())),
        }
    }

    pub fn receive_initial_packet(&self, packet: ProtectedInitialPacket) {
        self.initial_packets.lock().unwrap().push(packet);
    }

    pub fn receive_handshake_packet(&self, packet: ProtectedHandshakePacket) {
        self.handshake_packets.lock().unwrap().push(packet);
    }

    pub fn receive_0rtt_packet(&self, packet: ProtectedZeroRTTPacket) {
        self.zero_rtt_packets.lock().unwrap().push(packet);
    }

    pub fn receive_1rtt_packet(&self, packet: ProtectedOneRttPacket) {
        self.one_rtt_packets.lock().unwrap().push(packet);
    }

    pub fn read_initial_packet(&self) -> ReadPacket<ProtectedInitialPacket> {
        ReadPacket(self.initial_packets.clone())
    }

    pub fn read_handshake_packet(&self) -> ReadPacket<ProtectedHandshakePacket> {
        ReadPacket(self.handshake_packets.clone())
    }

    pub fn read_zero_rtt_packet(&self) -> ReadPacket<ProtectedZeroRTTPacket> {
        ReadPacket(self.zero_rtt_packets.clone())
    }

    pub fn read_1rtt_packet(&self) -> ReadPacket<ProtectedOneRttPacket> {
        ReadPacket(self.one_rtt_packets.clone())
    }
}

struct ReadPacket<T>(ArcRcvdPackets<T>);

impl<T> Future for ReadPacket<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.lock().unwrap().poll_read(cx)
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

        let packet = path.read_1rtt_packet().await;

        todo!()
    }
}
