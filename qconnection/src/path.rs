use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use anti_amplifier::ANTI_FACTOR;
use observer::{ConnectionObserver, PathObserver};
use qbase::{
    cid::ConnectionId,
    frame::{PathChallengeFrame, PathResponseFrame},
    util::TransportLimit,
};
use qcongestion::congestion::{ArcCC, Epoch};
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

    /// Check whether the path is verified.
    pub fn is_validated(&self) -> bool {
        self.0.lock().unwrap().validator.is_validated()
    }

    /// Path challenge can be used by any terminal at any time.
    pub fn challenge(&self) {
        self.0.lock().unwrap().validator.challenge()
    }

    /// Path challenge, if the path is not validated, the path challenge frame in
    /// the validator will be written, otherwise nothing is written
    pub fn write_challenge(&self, limit: &mut TransportLimit, buf: &mut [u8]) -> usize {
        self.0.lock().unwrap().validator.write_challenge(limit, buf)
    }

    /// Path challenge, if the path requires sending a challenge response frame,
    /// the challenge response frame in the Transponder will be written, otherwise
    /// nothing will be written.
    pub fn write_challenge_response(&self, limit: &mut TransportLimit, buf: &mut [u8]) -> usize {
        self.0
            .lock()
            .unwrap()
            .transponder
            .write_response(limit, buf)
    }

    /// Path challenge, this function must be called after sending the challenge
    /// frame, record its space and pn to mark it as sent.
    pub fn on_sent_path_challenge(&self, space: Epoch, pn: u64) {
        self.0
            .lock()
            .unwrap()
            .validator
            .on_challenge_sent(space, pn)
    }

    /// Path challenge, this function must called after sending the response frame
    pub fn on_sent_path_challenge_response(&self, pn: u64) {
        self.0.lock().unwrap().transponder.on_response_sent(pn)
    }

    /// Path challenge, receive the challenge frame in the Transponder
    pub fn on_recv_path_challenge(&self, challenge: PathChallengeFrame) {
        self.0.lock().unwrap().transponder.on_challenge(challenge)
    }

    /// Path challenge, changes the state of the path to verified when receiving
    /// the correct response frame, turns off protection against amplification
    /// attacks
    pub fn on_recv_path_challenge_response(&self, response: PathResponseFrame) {
        let mut validator = self.0.lock().unwrap().validator.clone();
        // Check whether the received response is consistent with the issued
        // challenge
        validator.on_response(&response);
        // If the verification is not successful, exit directly without turning
        // off anti-amplification attack protection.
        if !validator.is_validated() {
            return;
        }

        // Turn off anti amplification attacks protection
        if let Some(anti_amplifier) = self.0.lock().unwrap().anti_amplifier.take() {
            let waker = anti_amplifier.waker();
            if let Some(waker) = waker {
                waker.wake();
            }
        };
    }

    /// After the address validation passes, you can use this function to change
    /// the verification status and remove the anti-amplification attack protection.
    ///
    /// See [Section 8](https://www.rfc-editor.org/rfc/rfc9000.html#section-8)
    pub fn validated(&self) {
        self.0.lock().unwrap().validator.validated();

        // Turn off anti amplification attacks protection
        if let Some(anti_amplifier) = self.0.lock().unwrap().anti_amplifier.take() {
            let waker = anti_amplifier.waker();
            if let Some(waker) = waker {
                waker.wake();
            }
        };
    }

    // TODO: 在收到 challenge_response 的 ack 时, 需要调用此函数来更新状态
    /// When the peer receives the ack of the returned challenge response, the
    /// status is updated
    pub fn on_challenge_response_pkt_acked(&self, pn: u64) {
        self.0.lock().unwrap().transponder.on_pkt_acked(pn)
    }

    /// Anti-amplification attack protection, records the amount of data received
    /// by the current path
    pub fn deposit(&self, amount: usize) {
        if let Some(anti_amplifier) = self.0.lock().unwrap().anti_amplifier.as_ref() {
            anti_amplifier.deposit(amount);
        }
    }

    // TODO: 在发送 packet 时, 需要调用此函数来确认抗放大攻击保护信用
    /// Anti-amplification attack protection, detects whether the current path can
    /// send data of the specified size, and detects it before each packet is sent.
    pub fn poll_apply(&self, cx: &mut Context<'_>) -> Poll<Option<usize>> {
        match self.0.lock().unwrap().anti_amplifier.as_ref() {
            Some(anti_amplifier) => anti_amplifier.poll_apply(cx),
            None => Poll::Ready(None),
        }
    }

    // TODO: 发送 packet 后, 需要调用此函数, 以更新剩余的发送信用
    /// Called after each transmission, if the current path has anti-amplification
    /// attack protection, record the amount of data sent.
    pub fn post_sent(&self, amount: usize) {
        if let Some(anti_amplifier) = self.0.lock().unwrap().anti_amplifier.as_ref() {
            anti_amplifier.post_sent(amount)
        }
    }

    /// When the challenge frame may be lost, setting pn in the validator state
    /// to None will trigger a retransmission, but the transmitted frame will be
    /// the same. Even if the challenge is re-challenged, the frame will only
    /// change when the state changed from `Success` to `Rechallenging`.
    pub fn may_loss_challenge_pkt(&self) {
        self.0.lock().unwrap().validator.may_loss()
    }

    /// When the response frame may be lost, setting pn in the transponder state
    pub fn may_loss_challenge_response_pkt(&self, pn: u64) {
        self.0.lock().unwrap().transponder.may_loss_pkt(pn)
    }

    /// When creating a new path, start the path challenge timer
    pub fn set_path_challenge_timeout(&self) {
        self.0.lock().unwrap().validator.set_timeout()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        array,
        net::{IpAddr, Ipv4Addr},
    };

    use futures::task::noop_waker_ref;
    use observer::{HandShakeObserver, PtoObserver};
    use qrecovery::reliable::rcvdpkt::ArcRcvdPktRecords;
    use tokio::sync::mpsc;

    use super::*;
    use crate::connection::state::ArcConnectionState;

    async fn create_path(port: u16) -> ArcPath {
        // 构造一个Path结构
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
        let usc = ArcUsc::new(addr);
        let max_ack_delay = Duration::from_millis(100);
        let ack_observer = AckObserver::new(array::from_fn(|_| ArcRcvdPktRecords::default()));
        let (loss_tx1, _) = mpsc::unbounded_channel();
        let (loss_tx2, _) = mpsc::unbounded_channel();
        let (loss_tx3, _) = mpsc::unbounded_channel();
        let loss_observer = LossObserver::new([loss_tx1, loss_tx2, loss_tx3]);
        let handshake_observer = HandShakeObserver::new(ArcConnectionState::new());

        let (pto_tx1, _) = mpsc::unbounded_channel();
        let (pto_tx2, _) = mpsc::unbounded_channel();
        let (pto_tx3, _) = mpsc::unbounded_channel();
        let pto_observer = PtoObserver::new([pto_tx1, pto_tx2, pto_tx3]);
        ArcPath::new(
            usc,
            max_ack_delay,
            ConnectionObserver {
                ack_observer,
                loss_observer,
                handshake_observer,
                pto_observer,
            },
        )
    }

    #[tokio::test]
    async fn test_initial_packet() {
        let path = create_path(18000).await;
        assert!(!path.is_validated());
    }

    #[tokio::test]
    async fn test_challenge() {
        let path = create_path(18001).await;
        let mut cx = Context::from_waker(noop_waker_ref());

        assert_eq!(path.poll_apply(&mut cx), Poll::Pending);

        // Mock receiving a certain amount of data
        path.deposit(10);

        assert_eq!(path.poll_apply(&mut cx), Poll::Ready(Some(30)));
        path.post_sent(30);
        assert_eq!(path.poll_apply(&mut cx), Poll::Pending);

        let mut buf = [0; 1024];
        let mut limit = TransportLimit::new(Some(usize::MAX), usize::MAX, usize::MAX);
        let length = path.write_challenge(&mut limit, &mut buf);
        let buf = &buf[1..length];
        let response = PathChallengeFrame::from_slice(buf);

        // Mock receiving response frames
        path.on_recv_path_challenge_response((&response).into());

        assert!(path.is_validated());
        assert_eq!(path.poll_apply(&mut cx), Poll::Ready(None));
    }

    #[tokio::test]
    async fn test_challenge_response() {
        let path = create_path(18003).await;
        path.on_recv_path_challenge(PathChallengeFrame::random());
        path.on_sent_path_challenge_response(0);
        path.on_challenge_response_pkt_acked(0);
    }

    #[tokio::test]
    async fn test_set_path_challenge_timeout() {
        let path = create_path(18004).await;
        path.set_path_challenge_timeout();
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(!path.is_validated());
    }
}
