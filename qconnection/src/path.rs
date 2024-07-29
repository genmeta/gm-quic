use std::{
    future::poll_fn,
    io::IoSlice,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{ready, Context, Poll},
    time::{Duration, Instant},
};

use anti_amplifier::ANTI_FACTOR;
use bytes::BufMut;
use futures::{Future, FutureExt};
use log::*;
use qbase::{
    cid::{ArcCidCell, ConnectionId, MAX_CID_SIZE},
    flow::FlowController,
    frame::{AckFrame, ConnFrame, ConnectionCloseFrame, PathChallengeFrame, PathResponseFrame},
    packet::{
        keys::{ArcKeys, ArcOneRttKeys},
        LongHeaderBuilder, OneRttHeader, SpinBit,
    },
    util::TransportLimit,
};
use qcongestion::{
    congestion::{ArcCC, MSS},
    rtt::INITIAL_RTT,
    CongestionControl,
};
use qrecovery::space::{DataSpace, Epoch, HandshakeSpace, InitialSpace, ReliableTransmit, Space};
use qudp::ArcUsc;

pub mod anti_amplifier;
pub use anti_amplifier::ArcAntiAmplifier;

pub mod validate;
use qunreliable::DatagramFlow;
use validate::ValidatorState;
pub use validate::{Transponder, Validator};

use crate::{
    connection::{ConnectionState, ConnectionStateData, RawConnection},
    transmit::{self, FillPolicy},
    Sendmsg,
};

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct RelayAddr {
    pub agent: SocketAddr, // 代理人
    pub addr: SocketAddr,
}

/// 无论哪种Pathway，socket都必须绑定local地址
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
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

pub enum PathState {
    Initial {
        init_keys: ArcKeys,
        init_space: InitialSpace,

        hs_keys: ArcKeys,
        hs_space: HandshakeSpace,

        one_rtt_keys: ArcOneRttKeys,
        data_space: DataSpace,
        flow_ctrl: FlowController,
        spin: SpinBit,

        datagram_flow: DatagramFlow,
    },
    Handshaking {
        hs_keys: ArcKeys,
        hs_space: HandshakeSpace,

        one_rtt_keys: ArcOneRttKeys,
        data_space: DataSpace,
        flow_ctrl: FlowController,
        spin: SpinBit,

        datagram_flow: DatagramFlow,
    },
    Normal {
        one_rtt_keys: ArcOneRttKeys,
        data_space: DataSpace,
        flow_ctrl: FlowController,
        spin: SpinBit,

        datagram_flow: DatagramFlow,
    },
    Closing {
        /// udp datagram
        datagram: Arc<Vec<Vec<u8>>>,
    },
    Invalid,
}

impl PathState {
    pub fn enter_handshake(&mut self) {
        let state = std::mem::replace(self, PathState::Invalid);
        if let PathState::Initial {
            hs_keys,
            hs_space,
            one_rtt_keys,
            data_space,
            flow_ctrl,
            spin,
            datagram_flow,
            ..
        } = state
        {
            *self = PathState::Handshaking {
                hs_keys,
                hs_space,
                one_rtt_keys,
                data_space,
                flow_ctrl,
                spin,
                datagram_flow,
            }
        }
    }

    pub fn enter_handshake_done(&mut self) {
        let state = std::mem::replace(self, PathState::Invalid);
        if let PathState::Handshaking {
            one_rtt_keys,
            data_space,
            flow_ctrl,
            spin,
            datagram_flow,
            ..
        } = state
        {
            *self = PathState::Normal {
                one_rtt_keys,
                data_space,
                flow_ctrl,
                spin,
                datagram_flow,
            }
        }
    }

    pub fn reliable_space(&self, epoch: Epoch) -> Option<Space> {
        match epoch {
            Epoch::Initial => self.try_get_initial_space().map(Into::into),
            Epoch::Handshake => self.try_get_handshake_space().map(Into::into),
            Epoch::Data => self.try_get_data_space().map(Into::into),
        }
    }

    fn try_get_initial_space(&self) -> Option<InitialSpace> {
        match self {
            Self::Initial { init_space, .. } => Some(init_space.clone()),
            _ => None,
        }
    }

    fn try_get_handshake_space(&self) -> Option<HandshakeSpace> {
        match self {
            Self::Initial { hs_space, .. } | Self::Handshaking { hs_space, .. } => {
                Some(hs_space.clone())
            }
            _ => None,
        }
    }

    fn try_get_data_space(&self) -> Option<DataSpace> {
        match self {
            Self::Initial { data_space, .. }
            | Self::Handshaking { data_space, .. }
            | Self::Normal { data_space, .. } => Some(data_space.clone()),
            _ => None,
        }
    }

    pub fn get_flow_controller(&self) -> &FlowController {
        match self {
            Self::Initial { flow_ctrl, .. }
            | Self::Handshaking { flow_ctrl, .. }
            | Self::Normal { flow_ctrl, .. } => flow_ctrl,
            _ => unreachable!(),
        }
    }

    pub fn for_initial_space(&self, f: impl FnOnce(&InitialSpace, &ArcKeys)) {
        if let Self::Initial {
            init_space,
            init_keys,
            ..
        } = self
        {
            f(init_space, init_keys)
        }
    }

    pub fn for_handshake_space(&self, f: impl FnOnce(&HandshakeSpace, &ArcKeys)) {
        if let Self::Initial {
            hs_space, hs_keys, ..
        }
        | Self::Handshaking {
            hs_space, hs_keys, ..
        } = self
        {
            f(hs_space, hs_keys)
        }
    }

    pub fn for_data_space(
        &mut self,
        f: impl FnOnce(&DataSpace, &ArcOneRttKeys, &FlowController, &mut SpinBit),
    ) {
        if let Self::Initial {
            data_space,
            one_rtt_keys,
            flow_ctrl,
            spin,
            ..
        }
        | Self::Handshaking {
            data_space,
            one_rtt_keys,
            flow_ctrl,
            spin,
            ..
        }
        | Self::Normal {
            data_space,
            one_rtt_keys,
            flow_ctrl,
            spin,
            ..
        } = self
        {
            f(data_space, one_rtt_keys, flow_ctrl, spin)
        }
    }

    fn enter_closing(
        &mut self,
        send_guard: &mut SendGuard,
        ccf: Arc<ConnectionCloseFrame>,
        scid: ConnectionId,
        token: &[u8],
    ) {
        use qbase::{
            frame::io::WriteConnectionCloseFrame,
            packet::{PacketNumber, WritePacketNumber},
        };
        use qrecovery::space::{FillPacket, FillPacketResult};
        let pn = match &self {
            PathState::Initial { init_space, .. } => init_space.sent_pkt_records.send().next_pn(),
            PathState::Handshaking { hs_space, .. } => hs_space.sent_pkt_records.send().next_pn(),
            PathState::Normal { data_space, .. } => data_space.sent_pkt_records.send().next_pn(),
            PathState::Closing { .. } | PathState::Invalid => return,
        };

        struct Filler(Arc<ConnectionCloseFrame>, u64, PacketNumber);
        let filler = Filler(ccf, pn.0, pn.1);

        impl FillPacket for Filler {
            fn fill_packet(
                &self,
                _: &mut TransportLimit,
                mut buf: &mut [u8],
                _: Option<(u64, Instant)>,
            ) -> FillPacketResult {
                let origin = buf.remaining_mut();

                buf.put_packet_number(self.2);
                buf.put_connection_close_frame(&self.0);

                FillPacketResult::new(self.1, self.2.size(), origin - buf.remaining_mut(), false)
            }
        }

        let mut buffers = vec![];
        match self {
            PathState::Initial { .. } => self.for_initial_space(|_, init_keys| {
                let builder = LongHeaderBuilder::with_cid(send_guard.dcid, scid);
                let header = builder.initial(token.to_vec());
                let fill_policy = FillPolicy::Redundancy;
                transmit::read_long_header_space(
                    &mut buffers,
                    &header,
                    fill_policy,
                    init_keys,
                    &filler,
                    Epoch::Initial,
                    send_guard,
                );
            }),
            PathState::Handshaking { .. } => self.for_handshake_space(|_, hs_keys| {
                let builder = LongHeaderBuilder::with_cid(send_guard.dcid, scid);
                let header = builder.handshake();
                let fill_policy = FillPolicy::Redundancy;
                transmit::read_long_header_space(
                    &mut buffers,
                    &header,
                    fill_policy,
                    hs_keys,
                    &filler,
                    Epoch::Handshake,
                    send_guard,
                );
            }),
            PathState::Normal { .. } => self.for_data_space(|_, one_rtt_keys, _flow_ctrl, spin| {
                let dcid = send_guard.dcid;
                let header = OneRttHeader { spin: *spin, dcid };
                transmit::read_short_header_space(
                    &mut buffers,
                    header,
                    one_rtt_keys,
                    &filler,
                    Epoch::Data,
                    send_guard,
                );
            }),
            _ => return,
        }
        *self = PathState::Closing {
            datagram: Arc::new(buffers),
        }
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
    peer_cid: ArcCidCell,

    // 拥塞控制器。另外还有连接级的流量控制、流级别的流量控制，以及抗放大攻击
    // 但这只是正常情况下。当连接处于Closing状态时，庞大的拥塞控制器便不再适用，而是简单的回应ConnectionCloseFrame。
    cc: ArcCC,

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

    state: PathState,
    // TODO: 处理socket发送错误
}

impl RawPath {
    fn new(usc: ArcUsc, max_ack_delay: Duration, peer_cid: ArcCidCell, state: PathState) -> Self {
        use qcongestion::congestion::CongestionAlgorithm;
        let anti_amplifier = ArcAntiAmplifier::default();

        Self {
            usc,
            peer_cid,
            validator: Validator::default(),
            transponder: Transponder::default(),
            anti_amplifier: Some(anti_amplifier),
            cc: ArcCC::new(CongestionAlgorithm::Bbr, max_ack_delay),
            state,
        }
    }

    fn poll_send(&mut self, cx: &mut Context<'_>) -> Poll<SendGuard> {
        let congestion_control = ready!(self.cc.poll_send(cx));
        let anti_amplification = if let Some(anti_amplifier) = self.anti_amplifier.as_ref() {
            match anti_amplifier.poll_get_credit(cx) {
                Poll::Ready(credit) => {
                    self.cc.anti_amplification_limit_off();
                    credit
                }
                Poll::Pending => {
                    self.cc.anti_amplification_limit_on();
                    return Poll::Pending;
                }
            }
        } else {
            self.cc.anti_amplification_limit_off();
            None
        };

        let peer_cid = ready!(self.peer_cid.poll_unpin(cx));
        let flow_control = 0;
        // ready!(self.state.get_flow_controller().sender.poll_apply(cx)).available();

        let mut ack_pkts = [None; 3];
        for &epoch in Epoch::iter() {
            let ack_pkt = self.cc.need_ack(epoch);
            ack_pkts[epoch as usize] = ack_pkt;
        }
        let send_guard = SendGuard {
            transport_limit: TransportLimit::new(
                anti_amplification,
                congestion_control,
                flow_control,
            ),
            usc: self.usc.clone(),
            dcid: peer_cid,
            cc: self.cc.clone(),
            ack_pkts,
        };
        Poll::Ready(send_guard)
    }
}

#[derive(Clone)]
pub struct ArcPath(Arc<Mutex<RawPath>>);

impl ArcPath {
    pub fn new(
        usc: ArcUsc,
        max_ack_delay: Duration,
        peer_cid: ArcCidCell,
        state: PathState,
    ) -> Self {
        Self(Arc::new(Mutex::new(RawPath::new(
            usc,
            max_ack_delay,
            peer_cid,
            state,
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
    pub fn on_sent_path_challenge(&self) {
        self.0.lock().unwrap().validator.on_challenge_sent()
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

    /// Path is waiting for the path challenge response frame ack
    pub fn waiting_response_ack(&self) -> Option<u64> {
        self.0.lock().unwrap().transponder.waiting_ack()
    }

    /// When the peer receives the ack of the returned challenge response, the
    /// status is updated
    pub fn on_challenge_response_pkt_acked(&self) {
        self.0.lock().unwrap().transponder.to_acked()
    }

    /// Anti-amplification attack protection, records the amount of data received
    /// by the current path
    pub fn deposit(&self, amount: usize) {
        if let Some(anti_amplifier) = self.0.lock().unwrap().anti_amplifier.as_ref() {
            anti_amplifier.deposit(amount);
        }
    }

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
    ///
    /// Endpoints SHOULD abandon path validation based on a timer. When setting
    /// this timer, implementations are cautioned that the new path could have
    /// a longer round-trip time than the original. A value of three times the
    /// larger of the current PTO or the PTO for the new path (using kInitialRtt,
    /// as defined in [QUIC-RECOVERY]) is RECOMMENDED.
    ///
    /// See [Section 8.2.4-2](https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2.4-2)
    pub fn set_path_challenge_timeout(&self, epoch: Epoch) {
        let timeout = self.get_pto_time(epoch).max(INITIAL_RTT);
        self.0.lock().unwrap().validator.set_timeout(timeout * 3);
    }

    /// get connection controller pto time
    pub fn get_pto_time(&self, epoch: Epoch) -> Duration {
        self.0.lock().unwrap().cc.get_pto_time(epoch)
    }

    pub fn poll_send(&self) -> SendState {
        SendState(self.clone())
    }

    pub fn get_validate_state(&self) -> ValidatorState {
        self.0.lock().unwrap().validator.get_validate_state()
    }

    pub fn on_recv_pkt(&self, space: Epoch, pn: u64, is_ack_eliciting: bool) {
        let guard = self.0.lock().unwrap();
        guard.cc.on_recv_pkt(space, pn, is_ack_eliciting)
    }

    pub fn on_ack(&self, space: Epoch, frame: &AckFrame) {
        // Whether the pn of path challenge response need to be confirmed is in
        // the current ack frame
        if let Some(pn) = self.waiting_response_ack() {
            if frame.iter().flat_map(|r| r.rev()).any(|rpn| rpn == pn) {
                self.on_challenge_response_pkt_acked();
            }
        }

        let guard = self.0.lock().unwrap();
        guard.cc.on_ack(space, frame);
    }
}

pub fn create_path(connection: &RawConnection, pathway: Pathway, usc: &ArcUsc) -> Option<ArcPath> {
    // TODO: 要为该新路径创建发送任务，需要连接id...spawn出一个任务，直到{何时}终止?
    // path 的任务在连接迁移后或整个连接断开后终止
    // 考虑多路径并存，在连接迁移后，旧路径可以发起路径验证看旧路径是否还有效判断是否终止

    let path_state = connection
        .controller
        .state_data_guard()
        .create_path_state()?;

    debug_assert!(!matches!(path_state, PathState::Invalid));

    let path_stata_is_initial = matches!(path_state, PathState::Initial { .. });
    let path_stata_handshaking = !matches!(path_state, PathState::Normal { .. });

    let path = ArcPath::new(
        usc.clone(),
        Duration::from_millis(100),
        connection.cid_registry.remote.apply_cid(),
        path_state,
    );

    if path_stata_is_initial {
        // spawn_on_enter_handshake
        tokio::spawn({
            let path = path.clone();
            let on_enter_handshake = connection
                .controller
                .on_enter_state(ConnectionState::Handshaking);
            async move {
                on_enter_handshake.await;
                path.0.lock().unwrap().cc.on_get_handshake_keys();
                path.0.lock().unwrap().state.enter_handshake();
            }
        });
    }

    if path_stata_handshaking {
        // spawn_on_enter_normal
        tokio::spawn({
            let path = path.clone();
            let on_enter_normal = connection
                .controller
                .on_enter_state(ConnectionState::Normal);
            async move {
                on_enter_normal.await;
                path.0.lock().unwrap().cc.on_handshake_done();
                path.0.lock().unwrap().state.enter_handshake_done();
            }
        });
    }

    let cc_handle = tokio::spawn({
        let path = path.clone();
        let cc = path.0.lock().unwrap().cc.clone();
        async move {
            loop {
                tokio::select! {
                    (epoch, loss) = cc.may_loss() => {
                        let space = path.0.lock().unwrap().state.reliable_space(epoch);
                        if let Some(space) = space {
                            for pn in loss {
                                space.may_loss_pkt(pn);
                            }
                    }
                    },
                    epoch = cc.probe_timeout() => {
                        let space = path.0.lock().unwrap().state.reliable_space(epoch);
                        if let Some(space) = space {
                            space.probe_timeout();
                        }
                    },
                    (epoch, acked) = cc.indicate_ack() => {
                        let space = path.0.lock().unwrap().state.reliable_space(epoch);
                        if let Some(space) = space {
                            for pn in acked {
                                space.may_loss_pkt(pn);
                            }
                        }
                    },
                }
            }
        }
    });

    // spawn_send (auto close when path state is invalid)
    tokio::spawn({
        let path = path.clone();
        let cid_registry = connection.cid_registry.clone();
        let conn_controller = connection.controller.clone();
        async move {
            let predicate = |_: &ConnectionId| true;

            let (scid, token) = match cid_registry.local.issue_cid(MAX_CID_SIZE, predicate).await {
                Ok(frame) => {
                    let token = (*frame.reset_token).to_vec();
                    let scid = frame.id;
                    let Some(dataspace) = path.0.lock().unwrap().state.try_get_data_space() else {
                        return;
                    };

                    dataspace
                        .reliable_frame_queue
                        .write()
                        .push_conn_frame(ConnFrame::NewConnectionId(frame));
                    (scid, token)
                }
                Err(_) => {
                    return;
                }
            };

            while conn_controller.get_state() < ConnectionState::Draining {
                let mut guard = path.poll_send().await;
                let mut buffers = Vec::new();

                // 准备待发送的数据
                let data: &[Vec<u8>] = match &mut path.0.lock().unwrap().state {
                    // 如果路径失效，结束任务
                    PathState::Invalid => return,
                    // 如果连接正在关闭，直接使用已经准备好的数据
                    PathState::Closing { datagram } => &datagram.clone(),
                    // 如果连接的状态发生了改变且路径的状态没有跟进，进行状态切换
                    state if conn_controller.get_state() == ConnectionState::Closing => {
                        let ccf = match &*conn_controller.state_data_guard() {
                            ConnectionStateData::Closing { ccf, .. } => ccf.clone(),
                            _ => return,
                        };

                        state.enter_closing(&mut guard, ccf, scid, &token);
                        match &state {
                            PathState::Closing { datagram } => &datagram.clone(),
                            _ => unreachable!(),
                        }
                    }
                    state => {
                        state.for_initial_space(|space, init_keys| {
                            let builder = LongHeaderBuilder::with_cid(guard.dcid, scid);
                            let header = builder.initial(token.clone());
                            let fill_policy = FillPolicy::Redundancy;
                            transmit::read_long_header_space(
                                &mut buffers,
                                &header,
                                fill_policy,
                                init_keys,
                                space,
                                Epoch::Initial,
                                &mut guard,
                            );
                        });

                        state.for_handshake_space(|space, hs_keys| {
                            let builder = LongHeaderBuilder::with_cid(guard.dcid, scid);
                            let header = builder.handshake();
                            let fill_policy = FillPolicy::Redundancy;
                            transmit::read_long_header_space(
                                &mut buffers,
                                &header,
                                fill_policy,
                                hs_keys,
                                space,
                                Epoch::Handshake,
                                &mut guard,
                            );
                        });

                        state.for_data_space(|space, one_rtt_keys, _flow_ctrl, spin| {
                            let dcid = guard.dcid;
                            let header = OneRttHeader { spin: *spin, dcid };
                            transmit::read_short_header_space(
                                &mut buffers,
                                header,
                                one_rtt_keys,
                                space,
                                Epoch::Data,
                                &mut guard,
                            );
                        });

                        &buffers
                    }
                };

                let (src, dst) = match &pathway {
                    Pathway::Direct { local, remote } => (*local, *remote),
                    // todo: append relay hdr
                    Pathway::Relay { local, remote } => (local.addr, remote.agent),
                };

                let hdr = qudp::PacketHeader {
                    src,
                    dst,
                    ttl: 64,
                    ecn: None,
                    seg_size: MSS as u16,
                    gso: true,
                };

                let io_slices = data.iter().map(|b| IoSlice::new(b)).collect::<Vec<_>>();

                let ret = poll_fn(|cx| guard.usc.poll_send(&io_slices, &hdr, cx)).await;
                match ret {
                    Ok(n) => {
                        trace!("sent {} bytes", n);
                        // Reduce credit limit against amplification attack protection
                        path.post_sent(n);
                    }
                    Err(e) => {
                        // TODO: handle udp send error
                        error!("send failed: {}", e);
                    }
                }
            }
        }
    });

    tokio::spawn({
        let path = path.clone();
        let on_enter_closing = connection
            .controller
            .on_enter_state(ConnectionState::Closing);
        async move {
            // TODO: Path出错时也终止任务，连接迁移时也终止任务
            on_enter_closing.await;
            path.0.lock().unwrap().state = PathState::Invalid;
            cc_handle.abort();
        }
    });

    Some(path)
}

pub struct SendGuard {
    pub transport_limit: TransportLimit,
    pub usc: ArcUsc,
    pub dcid: ConnectionId,
    pub ack_pkts: [Option<(u64, Instant)>; 3],
    pub cc: ArcCC,
}

pub struct SendState(ArcPath);

impl Future for SendState {
    type Output = SendGuard;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0 .0.lock().unwrap().poll_send(cx)
    }
}

// #[cfg(test)]
// mod tests {
//     use std::net::{IpAddr, Ipv4Addr};

//     use futures::task::noop_waker_ref;
//     use observer::HandShakeObserver;

//     use super::*;
//     use crate::connection::ArcConnectionState;

//     async fn create_path(port: u16) -> ArcPath {
//         // 构造一个Path结构
//         let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
//         let usc = ArcUsc::new(addr);
//         let max_ack_delay = Duration::from_millis(100);

//         let flow_ctrl = ArcFlowController::default();
//         let peer_cid = ArcCidCell::default();
//         let handshake_observer = HandShakeObserver::new(ArcConnectionState::default());
//         ArcPath::new(
//             usc,
//             max_ack_delay,
//             ConnectionObserver { handshake_observer },
//             peer_cid,
//             flow_ctrl,
//         )
//     }

//     #[tokio::test]
//     async fn test_initial_packet() {
//         let path = create_path(18000).await;
//         assert!(!path.is_validated());
//     }

//     #[tokio::test]
//     async fn test_challenge() {
//         let path = create_path(18001).await;
//         let mut cx = Context::from_waker(noop_waker_ref());

//         assert_eq!(path.poll_get_anti_amplifier_credit(&mut cx), Poll::Pending);

//         // Mock receiving a certain amount of data
//         path.deposit(10);

//         assert_eq!(
//             path.poll_get_anti_amplifier_credit(&mut cx),
//             Poll::Ready(Some(30))
//         );
//         path.post_sent(30);
//         assert_eq!(path.poll_get_anti_amplifier_credit(&mut cx), Poll::Pending);

//         let mut buf = [0; 1024];
//         let mut limit = TransportLimit::new(Some(usize::MAX), usize::MAX, usize::MAX);
//         let length = path.write_challenge(&mut limit, &mut buf);
//         let buf = &buf[1..length];
//         let response = PathChallengeFrame::from_slice(buf);

//         // Mock receiving response frames
//         path.on_recv_path_challenge_response((&response).into());

//         assert!(path.is_validated());
//         assert_eq!(
//             path.poll_get_anti_amplifier_credit(&mut cx),
//             Poll::Ready(None)
//         );
//     }

//     #[tokio::test]
//     async fn test_challenge_response() {
//         let path = create_path(18003).await;
//         path.on_recv_path_challenge(PathChallengeFrame::random());
//         path.on_sent_path_challenge_response(0);
//         path.on_challenge_response_pkt_acked(0);
//     }

//     #[tokio::test]
//     async fn test_set_path_challenge_timeout() {
//         let path = create_path(18004).await;
//         path.set_path_challenge_timeout(Epoch::Initial);
//         tokio::time::sleep(Duration::from_millis(150)).await;
//         assert!(!path.is_validated());
//     }
// }
