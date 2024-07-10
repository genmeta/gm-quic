pub mod state;

use std::{sync::Arc, time::Duration};

use dashmap::DashMap;
use deref_derive::Deref;
use futures::StreamExt;
use qbase::{
    cid::{ConnectionId, Registry},
    error::{Error, ErrorKind},
    frame::{ConnFrame, ConnectionCloseFrame, HandshakeDoneFrame, MaxDataFrame},
    packet::{
        keys::{ArcKeys, ArcOneRttKeys},
        HandshakePacket, InitialPacket, OneRttPacket, SpacePacket, SpinBit, ZeroRttPacket,
    },
    streamid::Role,
    token::ResetToken,
    util::ArcAsyncDeque,
};
use qrecovery::space::{ArcSpace, ArcSpaces};
use qudp::ArcUsc;
use qunreliable::DatagramFlow;
use state::{ArcConnectionState, ConnectionState};
use tokio::sync::mpsc;

use crate::{
    auto,
    controller::ArcFlowController,
    crypto::TlsIO,
    handshake,
    path::{
        observer::{ConnectionObserver, HandShakeObserver, PtoObserver},
        AckObserver, ArcPath, LossObserver, Pathway,
    },
};

// 通过无效化密钥来丢弃接收端，来废除发送队列
type PacketQueue<T> = mpsc::UnboundedSender<(T, ArcPath)>;

pub struct RawConnection {
    cid_registry: Registry,

    // 所有Path的集合，Pathway作为key
    pathes: DashMap<Pathway, ArcPath>,

    init_pkt_queue: PacketQueue<InitialPacket>,
    hs_pkt_queue: PacketQueue<HandshakePacket>,
    zero_rtt_pkt_queue: PacketQueue<ZeroRttPacket>,
    one_rtt_pkt_queue: PacketQueue<OneRttPacket>,

    // Thus, a client MUST discard Initial keys when it first sends a Handshake packet
    // and a server MUST discard Initial keys when it first successfully processes a
    // Handshake packet. Endpoints MUST NOT send Initial packets after this point.
    initial_keys: ArcKeys,
    handshake_keys: ArcKeys,
    zero_rtt_keys: ArcKeys,
    one_rtt_keys: ArcOneRttKeys,

    spaces: ArcSpaces,

    // 创建新的path用的到，path中的拥塞控制器需要
    connection_observer: ConnectionObserver,

    spin: SpinBit,
    state: ArcConnectionState,

    // 连接级流控制器
    flow_ctrl: ArcFlowController,
}

impl RawConnection {
    pub fn recv_init_pkt_via(&self, pkt: InitialPacket, usc: &ArcUsc, pathway: Pathway) {
        let path = self.get_path(pathway, usc);
        _ = self.init_pkt_queue.send((pkt, path));
    }

    pub fn recv_hs_pkt_via(&self, pkt: HandshakePacket, usc: &ArcUsc, pathway: Pathway) {
        let path = self.get_path(pathway, usc);
        _ = self.hs_pkt_queue.send((pkt, path));
    }

    pub fn recv_0rtt_pkt_via(&self, pkt: ZeroRttPacket, usc: &ArcUsc, pathway: Pathway) {
        let path = self.get_path(pathway, usc);
        _ = self.zero_rtt_pkt_queue.send((pkt, path));
    }

    pub fn recv_1rtt_pkt_via(&self, pkt: OneRttPacket, usc: &ArcUsc, pathway: Pathway) {
        let path = self.get_path(pathway, usc);
        _ = self.one_rtt_pkt_queue.send((pkt, path));
    }

    pub fn recv_protected_pkt_via(&mut self, pkt: SpacePacket, usc: &ArcUsc, pathway: Pathway) {
        // TODO: 在不同状态会有不同反应
        match pkt {
            SpacePacket::Initial(pkt) => self.recv_init_pkt_via(pkt, usc, pathway),
            SpacePacket::Handshake(pkt) => self.recv_hs_pkt_via(pkt, usc, pathway),
            SpacePacket::ZeroRtt(pkt) => self.recv_0rtt_pkt_via(pkt, usc, pathway),
            SpacePacket::OneRtt(pkt) => self.recv_1rtt_pkt_via(pkt, usc, pathway),
        }
    }

    fn enter_handshake_done(&self) {
        self.state.set_state(ConnectionState::HandshakeDone);
        self.handshake_keys.invalid();
        self.zero_rtt_keys.invalid();
    }

    fn enter_closing(&self) {
        self.state.set_state(ConnectionState::Closing);

        // 启用计时器
    }

    fn enter_draining(&self) {
        self.state.set_state(ConnectionState::Draining);
        self.one_rtt_keys.invalid();
    }

    pub fn get_path(&self, pathway: Pathway, usc: &ArcUsc) -> ArcPath {
        self.pathes
            .entry(pathway)
            .or_insert_with({
                let usc = usc.clone();
                let observer = self.connection_observer.clone();
                || {
                    // TODO: 要为该新路径创建发送任务，需要连接id...spawn出一个任务，直到{何时}终止?
                    ArcPath::new(usc, Duration::from_millis(100), observer)
                }
            })
            .clone()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionInternalId(usize);

impl ConnectionInternalId {
    pub fn new(id: usize) -> Self {
        Self(id)
    }
}

#[derive(Deref, Clone)]
pub struct ArcConnectionHandle {
    #[deref]
    pub inner: Arc<RawConnection>,
    pub internal_id: ConnectionInternalId,
}

pub struct ConnectionBuilder {
    tls_session: TlsIO,
    role: Role,
    retire_conn_id_tx: mpsc::UnboundedSender<ConnectionId>,
    issue_conn_id_tx: mpsc::UnboundedSender<(ConnectionId, ArcConnectionHandle)>,
    new_reset_token_tx: mpsc::UnboundedSender<(ResetToken, ArcConnectionHandle)>,
    retire_reset_token_tx: mpsc::UnboundedSender<ResetToken>,
    close_conn_tx: mpsc::UnboundedSender<ConnectionInternalId>,
    internal_id: ConnectionInternalId,
}

pub fn new(initializer: ConnectionBuilder) -> ArcConnectionHandle {
    let ConnectionBuilder {
        tls_session,
        role,
        retire_conn_id_tx,
        issue_conn_id_tx,
        new_reset_token_tx,
        retire_reset_token_tx,
        close_conn_tx,
        internal_id,
    } = initializer;

    let conn_state = ArcConnectionState::new();
    let mut conn_frame_deque = ArcAsyncDeque::new();
    // todo：发送CCF
    let (error_tx, mut error_rx) = mpsc::unbounded_channel();

    let initial_keys = ArcKeys::new_pending();

    let initial_space = ArcSpace::new_initial_space();
    let initial_ack_tx = initial_space.spawn_recv_ack();
    let (initial_pkt_tx, initial_packet_stream) = auto::InitialPacketStream::new(
        initial_keys.clone(),
        initial_space.rcvd_pkt_records.clone(),
    );

    let initial_space_frame_queue = initial_space.spawn_recv_space_frames(error_tx.clone());

    initial_packet_stream.spawn_parse_packet_and_then_dispatch(
        Some(conn_frame_deque.clone()),
        Some(initial_space_frame_queue.clone()),
        None,
        initial_ack_tx.clone(),
        error_tx.clone(),
    );

    let handshake_keys = ArcKeys::new_pending();

    let handshake_space = ArcSpace::new_handshake_space();
    let handshake_ack_tx = handshake_space.spawn_recv_ack();
    let (handshake_pkt_tx, handshake_packet_stream) = auto::HandshakePacketStream::new(
        handshake_keys.clone(),
        handshake_space.rcvd_pkt_records.clone(),
    );

    let handshake_space_frame_queue = handshake_space.spawn_recv_space_frames(error_tx.clone());

    let server_start_handshake_hook = {
        let initial_keys = initial_keys.clone();
        let state = conn_state.clone();
        move || {
            // todo: 客户端发送第一个握手包时，进入Handshaking状态
            if role == Role::Server {
                initial_keys.invalid();
                state.set_state(ConnectionState::Handshaking)
            }
        }
    };
    handshake_packet_stream.spawn_parse_packet_and_then_dispatch(
        Some(conn_frame_deque.clone()),
        Some(handshake_space_frame_queue),
        None,
        handshake_ack_tx.clone(),
        error_tx.clone(),
        // a server MUST discard Initial keys when it first successfully processes a
        // Handshake packet.
        server_start_handshake_hook,
    );

    tokio::spawn(
        handshake::exchange_initial_crypto_msg_until_getting_handshake_key(
            tls_session.clone(),
            handshake_keys.clone(),
            initial_space.as_ref().split(),
        ),
    );

    let datagram_flow = DatagramFlow::new(65535, 0);
    let datagram_queue = datagram_flow.spawn_recv_datagram_frames(error_tx.clone());

    let zero_rtt_keys = ArcKeys::new_pending();
    let one_rtt_keys = ArcOneRttKeys::new_pending();

    let data_space = ArcSpace::new_data_space(role, 0, 0);
    let data_ack_tx = data_space.spawn_recv_ack();
    let (zero_rtt_pkt_tx, zero_rtt_packet_stream) =
        auto::ZeroRttPacketStream::new(zero_rtt_keys.clone(), data_space.rcvd_pkt_records.clone());

    let data_space_frame_queue = data_space.spawn_recv_space_frames(error_tx.clone());

    zero_rtt_packet_stream.spawn_parse_packet_and_then_dispatch(
        Some(conn_frame_deque.clone()),
        Some(data_space_frame_queue),
        Some(datagram_queue.clone()),
        data_ack_tx.clone(),
        error_tx.clone(),
    );

    let (one_rtt_pkt_tx, dataspace_packets) =
        auto::OneRttPacketStream::new(one_rtt_keys.clone(), data_space.rcvd_pkt_records.clone());

    let data_space_frame_queue = data_space.spawn_recv_space_frames(error_tx.clone());

    dataspace_packets.spawn_parse_packet_and_then_dispatch(
        Some(conn_frame_deque.clone()),
        Some(data_space_frame_queue),
        Some(datagram_queue.clone()),
        data_ack_tx.clone(),
        error_tx.clone(),
    );

    let ack_observer = AckObserver::new([
        initial_space.rcvd_pkt_records.clone(),
        handshake_space.rcvd_pkt_records.clone(),
        data_space.rcvd_pkt_records.clone(),
    ]);
    let loss_observer = LossObserver::new([
        initial_space.spawn_handle_may_loss(),
        handshake_space.spawn_handle_may_loss(),
        data_space.spawn_handle_may_loss(),
    ]);
    let handshake_observer = HandShakeObserver::new(conn_state.clone());

    let pto_observer = PtoObserver::new([
        initial_space.spawn_probe_timeout(),
        handshake_space.spawn_probe_timeout(),
        data_space.spawn_probe_timeout(),
    ]);

    let connection_observer = ConnectionObserver {
        handshake_observer,
        ack_observer,
        loss_observer,
        pto_observer,
    };

    let flow_controller = ArcFlowController::with_initial(0, 0);
    let connection = Arc::new(RawConnection {
        cid_registry: Registry::new(2),
        pathes: DashMap::new(),
        init_pkt_queue: initial_pkt_tx,
        hs_pkt_queue: handshake_pkt_tx,
        zero_rtt_pkt_queue: zero_rtt_pkt_tx,
        one_rtt_pkt_queue: one_rtt_pkt_tx,
        initial_keys,
        handshake_keys,
        zero_rtt_keys,
        one_rtt_keys,
        spaces: ArcSpaces::new(initial_space, handshake_space, data_space),
        connection_observer,
        spin: SpinBit::default(),
        state: conn_state.clone(),
        flow_ctrl: flow_controller.clone(),
    });

    tokio::spawn({
        let connection = connection.clone();
        let error_tx = error_tx.clone();
        let data_space = connection.spaces.data_space();
        let handshake_space = connection.spaces.handshake_space().unwrap();
        let handshake_crypto_handler = handshake_space.as_ref().split();
        let one_rtt_keys = connection.one_rtt_keys.clone();
        async move {
            handshake::exchange_handshake_crypto_msg_until_getting_1rtt_key(
                tls_session.clone(),
                one_rtt_keys,
                handshake_crypto_handler,
            )
            .await;

            let transport_parameters = tls_session.get_transport_parameters().unwrap();
            data_space.accept_transmute_parameters(&transport_parameters);
            // TODO: 对连接参数进行检查
            let update_limit_result = connection
                .cid_registry
                .local
                .lock_guard()
                .set_limit(transport_parameters.active_connection_id_limit().into());
            if let Err(error) = update_limit_result {
                _ = error_tx.send(error);
            }
            if role == Role::Server {
                data_space
                    .reliable_frame_queue
                    .write()
                    .push_conn_frame(ConnFrame::HandshakeDone(HandshakeDoneFrame));
            }
            connection.enter_handshake_done();
        }
    });

    tokio::spawn({
        let connection = connection.clone();
        async move {
            while let Some(conn_frame) = conn_frame_deque.next().await {
                let handle_conn_frmae = |conn_frame: ConnFrame| {
                    match conn_frame {
                        ConnFrame::Close(error) => {
                            // 该不该等CCF发送再进入排空状态
                            connection.enter_draining();
                            _ = error_tx.send(error.into());
                            Ok(())
                        }
                        ConnFrame::NewToken(_) => todo!(),
                        ConnFrame::MaxData(MaxDataFrame { max_data }) => {
                            flow_controller.sender.permit(max_data.into_inner());
                            Ok(())
                        }
                        ConnFrame::NewConnectionId(frame) => connection
                            .cid_registry
                            .remote
                            .lock_guard()
                            .recv_new_cid_frame(&frame),
                        ConnFrame::RetireConnectionId(frame) => {
                            let retired_cid = connection
                                .cid_registry
                                .local
                                .lock_guard()
                                .recv_retire_cid_frame(&frame)?;
                            if let Some(cid) = retired_cid {
                                retire_conn_id_tx.send(cid).unwrap();
                            }
                            Ok(())
                        }
                        ConnFrame::HandshakeDone(_) => {
                            if role == Role::Client {
                                connection.enter_handshake_done();
                                Ok(())
                            } else {
                                Err(Error::new_with_default_fty(
                                    ErrorKind::ProtocolViolation,
                                    "client should not send HandshakeDoneFrame",
                                ))
                            }
                        }
                        ConnFrame::DataBlocked(_) => Ok(()),
                    }
                };
                let error: Option<Error> = handle_conn_frmae(conn_frame).err();

                // 处理连接错误
                if let Some(error) = error {
                    _ = error_tx.send(error);
                }
            }
        }
    });

    tokio::spawn({
        let connection = connection.clone();
        async move {
            let Some(error) = error_rx.recv().await else {
                return;
            };

            // 向应用层报告错误

            let data_space = connection.spaces.data_space();
            data_space.data_stream.on_conn_error(&error);
            datagram_flow.on_conn_error(&error);

            let state = connection.state.get_state();

            let error = match state {
                // Sending a CONNECTION_CLOSE of type 0x1d in an Initial or Handshake
                // packet could expose application state or be used to alter application
                // state. A CONNECTION_CLOSE of type 0x1d MUST be replaced by a CONNECTION_CLOSE
                // of type 0x1c when sending the frame in Initial or Handshake packets. Otherwise,
                // information about the application state might be revealed. Endpoints MUST clear
                // the value of the Reason Phrase field and SHOULD use the APPLICATION_ERROR code
                // when converting to a CONNECTION_CLOSE of type 0x1c.
                ConnectionState::Initial | ConnectionState::Handshaking => {
                    Error::new_with_default_fty(ErrorKind::Application, "")
                }
                ConnectionState::HandshakeDone => error,
                ConnectionState::Closing | ConnectionState::Draining => unreachable!(),
            };

            let ccf = ConnectionCloseFrame::from(error.clone());

            // TODO 组装一个数据包
            let pkt = match state {
                ConnectionState::Initial => {}
                ConnectionState::Handshaking => todo!(),
                ConnectionState::HandshakeDone => todo!(),
                ConnectionState::Closing => todo!(),
                ConnectionState::Draining => todo!(),
            };

            // TODO: 组装出数据包

            // 发送CCF

            // 准备发送连接关闭帧

            // 等待连接关闭
            // let duration = todo!("PTOx3");
            // tokio::time::sleep(duration).await;

            // 告知终端连接已经关闭，释放资源
        }
    });

    ArcConnectionHandle {
        inner: connection,
        internal_id,
    }
}

#[cfg(test)]
mod tests {}
