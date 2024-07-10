pub mod state;

use std::{sync::Arc, time::Duration};

use dashmap::DashMap;
use deref_derive::Deref;
use futures::{FutureExt, StreamExt};
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
use qrecovery::space::{ArcSpace, ArcSpaces, ReliableTransmit};
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

    let initial_keys = ArcKeys::new_pending();
    let initial_space = ArcSpace::new_initial_space();

    // decode initial packet
    // producer -> producer
    // return:
    //     initial_pkt_tx dropped
    //     initial_key invalid(
    //         for SERVER: rcvd handshake pkt
    //         for CLIENT: sent handshake pkt
    //         or enter_closing
    let (initial_pkt_tx, initial_pkt_rx) = mpsc::unbounded_channel();
    let mut initial_packet_stream = auto::InitialPacketStream::new(
        initial_pkt_rx,
        initial_keys.clone(),
        initial_space.rcvd_pkt_records.clone(),
    );

    // dispatch initial packet
    // producer -> producer
    // return: initial_packet_stream closed
    let initial_crypto_deque_writer = ArcAsyncDeque::new();
    let initial_ccf_deque_writer = ArcAsyncDeque::new();
    let (initial_ack_tx, mut initial_ack_rx) = mpsc::unbounded_channel();
    let mut initial_crypto_deque_reader = initial_crypto_deque_writer.clone();
    let mut initial_ccf_deque_reader = initial_ccf_deque_writer.clone();
    // 通过select它来获取错误
    let initial_dispatch_handle = tokio::spawn({
        async move {
            while let Some(packet) = initial_packet_stream.next().await {
                let pn = packet.pn;
                // TODO: 该包要认的话，还得向对方返回错误信息，并终止连接
                let _is_ack_eliciting = packet.dispatch_initial_space(
                    &initial_crypto_deque_writer,
                    &initial_ccf_deque_writer,
                    &initial_ack_tx,
                )?;
                initial_packet_stream.rcvd_pkt_records.register_pn(pn)
            }

            initial_crypto_deque_writer.close();
            initial_ccf_deque_writer.close();

            Ok::<_, Error>(())
        }
    });

    // initial handle ack
    // -> consumer
    // return: initial_ack_tx dropped
    tokio::spawn({
        let initial_space = initial_space.clone();
        async move {
            while let Some(ack) = initial_ack_rx.recv().await {
                initial_space.on_ack(ack);
            }
        }
    });

    // intiial recv crypto frame
    // -> consumer
    // return:
    //     initial_crypto_stream_writer.close() called
    //     error
    let initial_crypto_stream_handle = tokio::spawn({
        let crypto_stream = initial_space.as_ref().clone();
        async move {
            while let Some((frame, byte)) = initial_crypto_deque_reader.next().await {
                crypto_stream.recv_data(frame, byte)?;
            }
            Ok::<_, Error>(())
        }
    });

    let handshake_keys = ArcKeys::new_pending();
    let handshake_space = ArcSpace::new_handshake_space();

    // decode handshake packet
    // producer -> producer
    // return:
    //     handshake_pkt_tx dropped
    //     handshake_keys invalid
    //         handshake done
    //         enter closing
    let (handshake_pkt_tx, handshake_pkt_rx) = mpsc::unbounded_channel();
    let mut handshake_packet_stream = auto::HandshakePacketStream::new(
        handshake_pkt_rx,
        handshake_keys.clone(),
        handshake_space.rcvd_pkt_records.clone(),
    );

    // dispatch handshake packet
    // producer -> producer
    // return: handshake_packet_stream closed
    let (handshake_ack_tx, mut handshake_ack_rx) = mpsc::unbounded_channel();
    let handshake_crypto_deque_writer = ArcAsyncDeque::new();
    let handshake_ccf_deque_writer = ArcAsyncDeque::new();
    let mut handshake_crypto_deque_reader = handshake_crypto_deque_writer.clone();
    let mut handshake_ccf_deque_reader = handshake_ccf_deque_writer.clone();
    let handshake_dispatch_handle = tokio::spawn({
        let conn_state = conn_state.clone();
        let initial_keys = initial_keys.clone();
        async move {
            while let Some(packet) = handshake_packet_stream.next().await {
                let pn = packet.pn;
                let _is_ack_eliciting = packet.dispatch_handshake_space(
                    &handshake_crypto_deque_writer,
                    &handshake_ccf_deque_writer,
                    &handshake_ack_tx,
                )?;
                if role == Role::Server {
                    initial_keys.invalid();
                    conn_state.set_state(ConnectionState::Handshaking)
                }

                handshake_packet_stream.rcvd_pkt_records.register_pn(pn)
            }

            handshake_crypto_deque_writer.close();
            handshake_ccf_deque_writer.close();

            Ok::<_, Error>(())
        }
    });

    // handle handshake ack
    // -> consumer
    // return: handshake_ack_tx dropped
    tokio::spawn({
        let handshake_space = handshake_space.clone();
        async move {
            while let Some(ack) = handshake_ack_rx.recv().await {
                handshake_space.on_ack(ack);
            }
        }
    });

    // handshake recv crypto frame
    // -> consumer
    // return:
    //     handshake_crypto_stream_writer.close() called
    //     error
    let handshake_crypto_stream_handle = tokio::spawn({
        let crypto_stream = handshake_space.as_ref().clone();
        async move {
            while let Some((frame, data)) = handshake_crypto_deque_reader.next().await {
                crypto_stream.recv_data(frame, data)?;
            }
            Ok::<_, Error>(())
        }
    });

    tokio::spawn(
        handshake::exchange_initial_crypto_msg_until_getting_handshake_key(
            tls_session.clone(),
            handshake_keys.clone(),
            initial_space.as_ref().split(),
        ),
    );

    let zero_rtt_keys = ArcKeys::new_pending();
    let one_rtt_keys = ArcOneRttKeys::new_pending();
    let data_space = ArcSpace::new_data_space(role, 0, 0);

    let datagram_flow = DatagramFlow::new(65535, 0);

    // decode 0rtt packet
    // producer -> producer
    // return:
    //     zero_rtt_pkt_tx dropped
    //     zero_rtt_keys invalid
    //         handshake done
    //         enter closing
    let (zero_rtt_pkt_tx, zero_rtt_pkt_rx) = mpsc::unbounded_channel();
    let zero_rtt_packet_stream = auto::ZeroRttPacketStream::new(
        zero_rtt_pkt_rx,
        zero_rtt_keys.clone(),
        data_space.rcvd_pkt_records.clone(),
    );

    // decode 1rtt packet
    // producer -> producer
    // return: enter closing
    let (one_rtt_pkt_tx, one_rtt_pkt_rx) = mpsc::unbounded_channel();
    // producer -> producer
    let one_rtt_packet_stream = auto::OneRttPacketStream::new(
        one_rtt_pkt_rx,
        one_rtt_keys.clone(),
        data_space.rcvd_pkt_records.clone(),
    );

    let ack_observer = AckObserver::new([
        initial_space.rcvd_pkt_records.clone(),
        handshake_space.rcvd_pkt_records.clone(),
        data_space.rcvd_pkt_records.clone(),
    ]);

    let (loss_observer, [mut initial_loss_rx, mut handshake_loss_rx, mut data_loss_rx]) =
        LossObserver::new();

    // handle may loss tasks
    {
        tokio::spawn({
            let initial_space = initial_space.clone();
            async move {
                while let Some(pn) = initial_loss_rx.recv().await {
                    initial_space.may_loss_pkt(pn);
                }
            }
        });

        tokio::spawn({
            let handshake_space = handshake_space.clone();
            async move {
                while let Some(pn) = handshake_loss_rx.recv().await {
                    handshake_space.may_loss_pkt(pn);
                }
            }
        });

        tokio::spawn({
            let data_space = data_space.clone();
            async move {
                while let Some(pn) = data_loss_rx.recv().await {
                    data_space.may_loss_pkt(pn);
                }
            }
        });
    }

    let handshake_observer = HandShakeObserver::new(conn_state.clone());
    let (pto_observer, [mut initial_timeout_rx, mut handshake_timeout_rx, mut data_timeout_rx]) =
        PtoObserver::new();

    // handle pto probe tasks
    {
        tokio::spawn({
            let initial_space = initial_space.clone();
            async move {
                while initial_timeout_rx.recv().await.is_some() {
                    initial_space.probe_timeout();
                }
            }
        });

        tokio::spawn({
            let handshake_space = handshake_space.clone();
            async move {
                while handshake_timeout_rx.recv().await.is_some() {
                    handshake_space.probe_timeout();
                }
            }
        });

        tokio::spawn({
            let data_space = data_space.clone();
            async move {
                while data_timeout_rx.recv().await.is_some() {
                    data_space.probe_timeout();
                }
            }
        });
    }

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

    let handshake_done_handle = tokio::spawn({
        let connection = connection.clone();
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
            connection
                .cid_registry
                .local
                .lock_guard()
                .set_limit(transport_parameters.active_connection_id_limit().into())?;

            if role == Role::Server {
                data_space
                    .reliable_frame_queue
                    .write()
                    .push_conn_frame(ConnFrame::HandshakeDone(HandshakeDoneFrame));
            }
            connection.enter_handshake_done();

            Ok::<_, Error>(())
        }
    });

    // tokio::spawn({
    //     let connection = connection.clone();
    //     async move {
    //         while let Some(conn_frame) = conn_frame_deque.next().await {
    //             match conn_frame {
    //                 ConnFrame::Close(error) => {
    //                     connection.enter_draining();
    //                     return;
    //                 }
    //                 ConnFrame::NewToken(_) => todo!(),
    //                 ConnFrame::MaxData(MaxDataFrame { max_data }) => {
    //                     flow_controller.sender.permit(max_data.into_inner());
    //                     Ok(())
    //                 }
    //                 ConnFrame::NewConnectionId(frame) => connection
    //                     .cid_registry
    //                     .remote
    //                     .lock_guard()
    //                     .recv_new_cid_frame(&frame),
    //                 ConnFrame::RetireConnectionId(frame) => {
    //                     let retired_cid = connection
    //                         .cid_registry
    //                         .local
    //                         .lock_guard()
    //                         .recv_retire_cid_frame(&frame)?;
    //                     if let Some(cid) = retired_cid {
    //                         retire_conn_id_tx.send(cid).unwrap();
    //                     }
    //                     Ok(())
    //                 }
    //                 ConnFrame::HandshakeDone(_) => {
    //                     if role == Role::Client {
    //                         connection.enter_handshake_done();
    //                         Ok(())
    //                     } else {
    //                         Err(Error::new_with_default_fty(
    //                             ErrorKind::ProtocolViolation,
    //                             "client should not send HandshakeDoneFrame",
    //                         ))
    //                     }
    //                 }
    //                 ConnFrame::DataBlocked(_) => Ok(()),
    //             }?;
    //         }
    //     }
    // });

    tokio::spawn({
        let connection = connection.clone();
        async move {
            // let Some(error) = error_rx.recv().await else {
            //     return;
            // };

            let error = tokio::select! {
                Err(e) = initial_dispatch_handle.map(|je| je.unwrap()) => e,
                Err(e) = initial_crypto_stream_handle.map(|je| je.unwrap()) => e,
                Err(e) = handshake_done_handle.map(|je| je.unwrap()) => e,
                Err(e) = handshake_dispatch_handle.map(|je| je.unwrap()) => e,
                Err(e) = handshake_crypto_stream_handle.map(|je| je.unwrap()) => e,

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
            // let pkt = match state {
            //     ConnectionState::Initial => {}
            //     ConnectionState::Handshaking => todo!(),
            //     ConnectionState::HandshakeDone => todo!(),
            //     ConnectionState::Closing => todo!(),
            //     ConnectionState::Draining => todo!(),
            // };

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
