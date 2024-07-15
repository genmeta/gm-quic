pub mod state;

use std::{
    ops::Deref,
    sync::{Arc, Mutex},
    time::Duration,
};

use dashmap::{DashMap, DashSet};
use deref_derive::Deref;
use futures::{FutureExt, StreamExt};
use qbase::{
    cid::{ConnectionId, Registry},
    error::{Error, ErrorKind},
    frame::{ConnFrame, ConnectionCloseFrame, HandshakeDoneFrame},
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
use tokio::sync::{mpsc, Notify};

use crate::{
    auto::{self, PacketPayload},
    controller::ArcFlowController,
    crypto::TlsIO,
    handshake,
    path::{
        observer::{ConnectionObserver, HandShakeObserver, PtoObserver},
        AckObserver, ArcPath, LossObserver, Pathway,
    },
};

type PacketQueue<T> = mpsc::UnboundedSender<(T, ArcPath)>;
type RxPacketQueue<T> = Mutex<Option<PacketQueue<T>>>;

pub struct PacketQueues {
    init_pkt_queue: RxPacketQueue<InitialPacket>,
    hs_pkt_queue: RxPacketQueue<HandshakePacket>,
    zero_rtt_pkt_queue: RxPacketQueue<ZeroRttPacket>,
    one_rtt_pkt_queue: RxPacketQueue<OneRttPacket>,
}

impl PacketQueues {
    pub fn new(
        init_pkt_queue: PacketQueue<InitialPacket>,
        hs_pkt_queue: PacketQueue<HandshakePacket>,
        zero_rtt_pkt_queue: PacketQueue<ZeroRttPacket>,
        one_rtt_pkt_queue: PacketQueue<OneRttPacket>,
    ) -> Self {
        Self {
            init_pkt_queue: Mutex::new(Some(init_pkt_queue)),
            hs_pkt_queue: Mutex::new(Some(hs_pkt_queue)),
            zero_rtt_pkt_queue: Mutex::new(Some(zero_rtt_pkt_queue)),
            one_rtt_pkt_queue: Mutex::new(Some(one_rtt_pkt_queue)),
        }
    }

    pub fn send_initial_packet(&self, packet: InitialPacket, path: ArcPath) {
        if let Some(tx) = self.init_pkt_queue.lock().unwrap().deref() {
            _ = tx.send((packet, path));
        }
    }

    pub fn send_handshake_packet(&self, packet: HandshakePacket, path: ArcPath) {
        if let Some(tx) = self.hs_pkt_queue.lock().unwrap().deref() {
            _ = tx.send((packet, path));
        }
    }

    pub fn send_zero_rtt_packet(&self, packet: ZeroRttPacket, path: ArcPath) {
        if let Some(tx) = self.zero_rtt_pkt_queue.lock().unwrap().deref() {
            _ = tx.send((packet, path));
        }
    }

    pub fn send_one_rtt_packet(&self, packet: OneRttPacket, path: ArcPath) {
        if let Some(tx) = self.one_rtt_pkt_queue.lock().unwrap().deref() {
            _ = tx.send((packet, path));
        }
    }

    pub fn close_all(&self) {
        self.init_pkt_queue.lock().unwrap().take();
        self.hs_pkt_queue.lock().unwrap().take();
        self.zero_rtt_pkt_queue.lock().unwrap().take();
        self.one_rtt_pkt_queue.lock().unwrap().take();
    }
}

pub struct RawConnection {
    cid_registry: Registry,

    // 所有Path的集合，Pathway作为key
    pathes: DashMap<Pathway, ArcPath>,

    packet_queues: PacketQueues,

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
    pub fn recv_protected_pkt_via(&self, pkt: SpacePacket, usc: &ArcUsc, pathway: Pathway) {
        let path = self.get_path(pathway, usc);
        // TODO: 在不同状态会有不同反应
        match pkt {
            SpacePacket::Initial(pkt) => self.packet_queues.send_initial_packet(pkt, path),
            SpacePacket::Handshake(pkt) => self.packet_queues.send_handshake_packet(pkt, path),
            SpacePacket::ZeroRtt(pkt) => self.packet_queues.send_zero_rtt_packet(pkt, path),
            SpacePacket::OneRtt(pkt) => self.packet_queues.send_one_rtt_packet(pkt, path),
        }
    }

    fn enter_handshake_done(&self) {
        self.state.set_state(ConnectionState::HandshakeDone);
        self.initial_keys.invalid();
        self.handshake_keys.invalid();
        self.zero_rtt_keys.invalid();
    }

    fn enter_closing(&self) {
        self.state.set_state(ConnectionState::Closing);
    }

    fn enter_draining(&self) {
        self.state.set_state(ConnectionState::Draining);
        self.packet_queues.close_all();
        self.initial_keys.invalid();
        self.handshake_keys.invalid();
        self.zero_rtt_keys.invalid();
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

#[derive(Deref)]
pub struct ConnectionHandle {
    #[deref]
    pub connection: RawConnection,
    pub resources: ConnectionResources,
}

#[derive(Deref, Clone)]
pub struct ArcConnectionHandle(Arc<ConnectionHandle>);

#[derive(Default, Debug, Clone)]
pub struct ConnectionResources {
    pub connection_ids: DashSet<ConnectionId>,
    pub reset_tokens: DashSet<ResetToken>,
}

pub fn new(
    tls_session: TlsIO,
    role: Role,
    // 尚未实现连接迁移
    endpoint_connection_ids: Arc<DashMap<ConnectionId, ArcConnectionHandle>>,
    // 某条连接的对端的无状态重置令牌
    endpoint_reset_tokens: Arc<DashMap<ResetToken, ArcConnectionHandle>>,
) -> ArcConnectionHandle {
    let resources = ConnectionResources::default();

    let conn_state = ArcConnectionState::new();
    let cid_registry = Registry::new(2);

    let initial_keys = ArcKeys::new_pending();
    let initial_space = ArcSpace::new_initial_space();

    let handshake_keys = ArcKeys::new_pending();
    let handshake_space = ArcSpace::new_handshake_space();

    let zero_rtt_keys = ArcKeys::new_pending();
    let one_rtt_keys = ArcOneRttKeys::new_pending();
    let flow_controller = ArcFlowController::with_initial(0, 0);
    let data_space = ArcSpace::new_data_space(role, 0, 0);

    let datagram_flow = DatagramFlow::new(65535, 0);

    let ack_observer = AckObserver::new([
        initial_space.rcvd_pkt_records.clone(),
        handshake_space.rcvd_pkt_records.clone(),
        data_space.rcvd_pkt_records.clone(),
    ]);

    let (loss_observer, [mut initial_loss_rx, mut handshake_loss_rx, mut data_loss_rx]) =
        LossObserver::new();

    let handshake_observer = HandShakeObserver::new(conn_state.clone());
    let (pto_observer, [mut initial_timeout_rx, mut handshake_timeout_rx, mut data_timeout_rx]) =
        PtoObserver::new();

    let connection_observer = ConnectionObserver {
        handshake_observer,
        ack_observer,
        loss_observer,
        pto_observer,
    };

    let (initial_pkt_tx, initial_pkt_rx) = mpsc::unbounded_channel();
    let (handshake_pkt_tx, handshake_pkt_rx) = mpsc::unbounded_channel();
    let (zero_rtt_pkt_tx, zero_rtt_pkt_rx) = mpsc::unbounded_channel();
    let (one_rtt_pkt_tx, one_rtt_pkt_rx) = mpsc::unbounded_channel();

    let packet_queues = PacketQueues::new(
        initial_pkt_tx,
        handshake_pkt_tx,
        zero_rtt_pkt_tx,
        one_rtt_pkt_tx,
    );

    let connection = RawConnection {
        cid_registry: cid_registry.clone(),
        pathes: DashMap::new(),
        packet_queues,
        initial_keys: initial_keys.clone(),
        handshake_keys: handshake_keys.clone(),
        zero_rtt_keys: zero_rtt_keys.clone(),
        one_rtt_keys: one_rtt_keys.clone(),
        spaces: ArcSpaces::new(
            initial_space.clone(),
            handshake_space.clone(),
            data_space.clone(),
        ),
        connection_observer,
        spin: SpinBit::default(),
        state: conn_state.clone(),
        flow_ctrl: flow_controller.clone(),
    };

    let connection_handle = ArcConnectionHandle(Arc::new(ConnectionHandle {
        connection,
        resources,
    }));

    let connection_closing = Arc::new(Notify::new());
    let connection_draining = Arc::new(Notify::new());
    let countdown = Arc::new(Notify::new());

    let (dispath_error_tx, mut dispatch_error_rx) = mpsc::unbounded_channel();

    // decode initial packet
    // producer -> producer
    // return:
    //     initial_pkt_tx dropped
    //     initial_key invalid(
    //         for SERVER: rcvd handshake pkt
    //         for CLIENT: sent handshake pkt
    //         or enter_closing
    let mut initial_packet_stream = auto::InitialPacketStream::new(
        initial_pkt_rx,
        initial_keys.clone(),
        initial_space.rcvd_pkt_records.clone(),
    );

    #[derive(Debug, Clone, Copy, PartialEq)]
    enum DispatchControlFlow {
        Continue,
        Closing,
        Exit,
    }

    // dispatch initial packet
    // producer -> producer
    // return: initial_packet_stream closed
    let initial_crypto_queue_writer = ArcAsyncDeque::new();
    let mut initial_crypto_queue_reader = initial_crypto_queue_writer.clone();
    let initial_close_frame_queue_writer = ArcAsyncDeque::new();
    let mut initial_close_frame_queue_reader = initial_close_frame_queue_writer.clone();
    let initial_ack_frame_queue_writer = ArcAsyncDeque::new();
    let mut initial_ack_frame_queue_reader = initial_ack_frame_queue_writer.clone();
    // 通过select它来获取错误
    tokio::spawn({
        let connection_closing = connection_closing.clone();
        let connection_draining = connection_draining.clone();
        let initial_dispatch_error_tx = dispath_error_tx.clone();
        let conn_state = conn_state.clone();

        async move {
            let dispatch = |stream: &auto::InitialPacketStream, packet: PacketPayload| {
                let pn = packet.pn;
                // TODO: 该包要认的话，还得向对方返回错误信息，并终止连接
                let dispath_result = match conn_state.get_state() {
                    ConnectionState::Initial
                    | ConnectionState::Handshaking
                    | ConnectionState::HandshakeDone => packet.dispatch_initial_space(
                        &initial_crypto_queue_writer,
                        &initial_close_frame_queue_writer,
                        &initial_ack_frame_queue_writer,
                    ),
                    ConnectionState::Closing => {
                        packet.dispatch_closing(&initial_close_frame_queue_writer)
                    }
                    ConnectionState::Draining => return,
                };
                match dispath_result {
                    Ok(_is_ack_eliciting) => {
                        stream.rcvd_pkt_records.register_pn(pn);
                    }
                    Err(e) => {
                        _ = initial_dispatch_error_tx.send(e);
                    }
                }
            };
            loop {
                let flow = tokio::select! {
                    packet = initial_packet_stream.next() => {
                        if let Some(packet) = packet {
                            dispatch(&initial_packet_stream, packet);
                            DispatchControlFlow::Continue
                        } else {
                            DispatchControlFlow::Exit
                        }
                    },
                    _ = connection_closing.notified() => {
                        DispatchControlFlow::Closing
                    }
                    _ = connection_draining.notified() => {
                        DispatchControlFlow::Exit
                    }
                };
                if flow == DispatchControlFlow::Closing || flow == DispatchControlFlow::Exit {
                    initial_crypto_queue_writer.close();
                    initial_ack_frame_queue_writer.close();
                }
                if flow == DispatchControlFlow::Exit {
                    initial_close_frame_queue_writer.close();
                    return;
                }
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
            while let Some((frame, byte)) = initial_crypto_queue_reader.next().await {
                crypto_stream.recv_data(frame, byte)?;
            }
            Ok::<_, Error>(())
        }
    });

    // decode handshake packet
    // producer -> producer
    // return:
    //     handshake_pkt_tx dropped
    //     handshake_keys invalid
    //         handshake done
    //         connection enter closing/draining
    let mut handshake_packet_stream = auto::HandshakePacketStream::new(
        handshake_pkt_rx,
        handshake_keys.clone(),
        handshake_space.rcvd_pkt_records.clone(),
    );

    // initial handle ack
    // -> consumer
    // return: initial_ack_frame_queue_writer dropped
    tokio::spawn({
        let initial_space = initial_space.clone();
        async move {
            while let Some(ack) = initial_ack_frame_queue_reader.next().await {
                initial_space.on_ack(ack);
            }
        }
    });

    // dispatch handshake packet
    // producer -> producer
    // return: handshake_packet_stream closed
    let handshake_crypto_queue_writer = ArcAsyncDeque::new();
    let mut handshake_crypto_queue_reader = handshake_crypto_queue_writer.clone();
    let handshake_close_frame_queue_writer = ArcAsyncDeque::new();
    let mut handshake_close_frame_queue_reader = handshake_close_frame_queue_writer.clone();
    let handshake_ack_frame_writer = ArcAsyncDeque::new();
    let mut handshake_ack_frame_reader = handshake_ack_frame_writer.clone();
    tokio::spawn({
        let conn_state = conn_state.clone();
        let initial_keys = initial_keys.clone();
        let connection_closing = connection_closing.clone();
        let connection_draining = connection_draining.clone();
        let handshake_dispatch_error_tx = dispath_error_tx.clone();
        let conn_state = conn_state.clone();
        async move {
            let dispatch = |stream: &auto::HandshakePacketStream, packet: PacketPayload| {
                let pn = packet.pn;
                // TODO: 该包要认的话，还得向对方返回错误信息，并终止连接
                let dispatch_result = match conn_state.get_state() {
                    ConnectionState::Initial
                    | ConnectionState::Handshaking
                    | ConnectionState::HandshakeDone => packet.dispatch_handshake_space(
                        &handshake_crypto_queue_writer,
                        &handshake_close_frame_queue_writer,
                        &handshake_ack_frame_writer,
                    ),
                    ConnectionState::Closing => {
                        packet.dispatch_closing(&handshake_close_frame_queue_writer)
                    }
                    ConnectionState::Draining => return,
                };
                match dispatch_result {
                    Ok(_is_ack_eliciting) => {
                        if role == Role::Server {
                            initial_keys.invalid();
                            conn_state.set_state(ConnectionState::Handshaking)
                        }
                        stream.rcvd_pkt_records.register_pn(pn);
                    }
                    Err(e) => {
                        _ = handshake_dispatch_error_tx.send(e);
                    }
                }
            };
            loop {
                let flow = tokio::select! {
                    packet = handshake_packet_stream.next() => {
                        if let Some(packet) = packet {
                            dispatch(&handshake_packet_stream, packet);
                            DispatchControlFlow::Continue
                        } else {
                            DispatchControlFlow::Exit
                        }
                    }
                    _ = connection_closing.notified() => {
                        DispatchControlFlow::Closing
                    }
                    _ = connection_draining.notified() => {
                        DispatchControlFlow::Exit
                    }
                };

                if flow == DispatchControlFlow::Closing || flow == DispatchControlFlow::Exit {
                    handshake_crypto_queue_writer.close();
                    handshake_ack_frame_writer.close();
                }
                if flow == DispatchControlFlow::Exit {
                    handshake_close_frame_queue_writer.close();
                    return;
                }
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
            while let Some((frame, data)) = handshake_crypto_queue_reader.next().await {
                crypto_stream.recv_data(frame, data)?;
            }
            Ok::<_, Error>(())
        }
    });

    // handle handshake ack
    // -> consumer
    // return: handshake_ack_frame_writer dropped
    tokio::spawn({
        let handshake_space = handshake_space.clone();
        async move {
            while let Some(ack) = handshake_ack_frame_reader.next().await {
                handshake_space.on_ack(ack);
            }
        }
    });

    tokio::spawn(
        handshake::exchange_initial_crypto_msg_until_getting_handshake_key(
            tls_session.clone(),
            handshake_keys,
            initial_space.as_ref().split(),
        ),
    );

    let handshake_done_handle = tokio::spawn({
        let connection = connection_handle.clone();
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

    // decode 0rtt packet
    // producer -> producer
    // return:
    //     zero_rtt_pkt_tx dropped
    //     zero_rtt_keys invalid
    //         handshake done
    //         connection enter closing/draining
    let mut zero_rtt_packet_stream = auto::ZeroRttPacketStream::new(
        zero_rtt_pkt_rx,
        zero_rtt_keys,
        data_space.rcvd_pkt_records.clone(),
    );

    // dispatch zero rtt packet
    // producer -> producer
    // return: zero_rtt_packet_stream closed
    let zero_rtt_datagram_frame_queue_writer = ArcAsyncDeque::new();
    let mut zero_rtt_datagram_frame_queue_reader = zero_rtt_datagram_frame_queue_writer.clone();
    let zero_rtt_max_data_frame_queue_writer = ArcAsyncDeque::new();
    let mut zero_rtt_max_data_frame_queue_reader = zero_rtt_max_data_frame_queue_writer.clone();
    let zero_rtt_stream_frame_queue_writer = ArcAsyncDeque::new();
    let mut zero_rtt_stream_frame_queue_reader = zero_rtt_stream_frame_queue_writer.clone();
    let zero_rtt_stream_ctl_frame_queue_writer = ArcAsyncDeque::new();
    let mut zero_rtt_stream_ctl_frame_queue_reader = zero_rtt_stream_ctl_frame_queue_writer.clone();
    let zero_rtt_close_frame_queue_writer = ArcAsyncDeque::new();
    let mut zero_rtt_close_frame_queue_reader = zero_rtt_close_frame_queue_writer.clone();
    tokio::spawn({
        let connection_closing = connection_closing.clone();
        let connection_draining = connection_draining.clone();
        let zero_rtt_dispatch_error_tx = dispath_error_tx.clone();
        let conn_state = conn_state.clone();
        async move {
            let dispatch = |stream: &auto::ZeroRttPacketStream, packet: PacketPayload| {
                let pn = packet.pn;
                let dispatch_result = match conn_state.get_state() {
                    ConnectionState::Initial
                    | ConnectionState::Handshaking
                    | ConnectionState::HandshakeDone => packet.dispatch_zero_rtt(
                        &zero_rtt_datagram_frame_queue_writer,
                        &zero_rtt_max_data_frame_queue_writer,
                        &zero_rtt_stream_frame_queue_writer,
                        &zero_rtt_stream_ctl_frame_queue_writer,
                        &zero_rtt_close_frame_queue_writer,
                    ),
                    ConnectionState::Closing => {
                        packet.dispatch_closing(&zero_rtt_close_frame_queue_writer)
                    }
                    ConnectionState::Draining => return,
                };
                match dispatch_result {
                    Ok(_is_ack_eliciting) => {
                        stream.rcvd_pkt_records.register_pn(pn);
                    }
                    Err(e) => {
                        _ = zero_rtt_dispatch_error_tx.send(e);
                    }
                }
            };
            loop {
                let flow = tokio::select! {
                    packet = zero_rtt_packet_stream.next() => {
                        if let Some(packet) = packet {
                            dispatch(&zero_rtt_packet_stream, packet);
                            DispatchControlFlow::Continue
                        } else {
                            DispatchControlFlow::Exit
                        }
                    }
                    _ = connection_closing.notified() => {
                        DispatchControlFlow::Closing
                    }
                    _ = connection_draining.notified() => {
                        DispatchControlFlow::Exit
                    }
                };
                if flow == DispatchControlFlow::Closing || flow == DispatchControlFlow::Exit {
                    zero_rtt_datagram_frame_queue_writer.close();
                    zero_rtt_max_data_frame_queue_writer.close();
                    zero_rtt_stream_frame_queue_writer.close();
                    zero_rtt_stream_ctl_frame_queue_writer.close();
                }
                if flow == DispatchControlFlow::Exit {
                    zero_rtt_close_frame_queue_writer.close();
                    return;
                }
            }
        }
    });

    // zero rtt recv datagram frame
    // -> consumer
    // return:
    //     zero_rtt_datagram_frame_queue_writer.close() called
    //     error
    let zero_rtt_datagram_flow_handle = tokio::spawn({
        let zero_rtt_datagram_flow = datagram_flow.clone();
        async move {
            while let Some((frame, data)) = zero_rtt_datagram_frame_queue_reader.next().await {
                zero_rtt_datagram_flow.recv_datagram(frame, data)?;
            }

            Ok::<_, Error>(())
        }
    });

    // zero rtt recv datagram frame
    // -> consumer
    // return:
    //     zero_rtt_max_data_frame_queue_reader.close() called
    tokio::spawn({
        let flow_controller = flow_controller.clone();
        async move {
            while let Some(frame) = zero_rtt_max_data_frame_queue_reader.next().await {
                flow_controller.sender.permit(frame.max_data.into_inner());
            }
        }
    });

    // zero rtt recv stream frame
    // -> consumer
    // return:
    //     zero_rtt_stream_frame_queue_writer.close() called
    //     error
    let zero_rtt_data_stream_handle = tokio::spawn({
        let data_streams = data_space.data_stream.clone();
        async move {
            while let Some((frame, data)) = zero_rtt_stream_frame_queue_reader.next().await {
                data_streams.recv_data(frame, data)?;
            }
            Ok::<_, Error>(())
        }
    });

    // zero rtt recv stream control frame
    // -> consumer
    // return:
    //     zero_rtt_stream_ctl_frame_queue_writer.close() called
    //     error
    let zero_rtt_stream_control_frame_handle = tokio::spawn({
        let data_streams = data_space.data_stream.clone();
        async move {
            while let Some(frame) = zero_rtt_stream_ctl_frame_queue_reader.next().await {
                data_streams.recv_stream_control(frame)?;
            }
            Ok::<_, Error>(())
        }
    });

    // decode 1rtt packet
    // producer -> producer
    // return: connection enter closing/draining
    let mut one_rtt_packet_stream = auto::OneRttPacketStream::new(
        one_rtt_pkt_rx,
        one_rtt_keys.clone(),
        data_space.rcvd_pkt_records.clone(),
    );

    // dispatch 1rtt packet
    // producer -> producer
    // return: connection enter closing/draining
    let one_rtt_conn_id_frame_queue_writer = ArcAsyncDeque::new();
    let mut one_rtt_conn_id_frame_queue_reader = one_rtt_conn_id_frame_queue_writer.clone();
    let one_rtt_token_frame_queue_writer = ArcAsyncDeque::new();
    let mut one_rtt_token_frame_queue_reader = one_rtt_token_frame_queue_writer.clone();
    let one_rtt_datagram_frame_queue_writer = ArcAsyncDeque::new();
    let mut one_rtt_datagram_frame_queue_reader = one_rtt_datagram_frame_queue_writer.clone();
    let one_rtt_max_data_frame_queue_writer = ArcAsyncDeque::new();
    let mut one_rtt_max_data_frame_queue_reader = one_rtt_max_data_frame_queue_writer.clone();
    let one_rtt_hs_done_frame_queue_writer = ArcAsyncDeque::new();
    let mut one_rtt_hs_done_frame_queue_reader = one_rtt_hs_done_frame_queue_writer.clone();
    let one_rtt_stream_frame_queue_writer = ArcAsyncDeque::new();
    let mut one_rtt_stream_frame_queue_reader = one_rtt_stream_frame_queue_writer.clone();
    let one_rtt_stream_ctl_frame_queue_writer = ArcAsyncDeque::new();
    let mut one_rtt_stream_ctl_frame_queue_reader = one_rtt_stream_ctl_frame_queue_writer.clone();
    let one_rtt_crypto_frame_queue_writer = ArcAsyncDeque::new();
    let mut one_rtt_crypto_frame_queue_reader = one_rtt_crypto_frame_queue_writer.clone();
    let one_rtt_close_frame_queue_writer = ArcAsyncDeque::new();
    let mut one_rtt_close_frame_queue_reader = one_rtt_close_frame_queue_writer.clone();
    let one_rtt_ack_frame_queue_writer = ArcAsyncDeque::new();
    let mut one_rtt_ack_frame_queue_reader = one_rtt_ack_frame_queue_writer.clone();
    tokio::spawn({
        let connection_closing = connection_closing.clone();
        let connection_draining = connection_draining.clone();
        let one_rtt_dispatch_error_tx = dispath_error_tx;
        let conn_state = conn_state.clone();
        async move {
            let dispatch = |stream: &auto::OneRttPacketStream, packet: PacketPayload| {
                let pn = packet.pn;
                let dispatch_result = match conn_state.get_state() {
                    ConnectionState::Initial
                    | ConnectionState::Handshaking
                    | ConnectionState::HandshakeDone => packet.dispatch_one_rtt(
                        &one_rtt_conn_id_frame_queue_writer,
                        &one_rtt_token_frame_queue_writer,
                        &one_rtt_datagram_frame_queue_writer,
                        &one_rtt_max_data_frame_queue_writer,
                        &one_rtt_hs_done_frame_queue_writer,
                        &one_rtt_stream_frame_queue_writer,
                        &one_rtt_stream_ctl_frame_queue_writer,
                        &one_rtt_crypto_frame_queue_writer,
                        &one_rtt_close_frame_queue_writer,
                        &one_rtt_ack_frame_queue_writer,
                    ),
                    ConnectionState::Closing => {
                        packet.dispatch_closing(&one_rtt_close_frame_queue_writer)
                    }
                    ConnectionState::Draining => return,
                };
                match dispatch_result {
                    Ok(_is_ack_eliciting) => {
                        stream.rcvd_pkt_records.register_pn(pn);
                    }
                    Err(error) => {
                        _ = one_rtt_dispatch_error_tx.send(error);
                    }
                }
            };
            loop {
                let flow = tokio::select! {
                    packet = one_rtt_packet_stream.next() => {
                        if let Some(packet) = packet {
                            dispatch(&one_rtt_packet_stream, packet);
                            DispatchControlFlow::Continue
                        } else {
                            DispatchControlFlow::Exit
                        }
                    }
                    _ = connection_closing.notified() => {
                        DispatchControlFlow::Closing
                    }
                    _ = connection_draining.notified() => {
                        DispatchControlFlow::Exit
                    }
                };

                if flow == DispatchControlFlow::Closing || flow == DispatchControlFlow::Exit {
                    one_rtt_conn_id_frame_queue_writer.close();
                    one_rtt_token_frame_queue_writer.close();
                    one_rtt_datagram_frame_queue_writer.close();
                    one_rtt_max_data_frame_queue_writer.close();
                    one_rtt_hs_done_frame_queue_writer.close();
                    one_rtt_stream_frame_queue_writer.close();
                    one_rtt_stream_ctl_frame_queue_writer.close();
                    one_rtt_crypto_frame_queue_writer.close();
                    one_rtt_ack_frame_queue_writer.close();
                }

                if flow == DispatchControlFlow::Exit {
                    one_rtt_close_frame_queue_writer.close();
                    return;
                }
            }
        }
    });

    // one rtt recv connection id frame
    // -> consumer
    // return:
    //     one_rtt_conn_id_frame_queue_reader.close() called
    //     error
    let one_rtt_handle_cid_frame_handle = tokio::spawn({
        let cid_registry = cid_registry.clone();
        let connection_ids = endpoint_connection_ids.clone();
        let peer_reset_tokens = endpoint_reset_tokens.clone();
        let connection_handle = connection_handle.clone();

        // TODO：收到对方对retire_connection_id的确认后，从表中移除reset token
        // TODO: 创建新链接ID时，插入表中
        async move {
            while let Some(frame) = one_rtt_conn_id_frame_queue_reader.next().await {
                match frame {
                    auto::ConnIdFrame::NewConnectionId(frame) => {
                        let new_token = cid_registry
                            .remote
                            .lock_guard()
                            .recv_new_cid_frame(&frame)?;
                        if let Some(new_token) = new_token {
                            peer_reset_tokens.insert(new_token, connection_handle.clone());
                            connection_handle.resources.reset_tokens.insert(new_token);
                        }
                    }
                    auto::ConnIdFrame::RetireConnectionId(frame) => {
                        let retired = cid_registry
                            .local
                            .lock_guard()
                            .recv_retire_cid_frame(&frame)?;
                        if let Some(retired) = retired {
                            connection_handle.resources.connection_ids.remove(&retired);
                            connection_ids.remove(&retired);
                        }
                    }
                }
            }
            Ok::<_, Error>(())
        }
    });

    // one rtt recv new token frame
    // -> consumer
    // return:
    //     one_rtt_token_frame_queue_reader.close() called
    tokio::spawn({
        async move {
            if let Some(_frame) = one_rtt_token_frame_queue_reader.next().await {
                // TODO: 备用
            }
        }
    });

    // one rtt recv datagram frame
    // -> consumer
    // return:
    //     one_rtt_datagram_frame_queue_writer.close() called
    //     error
    let one_rtt_datagram_flow_handle = tokio::spawn({
        let one_rtt_datagram_flow = datagram_flow.clone();
        async move {
            while let Some((frame, data)) = one_rtt_datagram_frame_queue_reader.next().await {
                one_rtt_datagram_flow.recv_datagram(frame, data)?;
            }

            Ok::<_, Error>(())
        }
    });

    // one rtt recv datagram frame
    // -> consumer
    // return:
    //     one_rtt_max_data_frame_queue_reader.close() called
    tokio::spawn({
        let flow_controller = flow_controller.clone();
        async move {
            while let Some(frame) = one_rtt_max_data_frame_queue_reader.next().await {
                flow_controller.sender.permit(frame.max_data.into_inner());
            }
        }
    });

    // one rtt recv handshake done frame
    // -> consumer
    // return:
    //    one_rtt_hs_done_frame_queue_writer.close() called
    let one_rtt_hs_done_frame_handle = tokio::spawn({
        let connection_handle = connection_handle.clone();
        async move {
            if let Some(_frame) = one_rtt_hs_done_frame_queue_reader.next().await {
                if role == Role::Server {
                    return Err(Error::new_with_default_fty(
                        ErrorKind::ProtocolViolation,
                        "client should not send HandshakeDoneFrame",
                    ));
                }
                connection_handle.enter_handshake_done();
            }
            Ok(())
        }
    });

    // one rtt recv stream frame
    // -> consumer
    // return:
    //     one_rtt_stream_frame_queue_writer.close() called
    //     error
    let one_rtt_data_stream_handle = tokio::spawn({
        let data_streams = data_space.data_stream.clone();
        async move {
            while let Some((frame, data)) = one_rtt_stream_frame_queue_reader.next().await {
                data_streams.recv_data(frame, data)?;
            }
            Ok::<_, Error>(())
        }
    });

    // one rtt recv stream control frame
    // -> consumer
    // return:
    //     one_rtt_stream_ctl_frame_queue_writer.close() called
    //     error
    let one_rtt_stream_control_frame_handle = tokio::spawn({
        let data_streams = data_space.data_stream.clone();
        async move {
            while let Some(frame) = one_rtt_stream_ctl_frame_queue_reader.next().await {
                data_streams.recv_stream_control(frame)?;
            }
            Ok::<_, Error>(())
        }
    });

    // one rtt recv crypto frame
    // -> consumer
    // return:
    //     handshake_crypto_stream_writer.close() called
    //     error
    let one_rtt_crypto_stream_handle = tokio::spawn({
        let crypto_stream = handshake_space.as_ref().clone();
        async move {
            while let Some((frame, data)) = one_rtt_crypto_frame_queue_reader.next().await {
                crypto_stream.recv_data(frame, data)?;
            }
            Ok::<_, Error>(())
        }
    });

    // handle handshake ack
    // -> consumer
    // return: one_rtt_ack_frame_queue_writer dropped
    tokio::spawn({
        let data_space = data_space.clone();
        async move {
            while let Some(ack) = one_rtt_ack_frame_queue_reader.next().await {
                data_space.on_ack(ack);
            }
        }
    });

    // handle may loss tasks
    // -> consumer
    // return: loss_observer dropped
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

    // handle pto probe tasks
    // -> consumer
    // return: pto_observer dropped
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

    // handle connection error
    tokio::spawn({
        let connection_handle = connection_handle.clone();
        let data_space = data_space.clone();
        let datagram_flow = datagram_flow.clone();
        let connection_closing = connection_closing.clone();
        let countdown = countdown.clone();
        async move {
            let error = tokio::select! {
                // Err(e) = initial_dispatch_handle.map(Result::unwrap) => e,
                Err(e) = initial_crypto_stream_handle.map(Result::unwrap) => e,
                Err(e) = handshake_crypto_stream_handle.map(Result::unwrap) => e,
                Err(e) = handshake_done_handle.map(Result::unwrap) => e,
                Err(e) = zero_rtt_datagram_flow_handle.map(Result::unwrap) => e,
                Err(e) = zero_rtt_data_stream_handle.map(Result::unwrap) => e,
                Err(e) = zero_rtt_stream_control_frame_handle.map(Result::unwrap) => e,
                Err(e) = one_rtt_handle_cid_frame_handle.map(Result::unwrap) => e,
                Err(e) = one_rtt_datagram_flow_handle.map(Result::unwrap) => e,
                Err(e) = one_rtt_hs_done_frame_handle.map(Result::unwrap) => e,
                Err(e) = one_rtt_data_stream_handle.map(Result::unwrap) => e,
                Err(e) = one_rtt_stream_control_frame_handle.map(Result::unwrap) => e,
                Err(e) = one_rtt_crypto_stream_handle.map(Result::unwrap) => e,
                // connection closed is handled by another task
                Some(e) = dispatch_error_rx.recv() => e,
                _ = connection_closing.notified() => return,
            };

            // 向应用层报告错误

            let state = connection_handle.state.get_state();

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
            data_space.data_stream.on_conn_error(&error);
            datagram_flow.on_conn_error(&error);

            connection_handle.enter_closing();
            connection_closing.notify_waiters();
            countdown.notify_waiters();
        }
    });

    // * recv connection close frame
    // -> consumer
    // return:
    //     intiial_close_frame_queue_reader closed
    //     handshake_close_frame_queue_reader closed
    //     zero_rtt_close_frame_queue_reader closed
    //     one_rtt_close_frame_queue_reader closed
    //     connection closed
    tokio::spawn({
        let connection_handle = connection_handle.clone();
        let connection_draining = connection_draining.clone();
        let connection_closing = connection_closing.clone();
        let countdown = countdown.clone();
        async move {
            let ccf = tokio::select! {
                Some(ccf) = initial_close_frame_queue_reader.next() => ccf,
                Some(ccf) = handshake_close_frame_queue_reader.next() => ccf,
                Some(ccf) = zero_rtt_close_frame_queue_reader.next() => ccf,
                Some(ccf) = one_rtt_close_frame_queue_reader.next() => ccf,
                // connection closed is handled by another task
                _ = connection_draining.notified() => return,
            };

            let error = Error::from(ccf);
            data_space.data_stream.on_conn_error(&error);
            datagram_flow.on_conn_error(&error);

            connection_handle.enter_draining();
            connection_closing.notify_waiters();
            countdown.notify_waiters();
        }
    });

    // connection close
    tokio::spawn({
        let connection_ids = endpoint_connection_ids.clone();
        let peer_reset_tokens = endpoint_reset_tokens.clone();
        let connection_handle = connection_handle.clone();

        async move {
            countdown.notified().await;

            // TOOD: wait 3xPTO

            for local_cid in connection_handle.resources.connection_ids.iter() {
                connection_ids.remove(local_cid.deref());
            }
            for remote_token in connection_handle.resources.reset_tokens.iter() {
                peer_reset_tokens.remove(remote_token.deref());
            }

            connection_closing.notified();
            connection_draining.notified();
        }
    });

    connection_handle
}

#[cfg(test)]
mod tests {}
