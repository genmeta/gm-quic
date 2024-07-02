pub mod state;

use std::{
    sync::{Arc, RwLock},
    time::Duration,
};

use dashmap::DashMap;
use deref_derive::Deref;
use futures::StreamExt;
use qbase::{
    error::{Error, ErrorKind},
    frame::{ConnFrame, ConnectionCloseFrame, HandshakeDoneFrame, MaxDataFrame},
    packet::{
        keys::{ArcKeys, ArcOneRttKeys},
        HandshakePacket, InitialPacket, OneRttPacket, SpacePacket, SpinBit, ZeroRttPacket,
    },
    streamid::Role,
    util::ArcAsyncDeque,
};
use qrecovery::space::ArcSpace;
use qudp::ArcUsc;
use state::{ArcConnectionState, ConnectionState};
use tokio::sync::mpsc;

use crate::{
    auto,
    controller::ArcFlowController,
    crypto::TlsIO,
    handshake,
    path::{AckObserver, ArcPath, LossObserver, Pathway},
};

type PacketQueue<T> = mpsc::UnboundedSender<(T, ArcPath)>;
/// Option是为了能丢弃前期空间，包括这些空间的收包队列，
/// 一旦丢弃，后续再收到该空间的包，直接丢弃。
type RxPacketQueue<T> = Option<PacketQueue<T>>;

pub struct RawConnection {
    // local_cids: ArcLocalCids,
    // remote_cids: RemoteCids,

    // 所有Path的集合，Pathway作为key
    pathes: DashMap<Pathway, ArcPath>,

    init_pkt_queue: RwLock<RxPacketQueue<InitialPacket>>,
    hs_pkt_queue: RwLock<RxPacketQueue<HandshakePacket>>,
    zero_rtt_pkt_queue: RwLock<RxPacketQueue<ZeroRttPacket>>,
    one_rtt_pkt_queue: mpsc::UnboundedSender<(OneRttPacket, ArcPath)>,

    // Thus, a client MUST discard Initial keys when it first sends a Handshake packet
    // and a server MUST discard Initial keys when it first successfully processes a
    // Handshake packet. Endpoints MUST NOT send Initial packets after this point.
    initial_keys: ArcKeys,
    handshake_keys: ArcKeys,
    zero_rtt_keys: ArcKeys,

    // 创建新的path用的到，path中的拥塞控制器需要
    ack_observer: AckObserver,
    loss_observer: LossObserver,

    spin: SpinBit,
    state: ArcConnectionState,

    // 连接级流控制器
    flow_ctrl: ArcFlowController,
}

impl RawConnection {
    pub fn recv_init_pkt_via(&self, pkt: InitialPacket, usc: &ArcUsc, pathway: Pathway) {
        if let Some(queue) = self.init_pkt_queue.read().unwrap().as_ref() {
            let path = self.get_path(pathway, usc);
            _ = queue.send((pkt, path));
        }
    }

    pub fn recv_hs_pkt_via(&self, pkt: HandshakePacket, usc: &ArcUsc, pathway: Pathway) {
        if let Some(queue) = self.hs_pkt_queue.read().unwrap().as_ref() {
            let path = self.get_path(pathway, usc);
            _ = queue.send((pkt, path));
        }
    }

    pub fn recv_0rtt_pkt_via(&self, pkt: ZeroRttPacket, usc: &ArcUsc, pathway: Pathway) {
        if let Some(queue) = self.zero_rtt_pkt_queue.read().unwrap().as_ref() {
            let path = self.get_path(pathway, usc);
            _ = queue.send((pkt, path));
        }
    }

    pub fn recv_1rtt_pkt_via(&self, pkt: OneRttPacket, usc: &ArcUsc, pathway: Pathway) {
        let path = self.get_path(pathway, usc);
        self.one_rtt_pkt_queue
            .send((pkt, path))
            .expect("must success");
    }

    pub fn recv_protected_pkt_via(&mut self, pkt: SpacePacket, usc: &ArcUsc, pathway: Pathway) {
        match pkt {
            SpacePacket::Initial(pkt) => self.recv_init_pkt_via(pkt, usc, pathway),
            SpacePacket::Handshake(pkt) => self.recv_hs_pkt_via(pkt, usc, pathway),
            SpacePacket::ZeroRtt(pkt) => self.recv_0rtt_pkt_via(pkt, usc, pathway),
            SpacePacket::OneRtt(pkt) => self.recv_1rtt_pkt_via(pkt, usc, pathway),
        }
    }

    fn handshake_done(&self) {
        self.state.set_state(ConnectionState::HandshakeDone);

        self.initial_keys.invalid();
        self.init_pkt_queue.write().unwrap().take();

        self.handshake_keys.invalid();
        self.hs_pkt_queue.write().unwrap().take();

        self.zero_rtt_keys.invalid();
        self.zero_rtt_pkt_queue.write().unwrap().take();
    }

    pub fn get_path(&self, pathway: Pathway, usc: &ArcUsc) -> ArcPath {
        self.pathes
            .entry(pathway)
            .or_insert_with({
                let usc = usc.clone();
                let ack_observer = self.ack_observer.clone();
                let loss_observer = self.loss_observer.clone();
                || {
                    // TODO: 要为该新路径创建发送任务，需要连接id...spawn出一个任务，直到{何时}终止?
                    ArcPath::new(usc, Duration::from_millis(100), ack_observer, loss_observer)
                }
            })
            .clone()
    }
}

#[derive(Deref)]
pub struct ArcConnection(Arc<RawConnection>);

pub fn new(tls_session: TlsIO, role: Role) -> ArcConnection {
    let conn_frame_deque = ArcAsyncDeque::new();
    let conn_state = ArcConnectionState::new();

    let initial_keys = ArcKeys::new_pending();

    let initial_space = ArcSpace::new_initial_space();
    let initial_ack_tx = initial_space.spawn_recv_ack();
    let (initial_pkt_tx, initial_packet_stream) = auto::InitialPacketStream::new(
        initial_keys.clone(),
        initial_space.rcvd_pkt_records.clone(),
    );

    let initial_space_frame_queue = initial_space.spawn_recv_space_frames();

    initial_packet_stream.parse_packet_and_then_dispatch(
        Some(conn_frame_deque.clone()),
        Some(initial_space_frame_queue.clone()),
        None,
        initial_ack_tx.clone(),
    );

    let handshake_keys = ArcKeys::new_pending();

    let handshake_space = ArcSpace::new_handshake_space();
    let handshake_ack_tx = handshake_space.spawn_recv_ack();
    let (handshake_pkt_tx, handshake_packet_stream) = auto::HandshakePacketStream::new(
        handshake_keys.clone(),
        handshake_space.rcvd_pkt_records.clone(),
    );

    let handshake_space_frame_queue = handshake_space.spawn_recv_space_frames();

    handshake_packet_stream.parse_packet_and_then_dispatch(
        Some(conn_frame_deque.clone()),
        Some(handshake_space_frame_queue),
        None,
        handshake_ack_tx.clone(),
    );

    tokio::spawn(
        handshake::exchange_initial_crypto_msg_until_getting_handshake_key(
            tls_session.clone(),
            handshake_keys.clone(),
            initial_space.as_ref().split(),
        ),
    );

    let datagram_queue = ArcAsyncDeque::new();

    let zero_rtt_keys = ArcKeys::new_pending();
    let one_rtt_keys = ArcOneRttKeys::new_pending();

    let data_space = ArcSpace::new_data_space(role, 0, 0);
    let data_ack_tx = data_space.spawn_recv_ack();
    let (zero_rtt_pkt_tx, zero_rtt_packet_stream) =
        auto::ZeroRttPacketStream::new(zero_rtt_keys.clone(), data_space.rcvd_pkt_records.clone());

    let data_space_frame_queue = data_space.spawn_recv_space_frames();

    zero_rtt_packet_stream.parse_packet_and_then_dispatch(
        Some(conn_frame_deque.clone()),
        Some(data_space_frame_queue),
        Some(datagram_queue.clone()),
        data_ack_tx.clone(),
    );

    let (one_rtt_pkt_tx, dataspace_packets) =
        auto::OneRttPacketStream::new(one_rtt_keys.clone(), data_space.rcvd_pkt_records.clone());

    let data_space_frame_queue = data_space.spawn_recv_space_frames();

    dataspace_packets.parse_packet_and_then_dispatch(
        Some(conn_frame_deque.clone()),
        Some(data_space_frame_queue),
        Some(datagram_queue.clone()),
        data_ack_tx.clone(),
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

    let flow_controller = ArcFlowController::with_initial(0, 0);
    let connection = Arc::new(RawConnection {
        pathes: DashMap::new(),
        init_pkt_queue: Some(initial_pkt_tx).into(),
        hs_pkt_queue: Some(handshake_pkt_tx).into(),
        zero_rtt_pkt_queue: Some(zero_rtt_pkt_tx).into(),
        one_rtt_pkt_queue: one_rtt_pkt_tx,
        initial_keys,
        handshake_keys,
        zero_rtt_keys,
        ack_observer,
        loss_observer,
        spin: SpinBit::default(),
        state: conn_state.clone(),
        flow_ctrl: flow_controller.clone(),
    });

    tokio::spawn({
        let connection = connection.clone();

        async move {
            let transport_parameters =
                handshake::exchange_handshake_crypto_msg_until_getting_1rtt_key(
                    tls_session.clone(),
                    one_rtt_keys.clone(),
                    handshake_space.as_ref().split(),
                )
                .await;
            data_space.accept_transmute_parameters(&transport_parameters);
            if role == Role::Server {
                data_space
                    .reliable_frame_queue
                    .write()
                    .push_conn_frame(ConnFrame::HandshakeDone(HandshakeDoneFrame));
                connection.handshake_done();
            }
        }
    });

    tokio::spawn({
        let mut conn_frame_deque = conn_frame_deque;
        let connection = connection.clone();
        async move {
            while let Some(conn_frame) = conn_frame_deque.next().await {
                let error: Option<Error> = match conn_frame {
                    ConnFrame::Close(_err) => {
                        conn_state.set_state(ConnectionState::Draining);
                        // TODO: 可以发送一个CCF
                        // TODO: 向应用层告知错误？
                        Ok(())
                    }
                    ConnFrame::NewToken(_) => todo!(),
                    ConnFrame::MaxData(MaxDataFrame { max_data }) => {
                        flow_controller.sender.permit(max_data.into_inner());
                        Ok(())
                    }
                    ConnFrame::NewConnectionId(frame) => todo!(),
                    ConnFrame::RetireConnectionId(frame) => {
                        todo!()
                    }
                    ConnFrame::HandshakeDone(_) => {
                        if role == Role::Client {
                            connection.handshake_done();
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
                .err();

                // 发送CCF到对端
                if let Some(frame) = error.map(ConnectionCloseFrame::from) {
                    match connection.state.get_state() {
                        ConnectionState::Handshaking => todo!(),
                        ConnectionState::HandshakeDone => todo!(),
                        ConnectionState::Closing => todo!(),
                        ConnectionState::Draining => todo!(),
                    }
                }
            }
        }
    });

    ArcConnection(connection)
}

#[cfg(test)]
mod tests {}
