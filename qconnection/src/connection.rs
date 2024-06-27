use std::{collections::HashMap, time::Duration};

use qbase::{
    packet::{
        keys::{ArcKeys, ArcOneRttKeys},
        HandshakePacket, InitialPacket, OneRttPacket, SpinBit, ZeroRttPacket,
    },
    streamid::Role,
    util::ArcAsyncDeque,
};
use qudp::ArcUsc;
use tokio::sync::mpsc;

use crate::{
    auto,
    controller::ArcFlowController,
    crypto::TlsIO,
    handshake,
    path::{AckObserver, ArcPath, LossObserver, Pathway},
    space::{ArcSpace, DataSpace, HandshakeSpace, InitalSpace, Space},
};

/// Option是为了能丢弃前期空间，包括这些空间的收包队列，
/// 一旦丢弃，后续再收到该空间的包，直接丢弃。
type RxPacketQueue<T> = Option<mpsc::UnboundedSender<(T, ArcPath)>>;

pub struct RawConnection {
    // 所有Path的集合，Pathway作为key
    pathes: HashMap<Pathway, ArcPath>,
    init_pkt_queue: RxPacketQueue<InitialPacket>,
    hs_pkt_queue: RxPacketQueue<HandshakePacket>,
    zero_rtt_pkt_queue: RxPacketQueue<ZeroRttPacket>,
    one_rtt_pkt_queue: mpsc::UnboundedSender<(OneRttPacket, ArcPath)>,

    // Thus, a client MUST discard Initial keys when it first sends a Handshake packet
    // and a server MUST discard Initial keys when it first successfully processes a
    // Handshake packet. Endpoints MUST NOT send Initial packets after this point.
    initial_keys: ArcKeys,
    handshake_keys: ArcKeys,
    zero_rtt_keys: ArcKeys,

    // 发送数据，也可以随着升级到Handshake空间而丢弃
    initial_space: ArcSpace<InitalSpace>,
    // An endpoint MUST discard its Handshake keys when the TLS handshake is confirmed.
    // 发送数据，也可以随着升级到1RTT空间而丢弃
    handshake_space: ArcSpace<HandshakeSpace>,
    // 发送数据，也可以随着升级到1RTT空间而丢弃
    data_space: ArcSpace<DataSpace>,

    // 创建新的path用的到，path中的拥塞控制器需要
    ack_observer: AckObserver,
    loss_observer: LossObserver,

    spin: SpinBit,

    // 连接级流控制器
    flow_ctrl: ArcFlowController,
}

pub fn new(tls_session: TlsIO) -> RawConnection {
    let rcvd_conn_frames = ArcAsyncDeque::new();

    let (initial_ack_tx, initial_ack_rx) = mpsc::unbounded_channel();
    let (initial_loss_tx, initial_loss_rx) = mpsc::unbounded_channel();
    let initial_keys = ArcKeys::new_pending();
    // 实际上从未被读取/写入
    let initial_space_frame_queue = ArcAsyncDeque::new();
    let initial_space = ArcSpace::new_initial_space();

    let (initial_pkt_tx, initial_packet_stream) = auto::InitialPacketStream::new(
        initial_keys.clone(),
        initial_space.rcvd_pkt_records.clone(),
    );

    initial_packet_stream.parse_packet_and_then_dispatch(
        Some(rcvd_conn_frames.clone()),
        Some(initial_space_frame_queue.clone()),
        None,
        initial_ack_tx.clone(),
    );

    tokio::spawn({
        let space = initial_space.clone();
        let mut ack_rx = initial_ack_rx;
        async move {
            // 通过rx接收并处理AckFrame，AckFrame是Path收包解包得到
            while let Some(ack) = ack_rx.recv().await {
                space.on_ack(ack);
            }
        }
    });
    tokio::spawn({
        let space = initial_space.clone();
        let mut loss_pkt_rx = initial_loss_rx;
        async move {
            // 不停地接收丢包序号，这些丢包序号由path记录反馈，更新Transmiter的状态
            while let Some(pn) = loss_pkt_rx.recv().await {
                space.may_loss_pkt(pn);
            }
        }
    });

    let (handshake_ack_tx, handshake_ack_rx) = mpsc::unbounded_channel();
    let (handshake_loss_tx, handshake_loss_rx) = mpsc::unbounded_channel();

    let handshake_keys = ArcKeys::new_pending();

    let handshake_space_frame_queue = ArcAsyncDeque::new();
    let handshake_space = ArcSpace::new_handshake_space();

    let (handshake_pkt_tx, handshake_packet_stream) = auto::HandshakePacketStream::new(
        handshake_keys.clone(),
        handshake_space.rcvd_pkt_records.clone(),
    );

    handshake_packet_stream.parse_packet_and_then_dispatch(
        Some(rcvd_conn_frames.clone()),
        Some(handshake_space_frame_queue.clone()),
        None,
        handshake_ack_tx.clone(),
    );

    tokio::spawn({
        let space = handshake_space.clone();
        let mut ack_rx = handshake_ack_rx;
        async move {
            // 通过rx接收并处理AckFrame，AckFrame是Path收包解包得到
            while let Some(ack) = ack_rx.recv().await {
                space.on_ack(ack);
            }
        }
    });
    tokio::spawn({
        let space = handshake_space.clone();
        let mut loss_pkt_rx = handshake_loss_rx;
        async move {
            // 不停地接收丢包序号，这些丢包序号由path记录反馈，更新Transmiter的状态
            while let Some(pn) = loss_pkt_rx.recv().await {
                space.may_loss_pkt(pn);
            }
        }
    });
    tokio::spawn(
        handshake::exchange_initial_crypto_msg_until_getting_handshake_key(
            tls_session.clone(),
            handshake_keys.clone(),
            initial_space.crypto_stream.split(),
        ),
    );

    let datagram_queue = ArcAsyncDeque::new();

    let zero_rtt_keys = ArcKeys::new_pending();
    let one_rtt_keys = ArcOneRttKeys::new_pending();
    let data_space_frame_queue = ArcAsyncDeque::new();
    let (data_ack_tx, data_ack_rx) = mpsc::unbounded_channel();
    let (data_loss_tx, data_loss_rx) = mpsc::unbounded_channel();
    let data_space = ArcSpace::new_data_space(Role::Client, 20, 20);

    tokio::spawn({
        let space = data_space.clone();
        let mut ack_rx = data_ack_rx;
        async move {
            // 通过rx接收并处理AckFrame，AckFrame是Path收包解包得到
            while let Some(ack) = ack_rx.recv().await {
                space.on_ack(ack);
            }
        }
    });
    tokio::spawn({
        let space = data_space.clone();
        let mut loss_pkt_rx = data_loss_rx;
        async move {
            // 不停地接收丢包序号，这些丢包序号由path记录反馈，更新Transmiter的状态
            while let Some(pn) = loss_pkt_rx.recv().await {
                space.may_loss_pkt(pn);
            }
        }
    });

    let (zero_rtt_pkt_tx, zero_rtt_packet_stream) =
        auto::ZeroRttPacketStream::new(zero_rtt_keys.clone(), data_space.rcvd_pkt_records.clone());

    zero_rtt_packet_stream.parse_packet_and_then_dispatch(
        Some(rcvd_conn_frames.clone()),
        Some(data_space_frame_queue.clone()),
        Some(datagram_queue.clone()),
        data_ack_tx.clone(),
    );

    let (one_rtt_pkt_tx, dataspace_packets) =
        auto::OneRttPacketStream::new(one_rtt_keys.clone(), data_space.rcvd_pkt_records.clone());

    dataspace_packets.parse_packet_and_then_dispatch(
        Some(rcvd_conn_frames.clone()),
        Some(data_space_frame_queue.clone()),
        Some(datagram_queue.clone()),
        data_ack_tx.clone(),
    );

    tokio::spawn(
        handshake::exchange_handshake_crypto_msg_until_getting_1rtt_key(
            tls_session,
            one_rtt_keys,
            handshake_space.crypto_stream.split(),
        ),
    );

    let ack_observer = AckObserver::new([
        initial_space.rcvd_pkt_records.clone(),
        handshake_space.rcvd_pkt_records.clone(),
        data_space.rcvd_pkt_records.clone(),
    ]);
    let loss_observer = LossObserver::new([initial_loss_tx, handshake_loss_tx, data_loss_tx]);
    RawConnection {
        pathes: HashMap::new(),
        init_pkt_queue: Some(initial_pkt_tx),
        hs_pkt_queue: Some(handshake_pkt_tx),
        zero_rtt_pkt_queue: Some(zero_rtt_pkt_tx),
        one_rtt_pkt_queue: one_rtt_pkt_tx,
        handshake_keys,
        initial_keys,
        zero_rtt_keys,
        initial_space,
        handshake_space,
        data_space,
        ack_observer,
        loss_observer,
        spin: SpinBit::default(),
        flow_ctrl: ArcFlowController::with_initial(0, 0),
    }
}

impl RawConnection {
    pub fn recv_init_pkt_via(&mut self, pkt: InitialPacket, usc: &ArcUsc, pathway: Pathway) {
        if self.init_pkt_queue.is_some() {
            let path = self.get_path(pathway, usc);
            _ = self.init_pkt_queue.as_ref().unwrap().send((pkt, path));
        }
    }

    pub fn recv_hs_pkt_via(&mut self, pkt: HandshakePacket, usc: &ArcUsc, pathway: Pathway) {
        if self.hs_pkt_queue.is_some() {
            let path = self.get_path(pathway, usc);
            _ = self.hs_pkt_queue.as_ref().unwrap().send((pkt, path));
        }
    }

    pub fn recv_0rtt_pkt_via(&mut self, pkt: ZeroRttPacket, usc: &ArcUsc, pathway: Pathway) {
        if self.zero_rtt_pkt_queue.is_some() {
            let path = self.get_path(pathway, usc);
            _ = self.zero_rtt_pkt_queue.as_ref().unwrap().send((pkt, path));
        }
    }

    pub fn recv_1rtt_pkt_via(&mut self, pkt: OneRttPacket, usc: &ArcUsc, pathway: Pathway) {
        let path = self.get_path(pathway, usc);
        self.one_rtt_pkt_queue
            .send((pkt, path))
            .expect("must success");
    }

    pub fn invalid_init_keys(&self) {
        self.initial_keys.invalid();
    }

    pub fn invalid_hs_keys(&self) {
        self.handshake_keys.invalid();
    }

    pub fn invalid_0rtt_keys(&self) {
        self.zero_rtt_keys.invalid();
    }

    pub fn get_path(&mut self, pathway: Pathway, usc: &ArcUsc) -> ArcPath {
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

#[cfg(test)]
mod tests {}
