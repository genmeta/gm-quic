use std::{collections::HashMap, time::Duration};

use qbase::{
    packet::{HandshakePacket, InitialPacket, OneRttPacket, SpinBit, ZeroRttPacket},
    streamid::Role,
    util::ArcAsyncQueue,
};
use qrecovery::crypto::CryptoStream;
use qudp::ArcUsc;

use crate::{
    controller::ArcFlowController,
    crypto::TlsIO,
    handshake,
    path::{AckObserver, ArcPath, LossObserver, Pathway},
    space::{ArcSpace, DataSpace, NoDataSpace, PacketQueue},
};

/// Option是为了能丢弃前期空间，包括这些空间的收包队列，
/// 一旦丢弃，后续再收到该空间的包，直接丢弃。
type RxPacketQueue<T> = Option<PacketQueue<T>>;

pub struct RawConnection {
    // 所有Path的集合，Pathway作为key
    pathes: HashMap<Pathway, ArcPath>,
    init_pkt_queue: RxPacketQueue<InitialPacket>,
    hs_pkt_queue: RxPacketQueue<HandshakePacket>,
    zero_rtt_pkt_queue: RxPacketQueue<ZeroRttPacket>,
    one_rtt_pkt_queue: PacketQueue<OneRttPacket>,

    // 发送数据，也可以随着升级到Handshake空间而丢弃
    initial_space: ArcSpace<NoDataSpace>,
    // An endpoint MUST discard its Handshake keys when the TLS handshake is confirmed.
    // 发送数据，也可以随着升级到1RTT空间而丢弃
    handshake_space: ArcSpace<NoDataSpace>,
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
    let rcvd_conn_frames = ArcAsyncQueue::new();

    let initial_crypto_stream = CryptoStream::new(1_000_000, 1_000_000);
    let initial_crypto_handler = initial_crypto_stream.split();
    let initial_space = ArcSpace::new_nodata_space(initial_crypto_stream);
    let initial_loss_tx = initial_space.receive_may_loss_pkts();
    let initial_pkt_tx = initial_space.receive_initial_packet(rcvd_conn_frames.clone());

    let handshake_crypto_stream = CryptoStream::new(1_000_000, 1_000_000);
    let handshake_crypto_handler = handshake_crypto_stream.split();
    let handshake_space = ArcSpace::new_nodata_space(handshake_crypto_stream);
    let handshake_loss_tx = handshake_space.receive_may_loss_pkts();
    let handshake_pkt_tx = handshake_space.receive_handshake_packet(rcvd_conn_frames.clone());

    tokio::spawn(
        handshake::exchange_initial_crypto_msg_until_getting_handshake_key(
            tls_session.clone(),
            handshake_space.keys.clone(),
            initial_crypto_handler,
        ),
    );

    let one_rtt_crypto_stream = CryptoStream::new(1_000_000, 1_000_000);
    let data_space =
        ArcSpace::<DataSpace>::new_data_space(Role::Client, 20, 20, 0, one_rtt_crypto_stream);

    // 应用的操作接口，后续有必要在连接里直接调用
    // let _streams = data_space.data_streams();

    let zero_rtt_pkt_tx = data_space.receive_0rtt_packet(rcvd_conn_frames.clone());
    let one_rtt_pkt_tx = data_space.receive_1rtt_packet(rcvd_conn_frames.clone());

    let data_loss_tx = data_space.receive_may_loss_pkts();
    tokio::spawn(
        handshake::exchange_handshake_crypto_msg_until_getting_1rtt_key(
            tls_session,
            data_space.one_rtt_keys.clone(),
            handshake_crypto_handler,
        ),
    );

    let ack_observer = AckObserver::new([
        initial_space.rcvd_pkt_records().clone(),
        handshake_space.rcvd_pkt_records().clone(),
        data_space.rcvd_pkt_records().clone(),
    ]);
    let loss_observer = LossObserver::new([initial_loss_tx, handshake_loss_tx, data_loss_tx]);
    RawConnection {
        pathes: HashMap::new(),
        init_pkt_queue: Some(initial_pkt_tx),
        hs_pkt_queue: Some(handshake_pkt_tx),
        zero_rtt_pkt_queue: Some(zero_rtt_pkt_tx),
        one_rtt_pkt_queue: one_rtt_pkt_tx,
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
