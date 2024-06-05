use crate::{auto, crypto::TlsIO, handshake, old_path::ArcPath};
use qbase::{
    packet::{
        keys::{ArcKeys, ArcOneRttKeys},
        HandshakePacket, InitialPacket, OneRttPacket, SpinBit, ZeroRttPacket,
    },
    streamid::Role,
    util::ArcAsyncQueue,
};
use qrecovery::{
    crypto::CryptoStream,
    space::ArcSpace,
    streams::{none::NoDataStreams, ArcDataStreams},
};
use tokio::sync::mpsc;

/// Option是为了能丢弃前期空间，包括这些空间的收包队列，
/// 一旦丢弃，后续再收到该空间的包，直接丢弃。
type RxPacketsQueue<T> = Option<mpsc::UnboundedSender<(T, ArcPath)>>;

pub struct RawConnection {
    // Thus, a client MUST discard Initial keys when it first sends a Handshake packet
    // and a server MUST discard Initial keys when it first successfully processes a
    // Handshake packet. Endpoints MUST NOT send Initial packets after this point.
    initial_keys: ArcKeys,
    initial_pkt_queue: RxPacketsQueue<InitialPacket>,
    // 发送数据，也可以随着升级到Handshake空间而丢弃
    initial_space: ArcSpace<NoDataStreams>,

    // An endpoint MUST discard its Handshake keys when the TLS handshake is confirmed.
    handshake_keys: ArcKeys,
    handshake_pkt_queue: RxPacketsQueue<HandshakePacket>,
    // 发送数据，也可以随着升级到1RTT空间而丢弃
    handshake_space: ArcSpace<NoDataStreams>,

    zero_rtt_keys: ArcKeys,
    // 发送数据，也可以随着升级到1RTT空间而丢弃
    zero_rtt_pkt_queue: RxPacketsQueue<ZeroRttPacket>,
    one_rtt_pkt_queue: mpsc::UnboundedSender<(OneRttPacket, ArcPath)>,
    data_space: ArcSpace<ArcDataStreams>,
    spin: SpinBit,
}

pub fn new(tls_session: TlsIO) -> RawConnection {
    let rcvd_conn_frames = ArcAsyncQueue::new();

    let (initial_pkt_tx, initial_pkt_rx) = mpsc::unbounded_channel::<(InitialPacket, ArcPath)>();
    let (initial_ack_tx, initial_ack_rx) = mpsc::unbounded_channel();
    let (initial_loss_tx, initial_loss_rx) = mpsc::unbounded_channel();
    let initial_crypto_stream = CryptoStream::new(1_000_000, 1_000_000);
    let initial_crypto_handler = initial_crypto_stream.split();
    let initial_keys = ArcKeys::new_pending();
    let initial_space_frame_queue = ArcAsyncQueue::new();
    let initial_space = ArcSpace::<NoDataStreams>::with_crypto_stream(initial_crypto_stream);
    tokio::spawn(
        auto::loop_read_long_packet_and_then_dispatch_to_space_frame_queue(
            initial_pkt_rx,
            initial_keys.clone(),
            initial_space.clone(),
            rcvd_conn_frames.clone(),
            initial_space_frame_queue,
            initial_ack_tx,
            true,
        ),
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

    let (handshake_pkt_tx, handshake_pkt_rx) =
        mpsc::unbounded_channel::<(HandshakePacket, ArcPath)>();
    let (handshake_ack_tx, handshake_ack_rx) = mpsc::unbounded_channel();
    let (handshake_loss_tx, handshake_loss_rx) = mpsc::unbounded_channel();
    let handshake_crypto_stream = CryptoStream::new(1_000_000, 1_000_000);
    let handshake_crypto_handler = handshake_crypto_stream.split();
    let handshake_keys = ArcKeys::new_pending();
    let handshake_space_frame_queue = ArcAsyncQueue::new();
    let handshake_space = ArcSpace::<NoDataStreams>::with_crypto_stream(handshake_crypto_stream);
    tokio::spawn(
        auto::loop_read_long_packet_and_then_dispatch_to_space_frame_queue(
            handshake_pkt_rx,
            handshake_keys.clone(),
            handshake_space.clone(),
            rcvd_conn_frames.clone(),
            handshake_space_frame_queue,
            handshake_ack_tx,
            true,
        ),
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
            initial_crypto_handler,
        ),
    );

    let (zero_rtt_pkt_tx, zero_rtt_pkt_rx) = mpsc::unbounded_channel::<(ZeroRttPacket, ArcPath)>();
    let (one_rtt_pkt_tx, one_rtt_pkt_rx) = mpsc::unbounded_channel::<(OneRttPacket, ArcPath)>();
    let zero_rtt_keys = ArcKeys::new_pending();
    let one_rtt_keys = ArcOneRttKeys::new_pending();
    let one_rtt_crypto_stream = CryptoStream::new(1_000_000, 1_000_000);
    let _one_rtt_crypto_handler = one_rtt_crypto_stream.split();
    let data_space_frame_queue = ArcAsyncQueue::new();
    let (data_ack_tx, data_ack_rx) = mpsc::unbounded_channel();
    let (data_loss_tx, data_loss_rx) = mpsc::unbounded_channel();
    let data_space = ArcSpace::<ArcDataStreams>::new(Role::Client, 20, 20, one_rtt_crypto_stream);
    let streams = data_space.data_streams();
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
    tokio::spawn(
        auto::loop_read_long_packet_and_then_dispatch_to_space_frame_queue(
            zero_rtt_pkt_rx,
            zero_rtt_keys.clone(),
            data_space.clone(),
            rcvd_conn_frames.clone(),
            data_space_frame_queue.clone(),
            data_ack_tx.clone(),
            false,
        ),
    );
    tokio::spawn(
        auto::loop_read_short_packet_and_then_dispatch_to_space_frame_queue(
            one_rtt_pkt_rx,
            one_rtt_keys.clone(),
            data_space.clone(),
            rcvd_conn_frames.clone(),
            data_space_frame_queue,
            data_ack_tx,
        ),
    );
    tokio::spawn(
        handshake::exchange_handshake_crypto_msg_until_getting_1rtt_key(
            tls_session,
            one_rtt_keys,
            handshake_crypto_handler,
        ),
    );

    RawConnection {
        initial_keys,
        initial_pkt_queue: Some(initial_pkt_tx),
        initial_space,
        handshake_keys,
        handshake_pkt_queue: Some(handshake_pkt_tx),
        handshake_space,
        zero_rtt_keys,
        zero_rtt_pkt_queue: Some(zero_rtt_pkt_tx),
        one_rtt_pkt_queue: one_rtt_pkt_tx,
        data_space,
        spin: SpinBit::default(),
    }
}

impl RawConnection {
    pub fn recv_initial_packet(&mut self, pkt: InitialPacket, path: ArcPath) {
        if let Some(q) = &mut self.initial_pkt_queue {
            let _ = q.send((pkt, path));
        }
    }

    pub fn recv_handshake_packet(&mut self, pkt: HandshakePacket, path: ArcPath) {
        if let Some(q) = &mut self.handshake_pkt_queue {
            let _ = q.send((pkt, path));
        }
    }

    pub fn recv_0rtt_packet(&mut self, pkt: ZeroRttPacket, path: ArcPath) {
        if let Some(q) = &mut self.zero_rtt_pkt_queue {
            let _ = q.send((pkt, path));
        }
    }

    pub fn recv_1rtt_packet(&mut self, pkt: OneRttPacket, path: ArcPath) {
        self.one_rtt_pkt_queue
            .send((pkt, path))
            .expect("must success");
    }

    pub fn invalid_initial_keys(&self) {
        self.initial_keys.invalid();
    }

    pub fn invalid_handshake_keys(&self) {
        self.handshake_keys.invalid();
    }

    pub fn invalid_zero_rtt_keys(&self) {
        self.zero_rtt_keys.invalid();
    }
}

#[cfg(test)]
mod tests {}
