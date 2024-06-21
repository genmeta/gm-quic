use std::{ops::Deref, sync::Arc, time::Instant};

use bytes::{BufMut, Bytes};
use deref_derive::Deref;
use futures::StreamExt;
use qbase::{
    error::Error,
    frame::{AckFrame, CryptoFrame, DataFrame, DatagramFrame, StreamCtlFrame, StreamFrame},
    packet::{
        keys::{ArcKeys, ArcOneRttKeys},
        PacketNumber,
    },
    streamid::Role,
    util::ArcAsyncQueue,
};
use qrecovery::{
    crypto::CryptoStream,
    reliable::{ArcRcvdPktRecords, Error as RecvPnError, ReliableTransmit},
    streams::{data::RawDataStreams, ArcDataStreams},
};
use qunreliable::DatagramFlow;
use tokio::sync::mpsc::{self, UnboundedSender};

trait Transmit<F: 'static> {
    fn read_frame(&self, buf: &mut impl BufMut) -> Option<F>;

    fn recv_frame(&self, frame: F, data: Bytes) -> Result<(), Error>;

    fn on_frame_acked(&self, frame: F);

    fn may_loss_frame(&self, frame: F);
}

impl Transmit<CryptoFrame> for CryptoStream {
    fn read_frame(&self, buf: &mut impl BufMut) -> Option<CryptoFrame> {
        self.try_read_data(buf)
    }

    fn recv_frame(&self, frame: CryptoFrame, data: Bytes) -> Result<(), Error> {
        self.recv_data(frame, data)
    }

    fn on_frame_acked(&self, frame: CryptoFrame) {
        self.on_data_acked(frame)
    }

    fn may_loss_frame(&self, frame: CryptoFrame) {
        self.may_loss_data(frame)
    }
}

impl Transmit<StreamFrame> for RawDataStreams {
    fn read_frame(&self, buf: &mut impl BufMut) -> Option<StreamFrame> {
        self.try_read_stream(buf)
    }

    fn recv_frame(&self, frame: StreamFrame, data: Bytes) -> Result<(), Error> {
        self.recv_stream(frame, data)
    }

    fn on_frame_acked(&self, frame: StreamFrame) {
        self.on_data_acked(frame)
    }

    fn may_loss_frame(&self, frame: StreamFrame) {
        self.may_loss_data(frame)
    }
}

impl indirect_impl::Transmit<StreamFrame> for ArcDataStreams {
    fn implementer(&self) -> &impl Transmit<StreamFrame> {
        self.deref().deref()
    }
}

impl Transmit<DatagramFrame> for DatagramFlow {
    fn read_frame(&self, buf: &mut impl BufMut) -> Option<DatagramFrame> {
        self.try_read_datagram(buf)
    }

    fn recv_frame(&self, frame: DatagramFrame, data: Bytes) -> Result<(), Error> {
        self.recv_datagram(frame, data)
    }

    fn on_frame_acked(&self, _frame: DatagramFrame) {
        // no nothing
    }

    fn may_loss_frame(&self, _frame: DatagramFrame) {
        // no nothing
    }
}

#[derive(Debug, Clone)]
pub enum SpaceFrame {
    Stream(StreamCtlFrame),
    Data(DataFrame, Bytes),
}

pub trait Space: Send + Sync + 'static {
    // 这个方法的签名很奇怪，但是目前只能这样写...
    fn try_read_data(&self, buf: &mut impl BufMut) -> Option<DataFrame>;

    fn recv_space_frame(&self, frame: SpaceFrame) -> Result<(), Error>;

    fn on_data_acked(&self, frame: DataFrame);

    fn may_loss_data(&self, frame: DataFrame);

    fn on_conn_error(&self, error: &Error);
}

// 主要是为了减少同质化的代码
// 虽然ra有一个 代码操作 可以实现这个，但是，不美观
mod indirect_impl {
    use bytes::{BufMut, Bytes};
    use qbase::{error::Error, frame::DataFrame};

    use super::SpaceFrame;

    pub trait Transmit<F: 'static> {
        fn implementer(&self) -> &impl super::Transmit<F>;
    }

    impl<F, T> super::Transmit<F> for T
    where
        T: Transmit<F>,
        F: 'static,
    {
        fn read_frame(&self, buf: &mut impl BufMut) -> Option<F> {
            self.implementer().read_frame(buf)
        }

        fn recv_frame(&self, frame: F, data: Bytes) -> Result<(), super::Error> {
            self.implementer().recv_frame(frame, data)
        }

        fn on_frame_acked(&self, frame: F) {
            self.implementer().on_frame_acked(frame)
        }

        fn may_loss_frame(&self, frame: F) {
            self.implementer().may_loss_frame(frame)
        }
    }

    pub trait Space: Send + Sync + 'static {
        fn implementer(&self) -> &impl super::Space;
    }

    impl<S: Space> super::Space for S {
        fn try_read_data(&self, buf: &mut impl BufMut) -> Option<DataFrame> {
            self.implementer().try_read_data(buf)
        }

        fn recv_space_frame(&self, frame: SpaceFrame) -> Result<(), Error> {
            self.implementer().recv_space_frame(frame)
        }

        fn on_data_acked(&self, frame: DataFrame) {
            self.implementer().on_data_acked(frame)
        }

        fn may_loss_data(&self, frame: DataFrame) {
            self.implementer().may_loss_data(frame)
        }

        fn on_conn_error(&self, error: &Error) {
            self.implementer().on_conn_error(error)
        }
    }
}

#[derive(Debug, Clone)]
pub struct NoDataSpace {
    pub(crate) keys: ArcKeys,
    pub(crate) crypto: CryptoStream,
}

impl indirect_impl::Transmit<CryptoFrame> for NoDataSpace {
    fn implementer(&self) -> &impl Transmit<CryptoFrame> {
        &self.crypto
    }
}

impl Space for NoDataSpace {
    fn try_read_data(&self, buf: &mut impl BufMut) -> Option<DataFrame> {
        Transmit::<CryptoFrame>::read_frame(self, buf).map(Into::into)
    }

    fn recv_space_frame(&self, frame: SpaceFrame) -> Result<(), Error> {
        match frame {
            SpaceFrame::Data(DataFrame::Crypto(frame), data) => self.recv_frame(frame, data),
            _ => unreachable!(),
        }
    }

    fn on_data_acked(&self, frame: DataFrame) {
        match frame {
            DataFrame::Crypto(frame) => self.on_frame_acked(frame),
            _ => unreachable!(),
        }
    }

    fn may_loss_data(&self, frame: DataFrame) {
        match frame {
            DataFrame::Crypto(frame) => self.may_loss_frame(frame),
            _ => unreachable!(),
        }
    }

    fn on_conn_error(&self, _error: &Error) {}
}

#[derive(Debug, Clone)]
pub struct DataSpace {
    pub(crate) zero_rtt_keys: ArcKeys,
    pub(crate) one_rtt_keys: ArcOneRttKeys,
    pub(crate) crypto: CryptoStream,
    pub(crate) stream: ArcDataStreams,
    pub(crate) datagram: DatagramFlow,
}

impl indirect_impl::Transmit<CryptoFrame> for DataSpace {
    fn implementer(&self) -> &impl Transmit<CryptoFrame> {
        &self.crypto
    }
}

impl indirect_impl::Transmit<StreamFrame> for DataSpace {
    fn implementer(&self) -> &impl Transmit<StreamFrame> {
        &self.stream
    }
}

impl indirect_impl::Transmit<DatagramFrame> for DataSpace {
    fn implementer(&self) -> &impl self::Transmit<DatagramFrame> {
        &self.datagram
    }
}

impl Space for DataSpace {
    fn try_read_data(&self, buf: &mut impl BufMut) -> Option<DataFrame> {
        // todo: 不应该一直这样按照次序发送，应该有一个策略
        Transmit::<CryptoFrame>::read_frame(self, buf)
            .map(Into::into)
            .or_else(|| Transmit::<StreamFrame>::read_frame(self, buf).map(Into::into))
            .or_else(|| Transmit::<DatagramFrame>::read_frame(self, buf).map(Into::into))
    }

    fn recv_space_frame(&self, frame: SpaceFrame) -> Result<(), Error> {
        match frame {
            SpaceFrame::Stream(frame) => self.stream.recv_stream_control(frame),
            SpaceFrame::Data(DataFrame::Crypto(frame), data) => self.recv_frame(frame, data),
            SpaceFrame::Data(DataFrame::Stream(frame), data) => self.recv_frame(frame, data),
            SpaceFrame::Data(DataFrame::Datagram(frame), data) => self.recv_frame(frame, data),
        }
    }

    fn on_data_acked(&self, frame: DataFrame) {
        match frame {
            DataFrame::Crypto(frame) => self.on_frame_acked(frame),
            DataFrame::Stream(frame) => self.on_frame_acked(frame),
            DataFrame::Datagram(frame) => self.on_frame_acked(frame),
        }
    }

    fn may_loss_data(&self, frame: DataFrame) {
        match frame {
            DataFrame::Crypto(frame) => self.may_loss_frame(frame),
            DataFrame::Stream(frame) => self.may_loss_frame(frame),
            DataFrame::Datagram(frame) => self.may_loss_frame(frame),
        }
    }

    fn on_conn_error(&self, error: &Error) {
        self.stream.on_conn_error(error);
        self.datagram.on_conn_error(error);
    }
}

#[derive(Debug, Clone, Deref)]
pub struct RawSpace<T: Space> {
    pub(crate) reliable: ReliableTransmit,
    #[deref]
    inner: T,
}

impl<T: Space> RawSpace<T> {
    pub fn new(space: T) -> Self {
        Self {
            reliable: Default::default(),
            inner: space,
        }
    }

    pub fn read(&self, mut buf: &mut [u8], ack_pkt: Option<(u64, Instant)>) -> (u64, usize, usize) {
        let remain = buf.remaining_mut();
        let (pn, pn_encode_size) = self.reliable.try_read(&mut buf, ack_pkt);
        let mut recorder = self.reliable.sent_pkt_records.send();
        while let Some(frame) = self.inner.try_read_data(&mut buf) {
            recorder.record_data_frame(frame)
        }
        (pn, pn_encode_size, remain - buf.remaining_mut())
    }

    fn on_ack(&self, ack: &AckFrame) {
        // 数据报帧也是ack触发帧，也就是说它们也许要被记录
        // 虽然它们不会被重传
        self.reliable
            .on_rcvd_ack(ack, |data_frame| self.inner.on_data_acked(data_frame))
    }

    fn may_loss_pkt(&self, pn: u64) {
        self.reliable
            .may_loss_pkt(pn, |data_frame| self.inner.on_data_acked(data_frame))
    }

    pub fn decode_pn(&self, encoded_pn: PacketNumber) -> Result<u64, RecvPnError> {
        self.reliable.rcvd_pkt_records.decode_pn(encoded_pn)
    }

    pub fn rcvd_pkt_records(&self) -> &ArcRcvdPktRecords {
        &self.reliable.rcvd_pkt_records
    }
}

impl<T: Space> indirect_impl::Space for RawSpace<T> {
    fn implementer(&self) -> &impl self::Space {
        &self.inner
    }
}

#[derive(Debug, Deref)]
pub struct ArcSpace<T: Space>(Arc<RawSpace<T>>);

// 如果是derive(Clone)，则隐式要求T: Clone，才实现ArcSpace<T>::clone
// 但是并不能这么约束，Arc::clone不在乎T: Clone与否
impl<T: Space> Clone for ArcSpace<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Space> ArcSpace<T> {
    pub fn from_space(space: T) -> Self {
        ArcSpace(Arc::new(RawSpace::new(space)))
    }

    /// 创建一个队列，然后循环从队列读取和处理空间帧
    pub fn space_frame_queue(&self) -> ArcAsyncQueue<SpaceFrame> {
        let space_frmae_queue = ArcAsyncQueue::new();
        tokio::spawn({
            let mut space_frames_queue = space_frmae_queue.clone();
            let space = self.clone();
            async move {
                while let Some(frame) = space_frames_queue.next().await {
                    let result = space.recv_space_frame(frame);
                    if let Err(err) = result {
                        space.on_conn_error(&err);
                    }
                }
            }
        });
        space_frmae_queue
    }

    pub fn listen_may_loss_pkts(&self) -> UnboundedSender<u64> {
        let (loss_pkt_tx, mut loss_pkt_rx) = mpsc::unbounded_channel();
        let space = self.clone();

        tokio::spawn(async move {
            while let Some(pn) = loss_pkt_rx.recv().await {
                space.may_loss_pkt(pn)
            }
        });
        loss_pkt_tx
    }

    pub fn listen_acks(&self) -> UnboundedSender<AckFrame> {
        let (ack_tx, mut ack_rx) = mpsc::unbounded_channel();
        let space = self.clone();
        tokio::spawn(async move {
            while let Some(ack) = ack_rx.recv().await {
                space.on_ack(&ack)
            }
        });
        ack_tx
    }
}

impl ArcSpace<NoDataSpace> {
    pub fn new_nodata_space(crypto_stream: CryptoStream) -> Self {
        Self::from_space(NoDataSpace {
            keys: ArcKeys::new_pending(),
            crypto: crypto_stream,
        })
    }
}

impl ArcSpace<DataSpace> {
    /// 数据空间通过此函数创建
    pub fn new_data_space(
        role: Role,
        max_bi_streams: u64,
        max_uni_streams: u64,
        max_datagram_frame_size: u64,
        crypto_stream: CryptoStream,
    ) -> Self {
        use qrecovery::reliable::ArcReliableFrameQueue;
        let reliable_frame_queue = ArcReliableFrameQueue::default();
        let data_streams = ArcDataStreams::with_role_and_limit(
            role,
            max_bi_streams,
            max_uni_streams,
            reliable_frame_queue.clone(),
        );
        let datagram_flow = DatagramFlow::new(max_datagram_frame_size);
        Self::from_space(DataSpace {
            crypto: crypto_stream,
            stream: data_streams,
            datagram: datagram_flow,
            zero_rtt_keys: ArcKeys::new_pending(),
            one_rtt_keys: ArcOneRttKeys::new_pending(),
        })
    }
}

impl<T: Space> indirect_impl::Space for ArcSpace<T> {
    fn implementer(&self) -> &impl Space {
        self.0.implementer()
    }
}
