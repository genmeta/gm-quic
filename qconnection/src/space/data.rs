use qbase::{
    packet::{
        keys::{ArcKeys, ArcOneRttKeys},
        OneRttPacket, ZeroRttPacket,
    },
    streamid::Role,
};

use super::*;

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

    fn on_acked(&self, record: SentRecord) {
        match record {
            SentRecord::Reliable(ReliableFrame::Stream(StreamCtlFrame::ResetStream(reset))) => {
                self.stream.on_reset_acked(reset)
            }
            SentRecord::Data(frame) => match frame {
                DataFrame::Crypto(frame) => self.on_frame_acked(frame),
                DataFrame::Stream(frame) => self.on_frame_acked(frame),
                DataFrame::Datagram(frame) => self.on_frame_acked(frame),
            },
            _ => {}
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

impl ArcSpace<DataSpace> {
    /// 数据空间通过此函数创建
    pub fn new_data_space(
        role: Role,
        max_bi_streams: u64,
        max_uni_streams: u64,
        max_datagram_frame_size: u64,
    ) -> Self {
        use qrecovery::reliable::ArcReliableFrameQueue;
        let crypto_stream = CryptoStream::new(1_000_000, 1_000_000);
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

    pub fn receive_long_header_packet(
        &self,
        conn_frame_queue: ArcAsyncQueue<ConnFrame>,
    ) -> PacketQueue<ZeroRttPacket> {
        let (pkt_tx, pkt_rx) = mpsc::unbounded_channel();
        let ark_tx = self.receive_acks();
        tokio::spawn(
            crate::auto::loop_read_long_packet_and_then_dispatch_to_conn_and_space(
                pkt_rx,
                self.zero_rtt_keys.clone(),
                self.clone(),
                conn_frame_queue,
                ark_tx,
            ),
        );
        pkt_tx
    }

    pub fn receive_short_header_packet(
        &self,
        conn_frame_queue: ArcAsyncQueue<ConnFrame>,
    ) -> PacketQueue<OneRttPacket> {
        let (pkt_tx, pkt_rx) = mpsc::unbounded_channel();
        let ark_tx = self.receive_acks();
        tokio::spawn(
            crate::auto::loop_read_short_packet_and_then_dispatch_to_conn_and_space(
                pkt_rx,
                self.one_rtt_keys.clone(),
                self.clone(),
                conn_frame_queue,
                ark_tx,
            ),
        );
        pkt_tx
    }
}
