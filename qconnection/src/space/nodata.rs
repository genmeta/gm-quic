use data::DataSpace;
use qbase::packet::{keys::ArcKeys, HandshakePacket, InitialPacket};

use super::*;
use crate::crypto::TlsIO;

#[derive(Debug, Clone)]
pub struct NoDataSpace<K> {
    pub(crate) keys: ArcKeys,
    pub(crate) crypto: CryptoStream,
    _kind: PhantomData<K>,
}

impl<K> indirect_impl::Transmit<CryptoFrame> for NoDataSpace<K> {
    fn implementer(&self) -> &impl Transmit<CryptoFrame> {
        &self.crypto
    }
}

impl<K: Send + Sync + 'static> Space for NoDataSpace<K> {
    fn try_read_data(&self, buf: &mut impl BufMut) -> Option<DataFrame> {
        Transmit::<CryptoFrame>::read_frame(self, buf).map(Into::into)
    }

    fn recv_space_frame(&self, frame: SpaceFrame) -> Result<(), Error> {
        match frame {
            SpaceFrame::Data(DataFrame::Crypto(frame), data) => self.recv_frame(frame, data),
            _ => unreachable!(),
        }
    }

    fn on_acked(&self, record: SentRecord) {
        if let SentRecord::Data(frame) = record {
            match frame {
                DataFrame::Crypto(frame) => self.on_frame_acked(frame),
                _ => unreachable!(),
            }
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

impl<K: Send + Sync + 'static> ArcSpace<NoDataSpace<K>> {
    pub fn new_nodata_space() -> Self {
        let crypto_stream = CryptoStream::new(1_000_000, 1_000_000);
        Self::from_space(NoDataSpace {
            keys: ArcKeys::new_pending(),
            crypto: crypto_stream,
            _kind: PhantomData,
        })
    }
}
impl ArcSpace<NoDataSpace<InitialPacket>> {
    pub fn receive_long_header_packet(
        &self,
        conn_frame_queue: ArcAsyncQueue<ConnFrame>,
    ) -> PacketQueue<InitialPacket> {
        let (pkt_tx, pkt_rx) = mpsc::unbounded_channel();
        let ark_tx = self.receive_acks();
        tokio::spawn(
            crate::auto::loop_read_long_packet_and_then_dispatch_to_conn_and_space(
                pkt_rx,
                self.keys.clone(),
                self.clone(),
                conn_frame_queue,
                ark_tx,
            ),
        );
        pkt_tx
    }

    pub fn exchange_initial_crypto_msg_until_getting_handshake_key(
        &self,
        handshake_space: &NoDataSpace<HandshakePacket>,
        tls_session: TlsIO,
    ) {
        tokio::spawn(
            crate::handshake::exchange_initial_crypto_msg_until_getting_handshake_key(
                tls_session,
                self.keys.clone(),
                handshake_space.crypto.split(),
            ),
        );
    }
}

impl ArcSpace<NoDataSpace<HandshakePacket>> {
    pub fn receive_long_header_packet(
        &self,
        conn_frame_queue: ArcAsyncQueue<ConnFrame>,
    ) -> PacketQueue<HandshakePacket> {
        let (pkt_tx, pkt_rx) = mpsc::unbounded_channel();
        let ark_tx = self.receive_acks();
        tokio::spawn(
            crate::auto::loop_read_long_packet_and_then_dispatch_to_conn_and_space(
                pkt_rx,
                self.keys.clone(),
                self.clone(),
                conn_frame_queue,
                ark_tx,
            ),
        );
        pkt_tx
    }

    pub fn exchange_handshake_crypto_msg_until_getting_1rtt_key(
        &self,
        data_space: &DataSpace,
        tls_session: TlsIO,
    ) {
        tokio::spawn(
            crate::handshake::exchange_handshake_crypto_msg_until_getting_1rtt_key(
                tls_session,
                data_space.one_rtt_keys.clone(),
                self.crypto.split(),
            ),
        );
    }
}
