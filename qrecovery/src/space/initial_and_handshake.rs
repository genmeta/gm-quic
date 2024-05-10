use super::Transmit;
use crate::crypto_stream::CryptoStream;
use qbase::{
    error::Error,
    frame::{ConnectionFrame, CryptoFrame, NoFrame},
};

pub type InitialSpace = super::Space<NoFrame, CryptoFrame, Transmission>;
pub type HandshakeSpace = super::Space<NoFrame, CryptoFrame, Transmission>;

#[derive(Debug)]
pub struct Transmission {
    crypto_stream: CryptoStream,
}

impl Transmit<NoFrame, CryptoFrame> for Transmission {
    type Buffer = Vec<u8>;

    fn try_send(&mut self, buf: &mut Self::Buffer) -> Option<(CryptoFrame, usize)> {
        self.crypto_stream.try_send(buf)
    }

    fn confirm_data(&mut self, data_frame: CryptoFrame) {
        self.crypto_stream.confirm_data(data_frame)
    }

    fn may_loss(&mut self, data_frame: CryptoFrame) {
        self.crypto_stream.may_loss(data_frame)
    }

    fn recv_frame(&mut self, _: NoFrame) -> Result<Option<ConnectionFrame>, Error> {
        unreachable!("no signaling frame in initial or handshake space")
    }

    fn recv_data(&mut self, data_frame: CryptoFrame, data: bytes::Bytes) -> Result<(), Error> {
        self.crypto_stream.recv_data(data_frame, data)
    }
}

impl Transmission {
    pub fn new(crypto_stream: CryptoStream) -> Self {
        Self { crypto_stream }
    }

    pub fn crypto_stream(&mut self) -> &CryptoStream {
        &mut self.crypto_stream
    }
}
