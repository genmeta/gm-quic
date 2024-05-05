/// Application data space, 1-RTT data space
use crate::{crypto_stream::CryptoStream, streams::Streams};
use qbase::{
    error::Error,
    frame::{DataFrame, OneRttFrame},
};

type OneRttDataFrame = DataFrame;

pub type OneRttDataSpace = super::Space<OneRttFrame, OneRttDataFrame, Transmission>;

#[derive(Debug)]
pub struct Transmission {
    streams: Streams,
    crypto_stream: CryptoStream,
}

impl super::Transmit<OneRttFrame, OneRttDataFrame> for Transmission {
    type Buffer = Vec<u8>;

    fn try_send(&mut self, _buf: &mut Self::Buffer) -> Option<(OneRttDataFrame, usize)> {
        todo!()
    }

    fn confirm_data(&mut self, data_frame: OneRttDataFrame) {
        match data_frame {
            OneRttDataFrame::Stream(stream_frame) => {
                self.streams.confirm_data(stream_frame);
            }
            OneRttDataFrame::Crypto(crypto_frame) => {
                self.crypto_stream.confirm_data(crypto_frame);
            }
        }
    }

    fn may_loss(&mut self, data_frame: OneRttDataFrame) {
        match data_frame {
            OneRttDataFrame::Stream(stream_frame) => {
                self.streams.may_loss(stream_frame);
            }
            OneRttDataFrame::Crypto(crypto_frame) => {
                self.crypto_stream.may_loss(crypto_frame);
            }
        }
    }

    fn recv_data(&mut self, data_frame: OneRttDataFrame, body: bytes::Bytes) -> Result<(), Error> {
        match data_frame {
            OneRttDataFrame::Stream(stream_frame) => self.streams.recv_data(stream_frame, body),
            OneRttDataFrame::Crypto(crypto_frame) => {
                self.crypto_stream.recv_data(crypto_frame, body)
            }
        }
    }

    fn recv_frame(&mut self, frame: OneRttFrame) -> Result<(), Error> {
        match frame {
            OneRttFrame::Stream(frame) => self.streams.recv_frame(frame),
            _ => unreachable!("these are handled in space or connection layer"),
        }
    }
}

impl Transmission {
    pub(super) fn new(streams: Streams, crypto_stream: CryptoStream) -> Self {
        Self {
            streams,
            crypto_stream,
        }
    }

    pub fn streams(&mut self) -> &mut Streams {
        &mut self.streams
    }

    pub fn crypto_stream(&mut self) -> &mut CryptoStream {
        &mut self.crypto_stream
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
