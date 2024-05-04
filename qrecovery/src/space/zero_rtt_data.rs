/// Application data space, 0-RTT data space
use crate::streams::Streams;
use qbase::{
    error::Error,
    frame::{StreamFrame, ZeroRttFrame},
};

type ZeroRttDataFrame = StreamFrame;
pub type ZeroRttDataSpace = super::Space<ZeroRttFrame, ZeroRttDataFrame, Transmission, false>;

#[derive(Debug)]
pub struct Transmission {
    streams: Streams,
}

impl super::Transmit<ZeroRttFrame, ZeroRttDataFrame> for Transmission {
    type Buffer = Vec<u8>;

    fn try_send(&mut self, _buf: &mut Self::Buffer) -> Option<(ZeroRttDataFrame, usize)> {
        todo!()
    }

    fn confirm_data(&mut self, stream_frame: ZeroRttDataFrame) {
        self.streams.confirm_data(stream_frame);
    }

    fn may_loss(&mut self, stream_frame: ZeroRttDataFrame) {
        self.streams.may_loss(stream_frame);
    }

    fn recv_data(
        &mut self,
        stream_frame: ZeroRttDataFrame,
        body: bytes::Bytes,
    ) -> Result<(), Error> {
        self.streams.recv_data(stream_frame, body)
    }

    fn recv_frame(&mut self, frame: ZeroRttFrame) -> Result<(), Error> {
        match frame {
            ZeroRttFrame::Stream(frame) => self.streams.recv_frame(frame),
            _ => unreachable!("these are handled in connection layer"),
        }
    }
}

impl Transmission {
    pub fn new(streams: Streams) -> Self {
        Self { streams }
    }

    pub fn streams(&mut self) -> &mut Streams {
        &mut self.streams
    }
}

impl From<ZeroRttDataSpace> for super::OneRttDataSpace {
    fn from(_value: ZeroRttDataSpace) -> Self {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
