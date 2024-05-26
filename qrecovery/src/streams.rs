use qbase::{error::Error, frame::*};
use std::fmt::Debug;

pub trait Output {
    type Outgoing: TransmitStream + Debug;

    fn output(&self) -> Self::Outgoing;
}

/// For sending stream data
pub trait TransmitStream {
    /// read data to transmit
    fn try_read_data(&mut self, buf: &mut [u8]) -> Option<(StreamFrame, usize)>;

    fn confirm_data_rcvd(&self, stream_frame: StreamFrame);

    fn may_loss_data(&self, stream_frame: StreamFrame);

    fn confirm_reset_rcvd(&self, reset_frame: ResetStreamFrame);
}

pub trait ReceiveStream {
    fn recv_frame(&self, stream_ctl_frame: StreamCtlFrame) -> Result<(), Error>;

    fn recv_data(&self, stream_frame: StreamFrame, body: bytes::Bytes) -> Result<(), Error>;
}

pub mod data;
pub mod listener;
pub mod none;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
