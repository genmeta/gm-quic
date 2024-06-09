use qbase::{error::Error, frame::*};

/// 在Initial和Handshake空间中，是不需要传输Streams的，此时可以使用NoDataStreams
#[derive(Debug, Clone)]
pub struct NoDataStreams;

impl super::TransmitStream for NoDataStreams {
    fn try_read_stream(&self, _: &mut [u8]) -> Option<(StreamFrame, usize)> {
        None
    }

    fn try_read_datagram(&self, _: &mut [u8]) -> Option<(DatagramFrame, usize)> {
        None
    }

    fn on_data_acked(&self, _: StreamFrame) {
        unreachable!()
    }

    fn may_loss_data(&self, _: StreamFrame) {
        unreachable!()
    }

    fn on_reset_acked(&self, _: ResetStreamFrame) {
        unreachable!()
    }
}

impl super::ReceiveStream for NoDataStreams {
    fn recv_stream_control(&self, _: StreamCtlFrame) -> Result<(), Error> {
        unreachable!()
    }

    fn recv_datagram(&self, _: DatagramFrame, _: bytes::Bytes) -> Result<(), Error> {
        unreachable!()
    }

    fn recv_stream(&self, _: StreamFrame, _: bytes::Bytes) -> Result<(), Error> {
        unreachable!()
    }

    fn on_conn_error(&self, _: &Error) {}
}
