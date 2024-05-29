use qbase::{error::Error, frame::*};

/// 在Initial和Handshake空间中，是不需要传输Streams的，此时可以使用NoDataStreams
#[derive(Debug, Clone)]
pub struct NoDataStreams;

impl super::TransmitStream for NoDataStreams {
    fn try_read_data(&self, _buf: &mut [u8]) -> Option<(StreamFrame, usize)> {
        None
    }

    fn confirm_data_rcvd(&self, _stream_frame: StreamFrame) {
        unreachable!()
    }

    fn may_loss_data(&self, _stream_frame: StreamFrame) {
        unreachable!()
    }

    fn confirm_reset_rcvd(&self, _reset_frame: ResetStreamFrame) {
        unreachable!()
    }
}

impl super::ReceiveStream for NoDataStreams {
    fn recv_frame(&self, _stream_ctl_frame: StreamCtlFrame) -> Result<(), Error> {
        unreachable!()
    }

    fn recv_data(&self, _stream_frame: StreamFrame, _body: bytes::Bytes) -> Result<(), Error> {
        unreachable!()
    }

    fn conn_error(&self, _err: &Error) {}
}
