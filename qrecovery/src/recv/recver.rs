use super::rcvbuf;
use bytes::{BufMut, Bytes};
use qbase::{
    error::{Error, ErrorKind},
    frame::{BeFrame, ResetStreamFrame, StreamFrame},
};
use std::{
    io,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

#[derive(Debug)]
pub(super) struct Recv {
    rcvbuf: rcvbuf::RecvBuf,
    read_waker: Option<Waker>,
    is_stopped: bool,
    stop_waker: Option<Waker>,
    largest_data_size: u64,
    max_data_size: u64,
    buf_exceeds_half_waker: Option<Waker>,
}

impl Recv {
    pub(super) fn with(max_data_size: u64) -> Self {
        Self {
            rcvbuf: rcvbuf::RecvBuf::default(),
            read_waker: None,
            is_stopped: false,
            stop_waker: None,
            largest_data_size: 0,
            max_data_size,
            buf_exceeds_half_waker: None,
        }
    }

    pub(super) fn recv(&mut self, stream_frame: StreamFrame, body: Bytes) -> Result<(), Error> {
        let offset = stream_frame.offset.into_inner();
        let data_size = offset + body.len() as u64;
        if data_size > self.max_data_size {
            return Err(Error::new(
                ErrorKind::FlowControl,
                stream_frame.frame_type(),
                format!(
                    "{} send {data_size} bytes which exceeds the stream data limit {}",
                    stream_frame.id, self.max_data_size
                ),
            ));
        }
        self.largest_data_size = std::cmp::max(self.largest_data_size, data_size);
        self.rcvbuf.recv(offset, body);
        if self.rcvbuf.is_readable() {
            if let Some(waker) = self.read_waker.take() {
                waker.wake()
            }
        }
        Ok(())
    }

    /// 仅供学习用
    #[allow(dead_code)]
    pub(super) fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        if self.rcvbuf.is_readable() {
            let buflen = buf.remaining_mut();
            self.rcvbuf.read(&mut buf);

            let threshold = 1_000_000;
            if self.rcvbuf.offset() + threshold > self.max_data_size {
                if let Some(waker) = self.buf_exceeds_half_waker.take() {
                    waker.wake()
                }
            }

            Ok(buflen - buf.remaining_mut())
        } else {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }

    pub(super) fn poll_read<T: BufMut>(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut T,
    ) -> Poll<io::Result<()>> {
        assert!(self.read_waker.is_none());
        if self.rcvbuf.is_readable() {
            self.rcvbuf.read(buf);

            let threshold = 1_000_000;
            if self.rcvbuf.offset() + threshold > self.max_data_size {
                if let Some(waker) = self.buf_exceeds_half_waker.take() {
                    waker.wake()
                }
            }

            Poll::Ready(Ok(()))
        } else {
            self.read_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub(super) fn poll_window_update(&mut self, cx: &mut Context<'_>) -> Poll<Option<u64>> {
        assert!(self.buf_exceeds_half_waker.is_none());
        let threshold = 1_000_000;
        if self.rcvbuf.offset() + threshold > self.max_data_size {
            self.max_data_size = self.rcvbuf.offset() + threshold * 2;
            Poll::Ready(Some(self.max_data_size))
        } else {
            self.buf_exceeds_half_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub(super) fn poll_stop(&mut self, cx: &mut Context<'_>) -> Poll<bool> {
        assert!(self.stop_waker.is_none());
        if self.is_stopped {
            Poll::Ready(true)
        } else {
            self.stop_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub(super) fn abort(&mut self) {
        if !self.is_stopped {
            self.is_stopped = true;
            if let Some(waker) = self.stop_waker.take() {
                waker.wake()
            }
        }
    }

    pub(super) fn determin_size(self, total_size: u64) -> SizeKnown {
        if let Some(waker) = self.buf_exceeds_half_waker {
            waker.wake();
        }
        SizeKnown {
            rcvbuf: self.rcvbuf,
            read_waker: self.read_waker,
            is_stopped: self.is_stopped,
            stop_waker: self.stop_waker,
            total_size,
        }
    }

    pub(super) fn wake_all(&mut self) {
        if let Some(waker) = self.buf_exceeds_half_waker.take() {
            waker.wake()
        }
        if let Some(waker) = self.stop_waker.take() {
            waker.wake()
        }
        if let Some(waker) = self.read_waker.take() {
            waker.wake()
        }
    }

    pub(super) fn recv_reset(mut self, reset_frame: ResetStreamFrame) -> Result<u64, Error> {
        let final_size = reset_frame.final_size.into_inner();
        if final_size < self.largest_data_size {
            return Err(Error::new(
                ErrorKind::FinalSize,
                reset_frame.frame_type(),
                format!(
                    "{} reset with a wrong smaller final size {final_size} than the largest rcvd data offset {}",
                    reset_frame.stream_id, self.largest_data_size
                ),
            ));
        }
        self.wake_all();
        Ok(final_size)
    }
}

/// Once the size of the data stream is determined, MAX_STREAM_DATA will no longer
/// be updated. Receiving data on this stream is meaningless. At this point, it is
/// also meaningless for the application layer to continue receiving data.
#[derive(Debug)]
pub struct SizeKnown {
    rcvbuf: rcvbuf::RecvBuf,
    read_waker: Option<Waker>,
    is_stopped: bool,
    stop_waker: Option<Waker>,
    total_size: u64,
}

impl SizeKnown {
    pub(super) fn recv(&mut self, stream_frame: StreamFrame, buf: Bytes) -> Result<(), Error> {
        let offset = stream_frame.offset.into_inner();
        let data_size = offset + buf.len() as u64;
        if data_size > self.total_size {
            return Err(Error::new(
                ErrorKind::FinalSize,
                stream_frame.frame_type(),
                format!(
                    "{} send {data_size} bytes which exceeds the final_size {}",
                    stream_frame.id, self.total_size
                ),
            ));
        }
        if stream_frame.is_fin() && data_size != self.total_size {
            return Err(Error::new(
                ErrorKind::FinalSize,
                stream_frame.frame_type(),
                format!(
                    "{} change the final size from {} to {data_size}",
                    stream_frame.id, self.total_size
                ),
            ));
        }
        self.rcvbuf.recv(offset, buf);
        if self.rcvbuf.is_readable() {
            if let Some(waker) = self.read_waker.take() {
                waker.wake()
            }
        }
        Ok(())
    }

    pub(super) fn is_all_rcvd(&self) -> bool {
        self.rcvbuf.available() == self.total_size
    }

    #[allow(dead_code)]
    pub(super) fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        if self.rcvbuf.is_readable() {
            let buflen = buf.remaining_mut();
            self.rcvbuf.read(&mut buf);
            Ok(buflen - buf.remaining_mut())
        } else {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }

    pub(super) fn poll_read<T: BufMut>(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut T,
    ) -> Poll<io::Result<()>> {
        assert!(self.read_waker.is_none());
        if self.rcvbuf.is_readable() {
            self.rcvbuf.read(buf);
            Poll::Ready(Ok(()))
        } else {
            self.read_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub(super) fn poll_stop(&mut self, cx: &mut Context<'_>) -> Poll<bool> {
        assert!(self.stop_waker.is_none());
        if self.is_stopped {
            Poll::Ready(true)
        } else {
            self.stop_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    /// Abort can be called multiple times at the application level,
    /// but only the first call is effective.
    pub(super) fn abort(&mut self) -> u64 {
        if !self.is_stopped {
            self.is_stopped = true;
            if let Some(waker) = self.stop_waker.take() {
                waker.wake()
            }
        }
        self.total_size
    }

    pub(super) fn data_recvd(self) -> DataRecvd {
        // Notify the stop function that it will not be stopped anymore,
        // this stream will not send STOP_SENDING frames in the future.
        if let Some(waker) = self.stop_waker {
            waker.wake();
        }
        DataRecvd {
            rcvbuf: self.rcvbuf,
        }
    }

    pub(super) fn wake_all(&mut self) {
        if let Some(waker) = self.stop_waker.take() {
            waker.wake()
        }
        if let Some(waker) = self.read_waker.take() {
            waker.wake()
        }
    }

    pub(super) fn recv_reset(mut self, reset_frame: ResetStreamFrame) -> Result<u64, Error> {
        let final_size = reset_frame.final_size.into_inner();
        if final_size != self.total_size {
            return Err(Error::new(
                ErrorKind::FinalSize,
                reset_frame.frame_type(),
                format!(
                    "{} change the final size from {} to {final_size}",
                    reset_frame.stream_id, self.total_size
                ),
            ));
        }
        self.wake_all();
        Ok(final_size)
    }
}

/// Once all the data has been received, STOP_SENDING becomes meaningless.
/// If the application layer aborts reading, it will directly result in the termination
/// of the lifecycle, leading to the release of all states and data. There is also no
/// need for any further readable notifications to wake up. Subsequent reads will
/// immediately return the available data until the end.
#[derive(Debug)]
pub struct DataRecvd {
    rcvbuf: rcvbuf::RecvBuf,
}

impl DataRecvd {
    /// Unlike the previous states, when there is no more data, it no longer returns
    /// "WouldBlock" but instead returns 0, which typically indicates the end.
    #[allow(dead_code)]
    pub(super) fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        let buflen = buf.remaining_mut();
        self.rcvbuf.read(&mut buf);
        Ok(buflen - buf.remaining_mut())
    }

    /// Unlike the previous states, when there is no more data, it no longer returns
    /// "Pending" but instead returns "Ready". However, in reality, nothing has been
    /// read. This kind of result typically indicates the end.
    pub(super) fn poll_read<T: BufMut>(&mut self, buf: &mut T) {
        self.rcvbuf.read(buf);
    }

    pub(super) fn is_all_read(&self) -> bool {
        self.rcvbuf.is_empty()
    }
}

/// Receiving stream state machine. In fact, here the state variables such as
/// is_closed/is_reset are replaced by a state machine. This not only provides
/// clearer semantics and aligns with the QUIC RFC specification but also
/// allows the compiler to help us check if the state transitions are correct
#[derive(Default, Debug)]
pub(super) enum Recver {
    Recv(Recv),
    SizeKnown(SizeKnown),
    DataRecvd(DataRecvd),
    ResetRecvd(u64),
    #[default]
    DataRead,
    ResetRead,
}

pub(super) type ArcRecver = Arc<Mutex<io::Result<Recver>>>;

impl Recver {
    pub(super) fn new(max_data_size: u64) -> Self {
        Self::Recv(Recv::with(max_data_size))
    }

    pub(super) fn take(&mut self) -> Self {
        std::mem::take(self)
    }

    pub(super) fn replace(&mut self, other: Self) {
        let _ = std::mem::replace(self, other);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
