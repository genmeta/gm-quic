use std::{
    io,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use bytes::{BufMut, Bytes};
use qbase::{
    error::{Error, ErrorKind},
    frame::{BeFrame, ResetStreamFrame, StreamFrame},
};

use super::rcvbuf;

#[derive(Debug)]
pub(super) struct Recv {
    rcvbuf: rcvbuf::RecvBuf,
    read_waker: Option<Waker>,
    stop_state: Option<u64>,
    stop_waker: Option<Waker>,
    largest_data_offset: u64,
    max_data_size: u64,
    buf_exceeds_half_waker: Option<Waker>,
}

impl Recv {
    pub(super) fn with(max_data_size: u64) -> Self {
        Self {
            rcvbuf: rcvbuf::RecvBuf::default(),
            read_waker: None,
            stop_state: None,
            stop_waker: None,
            largest_data_offset: 0,
            max_data_size,
            buf_exceeds_half_waker: None,
        }
    }

    pub(super) fn recv(&mut self, stream_frame: &StreamFrame, body: Bytes) -> Result<usize, Error> {
        let begin = stream_frame.offset();

        let data_offset = begin + body.len() as u64;
        if data_offset > self.max_data_size {
            return Err(Error::new(
                ErrorKind::FlowControl,
                stream_frame.frame_type(),
                format!(
                    "{} send {data_offset} bytes which exceeds the stream data limit {}",
                    stream_frame.id, self.max_data_size
                ),
            ));
        }
        self.largest_data_offset = std::cmp::max(self.largest_data_offset, data_offset);
        let new_data_size = self.rcvbuf.recv(begin, body);
        if self.rcvbuf.is_readable() {
            if let Some(waker) = self.read_waker.take() {
                waker.wake()
            }
        }
        Ok(new_data_size)
    }

    pub(super) fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut impl BufMut,
    ) -> Poll<io::Result<()>> {
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

    pub(super) fn poll_update_window(&mut self, cx: &mut Context<'_>) -> Poll<Option<u64>> {
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

    pub(super) fn poll_stop(&mut self, cx: &mut Context<'_>) -> Poll<Option<u64>> {
        if let Some(err_code) = self.stop_state {
            Poll::Ready(Some(err_code))
        } else {
            self.stop_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub(super) fn stop(&mut self, err_code: u64) {
        assert!(self.stop_state.is_none());
        self.stop_state = Some(err_code);
        if let Some(waker) = self.stop_waker.take() {
            waker.wake()
        }
    }

    pub(super) fn is_stopped(&self) -> bool {
        self.stop_state.is_some()
    }

    pub(super) fn determin_size(&mut self, total_size: u64) -> SizeKnown {
        if let Some(waker) = self.buf_exceeds_half_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.read_waker.take() {
            waker.wake();
        }
        SizeKnown {
            total_size,
            rcvbuf: std::mem::take(&mut self.rcvbuf),
            stop_state: self.stop_state.take(),
            read_waker: self.read_waker.take(),
            stop_waker: self.stop_waker.take(),
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

    pub(super) fn recv_reset(&mut self, reset_frame: &ResetStreamFrame) -> Result<u64, Error> {
        let final_size = reset_frame.final_size.into_inner();
        if final_size < self.largest_data_offset {
            return Err(Error::new(
                ErrorKind::FinalSize,
                reset_frame.frame_type(),
                format!(
                    "{} reset with a wrong smaller final size {final_size} than the largest rcvd data offset {}",
                    reset_frame.stream_id, self.largest_data_offset
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
    stop_state: Option<u64>,
    stop_waker: Option<Waker>,
    total_size: u64,
}

impl SizeKnown {
    pub(super) fn recv(&mut self, stream_frame: &StreamFrame, buf: Bytes) -> Result<usize, Error> {
        let offset = stream_frame.offset();
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
        let new_data_size = self.rcvbuf.recv(offset, buf);
        if self.rcvbuf.is_readable() {
            if let Some(waker) = self.read_waker.take() {
                waker.wake()
            }
        }
        Ok(new_data_size)
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

    pub(super) fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut impl BufMut,
    ) -> Poll<io::Result<()>> {
        if self.rcvbuf.is_readable() {
            self.rcvbuf.read(buf);
            Poll::Ready(Ok(()))
        } else {
            self.read_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub(super) fn poll_stop(&mut self, cx: &mut Context<'_>) -> Poll<Option<u64>> {
        if let Some(err_code) = self.stop_state {
            Poll::Ready(Some(err_code))
        } else {
            self.stop_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    /// Abort can be called multiple times at the application level,
    /// but only the first call is effective.
    pub(super) fn stop(&mut self, err_code: u64) -> u64 {
        assert!(self.stop_state.is_none());
        self.stop_state = Some(err_code);
        if let Some(waker) = self.stop_waker.take() {
            waker.wake()
        }
        self.total_size
    }

    pub(super) fn is_stopped(&self) -> bool {
        self.stop_state.is_some()
    }

    pub(super) fn wake_all(&mut self) {
        if let Some(waker) = self.stop_waker.take() {
            waker.wake()
        }
        if let Some(waker) = self.read_waker.take() {
            waker.wake()
        }
    }

    pub(super) fn recv_reset(&mut self, reset_frame: &ResetStreamFrame) -> Result<u64, Error> {
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

impl From<&mut SizeKnown> for DataRcvd {
    fn from(size_known: &mut SizeKnown) -> Self {
        size_known.wake_all();
        DataRcvd {
            rcvbuf: std::mem::take(&mut size_known.rcvbuf),
        }
    }
}

impl From<SizeKnown> for DataRcvd {
    fn from(mut size_known: SizeKnown) -> Self {
        size_known.wake_all();
        DataRcvd {
            rcvbuf: size_known.rcvbuf,
        }
    }
}

/// Once all the data has been received, STOP_SENDING becomes meaningless.
/// If the application layer aborts reading, it will directly result in the termination
/// of the lifecycle, leading to the release of all states and data. There is also no
/// need for any further readable notifications to wake up. Subsequent reads will
/// immediately return the available data until the end.
#[derive(Debug)]
pub struct DataRcvd {
    rcvbuf: rcvbuf::RecvBuf,
}

impl DataRcvd {
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
    pub(super) fn poll_read(&mut self, buf: &mut impl BufMut) {
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
#[derive(Debug)]
pub(super) enum Recver {
    Recv(Recv),
    SizeKnown(SizeKnown),
    DataRcvd(DataRcvd),
    ResetRcvd(u64),
    DataRead,
    ResetRead,
}

pub(super) type ArcRecver = Arc<Mutex<io::Result<Recver>>>;

impl Recver {
    pub(super) fn new(max_data_size: u64) -> Self {
        Self::Recv(Recv::with(max_data_size))
    }
}

#[cfg(test)]
mod tests {}
