use super::rcvbuf;
use bytes::{BufMut, Bytes};
use std::{
    io,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

#[derive(Debug)]
pub struct Recv {
    rcvbuf: rcvbuf::RecvBuf,
    read_waker: Option<Waker>,
    is_stopped: bool,
    stop_waker: Option<Waker>,
    max_data_size: u64,
    low_buf_alert: Option<Waker>,
}

impl Recv {
    pub fn with(max_data_size: u64) -> Self {
        Self {
            rcvbuf: rcvbuf::RecvBuf::default(),
            read_waker: None,
            is_stopped: false,
            stop_waker: None,
            max_data_size,
            low_buf_alert: None,
        }
    }

    pub fn recv(&mut self, offset: u64, buf: Bytes) {
        self.rcvbuf.recv(offset, buf);
        if self.rcvbuf.is_readable() {
            if let Some(waker) = self.read_waker.take() {
                waker.wake()
            }
        }
    }

    pub fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        if self.rcvbuf.is_readable() {
            let buflen = buf.remaining_mut();
            self.rcvbuf.read(&mut buf);

            let threshold = 1_000_000;
            if self.rcvbuf.offset() + threshold > self.max_data_size {
                if let Some(waker) = self.low_buf_alert.take() {
                    waker.wake()
                }
            }

            Ok(buflen - buf.remaining_mut())
        } else {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }

    pub fn poll_read<T: BufMut>(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut T,
    ) -> Poll<io::Result<()>> {
        assert!(self.read_waker.is_none());
        if self.rcvbuf.is_readable() {
            self.rcvbuf.read(buf);

            let threshold = 1_000_000;
            if self.rcvbuf.offset() + threshold > self.max_data_size {
                if let Some(waker) = self.low_buf_alert.take() {
                    waker.wake()
                }
            }

            Poll::Ready(Ok(()))
        } else {
            self.read_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub fn poll_window_update(&mut self, cx: &mut Context<'_>) -> Poll<u64> {
        assert!(self.low_buf_alert.is_none());
        let threshold = 1_000_000;
        if self.rcvbuf.offset() + threshold > self.max_data_size {
            self.max_data_size = self.rcvbuf.offset() + threshold * 2;
            Poll::Ready(self.max_data_size)
        } else {
            self.low_buf_alert = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub fn poll_stop(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        assert!(self.stop_waker.is_none());
        if self.is_stopped {
            Poll::Ready(())
        } else {
            self.stop_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub fn abort(&mut self) {
        if !self.is_stopped {
            self.is_stopped = true;
        }
        if let Some(waker) = self.stop_waker.take() {
            waker.wake()
        }
    }

    pub fn determin_size(self, total_size: u64) -> SizeKnown {
        SizeKnown {
            rcvbuf: self.rcvbuf,
            read_waker: self.read_waker,
            is_stopped: self.is_stopped,
            stop_waker: self.stop_waker,
            total_size,
        }
    }

    pub fn recv_reset(mut self) {
        if let Some(waker) = self.read_waker.take() {
            waker.wake()
        }
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
    pub fn recv(&mut self, offset: u64, buf: Bytes) {
        self.rcvbuf.recv(offset, buf);
        if self.rcvbuf.is_readable() {
            if let Some(waker) = self.read_waker.take() {
                waker.wake()
            }
        }
    }

    pub fn is_all_rcvd(&self) -> bool {
        self.rcvbuf.available() == self.total_size
    }

    pub fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        if self.rcvbuf.is_readable() {
            let buflen = buf.remaining_mut();
            self.rcvbuf.read(&mut buf);
            Ok(buflen - buf.remaining_mut())
        } else {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }

    pub fn poll_read<T: BufMut>(
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

    pub fn poll_stop(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        assert!(self.stop_waker.is_none());
        if self.is_stopped {
            Poll::Ready(())
        } else {
            self.stop_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    /// Abort can be called multiple times at the application level,
    /// but only the first call is effective.
    pub fn abort(&mut self) {
        if !self.is_stopped {
            self.is_stopped = true;
        }
        if let Some(waker) = self.stop_waker.take() {
            waker.wake()
        }
    }

    pub fn data_recvd(self) -> DataRecvd {
        DataRecvd {
            rcvbuf: self.rcvbuf,
        }
    }

    pub fn recv_reset(mut self) {
        if let Some(waker) = self.read_waker.take() {
            waker.wake()
        }
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
    pub fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        let buflen = buf.remaining_mut();
        self.rcvbuf.read(&mut buf);
        Ok(buflen - buf.remaining_mut())
    }

    /// Unlike the previous states, when there is no more data, it no longer returns
    /// "Pending" but instead returns "Ready". However, in reality, nothing has been
    /// read. This kind of result typically indicates the end.
    pub fn poll_read<T: BufMut>(&mut self, buf: &mut T) {
        self.rcvbuf.read(buf);
    }

    pub fn is_all_read(&self) -> bool {
        self.rcvbuf.is_empty()
    }
}

/// Receiving stream state machine. In fact, here the state variables such as
/// is_closed/is_reset are replaced by a state machine. This not only provides
/// clearer semantics and aligns with the QUIC RFC specification but also
/// allows the compiler to help us check if the state transitions are correct
#[derive(Default)]
pub enum Recver {
    Recv(Recv),
    SizeKnown(SizeKnown),
    DataRecvd(DataRecvd),
    ResetRecvd,
    #[default]
    DataRead,
    ResetRead,
}

pub enum RecvState {
    Recv,
    SizeKnown,
    DataRecvd,
    ResetRecvd,
    DataRead,
    ResetRead,
}

pub(super) type ArcRecver = Arc<Mutex<Recver>>;

impl Recver {
    pub fn with(max_data_size: u64) -> Self {
        Self::Recv(Recv::with(max_data_size))
    }

    pub fn state(&self) -> RecvState {
        match self {
            Self::Recv(_) => RecvState::Recv,
            Self::SizeKnown(_) => RecvState::SizeKnown,
            Self::DataRecvd(_) => RecvState::DataRecvd,
            Self::ResetRecvd => RecvState::ResetRecvd,
            Self::DataRead => RecvState::DataRead,
            Self::ResetRead => RecvState::ResetRead,
        }
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
