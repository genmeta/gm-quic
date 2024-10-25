use std::{
    io,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
};

use bytes::{BufMut, Bytes};
use qbase::{
    error::{Error, ErrorKind},
    frame::{
        BeFrame, MaxStreamDataFrame, ResetStreamError, ResetStreamFrame, SendFrame,
        StopSendingFrame, StreamFrame,
    },
    sid::StreamId,
    varint::{VarInt, VARINT_MAX},
};

use super::rcvbuf;

#[derive(Debug)]
pub(super) struct Recv<TX> {
    stream_id: StreamId,
    rcvbuf: rcvbuf::RecvBuf,
    read_waker: Option<Waker>,
    stop_state: Option<u64>,
    frames_tx: TX,
    largest_data_offset: u64,
    max_data_size: u64,
}

impl<TX> Recv<TX>
where
    TX: SendFrame<StopSendingFrame> + SendFrame<MaxStreamDataFrame> + Clone + Send + 'static,
{
    pub(super) fn with(stream_id: StreamId, buf_size: u64, frames_tx: TX) -> Self {
        Self {
            stream_id,
            rcvbuf: rcvbuf::RecvBuf::default(),
            read_waker: None,
            stop_state: None,
            frames_tx,
            largest_data_offset: 0,
            max_data_size: buf_size,
        }
    }

    pub(super) fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut impl BufMut,
    ) -> Poll<io::Result<()>> {
        if self.rcvbuf.is_readable() {
            self.rcvbuf.try_read(buf);

            let threshold = 1_000_000;
            if self.rcvbuf.nread() + threshold > self.max_data_size {
                let max_data_size = (self.rcvbuf.nread() + threshold * 2).min(VARINT_MAX);
                if max_data_size > self.max_data_size {
                    self.max_data_size = max_data_size;
                    self.frames_tx.send_frame([MaxStreamDataFrame::new(
                        self.stream_id,
                        VarInt::from_u64(max_data_size).unwrap(),
                    )]);
                }
            }

            Poll::Ready(Ok(()))
        } else {
            self.read_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
    pub(super) fn stop(&mut self, err_code: u64) {
        if self.stop_state.is_none() {
            self.stop_state = Some(err_code);
            self.frames_tx.send_frame([StopSendingFrame::new(
                self.stream_id,
                VarInt::from_u64(err_code).expect("app error code must not exceed 2^62!"),
            )]);
        }
    }
    pub(super) fn determin_size(&mut self, total_size: u64) -> SizeKnown<TX> {
        if let Some(waker) = self.read_waker.take() {
            waker.wake();
        }
        SizeKnown {
            total_size,
            stream_id: self.stream_id,
            rcvbuf: std::mem::take(&mut self.rcvbuf),
            stop_state: self.stop_state.take(),
            stop_tx: self.frames_tx.clone(),
            read_waker: self.read_waker.take(),
        }
    }
}

impl<TX> Recv<TX> {
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
        self.wake_reader();
        Ok(final_size)
    }

    pub(super) fn is_stopped(&self) -> bool {
        self.stop_state.is_some()
    }
    pub(super) fn wake_reader(&mut self) {
        if let Some(waker) = self.read_waker.take() {
            waker.wake()
        }
    }
}

/// Once the size of the data stream is determined, MAX_STREAM_DATA will no longer
/// be updated. Receiving data on this stream is meaningless. At this point, it is
/// also meaningless for the application layer to continue receiving data.
#[derive(Debug)]
pub struct SizeKnown<TX> {
    stream_id: StreamId,
    rcvbuf: rcvbuf::RecvBuf,
    read_waker: Option<Waker>,
    stop_state: Option<u64>,
    stop_tx: TX,
    total_size: u64,
}

impl<TX> SizeKnown<TX>
where
    TX: SendFrame<StopSendingFrame> + Clone + Send + 'static,
{
    /// Abort can be called multiple times at the application level,
    /// but only the first call is effective.
    pub(super) fn stop(&mut self, err_code: u64) -> u64 {
        if self.stop_state.is_none() {
            self.stop_state = Some(err_code);
            self.stop_tx.send_frame([StopSendingFrame::new(
                self.stream_id,
                VarInt::from_u64(err_code).expect("app error code must not exceed 2^62!"),
            )]);
        }
        self.total_size
    }
}

impl<TX> SizeKnown<TX> {
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
            self.rcvbuf.try_read(&mut buf);
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
            self.rcvbuf.try_read(buf);
            Poll::Ready(Ok(()))
        } else {
            self.read_waker = Some(cx.waker().clone());
            Poll::Pending
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
        self.wake_reader();
        Ok(final_size)
    }

    pub(super) fn is_stopped(&self) -> bool {
        self.stop_state.is_some()
    }
    pub(super) fn wake_reader(&mut self) {
        if let Some(waker) = self.read_waker.take() {
            waker.wake()
        }
    }
}

impl<TX> From<&mut SizeKnown<TX>> for DataRcvd
where
    TX: SendFrame<StopSendingFrame> + Clone + Send + 'static,
{
    fn from(size_known: &mut SizeKnown<TX>) -> Self {
        size_known.wake_reader();
        DataRcvd {
            rcvbuf: std::mem::take(&mut size_known.rcvbuf),
        }
    }
}

impl<TX> From<SizeKnown<TX>> for DataRcvd
where
    TX: SendFrame<StopSendingFrame> + Clone + Send + 'static,
{
    fn from(mut size_known: SizeKnown<TX>) -> Self {
        size_known.wake_reader();
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
        self.rcvbuf.try_read(&mut buf);
        Ok(buflen - buf.remaining_mut())
    }

    /// Unlike the previous states, when there is no more data, it no longer returns
    /// "Pending" but instead returns "Ready". However, in reality, nothing has been
    /// read. This kind of result typically indicates the end.
    pub(super) fn poll_read(&mut self, buf: &mut impl BufMut) {
        self.rcvbuf.try_read(buf);
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
pub(super) enum Recver<TX> {
    Recv(Recv<TX>),
    SizeKnown(SizeKnown<TX>),
    DataRcvd(DataRcvd),
    ResetRcvd(ResetStreamError),
    DataRead,
    ResetRead(ResetStreamError),
}

impl<TX> Recver<TX>
where
    TX: SendFrame<StopSendingFrame> + SendFrame<MaxStreamDataFrame> + Clone + Send + 'static,
{
    pub(super) fn new(stream_id: StreamId, buf_size: u64, frames_tx: TX) -> Self {
        Self::Recv(Recv::with(stream_id, buf_size, frames_tx))
    }
}

/// The internal representations of [`Incoming`] and [`Reader`].
///
/// For the application layer, this structure is represented as [`Reader`]. The application can use it
/// to read the data from the peer on the stream, or ask the peer stop sending.
///
/// For the protocol layer, this structure is represented as [`Incoming`]. The protocol layer use it to
/// manages the status of the `Recver` through it, delivers received data to the application layer and
/// sends frames to the peer.
///
/// [`Incoming`]: super::Incoming
/// [`Reader`]: super::Reader
#[derive(Debug, Clone)]
pub struct ArcRecver<TX>(Arc<Mutex<Result<Recver<TX>, Error>>>);

impl<TX> ArcRecver<TX>
where
    TX: SendFrame<StopSendingFrame> + SendFrame<MaxStreamDataFrame> + Clone + Send + 'static,
{
    #[doc(hidden)]
    pub(crate) fn new(stream_id: StreamId, buf_size: u64, frames_tx: TX) -> Self {
        ArcRecver(Arc::new(Mutex::new(Ok(Recver::new(
            stream_id, buf_size, frames_tx,
        )))))
    }
}

impl<TX> ArcRecver<TX> {
    pub(super) fn recver(&self) -> MutexGuard<Result<Recver<TX>, Error>> {
        self.0.lock().unwrap()
    }
}
