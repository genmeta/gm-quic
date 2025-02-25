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
    varint::{VARINT_MAX, VarInt},
};
use qlog::quic::transport::{GranularStreamStates, StreamSide, StreamStateUpdated};

use super::rcvbuf;

#[derive(Debug)]
pub(super) struct Recv<TX> {
    stream_id: StreamId,
    rcvbuf: rcvbuf::RecvBuf,
    read_waker: Option<Waker>,
    stop_state: Option<u64>,
    broker: TX,
    largest: u64,
    max_stream_data: u64,
}

impl<TX> Recv<TX>
where
    TX: SendFrame<MaxStreamDataFrame>,
{
    pub(super) fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut impl BufMut,
    ) -> Poll<io::Result<()>> {
        if self.rcvbuf.is_readable() {
            self.rcvbuf.try_read(buf);

            let threshold = 1_000_000;
            if self.rcvbuf.nread() + threshold > self.max_stream_data {
                let max_stream_data = (self.rcvbuf.nread() + threshold * 2).min(VARINT_MAX);
                if max_stream_data > self.max_stream_data {
                    self.max_stream_data = max_stream_data;
                    self.broker.send_frame([MaxStreamDataFrame::new(
                        self.stream_id,
                        VarInt::from_u64(max_stream_data).unwrap(),
                    )]);
                }
            }

            Poll::Ready(Ok(()))
        } else {
            self.read_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

impl<TX> Recv<TX>
where
    TX: SendFrame<StopSendingFrame>,
{
    pub(super) fn stop(&mut self, err_code: u64) {
        if self.stop_state.is_none() {
            self.stop_state = Some(err_code);
            self.broker.send_frame([StopSendingFrame::new(
                self.stream_id,
                VarInt::from_u64(err_code).expect("app error code must not exceed 2^62!"),
            )]);
        }
    }
}

impl<TX: Clone> Recv<TX> {
    pub(super) fn determin_size(
        &mut self,
        stream_frame: &StreamFrame,
    ) -> Result<SizeKnown<TX>, Error> {
        if let Some(waker) = self.read_waker.take() {
            waker.wake();
        }

        let final_size = stream_frame.offset() + stream_frame.len() as u64;
        let received_largest_offset = self.rcvbuf.largest_offset();
        if received_largest_offset > final_size {
            return Err(Error::new(
                ErrorKind::FinalSize,
                stream_frame.frame_type(),
                format!(
                    "{} send a wrong smaller final size {} than the largest rcvd data offset {}",
                    stream_frame.stream_id(),
                    final_size,
                    received_largest_offset
                ),
            ));
        }

        qlog::event!(StreamStateUpdated {
            stream_id: self.stream_id,
            stream_type: self.stream_id.dir(),
            old: GranularStreamStates::Receive,
            new: GranularStreamStates::SizeKnown,
            stream_side: StreamSide::Receiving
        });
        Ok(SizeKnown {
            final_size,
            stream_id: self.stream_id,
            rcvbuf: std::mem::take(&mut self.rcvbuf),
            stop_state: self.stop_state.take(),
            broker: self.broker.clone(),
            read_waker: self.read_waker.take(),
        })
    }
}

impl<TX> Recv<TX> {
    pub(super) fn new(stream_id: StreamId, buf_size: u64, broker: TX) -> Self {
        Self {
            stream_id,
            rcvbuf: rcvbuf::RecvBuf::default(),
            read_waker: None,
            stop_state: None,
            broker,
            largest: 0,
            max_stream_data: buf_size,
        }
    }

    pub(super) fn recv(&mut self, stream_frame: &StreamFrame, body: Bytes) -> Result<usize, Error> {
        let data_start = stream_frame.offset();

        let data_end = data_start + body.len() as u64;
        if data_end > self.max_stream_data {
            return Err(Error::new(
                ErrorKind::FlowControl,
                stream_frame.frame_type(),
                format!(
                    "{} send {data_end} bytes which exceeds the stream data limit {}",
                    stream_frame.stream_id(),
                    self.max_stream_data
                ),
            ));
        }
        self.rcvbuf.recv(data_start, body);
        let mut fresh_data = 0;
        if self.largest < data_end {
            fresh_data = data_end - self.largest;
            self.largest = data_end;
        }
        if self.rcvbuf.is_readable() {
            if let Some(waker) = self.read_waker.take() {
                waker.wake()
            }
        }
        Ok(fresh_data as _)
    }

    pub(super) fn recv_reset(&mut self, reset_frame: &ResetStreamFrame) -> Result<usize, Error> {
        let final_size = reset_frame.final_size();
        if final_size < self.largest {
            return Err(Error::new(
                ErrorKind::FinalSize,
                reset_frame.frame_type(),
                format!(
                    "{} reset with a wrong smaller final size {final_size} than the largest rcvd data offset {}",
                    reset_frame.stream_id(),
                    self.largest
                ),
            ));
        }
        self.wake_reader();
        Ok((final_size - self.largest) as _)
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
    broker: TX,
    final_size: u64,
}

impl<TX> SizeKnown<TX>
where
    TX: SendFrame<StopSendingFrame>,
{
    /// Abort can be called multiple times at the application level,
    /// but only the first call is effective.
    pub(super) fn stop(&mut self, err_code: u64) {
        if self.stop_state.is_none() {
            self.stop_state = Some(err_code);
            self.broker.send_frame([StopSendingFrame::new(
                self.stream_id,
                VarInt::from_u64(err_code).expect("app error code must not exceed 2^62!"),
            )]);
        }
    }
}

impl<TX> SizeKnown<TX> {
    pub(super) fn recv(&mut self, stream_frame: &StreamFrame, data: Bytes) -> Result<usize, Error> {
        let data_start = stream_frame.offset();
        let data_end = data_start + data.len() as u64;
        if data_end > self.final_size {
            return Err(Error::new(
                ErrorKind::FinalSize,
                stream_frame.frame_type(),
                format!(
                    "{} send {data_end} bytes which exceeds the final_size {}",
                    stream_frame.stream_id(),
                    self.final_size
                ),
            ));
        }
        if stream_frame.is_fin() && data_end != self.final_size {
            return Err(Error::new(
                ErrorKind::FinalSize,
                stream_frame.frame_type(),
                format!(
                    "{} change the final size from {} to {data_end}",
                    stream_frame.stream_id(),
                    self.final_size
                ),
            ));
        }
        self.rcvbuf.recv(data_start, data);
        if self.rcvbuf.is_readable() {
            if let Some(waker) = self.read_waker.take() {
                waker.wake()
            }
        }
        Ok(0)
    }

    #[tracing::instrument(level = "trace", skip(self), ret)]
    pub(super) fn is_all_rcvd(&self) -> bool {
        self.rcvbuf.nread() + self.rcvbuf.available() == self.final_size
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

    pub(super) fn recv_reset(&mut self, reset_frame: &ResetStreamFrame) -> Result<(), Error> {
        let final_size = reset_frame.final_size();
        if final_size != self.final_size {
            return Err(Error::new(
                ErrorKind::FinalSize,
                reset_frame.frame_type(),
                format!(
                    "{} change the final size from {} to {final_size}",
                    reset_frame.stream_id(),
                    self.final_size
                ),
            ));
        }
        self.wake_reader();
        Ok(())
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
        qlog::event!(StreamStateUpdated {
            stream_id: size_known.stream_id,
            stream_type: size_known.stream_id.dir(),
            old: GranularStreamStates::SizeKnown,
            new: GranularStreamStates::DataReceived,
            stream_side: StreamSide::Receiving
        });
        size_known.wake_reader();
        DataRcvd {
            stream_id: size_known.stream_id,
            rcvbuf: std::mem::take(&mut size_known.rcvbuf),
        }
    }
}

impl<TX> From<SizeKnown<TX>> for DataRcvd
where
    TX: SendFrame<StopSendingFrame> + Clone + Send + 'static,
{
    fn from(mut size_known: SizeKnown<TX>) -> Self {
        (&mut size_known).into()
    }
}

/// Once all the data has been received, STOP_SENDING becomes meaningless.
/// If the application layer aborts reading, it will directly result in the termination
/// of the lifecycle, leading to the release of all states and data. There is also no
/// need for any further readable notifications to wake up. Subsequent reads will
/// immediately return the available data until the end.
#[derive(Debug)]
pub struct DataRcvd {
    stream_id: StreamId,
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

#[derive(Debug)]
pub struct ResetRcvd {
    stream_id: StreamId,
    reset: ResetStreamError,
}

impl ResetRcvd {
    pub fn read(&self) -> io::Error {
        io::Error::new(io::ErrorKind::BrokenPipe, self.reset)
    }
}

impl<TX> From<(&mut Recv<TX>, &ResetStreamFrame)> for ResetRcvd {
    fn from((recv, reset): (&mut Recv<TX>, &ResetStreamFrame)) -> Self {
        qlog::event!(StreamStateUpdated {
            stream_id: recv.stream_id,
            stream_type: recv.stream_id.dir(),
            old: GranularStreamStates::Receive,
            new: GranularStreamStates::ResetReceived,
            stream_side: StreamSide::Receiving
        });
        ResetRcvd {
            stream_id: recv.stream_id,
            reset: reset.into(),
        }
    }
}

impl<TX> From<(&mut SizeKnown<TX>, &ResetStreamFrame)> for ResetRcvd {
    fn from((size_known, reset): (&mut SizeKnown<TX>, &ResetStreamFrame)) -> Self {
        qlog::event!(StreamStateUpdated {
            stream_id: size_known.stream_id,
            stream_type: size_known.stream_id.dir(),
            old: GranularStreamStates::Receive,
            new: GranularStreamStates::ResetReceived,
            stream_side: StreamSide::Receiving
        });
        ResetRcvd {
            stream_id: size_known.stream_id,
            reset: reset.into(),
        }
    }
}

#[derive(Debug)]
pub struct DataRead(());

impl From<&mut DataRcvd> for DataRead {
    fn from(value: &mut DataRcvd) -> Self {
        qlog::event!(StreamStateUpdated {
            stream_id: value.stream_id,
            stream_type: value.stream_id.dir(),
            old: GranularStreamStates::DataReceived,
            new: GranularStreamStates::DataRead,
            stream_side: StreamSide::Receiving
        });
        Self(())
    }
}

#[derive(Debug)]
pub struct ResetRead {
    reset: ResetStreamError,
}

impl ResetRead {
    pub fn read(&self) -> io::Error {
        io::Error::new(io::ErrorKind::BrokenPipe, self.reset)
    }
}

impl From<&mut ResetRcvd> for ResetRead {
    fn from(value: &mut ResetRcvd) -> Self {
        qlog::event!(StreamStateUpdated {
            stream_id: value.stream_id,
            stream_type: value.stream_id.dir(),
            old: GranularStreamStates::ResetReceived,
            new: GranularStreamStates::ResetRead,
            stream_side: StreamSide::Receiving
        });
        Self { reset: value.reset }
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
    ResetRcvd(ResetRcvd),
    DataRead(DataRead),
    ResetRead(ResetRead),
}

impl<TX> Recver<TX> {
    pub(super) fn new(stream_id: StreamId, buf_size: u64, frames_tx: TX) -> Self {
        Self::Recv(Recv::new(stream_id, buf_size, frames_tx))
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
