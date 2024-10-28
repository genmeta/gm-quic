use std::{
    io,
    ops::Range,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
};

use qbase::{
    error::Error,
    frame::{ResetStreamError, ResetStreamFrame, SendFrame},
    sid::StreamId,
    util::DescribeData,
    varint::VarInt,
};

use super::sndbuf::SendBuf;

/// The "Ready" state represents a newly created stream that is able to accept data from the application.
/// Stream data might be buffered in this state in preparation for sending.
/// An implementation might choose to defer allocating a stream ID to a stream until it sends the first
/// STREAM frame and enters this state, which can allow for better stream prioritization.
#[derive(Debug)]
pub struct ReadySender<TX> {
    stream_id: StreamId,
    sndbuf: SendBuf,
    flush_waker: Option<Waker>,
    shutdown_waker: Option<Waker>,
    reset_frame_tx: TX,
    writable_waker: Option<Waker>,
    max_stream_data: u64,
}

impl<TX> ReadySender<TX>
where
    TX: SendFrame<ResetStreamFrame>,
{
    /// 应用层使用，取消发送流
    pub(super) fn cancel(&mut self, err_code: u64) -> ResetStreamError {
        let final_size = self.sndbuf.written();
        let reset_stream_err = ResetStreamError::new(
            VarInt::from_u64(err_code).expect("app error code must not exceed 2^62"),
            VarInt::from_u64(final_size).expect("final size must not exceed 2^62"),
        );
        self.reset_frame_tx
            .send_frame([reset_stream_err.combine(self.stream_id)]);
        reset_stream_err
    }
}

impl<TX> ReadySender<TX> {
    pub(super) fn new(stream_id: StreamId, buf_size: u64, reset_frame_tx: TX) -> ReadySender<TX> {
        ReadySender {
            stream_id,
            sndbuf: SendBuf::with_capacity(buf_size as usize),
            flush_waker: None,
            shutdown_waker: None,
            reset_frame_tx,
            writable_waker: None,
            max_stream_data: buf_size,
        }
    }

    /// 非阻塞写，如果没有多余的发送缓冲区，将返回WouldBlock错误。
    /// 但什么时候可写，是没通知的，只能不断去尝试写，直到写入成功。
    /// 仅供展示学习
    #[allow(dead_code)]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.sndbuf.written();
        if written < self.max_stream_data {
            let n = std::cmp::min((self.max_stream_data - written) as usize, buf.len());
            Ok(self.sndbuf.write(&buf[..n]))
        } else {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }

    pub(super) fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let stream_data = self.sndbuf.written();
        if stream_data < self.max_stream_data {
            let n = std::cmp::min((self.max_stream_data - stream_data) as usize, buf.len());
            Poll::Ready(Ok(self.sndbuf.write(&buf[..n])))
        } else {
            self.writable_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub(super) fn update_window(&mut self, max_stream_data: u64) {
        if max_stream_data > self.max_stream_data {
            self.max_stream_data = max_stream_data;
            if let Some(waker) = self.writable_waker.take() {
                waker.wake();
            }
        }
    }

    pub(super) fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flush_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    pub(super) fn shutdown(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        self.shutdown_waker = Some(cx.waker().clone());
        Ok(())
    }

    pub(super) fn is_finished(&self) -> bool {
        self.shutdown_waker.is_some()
    }

    pub(super) fn wake_all(&mut self) {
        if let Some(waker) = self.writable_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.flush_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.shutdown_waker.take() {
            waker.wake();
        }
    }
}

/// 状态转换，ReaderSender => SendingSender
impl<TX: Clone> From<&mut ReadySender<TX>> for SendingSender<TX> {
    fn from(value: &mut ReadySender<TX>) -> Self {
        SendingSender {
            stream_id: value.stream_id,
            sndbuf: std::mem::take(&mut value.sndbuf),
            flush_waker: value.flush_waker.take(),
            shutdown_waker: value.shutdown_waker.take(),
            reset_frame_tx: value.reset_frame_tx.clone(),
            writable_waker: value.writable_waker.take(),
            max_stream_data: value.max_stream_data,
        }
    }
}

/// 状态转换，ReaderSender => DataSentSender
impl<TX: Clone> From<&mut ReadySender<TX>> for DataSentSender<TX> {
    fn from(value: &mut ReadySender<TX>) -> Self {
        DataSentSender {
            stream_id: value.stream_id,
            sndbuf: std::mem::take(&mut value.sndbuf),
            flush_waker: value.flush_waker.take(),
            shutdown_waker: value.shutdown_waker.take(),
            reset_frame_tx: value.reset_frame_tx.clone(),
            fin_state: FinState::None,
        }
    }
}

#[derive(Debug)]
pub struct SendingSender<TX> {
    stream_id: StreamId,
    sndbuf: SendBuf,
    flush_waker: Option<Waker>,
    shutdown_waker: Option<Waker>,
    reset_frame_tx: TX,
    writable_waker: Option<Waker>,
    max_stream_data: u64,
}

type StreamData<'s> = (u64, bool, (&'s [u8], &'s [u8]), bool);

impl<TX> SendingSender<TX>
where
    TX: SendFrame<ResetStreamFrame>,
{
    pub(super) fn cancel(&mut self, err_code: u64) -> ResetStreamError {
        let final_size = self.sndbuf.written();
        let reset_stream_err = ResetStreamError::new(
            VarInt::from_u64(err_code).expect("app error code must not exceed 2^62"),
            VarInt::from_u64(final_size).expect("final size must not exceed 2^62"),
        );
        self.reset_frame_tx
            .send_frame([reset_stream_err.combine(self.stream_id)]);
        reset_stream_err
    }
}

impl<TX> SendingSender<TX> {
    pub(super) fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let written = self.sndbuf.written();
        if written < self.max_stream_data {
            let n = std::cmp::min((self.max_stream_data - written) as usize, buf.len());
            Poll::Ready(Ok(self.sndbuf.write(&buf[..n])))
        } else {
            self.writable_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    /// 传输层使用
    pub(super) fn update_window(&mut self, max_stream_data: u64) {
        if max_stream_data > self.max_stream_data {
            self.max_stream_data = max_stream_data;
            if let Some(waker) = self.writable_waker.take() {
                waker.wake();
            }
        }
    }

    pub(super) fn pick_up<P>(&mut self, predicate: P, flow_limit: usize) -> Option<StreamData>
    where
        P: Fn(u64) -> Option<usize>,
    {
        self.sndbuf
            .pick_up(predicate, flow_limit)
            .map(|(offset, is_fresh, data)| (offset, is_fresh, data, false))
    }

    pub(super) fn on_data_acked(&mut self, range: &Range<u64>) {
        self.sndbuf.on_data_acked(range);
        if self.sndbuf.is_all_rcvd() {
            if let Some(waker) = self.flush_waker.take() {
                waker.wake();
            }
            if let Some(waker) = self.shutdown_waker.take() {
                waker.wake();
            }
        }
    }

    pub(super) fn may_loss_data(&mut self, range: &Range<u64>) {
        self.sndbuf.may_loss_data(range)
    }

    pub(super) fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.sndbuf.is_all_rcvd() {
            Poll::Ready(Ok(()))
        } else {
            self.flush_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub(super) fn shutdown(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        self.shutdown_waker = Some(cx.waker().clone());
        Ok(())
    }

    pub(super) fn wake_all(&mut self) {
        if let Some(waker) = self.writable_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.flush_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.shutdown_waker.take() {
            waker.wake();
        }
    }

    /// 传输层使用
    pub(super) fn stop(&mut self) -> u64 {
        self.wake_all();
        // Actually, these remaining data is not acked and will not be acked
        self.sndbuf.written()
    }
}

/// 状态转换，SendingSender => DataSentSender
impl<TX: Clone> From<&mut SendingSender<TX>> for DataSentSender<TX> {
    fn from(value: &mut SendingSender<TX>) -> Self {
        DataSentSender {
            stream_id: value.stream_id,
            sndbuf: std::mem::take(&mut value.sndbuf),
            flush_waker: value.flush_waker.take(),
            shutdown_waker: value.shutdown_waker.take(),
            reset_frame_tx: value.reset_frame_tx.clone(),
            fin_state: FinState::None,
        }
    }
}

/// 表示发送fin标志位的状态。当所有数据都发完但没发过fin的Stream帧时，也应发一个携带fin标志位的空Stream帧
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum FinState {
    #[default]
    None, // 未发送过fin的Stream帧
    Sent, // 已发送过fin的Stream帧
    Rcvd, // 对端已确认收到fin状态
}

#[derive(Debug)]
pub struct DataSentSender<TX> {
    stream_id: StreamId,
    sndbuf: SendBuf,
    flush_waker: Option<Waker>,
    shutdown_waker: Option<Waker>,
    reset_frame_tx: TX,
    fin_state: FinState,
}

impl<TX> DataSentSender<TX>
where
    TX: SendFrame<ResetStreamFrame>,
{
    pub(super) fn cancel(&mut self, err_code: u64) -> ResetStreamError {
        let final_size = self.sndbuf.written();
        let reset_stream_err = ResetStreamError::new(
            VarInt::from_u64(err_code).expect("app error code must not exceed 2^62"),
            VarInt::from_u64(final_size).expect("final size must not exceed 2^62"),
        );
        self.reset_frame_tx
            .send_frame([reset_stream_err.combine(self.stream_id)]);
        reset_stream_err
    }
}

impl<TX> DataSentSender<TX> {
    pub(super) fn pick_up<P>(&mut self, predicate: P, flow_limit: usize) -> Option<StreamData>
    where
        P: Fn(u64) -> Option<usize>,
    {
        let final_size = self.sndbuf.written();
        self.sndbuf
            .pick_up(&predicate, flow_limit)
            .map(|(offset, is_fresh, data)| {
                let is_eos = offset + data.len() as u64 == final_size;
                if is_eos {
                    self.fin_state = FinState::Sent;
                }
                (offset, is_fresh, data, is_eos)
            })
            .or_else(|| {
                if self.fin_state == FinState::None {
                    let _ = predicate(final_size)?;
                    self.fin_state = FinState::Sent;
                    Some((final_size, false, (&[], &[]), true))
                } else {
                    None
                }
            })
    }

    pub(super) fn on_data_acked(&mut self, range: &Range<u64>, is_fin: bool) {
        self.sndbuf.on_data_acked(range);
        if is_fin {
            self.fin_state = FinState::Rcvd;
        }
        if self.is_all_rcvd() {
            if let Some(waker) = self.flush_waker.take() {
                waker.wake();
            }
            if let Some(waker) = self.shutdown_waker.take() {
                waker.wake();
            }
        }
    }

    pub(super) fn is_all_rcvd(&self) -> bool {
        self.sndbuf.is_all_rcvd() && self.fin_state == FinState::Rcvd
    }

    pub(super) fn may_loss_data(&mut self, range: &Range<u64>) {
        self.sndbuf.may_loss_data(range)
    }

    pub(super) fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.is_all_rcvd() {
            Poll::Ready(Ok(()))
        } else {
            self.flush_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub(super) fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.is_all_rcvd() {
            Poll::Ready(Ok(()))
        } else {
            self.shutdown_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub(super) fn wake_all(&mut self) {
        if let Some(waker) = self.flush_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.shutdown_waker.take() {
            waker.wake();
        }
    }

    pub(super) fn stop(&mut self) -> u64 {
        self.wake_all();
        // Actually, these remaining data is not acked and will not be acked
        self.sndbuf.written()
    }
}

#[derive(Debug)]
pub(super) enum Sender<TX> {
    Ready(ReadySender<TX>),
    Sending(SendingSender<TX>),
    DataSent(DataSentSender<TX>),
    ResetSent(ResetStreamError),
    DataRcvd,
    ResetRcvd(ResetStreamError),
}

impl<TX> Sender<TX> {
    pub fn new(stream_id: StreamId, buf_size: u64, reset_frame_tx: TX) -> Self {
        Sender::Ready(ReadySender::new(stream_id, buf_size, reset_frame_tx))
    }
}

/// The internal state representations of [`Outgoing`] and [`Writer`].
///
/// For the application layer, this struct is represented as [`Writer`]. The application can use it to
/// write data to the stream, or reset the stream.
///
/// For the protocol layer, this struct is represented as [`Outgoing`]. The protocol layer uses it to
/// manage the status of the `Sender`, sends data(stream frame),reset frames and other frames to peer.
///
/// [`Outgoing`]: super::Outgoing
/// [`Writer`]: super::Writer
#[derive(Debug, Clone)]
pub struct ArcSender<TX>(Arc<Mutex<Result<Sender<TX>, Error>>>);

impl<TX> ArcSender<TX> {
    #[doc(hidden)]
    pub(crate) fn new(stream_id: StreamId, buf_size: u64, reset_frame_tx: TX) -> Self {
        ArcSender(Arc::new(Mutex::new(Ok(Sender::new(
            stream_id,
            buf_size,
            reset_frame_tx,
        )))))
    }
}

impl<TX> ArcSender<TX> {
    pub(super) fn sender(&self) -> MutexGuard<Result<Sender<TX>, Error>> {
        self.0.lock().unwrap()
    }
}
