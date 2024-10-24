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
pub struct ReadySender<RESET> {
    stream_id: StreamId,
    sndbuf: SendBuf,
    cancel_state: Option<u64>,
    flush_waker: Option<Waker>,
    shutdown_waker: Option<Waker>,
    reset_frame_tx: RESET,
    writable_waker: Option<Waker>,
    max_data_size: u64,
}

impl<RESET> ReadySender<RESET>
where
    RESET: SendFrame<ResetStreamFrame> + Clone + Send + 'static,
{
    pub(super) fn with_wnd_size(
        stream_id: StreamId,
        wnd_size: u64,
        reset_frame_tx: RESET,
    ) -> ReadySender<RESET> {
        ReadySender {
            stream_id,
            sndbuf: SendBuf::with_capacity(wnd_size as usize),
            cancel_state: None,
            flush_waker: None,
            shutdown_waker: None,
            reset_frame_tx,
            writable_waker: None,
            max_data_size: wnd_size,
        }
    }

    /// 非阻塞写，如果没有多余的发送缓冲区，将返回WouldBlock错误。
    /// 但什么时候可写，是没通知的，只能不断去尝试写，直到写入成功。
    /// 仅供展示学习
    #[allow(dead_code)]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(err_code) = self.cancel_state {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("cancelled by app with error code {err_code}"),
            ))
        } else {
            let send_buf_len = self.sndbuf.len();
            if send_buf_len < self.max_data_size {
                let n = std::cmp::min((self.max_data_size - send_buf_len) as usize, buf.len());
                Ok(self.sndbuf.write(&buf[..n]))
            } else {
                Err(io::ErrorKind::WouldBlock.into())
            }
        }
    }

    pub(super) fn update_window(&mut self, max_data_size: u64) {
        if max_data_size > self.max_data_size {
            self.max_data_size = max_data_size;
            if let Some(waker) = self.writable_waker.take() {
                waker.wake();
            }
        }
    }

    pub(super) fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(err_code) = self.cancel_state {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("cancelled by app with error code {err_code}"),
            )))
        } else {
            let send_buf_len = self.sndbuf.len();
            if send_buf_len < self.max_data_size {
                let n = std::cmp::min((self.max_data_size - send_buf_len) as usize, buf.len());
                Poll::Ready(Ok(self.sndbuf.write(&buf[..n])))
            } else {
                self.writable_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    pub(super) fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(err_code) = self.cancel_state {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("cancelled by app with error code {err_code}"),
            )))
        } else {
            self.flush_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub(super) fn shutdown(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if let Some(err_code) = self.cancel_state {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("cancelled by app with error code {err_code}"),
            ))
        } else {
            self.shutdown_waker = Some(cx.waker().clone());
            Ok(())
        }
    }

    pub(super) fn is_shutdown(&self) -> bool {
        self.shutdown_waker.is_some()
    }

    /// 应用层使用，取消发送流
    pub(super) fn cancel(&mut self, err_code: u64) -> ResetStreamError {
        let final_size = self.sndbuf.len();
        let reset_stream_err = ResetStreamError::new(
            VarInt::from_u64(err_code).expect("app error code must not exceed 2^62"),
            VarInt::from_u64(final_size).expect("final size must not exceed 2^62"),
        );
        self.reset_frame_tx
            .send_frame([reset_stream_err.combine(self.stream_id)]);
        reset_stream_err
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
impl<RESET> From<&mut ReadySender<RESET>> for SendingSender<RESET>
where
    RESET: SendFrame<ResetStreamFrame> + Clone + Send + 'static,
{
    fn from(value: &mut ReadySender<RESET>) -> Self {
        SendingSender {
            stream_id: value.stream_id,
            sndbuf: std::mem::take(&mut value.sndbuf),
            cancel_state: value.cancel_state.take(),
            flush_waker: value.flush_waker.take(),
            shutdown_waker: value.shutdown_waker.take(),
            reset_frame_tx: value.reset_frame_tx.clone(),
            writable_waker: value.writable_waker.take(),
            max_data_size: value.max_data_size,
        }
    }
}

/// 状态转换，ReaderSender => DataSentSender
impl<RESET> From<&mut ReadySender<RESET>> for DataSentSender<RESET>
where
    RESET: SendFrame<ResetStreamFrame> + Clone + Send + 'static,
{
    fn from(value: &mut ReadySender<RESET>) -> Self {
        DataSentSender {
            stream_id: value.stream_id,
            sndbuf: std::mem::take(&mut value.sndbuf),
            cancel_state: value.cancel_state.take(),
            flush_waker: value.flush_waker.take(),
            shutdown_waker: value.shutdown_waker.take(),
            reset_frame_tx: value.reset_frame_tx.clone(),
            fin_state: FinState::None,
        }
    }
}

#[derive(Debug)]
pub struct SendingSender<RESET> {
    stream_id: StreamId,
    sndbuf: SendBuf,
    cancel_state: Option<u64>,
    flush_waker: Option<Waker>,
    shutdown_waker: Option<Waker>,
    reset_frame_tx: RESET,
    writable_waker: Option<Waker>,
    max_data_size: u64,
}

type StreamData<'s> = (u64, bool, (&'s [u8], &'s [u8]), bool);

impl<RESET> SendingSender<RESET>
where
    RESET: SendFrame<ResetStreamFrame> + Send + 'static,
{
    pub(super) fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(err_code) = self.cancel_state {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("cancelled by app with error code {err_code}"),
            )))
        } else {
            let send_buf_len = self.sndbuf.len();
            if send_buf_len < self.max_data_size {
                let n = std::cmp::min((self.max_data_size - send_buf_len) as usize, buf.len());
                Poll::Ready(Ok(self.sndbuf.write(&buf[..n])))
            } else {
                self.writable_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    /// 传输层使用
    pub(super) fn update_window(&mut self, max_data_size: u64) {
        if max_data_size > self.max_data_size {
            self.max_data_size = max_data_size;
            if let Some(waker) = self.writable_waker.take() {
                waker.wake();
            }
        }
    }

    pub(super) fn pick_up<P>(&mut self, predicate: P, flow_limit: usize) -> Option<StreamData>
    where
        P: Fn(u64) -> Option<usize>,
    {
        if self.cancel_state.is_some() {
            return None;
        }
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
        if let Some(err_code) = self.cancel_state {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("cancelled by app with error code {err_code}"),
            )))
        } else if self.sndbuf.is_all_rcvd() {
            Poll::Ready(Ok(()))
        } else {
            self.flush_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub(super) fn shutdown(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if let Some(err_code) = self.cancel_state {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("cancelled by app with error code {err_code}"),
            ))
        } else {
            self.shutdown_waker = Some(cx.waker().clone());
            Ok(())
        }
    }

    pub(super) fn cancel(&mut self, err_code: u64) -> ResetStreamError {
        let final_size = self.sndbuf.len();
        let reset_stream_err = ResetStreamError::new(
            VarInt::from_u64(err_code).expect("app error code must not exceed 2^62"),
            VarInt::from_u64(final_size).expect("final size must not exceed 2^62"),
        );
        self.reset_frame_tx
            .send_frame([reset_stream_err.combine(self.stream_id)]);
        reset_stream_err
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
        self.sndbuf.len()
    }
}

/// 状态转换，SendingSender => DataSentSender
impl<RESET> From<&mut SendingSender<RESET>> for DataSentSender<RESET>
where
    RESET: SendFrame<ResetStreamFrame> + Clone + Send + 'static,
{
    fn from(value: &mut SendingSender<RESET>) -> Self {
        DataSentSender {
            stream_id: value.stream_id,
            sndbuf: std::mem::take(&mut value.sndbuf),
            cancel_state: value.cancel_state.take(),
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
pub struct DataSentSender<RESET> {
    stream_id: StreamId,
    sndbuf: SendBuf,
    cancel_state: Option<u64>,
    flush_waker: Option<Waker>,
    shutdown_waker: Option<Waker>,
    reset_frame_tx: RESET,
    fin_state: FinState,
}

impl<RESET> DataSentSender<RESET>
where
    RESET: SendFrame<ResetStreamFrame> + Send + 'static,
{
    pub(super) fn pick_up<P>(&mut self, predicate: P, flow_limit: usize) -> Option<StreamData>
    where
        P: Fn(u64) -> Option<usize>,
    {
        if self.cancel_state.is_some() {
            return None;
        }

        let final_size = self.sndbuf.len();
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
        if let Some(err_code) = self.cancel_state {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("cancelled by app with error code {err_code}"),
            )))
        } else if self.is_all_rcvd() {
            Poll::Ready(Ok(()))
        } else {
            self.flush_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub(super) fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(err_code) = self.cancel_state {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("cancelled by app with error code {err_code}"),
            )))
        } else if self.is_all_rcvd() {
            Poll::Ready(Ok(()))
        } else {
            self.shutdown_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub(super) fn cancel(&mut self, err_code: u64) -> ResetStreamError {
        let final_size = self.sndbuf.len();
        let reset_stream_err = ResetStreamError::new(
            VarInt::from_u64(err_code).expect("app error code must not exceed 2^62"),
            VarInt::from_u64(final_size).expect("final size must not exceed 2^62"),
        );
        self.reset_frame_tx
            .send_frame([reset_stream_err.combine(self.stream_id)]);
        reset_stream_err
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
        self.sndbuf.len()
    }
}

#[derive(Debug)]
pub(super) enum Sender<RESET> {
    Ready(ReadySender<RESET>),
    Sending(SendingSender<RESET>),
    DataSent(DataSentSender<RESET>),
    ResetSent(ResetStreamError),
    DataRcvd,
    ResetRcvd(ResetStreamError),
}

impl<RESET> Sender<RESET>
where
    RESET: SendFrame<ResetStreamFrame> + Clone + Send + 'static,
{
    pub fn with_wnd_size(stream_id: StreamId, wnd_size: u64, reset_frame_tx: RESET) -> Self {
        Sender::Ready(ReadySender::with_wnd_size(
            stream_id,
            wnd_size,
            reset_frame_tx,
        ))
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
pub struct ArcSender<RESET>(Arc<Mutex<Result<Sender<RESET>, Error>>>);

impl<RESET> ArcSender<RESET>
where
    RESET: SendFrame<ResetStreamFrame> + Clone + Send + 'static,
{
    #[doc(hidden)]
    pub(crate) fn new(stream_id: StreamId, wnd_size: u64, reset_frame_tx: RESET) -> Self {
        ArcSender(Arc::new(Mutex::new(Ok(Sender::with_wnd_size(
            stream_id,
            wnd_size,
            reset_frame_tx,
        )))))
    }
}

impl<RESET> ArcSender<RESET> {
    pub(super) fn sender(&self) -> MutexGuard<Result<Sender<RESET>, Error>> {
        self.0.lock().unwrap()
    }
}
