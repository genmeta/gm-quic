use std::{
    io,
    ops::Range,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
};

use qbase::{error::Error, streamid::StreamId, util::DescribeData};

use super::sndbuf::SendBuf;
use crate::streams::StreamReset;

/// The "Ready" state represents a newly created stream that is able to accept data from the application.
/// Stream data might be buffered in this state in preparation for sending.
/// An implementation might choose to defer allocating a stream ID to a stream until it sends the first
/// STREAM frame and enters this state, which can allow for better stream prioritization.
#[derive(Debug)]
pub struct ReadySender {
    sndbuf: SendBuf,
    cancel_state: Option<u64>,
    flush_waker: Option<Waker>,
    shutdown_waker: Option<Waker>,
    cancel_waker: Option<Waker>,
    writable_waker: Option<Waker>,
    max_data_size: u64,
}

impl ReadySender {
    pub(super) fn with_wnd_size(wnd_size: u64) -> ReadySender {
        ReadySender {
            sndbuf: SendBuf::with_capacity(wnd_size as usize),
            cancel_state: None,
            flush_waker: None,
            shutdown_waker: None,
            cancel_waker: None,
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

    /// 传输层使用，用于发送RST_STREAM帧后，将Sender置为ResetSent状态
    pub(super) fn poll_cancel(&mut self, cx: &mut Context<'_>) -> Poll<(u64, u64)> {
        if let Some(err_code) = self.cancel_state {
            Poll::Ready((self.sndbuf.len(), err_code))
        } else {
            self.cancel_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    /// 应用层使用，取消发送流
    pub(super) fn cancel(&mut self, err_code: u64) {
        assert!(self.cancel_state.is_none());
        self.cancel_state = Some(err_code);
        if let Some(waker) = self.cancel_waker.take() {
            waker.wake();
        }
    }

    pub(super) fn is_cancelled(&self) -> bool {
        self.cancel_state.is_some()
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
        // 让space不再询问流是否被app层cancel
        if let Some(waker) = self.cancel_waker.take() {
            waker.wake();
        }
    }
}

/// 状态转换，ReaderSender => SendingSender
impl From<&mut ReadySender> for SendingSender {
    fn from(value: &mut ReadySender) -> Self {
        SendingSender {
            sndbuf: std::mem::take(&mut value.sndbuf),
            cancel_state: value.cancel_state.take(),
            flush_waker: value.flush_waker.take(),
            shutdown_waker: value.shutdown_waker.take(),
            cancel_waker: value.cancel_waker.take(),
            writable_waker: value.writable_waker.take(),
            max_data_size: value.max_data_size,
        }
    }
}

/// 状态转换，ReaderSender => DataSentSender
impl From<&mut ReadySender> for DataSentSender {
    fn from(value: &mut ReadySender) -> Self {
        DataSentSender {
            sndbuf: std::mem::take(&mut value.sndbuf),
            cancel_state: value.cancel_state.take(),
            flush_waker: value.flush_waker.take(),
            shutdown_waker: value.shutdown_waker.take(),
            cancel_waker: value.cancel_waker.take(),
            fin_state: FinState::None,
        }
    }
}

#[derive(Debug)]
pub struct SendingSender {
    sndbuf: SendBuf,
    cancel_state: Option<u64>,
    flush_waker: Option<Waker>,
    shutdown_waker: Option<Waker>,
    cancel_waker: Option<Waker>,
    writable_waker: Option<Waker>,
    max_data_size: u64,
}

type StreamData<'s> = (u64, bool, (&'s [u8], &'s [u8]), bool);

impl SendingSender {
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

    /// 传输层使用
    pub(super) fn poll_cancel(&mut self, cx: &mut Context<'_>) -> Poll<(u64, u64)> {
        if let Some(err_code) = self.cancel_state {
            Poll::Ready((self.sndbuf.len(), err_code))
        } else {
            self.cancel_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub(super) fn cancel(&mut self, err_code: u64) {
        assert!(self.cancel_state.is_none());
        self.cancel_state = Some(err_code);
        if let Some(waker) = self.cancel_waker.take() {
            waker.wake();
        }
    }

    pub(super) fn is_cancelled(&self) -> bool {
        self.cancel_state.is_some()
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
        // 让space不再询问流是否被app层cancel
        if let Some(waker) = self.cancel_waker.take() {
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
impl From<&mut SendingSender> for DataSentSender {
    fn from(value: &mut SendingSender) -> Self {
        DataSentSender {
            sndbuf: std::mem::take(&mut value.sndbuf),
            cancel_state: value.cancel_state.take(),
            flush_waker: value.flush_waker.take(),
            shutdown_waker: value.shutdown_waker.take(),
            cancel_waker: value.cancel_waker.take(),
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
pub struct DataSentSender {
    sndbuf: SendBuf,
    cancel_state: Option<u64>,
    flush_waker: Option<Waker>,
    shutdown_waker: Option<Waker>,
    cancel_waker: Option<Waker>,
    fin_state: FinState,
}

impl DataSentSender {
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

    pub(super) fn poll_cancel(&mut self, cx: &mut Context<'_>) -> Poll<(u64, u64)> {
        if let Some(err_code) = self.cancel_state {
            Poll::Ready((self.sndbuf.len(), err_code))
        } else {
            self.cancel_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub(super) fn cancel(&mut self, err_code: u64) {
        assert!(self.cancel_state.is_none());
        self.cancel_state = Some(err_code);
        if let Some(waker) = self.cancel_waker.take() {
            waker.wake();
        }
    }

    pub(super) fn is_cancelled(&self) -> bool {
        self.cancel_state.is_some()
    }

    pub(super) fn wake_all(&mut self) {
        if let Some(waker) = self.flush_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.shutdown_waker.take() {
            waker.wake();
        }
        // 让space不再询问流是否被app层cancel
        if let Some(waker) = self.cancel_waker.take() {
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
pub(super) enum Sender {
    Ready(ReadySender),
    Sending(SendingSender),
    DataSent(DataSentSender),
    ResetSent(StreamReset),
    DataRcvd,
    ResetRcvd(StreamReset),
}

impl Sender {
    pub fn with_wnd_size(wnd_size: u64) -> Self {
        Sender::Ready(ReadySender::with_wnd_size(wnd_size))
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
pub struct ArcSender {
    sender: Arc<Mutex<Result<Sender, Error>>>,
    sid: StreamId,
}

impl ArcSender {
    #[doc(hidden)]
    pub(crate) fn new(wnd_size: u64, sid: StreamId) -> Self {
        let sender = Arc::new(Mutex::new(Ok(Sender::with_wnd_size(wnd_size))));
        ArcSender { sender, sid }
    }

    pub(super) fn sender(&self) -> MutexGuard<Result<Sender, Error>> {
        self.sender.lock().unwrap()
    }

    pub(super) fn sid(&self) -> StreamId {
        self.sid
    }
}
