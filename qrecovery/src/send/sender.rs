use super::sndbuf::SendBuf;
use std::{
    io,
    ops::Range,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

/// The "Ready" state represents a newly created stream that is able to accept data from the application.
/// Stream data might be buffered in this state in preparation for sending.
/// An implementation might choose to defer allocating a stream ID to a stream until it sends the first
/// STREAM frame and enters this state, which can allow for better stream prioritization.
#[derive(Debug)]
pub struct ReadySender {
    sndbuf: SendBuf,
    max_data_size: u64,
    is_cancelled: bool,
    writable_waker: Option<Waker>,
    flush_waker: Option<Waker>,
    shutdown_waker: Option<Waker>,
    cancel_waker: Option<Waker>,
}

impl ReadySender {
    pub(super) fn with_buf_size(initial_max_stream_data: u64) -> ReadySender {
        ReadySender {
            sndbuf: SendBuf::with_capacity(initial_max_stream_data as usize),
            max_data_size: initial_max_stream_data,
            is_cancelled: false,
            writable_waker: None,
            flush_waker: None,
            shutdown_waker: None,
            cancel_waker: None,
        }
    }

    /// 非阻塞写，如果没有多余的发送缓冲区，将返回WouldBlock错误。
    /// 但什么时候可写，是没通知的，只能不断去尝试写，直到写入成功。
    /// 仅供展示学习
    #[allow(dead_code)]
    pub(self) fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.is_cancelled {
            Err(io::ErrorKind::BrokenPipe.into())
        } else {
            let range = self.sndbuf.range();
            if range.end < self.max_data_size {
                let n = std::cmp::min((self.max_data_size - range.end) as usize, buf.len());
                Ok(self.sndbuf.write(&buf[..n]))
            } else {
                Err(io::ErrorKind::WouldBlock.into())
            }
        }
    }

    pub(super) fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        assert!(self.writable_waker.is_none());
        if self.is_cancelled {
            Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
        } else {
            let range = self.sndbuf.range();
            if range.end < self.max_data_size {
                let n = std::cmp::min((self.max_data_size - range.end) as usize, buf.len());
                Poll::Ready(Ok(self.sndbuf.write(&buf[..n])))
            } else {
                self.writable_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    pub(super) fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        assert!(self.flush_waker.is_none());
        if self.is_cancelled {
            Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
        } else {
            self.flush_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub(super) fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        assert!(self.shutdown_waker.is_none());
        if self.is_cancelled {
            Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
        } else {
            self.shutdown_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub(super) fn is_shutdown(&self) -> bool {
        self.shutdown_waker.is_some()
    }

    pub(super) fn begin_sending(self) -> SendingSender {
        SendingSender {
            sndbuf: self.sndbuf,
            max_data_size: self.max_data_size,
            is_cancelled: self.is_cancelled,
            writable_waker: self.writable_waker,
            flush_waker: self.flush_waker,
            shutdown_waker: self.shutdown_waker,
            cancel_waker: self.cancel_waker,
        }
    }

    pub(super) fn end(self) -> DataSentSender {
        DataSentSender {
            sndbuf: self.sndbuf,
            is_cancelled: self.is_cancelled,
            flush_waker: self.flush_waker,
            shutdown_waker: self.shutdown_waker,
            cancel_waker: self.cancel_waker,
        }
    }

    pub(super) fn poll_cancel(&mut self, cx: &mut Context<'_>) -> Poll<u64> {
        assert!(self.cancel_waker.is_none());
        if self.is_cancelled {
            Poll::Ready(self.sndbuf.len())
        } else {
            self.cancel_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub(super) fn cancel(&mut self) {
        // 应用层多次cancel会被忽略
        if !self.is_cancelled {
            self.is_cancelled = true;
            if let Some(waker) = self.cancel_waker.take() {
                waker.wake();
            }
        }
    }
}

#[derive(Debug)]
pub struct SendingSender {
    sndbuf: SendBuf,
    max_data_size: u64,
    is_cancelled: bool,
    writable_waker: Option<Waker>,
    flush_waker: Option<Waker>,
    shutdown_waker: Option<Waker>,
    cancel_waker: Option<Waker>,
}

impl SendingSender {
    pub(super) fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        assert!(self.shutdown_waker.is_none());
        assert!(self.writable_waker.is_none());
        if self.is_cancelled {
            Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
        } else {
            let range = self.sndbuf.range();
            if range.end < self.max_data_size {
                let n = std::cmp::min((self.max_data_size - range.end) as usize, buf.len());
                Poll::Ready(Ok(self.sndbuf.write(&buf[..n])))
            } else {
                self.writable_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    pub(super) fn update_window(&mut self, max_data_size: u64) {
        assert!(max_data_size > self.max_data_size);
        self.max_data_size = max_data_size;
        if let Some(waker) = self.writable_waker.take() {
            waker.wake();
        }
    }

    pub(super) fn pick_up<F>(&mut self, estimate_capacity: F) -> Option<(u64, &[u8], bool)>
    where
        F: Fn(u64) -> Option<usize>,
    {
        if self.is_cancelled {
            return None;
        }
        self.sndbuf
            .pick_up(estimate_capacity)
            .map(|(offset, data)| (offset, data, false))
    }

    pub(super) fn confirm_rcvd(&mut self, range: &Range<u64>) {
        self.sndbuf.confirm_rcvd(range);
        if self.sndbuf.is_all_rcvd() {
            if let Some(waker) = self.flush_waker.take() {
                waker.wake();
            }
        }
    }

    pub(super) fn may_loss(&mut self, range: &Range<u64>) {
        self.sndbuf.may_loss(range)
    }

    pub(super) fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        assert!(self.flush_waker.is_none());
        if self.is_cancelled {
            Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
        } else if self.sndbuf.is_all_rcvd() {
            Poll::Ready(Ok(()))
        } else {
            self.flush_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub(super) fn end(self) -> DataSentSender {
        DataSentSender {
            sndbuf: self.sndbuf,
            is_cancelled: self.is_cancelled,
            flush_waker: self.flush_waker,
            shutdown_waker: self.shutdown_waker,
            cancel_waker: self.cancel_waker,
        }
    }

    pub(super) fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        assert!(self.shutdown_waker.is_none());
        if self.is_cancelled {
            Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
        } else if self.sndbuf.is_all_rcvd() {
            // 都已经关闭了，不再写数据数据了，如果所有数据都已发送完，那就是已关闭了
            Poll::Ready(Ok(()))
        } else {
            self.shutdown_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub(super) fn poll_cancel(&mut self, cx: &mut Context<'_>) -> Poll<u64> {
        assert!(self.cancel_waker.is_none());
        if self.is_cancelled {
            Poll::Ready(self.sndbuf.len())
        } else {
            self.cancel_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub(super) fn cancel(&mut self) {
        if !self.is_cancelled {
            self.is_cancelled = true;
            if let Some(waker) = self.cancel_waker.take() {
                waker.wake();
            }
        }
    }

    pub(super) fn stop(self) -> u64 {
        if let Some(waker) = self.writable_waker {
            waker.wake();
        }
        if let Some(waker) = self.flush_waker {
            waker.wake();
        }
        if let Some(waker) = self.shutdown_waker {
            waker.wake();
        }
        // 让stream controller不再询问流是否被app层cancel
        if let Some(waker) = self.cancel_waker {
            waker.wake();
        }
        // Actually, these remaining data is not acked and will not be acked
        self.sndbuf.len()
    }
}

#[derive(Debug)]
pub struct DataSentSender {
    sndbuf: SendBuf,
    is_cancelled: bool,
    flush_waker: Option<Waker>,
    shutdown_waker: Option<Waker>,
    cancel_waker: Option<Waker>,
}

impl DataSentSender {
    pub(super) fn pick_up<F>(&mut self, estimate_capacity: F) -> Option<(u64, &[u8], bool)>
    where
        F: Fn(u64) -> Option<usize>,
    {
        if self.is_cancelled {
            return None;
        }

        let final_size = self.sndbuf.len();
        self.sndbuf
            .pick_up(estimate_capacity)
            .map(|(offset, data)| {
                let is_eos = offset + data.len() as u64 == final_size;
                (offset, data, is_eos)
            })
    }

    pub(super) fn confirm_rcvd(&mut self, range: &Range<u64>) {
        self.sndbuf.confirm_rcvd(range);
        if self.sndbuf.is_all_rcvd() {
            if let Some(waker) = self.flush_waker.take() {
                waker.wake();
            }
            if let Some(waker) = self.shutdown_waker.take() {
                waker.wake();
            }
        }
    }

    pub(super) fn is_all_rcvd(&self) -> bool {
        self.sndbuf.is_all_rcvd()
    }

    pub(super) fn may_loss(&mut self, range: &Range<u64>) {
        self.sndbuf.may_loss(range)
    }

    pub(super) fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        assert!(self.flush_waker.is_none());
        if self.is_cancelled {
            Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
        } else if self.sndbuf.is_all_rcvd() {
            Poll::Ready(Ok(()))
        } else {
            self.flush_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub(super) fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        assert!(self.shutdown_waker.is_none());
        if self.is_cancelled {
            Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
        } else if self.is_all_rcvd() {
            Poll::Ready(Ok(()))
        } else {
            self.shutdown_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub(super) fn poll_cancel(&mut self, cx: &mut Context<'_>) -> Poll<u64> {
        assert!(self.cancel_waker.is_none());
        if self.is_cancelled {
            Poll::Ready(self.sndbuf.len())
        } else {
            self.cancel_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub(super) fn cancel(&mut self) {
        if !self.is_cancelled {
            self.is_cancelled = true;
            if let Some(waker) = self.cancel_waker.take() {
                waker.wake();
            }
        }
    }

    pub(super) fn stop(self) -> u64 {
        if let Some(waker) = self.flush_waker {
            waker.wake();
        }
        if let Some(waker) = self.shutdown_waker {
            waker.wake();
        }
        // 让stream controller不再询问流是否被app层cancel
        if let Some(waker) = self.cancel_waker {
            waker.wake();
        }
        // Actually, these remaining data is not acked and will not be acked
        self.sndbuf.len()
    }
}

#[derive(Default, Debug)]
pub enum Sender {
    Ready(ReadySender),
    Sending(SendingSender),
    DataSent(DataSentSender),
    ResetSent(u64),
    #[default]
    DataRecvd,
    ResetRecvd,
}

impl Sender {
    pub fn with_buf_size(initial_max_stream_data: u64) -> Self {
        Sender::Ready(ReadySender::with_buf_size(initial_max_stream_data))
    }

    pub(super) fn take(&mut self) -> Self {
        std::mem::take(self)
    }

    pub(super) fn replace(&mut self, sender: Sender) {
        let _ = std::mem::replace(self, sender);
    }
}

/// Sender是典型的一体两用，对应用层而言是Writer，对传输控制层而言是Outgoing。
/// Writer/Outgoing分别有不同的接口，而且生命周期独立，应用层可以在close、reset后
/// 直接丢弃不管；然而Outgoing还有DataRecvd、ResetRecvd两个状态，需要等待对端确认。
/// 所以Writer/Outgoing内部共享同一个Sender。
pub type ArcSender = Arc<Mutex<io::Result<Sender>>>;

#[cfg(test)]
mod tests {

    #[test]
    fn it_works() {
        println!("sender::tests::it_works");
    }
}
