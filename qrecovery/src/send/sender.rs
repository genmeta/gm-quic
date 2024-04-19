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
pub struct ReadySender {
    sndbuf: SendBuf,
    max_data_size: u64,
    writable_waker: Option<Waker>,
    flush_waker: Option<Waker>,
    shutdown_waker: Option<Waker>,
    cancel_waker: Option<Waker>,
}

impl ReadySender {
    pub fn with_buf_size(initial_max_stream_data: u64) -> ReadySender {
        ReadySender {
            sndbuf: SendBuf::with_capacity(initial_max_stream_data as usize),
            max_data_size: initial_max_stream_data,
            writable_waker: None,
            flush_waker: None,
            shutdown_waker: None,
            cancel_waker: None,
        }
    }

    /// 非阻塞写，如果没有多余的发送缓冲区，将返回WouldBlock错误。
    /// 但什么时候可写，是没通知的，只能不断去尝试写，直到写入成功。
    pub fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let range = self.sndbuf.range();
        if range.end < self.max_data_size {
            let n = std::cmp::min((self.max_data_size - range.end) as usize, buf.len());
            Ok(self.sndbuf.write(&buf[..n]))
        } else {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }

    pub fn poll_write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        assert!(self.writable_waker.is_none());
        let range = self.sndbuf.range();
        if range.end < self.max_data_size {
            let n = std::cmp::min((self.max_data_size - range.end) as usize, buf.len());
            Poll::Ready(Ok(self.sndbuf.write(&buf[..n])))
        } else {
            self.writable_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub fn poll_flush(&mut self, cx: &mut Context<'_>) {
        assert!(self.flush_waker.is_none());
        self.flush_waker = Some(cx.waker().clone());
    }

    pub fn poll_shutdown(&mut self, cx: &mut Context<'_>) {
        assert!(self.shutdown_waker.is_none());
        self.shutdown_waker = Some(cx.waker().clone());
    }

    pub fn is_shutdown(&self) -> bool {
        self.shutdown_waker.is_some()
    }

    pub fn begin(self) -> SendingSender {
        SendingSender {
            sndbuf: self.sndbuf,
            max_data_size: self.max_data_size,
            writable_waker: self.writable_waker,
            flush_waker: self.flush_waker,
            shutdown_waker: self.shutdown_waker,
            cancel_waker: self.cancel_waker,
        }
    }

    pub fn end(self) -> DataSentSender {
        DataSentSender {
            sndbuf: self.sndbuf,
            flush_waker: self.flush_waker,
            shutdown_waker: self.shutdown_waker,
            cancel_waker: self.cancel_waker,
        }
    }

    pub fn poll_cancel(&mut self, cx: &mut Context<'_>) {
        assert!(self.cancel_waker.is_none());
        self.cancel_waker = Some(cx.waker().clone());
    }

    pub fn cancel(self) {
        if let Some(waker) = self.cancel_waker {
            waker.wake();
        }
    }
}

pub struct SendingSender {
    sndbuf: SendBuf,
    max_data_size: u64,
    writable_waker: Option<Waker>,
    flush_waker: Option<Waker>,
    shutdown_waker: Option<Waker>,
    cancel_waker: Option<Waker>,
}

impl SendingSender {
    /// 非阻塞写，如果没有多余的发送缓冲区，将返回WouldBlock错误。
    /// 但什么时候可写，是没通知的，只能不断去尝试写，直到写入成功。
    pub fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let range = self.sndbuf.range();
        if range.end < self.max_data_size {
            let n = std::cmp::min((self.max_data_size - range.end) as usize, buf.len());
            Ok(self.sndbuf.write(&buf[..n]))
        } else {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }

    pub fn poll_write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        assert!(self.writable_waker.is_none());
        let range = self.sndbuf.range();
        if range.end < self.max_data_size {
            let n = std::cmp::min((self.max_data_size - range.end) as usize, buf.len());
            Poll::Ready(Ok(self.sndbuf.write(&buf[..n])))
        } else {
            self.writable_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub fn update_window(&mut self, max_data_size: u64) {
        assert!(max_data_size > self.max_data_size);
        self.max_data_size = max_data_size;
        if let Some(waker) = self.writable_waker.take() {
            waker.wake();
        }
    }

    pub fn pick_up(&mut self, max_len: usize) -> Option<(u64, &[u8])> {
        self.sndbuf.pick_up(max_len)
    }

    pub fn ack_recv(&mut self, range: &Range<u64>) {
        self.sndbuf.ack_recv(range);
        if self.sndbuf.is_all_recvd() {
            if let Some(waker) = self.flush_waker.take() {
                waker.wake();
            }
        }
    }

    pub fn may_loss(&mut self, range: &Range<u64>) {
        self.sndbuf.may_loss(range)
    }

    pub fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        assert!(self.flush_waker.is_none());
        if self.sndbuf.is_all_recvd() {
            Poll::Ready(Ok(()))
        } else {
            self.flush_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub fn end(self) -> DataSentSender {
        DataSentSender {
            sndbuf: self.sndbuf,
            flush_waker: self.flush_waker,
            shutdown_waker: self.shutdown_waker,
            cancel_waker: self.cancel_waker,
        }
    }

    pub fn poll_shutdown(&mut self, cx: &mut Context<'_>) {
        assert!(self.shutdown_waker.is_none());
        self.shutdown_waker = Some(cx.waker().clone());
    }

    pub fn poll_cancel(&mut self, cx: &mut Context<'_>) {
        assert!(self.cancel_waker.is_none());
        self.cancel_waker = Some(cx.waker().clone());
    }

    pub fn cancel(self) {
        if let Some(waker) = self.cancel_waker {
            waker.wake();
        }
    }

    pub fn stop(self) {
        if let Some(waker) = self.writable_waker {
            waker.wake();
        }
        if let Some(waker) = self.flush_waker {
            waker.wake();
        }
        if let Some(waker) = self.shutdown_waker {
            waker.wake();
        }
    }
}

pub struct DataSentSender {
    sndbuf: SendBuf,
    flush_waker: Option<Waker>,
    shutdown_waker: Option<Waker>,
    cancel_waker: Option<Waker>,
}

impl DataSentSender {
    pub fn pick_up(&mut self, max_len: usize) -> Option<(u64, &[u8])> {
        self.sndbuf.pick_up(max_len)
    }

    pub fn ack_recv(&mut self, range: &Range<u64>) {
        self.sndbuf.ack_recv(range);
        if self.sndbuf.is_all_recvd() {
            if let Some(waker) = self.flush_waker.take() {
                waker.wake();
            }
            if let Some(waker) = self.shutdown_waker.take() {
                waker.wake();
            }
        }
    }

    pub fn is_all_recvd(&self) -> bool {
        self.sndbuf.is_all_recvd()
    }

    pub fn may_loss(&mut self, range: &Range<u64>) {
        self.sndbuf.may_loss(range)
    }

    pub fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        assert!(self.flush_waker.is_none());
        if self.sndbuf.is_all_recvd() {
            Poll::Ready(Ok(()))
        } else {
            self.flush_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        assert!(self.shutdown_waker.is_none());
        if self.sndbuf.is_all_recvd() {
            Poll::Ready(Ok(()))
        } else {
            self.shutdown_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub fn poll_cancel(&mut self, cx: &mut Context<'_>) {
        assert!(self.cancel_waker.is_none());
        self.cancel_waker = Some(cx.waker().clone());
    }

    pub fn cancel(self) {
        if let Some(waker) = self.cancel_waker {
            waker.wake();
        }
    }

    pub fn stop(self) {
        if let Some(waker) = self.flush_waker {
            waker.wake();
        }
        if let Some(waker) = self.shutdown_waker {
            waker.wake();
        }
    }
}

#[derive(Default)]
pub enum Sender {
    Ready(ReadySender),
    Sending(SendingSender),
    DataSent(DataSentSender),
    ResetSent,
    #[default]
    DataRecvd,
    ResetRecvd,
}

impl Sender {
    pub fn with_buf_size(initial_max_stream_data: u64) -> Self {
        Sender::Ready(ReadySender::with_buf_size(initial_max_stream_data))
    }

    pub fn take(&mut self) -> Self {
        std::mem::take(self)
    }

    pub fn replace(&mut self, sender: Sender) {
        let _ = std::mem::replace(self, sender);
    }
}

/// Sender是典型的一体两用，对应用层而言是Writer，对传输控制层而言是Outgoing。
/// Writer/Outgoing分别有不同的接口，而且生命周期独立，应用层可以在close、reset后
/// 直接丢弃不管；然而Outgoing还有DataRecvd、ResetRecvd两个状态，需要等待对端确认。
/// 所以Writer/Outgoing内部共享同一个Sender。
pub type ArcSender = Arc<Mutex<Sender>>;

#[cfg(test)]
mod tests {

    #[test]
    fn it_works() {
        println!("sender::tests::it_works");
    }
}
