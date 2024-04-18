use std::{
    future::Future,
    ops::Range,
    pin::Pin,
    task::{Context, Poll},
};

use super::sndbuf::SendBuf;
use super::streamid::StreamId;

/// The "Ready" state represents a newly created stream that is able to accept data from the application.
/// Stream data might be buffered in this state in preparation for sending.
/// An implementation might choose to defer allocating a stream ID to a stream until it sends the first
/// STREAM frame and enters this state, which can allow for better stream prioritization.
pub struct ReadySender {
    inner: SendBuf,
}

impl ReadySender {
    pub fn with_window_size(wnd_size: usize) -> ReadySender {
        ReadySender {
            inner: SendBuf::with_capacity(wnd_size),
        }
    }

    pub fn write(&mut self, data: &[u8]) -> usize {
        self.inner.write(data)
    }

    pub fn cancel(self) -> ResetSentSender {
        ResetSentSender {}
    }

    pub fn assign_stream_id(self, id: StreamId) -> SendingSender {
        SendingSender {
            id,
            inner: self.inner,
        }
    }
}

pub struct SendingSender {
    id: StreamId,
    inner: SendBuf,
}

impl SendingSender {
    pub fn write(&mut self, data: &[u8]) -> usize {
        self.inner.write(data)
    }

    pub fn pick_up(&mut self, max_len: usize) -> Option<(u64, &[u8])> {
        self.inner.pick_up(max_len)
    }

    pub fn ack_recv(&mut self, range: &Range<u64>) {
        self.inner.ack_recv(range)
    }

    pub fn may_loss(&mut self, range: &Range<u64>) {
        self.inner.may_loss(range)
    }

    pub fn close(self) -> DataSentSender {
        DataSentSender {
            id: self.id,
            inner: self.inner,
        }
    }

    pub fn cancel(self) -> ResetSentSender {
        ResetSentSender {}
    }
}

pub struct DataSentSender {
    /// TODO: THINK: 是否需要id？可能真的没啥用
    #[allow(dead_code)]
    id: StreamId,
    inner: SendBuf,
}

impl DataSentSender {
    pub fn pick_up(&mut self, max_len: usize) -> Option<(u64, &[u8])> {
        self.inner.pick_up(max_len)
    }

    pub fn ack_recv(&mut self, range: &Range<u64>) {
        self.inner.ack_recv(range)
    }

    pub fn may_loss(&mut self, range: &Range<u64>) {
        self.inner.may_loss(range)
    }

    pub fn recv_all_acks(self) -> RecvAllAcks {
        RecvAllAcks { inner: self.inner }
    }

    pub fn cancel(self) -> ResetSentSender {
        ResetSentSender
    }
}

pub struct RecvAllAcks {
    inner: SendBuf,
}

impl Future for RecvAllAcks {
    type Output = DataRecvdSender;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        if self.inner.is_broken() {
            Poll::Ready(DataRecvdSender)
        } else {
            // TODO: cx.waker()注册在什么地方呢？
            Poll::Pending
        }
    }
}

pub struct ResetSentSender;

pub struct DataRecvdSender;

impl ResetSentSender {
    pub fn reset_recvd(self) -> ResetRecvdSender {
        ResetRecvdSender
    }
}

pub struct ResetRecvdSender;

pub enum Sender {
    Ready(ReadySender),
    Sending(SendingSender),
    DataSent(DataSentSender),
    ResetSent(ResetSentSender),
    DataRecvd(DataRecvdSender),
    ResetRecvd(ResetRecvdSender),
}

/// Sender是典型的一体两用，对应用层而言是Writer，对传输控制层而言是Outgoing。
/// Writer/Outgoing分别有不同的接口，而且生命周期独立，应用层可以在close、reset后
/// 直接丢弃不管；然而Outgoing还有DataRecvd、ResetRecvd两个状态，需要等待对端确认。
/// 所以Writer/Outgoing内部共享同一个Sender。
/// type Outgoing = Arc<Mutex<Sender>>;
/// type Writer = Arc<Mutex<Sender>>;

#[cfg(test)]
mod tests {

    #[test]
    fn it_works() {
        println!("sender::tests::it_works");
    }
}
