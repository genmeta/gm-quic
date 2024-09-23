use std::{
    ops::Deref,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use bytes::BufMut;
use qbase::{
    frame::{io::WriteFrame, BeFrame},
    util::ArcAsyncDeque,
};

#[derive(Default, Clone)]
pub struct SendBuffer<T>(Arc<Mutex<Option<T>>>);

impl<T> SendBuffer<T> {
    pub fn write(&self, frame: T) {
        *self.0.lock().unwrap() = Some(frame);
    }
}

impl<T> SendBuffer<T>
where
    T: BeFrame,
    for<'a> &'a mut [u8]: WriteFrame<T>,
{
    pub fn try_read(&self, mut buf: &mut [u8]) -> usize {
        let mut guard = self.0.lock().unwrap();
        if let Some(frame) = guard.deref() {
            let size = frame.encoding_size();
            if buf.remaining_mut() >= size {
                buf.put_frame(frame);
                *guard = None;
                return size;
            }
        }
        0
    }
}

#[derive(Clone, Debug, Default)]
pub struct RecvBuffer<T>(ArcAsyncDeque<T>);

impl<T> RecvBuffer<T> {
    pub fn new() -> Self {
        Self(ArcAsyncDeque::new())
    }

    pub fn write(&self, value: T) {
        self.0.push_back(value);
    }

    /// Waiting for a value to be received.
    /// # Example
    /// ```rust
    /// use qconnection::path::RecvBuffer;
    /// # async fn demo() {
    /// let rcv_buf = RecvBuffer::default();
    ///
    /// tokio::spawn({
    ///     let rcv_buf = rcv_buf.clone();
    ///     async move {
    ///         let value = rcv_buf.receive().await;
    ///          assert_eq!(value, Some(42u32));
    ///     }
    /// });
    ///
    /// rcv_buf.write(42u32);
    /// # }
    /// ```
    pub fn receive(&self) -> Self {
        Self(self.0.clone())
    }

    pub fn dismiss(&self) {
        self.0.close();
    }
}

impl<T> std::future::Future for RecvBuffer<T> {
    type Output = Option<T>;

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.poll_pop(cx)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Constraints {
    // 信用额度，源于抗放大攻击；当验证通过后，将不再设限，表现为usize::MAX
    // 作用于所有数据，包括包头
    credit_limit: usize,
    // 发送配额，源于拥塞控制算法，随着时间的流逝，得到的本次Burst应当发送的数据量
    // 作用于ack-eliciting数据包，除非该包只发送Padding/Ack/Ccf帧
    send_quota: usize,
}

impl Constraints {
    pub fn new(credit_limit: usize, send_quota: usize) -> Self {
        Self {
            credit_limit,
            send_quota,
        }
    }

    /// 结束条件
    /// - 抗放大攻击额度用完
    /// - 抗放大攻击额度没用完，但发送配额用完
    ///  + 此时，仍可以仅发送Ack帧
    pub fn is_available(&self) -> bool {
        self.credit_limit > 0
    }

    pub fn constrain<'b>(&self, buf: &'b mut [u8]) -> &'b mut [u8] {
        let min_len = buf
            .remaining_mut()
            .min(self.credit_limit)
            .min(self.send_quota);
        &mut buf[..min_len]
    }

    pub fn commit(&mut self, len: usize, is_just_ack: bool) {
        self.credit_limit = self.credit_limit.saturating_sub(len);
        if !is_just_ack {
            self.send_quota = self.send_quota.saturating_sub(len);
        }
    }
}

pub trait ApplyConstraints {
    fn apply(self, constraints: &Constraints) -> Self;
}

impl ApplyConstraints for &mut [u8] {
    fn apply(self, constraints: &Constraints) -> Self {
        constraints.constrain(self)
    }
}
