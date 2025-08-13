use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use bytes::BufMut;
use futures::StreamExt;
use qbase::{
    frame::PingFrame,
    net::tx::{ArcSendWaker, Signals},
    packet::Package,
    time::ArcDeferIdleTimer,
    util::ArcAsyncDeque,
};
use tokio::time::Instant;

#[derive(Debug)]
struct Heartbeat {
    defer_idle_timer: ArcDeferIdleTimer,
    triggered_heartbeat: bool,
    last_heartbeat: Option<Instant>,
    interval: Duration,
}

impl Heartbeat {
    fn new(defer_idle_timer: ArcDeferIdleTimer, interval: Duration) -> Self {
        Self {
            defer_idle_timer,
            triggered_heartbeat: false,
            last_heartbeat: None,
            interval,
        }
    }

    fn need_trigger(&mut self) -> bool {
        if self.triggered_heartbeat {
            return false;
        }
        let idle_too_long = self.defer_idle_timer.is_idle_lasted_for(self.interval);
        let is_defer_idle_timeout_run_out = self.defer_idle_timer.is_expired();
        if !idle_too_long || is_defer_idle_timeout_run_out {
            self.triggered_heartbeat = false;
            return false;
        }

        // 如果self.last_heartbeat为None，或者已经超过了interval，则需要发送心跳包
        if self
            .last_heartbeat
            .map_or(true, |last| last.elapsed() >= self.interval)
        {
            self.triggered_heartbeat = true;
            return true;
        }

        false
    }

    fn try_load_heartbeat_into<P: ?Sized>(&mut self, packet: &mut P) -> Result<(), Signals>
    where
        PingFrame: Package<P>,
    {
        if !self.triggered_heartbeat {
            return Err(Signals::TRANSPORT);
        }
        PingFrame.dump(packet)?;
        self.last_heartbeat = Some(Instant::now());
        self.triggered_heartbeat = false;
        Ok(())
    }

    fn on_effective_communicated(&mut self) {
        self.defer_idle_timer.renew_on_effective_communicated();
        self.triggered_heartbeat = false;
    }
}

#[derive(Debug, Clone)]
pub struct ArcHeartbeat(Arc<Mutex<Heartbeat>>);

impl ArcHeartbeat {
    pub fn new(defer_idle_timer: ArcDeferIdleTimer, interval: Duration) -> Self {
        Self(Arc::new(Mutex::new(Heartbeat::new(
            defer_idle_timer,
            interval,
        ))))
    }

    pub fn need_trigger(&self) -> bool {
        self.0.lock().unwrap().need_trigger()
    }

    fn try_load_heartbeat_into<P: ?Sized>(&self, packet: &mut P) -> Result<(), Signals>
    where
        PingFrame: Package<P>,
    {
        self.0.lock().unwrap().try_load_heartbeat_into(packet)
    }

    pub fn renew_on_effective_communicated(&self) {
        self.0.lock().unwrap().on_effective_communicated();
    }
}

impl<P: ?Sized> Package<P> for &ArcHeartbeat
where
    PingFrame: Package<P>,
{
    #[inline]
    fn dump(&mut self, packet: &mut P) -> Result<(), Signals> {
        self.try_load_heartbeat_into(packet)
    }
}

/// A buffer that contains a single frame to be sent.
///
/// This struct impl [`Default`], and the `new` method is not provided.
pub struct SendBuffer<T> {
    item: Mutex<Option<T>>,
    tx_waker: ArcSendWaker,
}

impl<T> SendBuffer<T> {
    pub fn new(tx_waker: ArcSendWaker) -> Self {
        Self {
            item: Default::default(),
            tx_waker,
        }
    }

    /// Write a frame to the buffer.
    ///
    /// [`SendBuffer`] can only buffer one frame at a time. If you write a new frame to the buffer before the previous
    /// frame is sent, the previous frame will be overwritten.
    pub fn write(&self, frame: T) {
        self.tx_waker.wake_by(Signals::TRANSPORT);
        *self.item.lock().unwrap() = Some(frame);
    }
}

impl<F> SendBuffer<F> {
    /// Try load the frame to be sent into the `packet`.
    pub fn try_load_frames_into<P: ?Sized>(&self, packet: &mut P) -> Result<(), Signals>
    where
        for<'a> &'a F: Package<P>,
    {
        let mut guard = self.item.lock().unwrap();
        match guard.as_ref() {
            Some(mut frame) => {
                frame.dump(packet)?;
                guard.take().unwrap();
                Ok(())
            }
            None => Err(Signals::TRANSPORT),
        }
    }
}

impl<F, P: ?Sized> Package<P> for &SendBuffer<F>
where
    for<'a> &'a F: Package<P>,
{
    #[inline]
    fn dump(&mut self, into: &mut P) -> Result<(), Signals> {
        self.try_load_frames_into(into)
    }
}

/// A buffer to cache received frames.
///
///
/// [`Stream`] is implemented for this struct, you can use it as a stream to receive frames.
///
/// You can also use the [`RecvBuffer::receive`] method to wait for a frame to be received.
///
/// # Example
/// ```rust
/// use qconnection::path::RecvBuffer;
/// use futures::StreamExt;
/// # async fn demo() {
/// let rcv_buf = RecvBuffer::default();
///
/// tokio::spawn({
///     let rcv_buf = rcv_buf.clone();
///     async move {
///         let value = rcv_buf.receive().await;
///         assert_eq!(value, Some(42u32));
///     }
/// });
///
/// rcv_buf.write(42u32);
/// # }
/// ```
///
/// [`Stream`]: futures::Stream
/// [`Future`]: core::future::Future
#[derive(Clone, Debug, Default)]
pub struct RecvBuffer<T>(ArcAsyncDeque<T>);

impl<T> RecvBuffer<T> {
    /// Create a new empty [`RecvBuffer`].
    pub fn new() -> Self {
        Self(ArcAsyncDeque::with_capacity(2))
    }

    /// Write a frame to the buffer.
    pub fn write(&self, value: T) {
        self.0.push_back(value);
    }

    /// Waiting for a frame to be received.
    pub async fn receive(&self) -> Option<T> {
        let mut this = self;
        this.next().await
    }

    /// Dismiss the buffer
    ///
    /// Append received frames will be Ignored, existing frames will be dropped, the future will return `None`.
    pub fn dismiss(&self) {
        self.0.close();
    }
}

impl<T> futures::Stream for RecvBuffer<T> {
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.poll_pop(cx)
    }
}

impl<T> futures::Stream for &RecvBuffer<T> {
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.poll_pop(cx)
    }
}

/// The constraints for sending data, appllied to the data buffer.
#[derive(Debug, Clone, Copy)]
pub struct Constraints {
    /// Credit limit which is from anti-amplification attack limit, appllied to all data, including the packet header.
    ///
    /// When the verification is passed, the limit will be removed, and the value is `usize::MAX`.
    // 信用额度，源于抗放大攻击；当验证通过后，将不再设限，表现为usize::MAX
    // 作用于所有数据，包括包头
    credit_limit: usize,
    /// Send quota, which is from the congestion control algorithm. As time goes by, the amount of data that should be
    /// sent.
    ///
    /// It is applied to ack-eliciting data packets, unless the packet only sends Padding/Ack/Ccf frames.
    // 发送配额，源于拥塞控制算法，随着时间的流逝，得到的本次Burst应当发送的数据量
    // 作用于ack-eliciting数据包，除非该包只发送Padding/Ack/Ccf帧
    send_quota: usize,
}

impl Constraints {
    /// Create a new [`Constraints`] with the given credit limit and send quota.
    pub fn new(credit_limit: usize, send_quota: usize) -> Self {
        Self {
            credit_limit,
            send_quota,
        }
    }

    /// Return whether the constraints are available(More frames can be send).
    ///
    /// The conditions for ending is the credit limit is used up. Even if the send quota is not used up, packets that
    /// only contain Padding/Ack/Ccf can still be sent.
    ///
    // 结束条件
    // - 抗放大攻击额度用完
    // - 抗放大攻击额度没用完，但发送配额用完
    //  + 此时，仍可以仅发送Ack帧
    pub fn is_available(&self) -> bool {
        self.credit_limit > 0
    }

    /// Constrain the buffer, make it smaller than the limit and quota.
    pub fn constrain<'b>(&self, buf: &'b mut [u8]) -> &'b mut [u8] {
        let min_len = buf
            .remaining_mut()
            .min(self.credit_limit)
            .min(self.send_quota);
        &mut buf[..min_len]
    }

    pub fn available(&self) -> usize {
        self.credit_limit.min(self.send_quota)
    }

    /// Commit consumption of credit limit and send quota.
    ///
    /// The `len` is how much data was written to the constrained buffer, `is_just_ack` instruct whether the send quota
    /// should be consume.
    ///
    /// See [section-12.4-14.4.1](https//rfc-editor.org/rfc/rfc9000.html#section-12.4-14.4.1)
    /// and [table 3](https//rfc-editor.org/rfc/rfc9000.html#table-3)
    /// of [RFC9000](https//rfc-editor.org/rfc/rfc9000.html) for more details.
    pub fn commit(&mut self, len: usize, in_flight: bool) {
        self.credit_limit = self.credit_limit.saturating_sub(len);
        if in_flight {
            self.send_quota = self.send_quota.saturating_sub(len);
        }
    }
}

/// The struct that can be constrained by the [`Constraints`], usually a buffer.
pub trait ApplyConstraints {
    /// Apply the [`Constraints`] on the struct.
    fn apply(self, constraints: &Constraints) -> Self;
}

impl ApplyConstraints for &mut [u8] {
    fn apply(self, constraints: &Constraints) -> Self {
        constraints.constrain(self)
    }
}
