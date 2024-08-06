use std::{
    future::Future,
    ops::{Deref, DerefMut},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use bytes::BufMut;
use qbase::{
    frame::{io::WriteFrame, BeFrame},
    util::Constraints,
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
    pub fn read(&self, constraints: &mut Constraints, mut buf: &mut [u8]) -> usize {
        let mut guard = self.0.lock().unwrap();
        if let Some(frame) = guard.deref() {
            let size = frame.encoding_size();
            if constraints.available() >= size && buf.remaining_mut() >= size {
                buf.put_frame(frame);
                constraints.post_write(size);
                *guard = None;
                return size;
            }
        }
        0
    }
}

#[derive(Debug, Default)]
enum RecvState<T> {
    #[default]
    None,
    Pending(Waker),
    Rcvd(T),
    Invalid,
}

#[derive(Clone, Debug, Default)]
pub struct RecvBuffer<T>(Arc<Mutex<RecvState<T>>>);

impl<T> RecvBuffer<T> {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(RecvState::None)))
    }

    pub fn write(&self, value: T) {
        let mut guard = self.0.lock().unwrap();
        match guard.deref() {
            RecvState::None => *guard = RecvState::Rcvd(value),
            RecvState::Pending(waker) => {
                waker.wake_by_ref();
                *guard = RecvState::Rcvd(value);
            }
            RecvState::Rcvd(_) => {
                *guard = RecvState::Rcvd(value);
            }
            RecvState::Invalid => {}
        }
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
        let mut guard = self.0.lock().unwrap();
        if let RecvState::Pending(waker) = guard.deref() {
            waker.wake_by_ref();
        }
        *guard = RecvState::Invalid;
    }
}

impl<T> Future for RecvBuffer<T> {
    type Output = Option<T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut guard = self.0.lock().unwrap();
        match std::mem::take(guard.deref_mut()) {
            RecvState::None | RecvState::Pending(_) => {
                *guard = RecvState::Pending(cx.waker().clone());
                Poll::Pending
            }
            RecvState::Rcvd(value) => {
                *guard = RecvState::None;
                Poll::Ready(Some(value))
            }
            RecvState::Invalid => {
                *guard = RecvState::Invalid;
                Poll::Ready(None)
            }
        }
    }
}
