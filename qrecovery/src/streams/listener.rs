use crate::AppStream;
use qbase::error::Error;
use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

#[derive(Debug, Default)]
struct RawListener {
    // 对方主动创建的流
    streams: VecDeque<AppStream>,
    waker: Option<Waker>,
}

impl RawListener {
    fn push(&mut self, stream: AppStream) {
        self.streams.push_back(stream);
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }

    fn poll_accept(&mut self, cx: &mut Context<'_>) -> Poll<Result<AppStream, Error>> {
        if let Some(stream) = self.streams.pop_front() {
            Poll::Ready(Ok(stream))
        } else {
            self.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ArcListener(Arc<Mutex<RawListener>>);

impl ArcListener {
    pub(crate) fn push(&self, stream: AppStream) {
        self.0.lock().unwrap().push(stream);
    }

    pub fn accept(&self) -> Accept {
        Accept {
            inner: self.clone(),
        }
    }

    pub fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<Result<AppStream, Error>> {
        self.0.lock().unwrap().poll_accept(cx)
    }
}

#[derive(Debug, Clone)]
pub struct Accept {
    inner: ArcListener,
}

impl Future for Accept {
    type Output = Result<AppStream, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.poll_accept(cx)
    }
}
