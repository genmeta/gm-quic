use crate::{recv::Reader, send::Writer};
use qbase::error::Error as QuicError;
use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
};

#[derive(Debug, Default)]
struct RawListener {
    // 对方主动创建的流
    bi_streams: VecDeque<(Reader, Writer)>,
    uni_streams: VecDeque<Reader>,
    bi_waker: Option<Waker>,
    uni_waker: Option<Waker>,
}

impl RawListener {
    fn push_bi_stream(&mut self, stream: (Reader, Writer)) {
        self.bi_streams.push_back(stream);
        if let Some(waker) = self.bi_waker.take() {
            waker.wake();
        }
    }

    fn push_recv_stream(&mut self, stream: Reader) {
        self.uni_streams.push_back(stream);
        if let Some(waker) = self.uni_waker.take() {
            waker.wake();
        }
    }

    fn poll_accept_bi_stream(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(Reader, Writer), QuicError>> {
        if let Some(stream) = self.bi_streams.pop_front() {
            Poll::Ready(Ok(stream))
        } else {
            self.bi_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    fn poll_accept_recv_stream(&mut self, cx: &mut Context<'_>) -> Poll<Result<Reader, QuicError>> {
        if let Some(stream) = self.uni_streams.pop_front() {
            Poll::Ready(Ok(stream))
        } else {
            self.uni_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

#[derive(Debug, Clone)]
pub struct ArcListener(Arc<Mutex<Result<RawListener, QuicError>>>);

impl Default for ArcListener {
    fn default() -> Self {
        ArcListener(Arc::new(Mutex::new(Ok(RawListener::default()))))
    }
}

impl ArcListener {
    pub(crate) fn guard(&self) -> Result<ListenerGuard, QuicError> {
        let guard = self.0.lock().unwrap();
        match guard.as_ref() {
            Ok(_) => Ok(ListenerGuard { inner: guard }),
            Err(e) => Err(e.clone()),
        }
    }

    pub fn accept_bi_stream(&self) -> AcceptBiStream {
        AcceptBiStream {
            inner: self.clone(),
        }
    }

    pub fn accept_uni_stream(&self) -> AcceptRecvStream {
        AcceptRecvStream {
            inner: self.clone(),
        }
    }

    pub fn poll_accept_bi_stream(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(Reader, Writer), QuicError>> {
        match self.0.lock().unwrap().as_mut() {
            Ok(set) => set.poll_accept_bi_stream(cx),
            Err(e) => Poll::Ready(Err(e.clone())),
        }
    }

    pub fn poll_accept_recv_stream(&self, cx: &mut Context<'_>) -> Poll<Result<Reader, QuicError>> {
        match self.0.lock().unwrap().as_mut() {
            Ok(set) => set.poll_accept_recv_stream(cx),
            Err(e) => Poll::Ready(Err(e.clone())),
        }
    }
}

pub(crate) struct ListenerGuard<'a> {
    inner: MutexGuard<'a, Result<RawListener, QuicError>>,
}

impl<'a> ListenerGuard<'a> {
    pub(crate) fn push_bi_stream(&mut self, stream: (Reader, Writer)) {
        match self.inner.as_mut() {
            Ok(set) => set.push_bi_stream(stream),
            Err(e) => unreachable!("listener is invalid: {e}"),
        }
    }

    pub(crate) fn push_uni_stream(&mut self, stream: Reader) {
        match self.inner.as_mut() {
            Ok(set) => set.push_recv_stream(stream),
            Err(e) => unreachable!("listener is invalid: {e}"),
        }
    }

    pub(crate) fn on_conn_error(&mut self, e: &QuicError) {
        match self.inner.as_mut() {
            Ok(set) => {
                if let Some(waker) = set.bi_waker.take() {
                    waker.wake();
                }
                if let Some(waker) = set.uni_waker.take() {
                    waker.wake();
                }
            }
            Err(e) => unreachable!("listener is invalid: {e}"),
        };
        *self.inner = Err(e.clone());
    }
}

#[derive(Debug, Clone)]
pub struct AcceptBiStream {
    inner: ArcListener,
}

impl Future for AcceptBiStream {
    type Output = Result<(Reader, Writer), QuicError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.poll_accept_bi_stream(cx)
    }
}

#[derive(Debug, Clone)]
pub struct AcceptRecvStream {
    inner: ArcListener,
}

impl Future for AcceptRecvStream {
    type Output = Result<Reader, QuicError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.poll_accept_recv_stream(cx)
    }
}
