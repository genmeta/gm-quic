use std::{
    collections::VecDeque,
    future::Future,
    io,
    ops::DerefMut,
    pin::Pin,
    sync::Arc,
    task::{ready, Context, Poll, Waker},
};

use bytes::{BufMut, Bytes};
use qbase::{
    error::{Error, ErrorKind},
    frame::{BeFrame, DatagramFrame},
};
use tokio::sync::Mutex;

#[derive(Default, Debug)]
pub struct RawDatagramReader {
    local_max_size: usize,
    queue: VecDeque<Bytes>,
    waker: Option<Waker>,
}

impl RawDatagramReader {
    pub(crate) fn new(local_max_size: usize) -> Self {
        Self {
            local_max_size,
            queue: Default::default(),
            waker: Default::default(),
        }
    }
}

pub type ArcDatagramReader = Arc<Mutex<io::Result<RawDatagramReader>>>;

#[derive(Debug, Clone)]
pub struct DatagramReader(pub(super) ArcDatagramReader);

impl DatagramReader {
    pub(crate) fn recv_datagram(
        &self,
        frame: DatagramFrame,
        data: bytes::Bytes,
    ) -> Result<(), Error> {
        let reader = &mut self.0.blocking_lock();
        let inner = reader.deref_mut();
        let Ok(reader) = inner else { unreachable!() };
        if (frame.encoding_size() + data.len()) > reader.local_max_size {
            return Err(Error::new(
                ErrorKind::ProtocolViolation,
                frame.frame_type(),
                format!(
                    "datagram size {} exceeds the maximum size {}",
                    data.len(),
                    reader.local_max_size
                ),
            ));
        }
        reader.queue.push_back(data);
        if let Some(waker) = reader.waker.take() {
            waker.wake();
        }
        Ok(())
    }

    pub(super) fn on_conn_error(&self, error: &Error) {
        let reader = &mut self.0.blocking_lock();
        let inner = reader.deref_mut();
        if let Ok(reader) = inner {
            if let Some(waker) = reader.waker.take() {
                waker.wake();
            }
            *inner = Err(io::Error::new(io::ErrorKind::BrokenPipe, error.to_string()));
        }
    }

    pub async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let reader = self.0.clone();
        ReadIntoSlice { reader, buf }.await
    }

    pub async fn recv_buf(&mut self, buf: &mut impl BufMut) -> io::Result<usize> {
        let reader = self.0.clone();
        ReadInfoBuf { reader, buf }.await
    }
}

struct ReadIntoSlice<'a> {
    reader: ArcDatagramReader,
    buf: &'a mut [u8],
}

impl Future for ReadIntoSlice<'_> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let s = self.get_mut();
        let reader = s.reader.lock();
        let mut reader = ready!(Box::pin(reader).as_mut().poll(cx));
        match reader.deref_mut() {
            Ok(reader) => match reader.queue.pop_front() {
                Some(bytes) => {
                    let len = bytes.len().min(s.buf.len());
                    s.buf.copy_from_slice(&bytes[..len]);
                    Poll::Ready(Ok(len))
                }
                None => {
                    reader.waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            },
            Err(e) => Poll::Ready(Err(io::Error::new(e.kind(), e.to_string()))),
        }
    }
}

struct ReadInfoBuf<'a, B> {
    reader: ArcDatagramReader,
    buf: &'a mut B,
}

impl<B> Future for ReadInfoBuf<'_, B>
where
    B: BufMut,
{
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let s = self.get_mut();
        let reader = s.reader.lock();
        let mut reader = ready!(Box::pin(reader).as_mut().poll(cx));
        match reader.deref_mut() {
            Ok(reader) => match reader.queue.pop_front() {
                Some(bytes) => {
                    let len = bytes.len();
                    s.buf.put(bytes);
                    Poll::Ready(Ok(len))
                }
                None => {
                    reader.waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            },
            Err(e) => Poll::Ready(Err(io::Error::new(e.kind(), e.to_string()))),
        }
    }
}
