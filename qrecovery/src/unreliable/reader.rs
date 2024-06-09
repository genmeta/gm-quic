use super::queue::DatagramQueue;
use bytes::BufMut;
use qbase::error::Error;
use std::{
    future::Future,
    io,
    ops::DerefMut,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
};

#[derive(Default, Debug)]
pub struct RawDatagramReader {
    queue: DatagramQueue,
    waker: Option<Waker>,
}

pub type ArcDatagramReader = Arc<Mutex<io::Result<RawDatagramReader>>>;

#[derive(Debug, Clone)]
pub struct DatagramReader(pub(super) ArcDatagramReader);

impl DatagramReader {
    pub(crate) fn recv_datagram(&self, data: bytes::Bytes) {
        let reader = &mut self.0.lock().unwrap();
        let inner = reader.deref_mut();
        match inner {
            Ok(reader) => {
                reader.queue.write(data);
                if let Some(waker) = reader.waker.take() {
                    waker.wake();
                }
            }
            Err(_) => unreachable!(),
        }
    }

    pub(super) fn on_conn_error(&self, error: &Error) {
        let reader = &mut self.0.lock().unwrap();
        let inner = reader.deref_mut();
        if let Ok(reader) = inner {
            if let Some(waker) = reader.waker.take() {
                waker.wake();
            }
            *inner = Err(io::Error::new(io::ErrorKind::BrokenPipe, error.to_string()));
        }
    }

    pub async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let reader = self.0.lock().unwrap();
        RecvBytes { reader, buf }.await
    }

    pub async fn read_buf(&mut self, buf: &mut impl BufMut) -> io::Result<usize> {
        let reader = self.0.lock().unwrap();
        RecvBuf { reader, buf }.await
    }
}

struct RecvBytes<'a> {
    // 以此保证Future唯一，waker不会出现冲突
    reader: MutexGuard<'a, io::Result<RawDatagramReader>>,
    buf: &'a mut [u8],
}

impl Future for RecvBytes<'_> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let s = self.get_mut();
        let reader = s.reader.deref_mut();
        match reader {
            Ok(reader) => match reader.queue.read() {
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

struct RecvBuf<'a, B> {
    reader: MutexGuard<'a, io::Result<RawDatagramReader>>,
    buf: &'a mut B,
}

impl<B> Future for RecvBuf<'_, B>
where
    B: BufMut,
{
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let s = self.get_mut();
        let reader = s.reader.deref_mut();
        match reader {
            Ok(reader) => match reader.queue.read() {
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
