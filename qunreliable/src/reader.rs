use std::{
    collections::VecDeque,
    future::Future,
    io,
    ops::DerefMut,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use bytes::{BufMut, Bytes};
use qbase::{
    error::{Error, ErrorKind},
    frame::{BeFrame, DatagramFrame},
};

#[derive(Default, Debug)]
pub struct RawDatagramReader {
    local_max_size: usize,
    queue: VecDeque<Bytes>,
    wakers: VecDeque<Waker>,
}

impl RawDatagramReader {
    pub(crate) fn new(local_max_size: usize) -> Self {
        Self {
            local_max_size,
            queue: Default::default(),
            wakers: Default::default(),
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
        let reader = &mut self.0.lock().unwrap();
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
        if let Some(waker) = reader.wakers.pop_front() {
            waker.wake();
        }

        Ok(())
    }

    pub(super) fn on_conn_error(&self, error: &Error) {
        let reader = &mut self.0.lock().unwrap();
        let inner = reader.deref_mut();
        if let Ok(reader) = inner {
            reader.wakers.drain(..).for_each(|waker| waker.wake());
            *inner = Err(io::Error::new(io::ErrorKind::BrokenPipe, error.to_string()));
        }
    }

    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let reader = self.0.clone();
        ReadIntoSlice { reader, buf }.await
    }

    pub async fn recv_buf(&self, buf: &mut impl BufMut) -> io::Result<usize> {
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

        let mut reader = s.reader.lock().unwrap();
        match reader.deref_mut() {
            Ok(reader) => match reader.queue.pop_front() {
                Some(bytes) => {
                    let len = bytes.len().min(s.buf.len());
                    s.buf[..len].copy_from_slice(&bytes[..len]);
                    Poll::Ready(Ok(len))
                }
                None => {
                    reader.wakers.push_back(cx.waker().clone());
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
        let mut reader = s.reader.lock().unwrap();
        match reader.deref_mut() {
            Ok(reader) => match reader.queue.pop_front() {
                Some(bytes) => {
                    let len = bytes.len();
                    s.buf.put(bytes);
                    Poll::Ready(Ok(len))
                }
                None => {
                    reader.wakers.push_back(cx.waker().clone());
                    Poll::Pending
                }
            },
            Err(e) => Poll::Ready(Err(io::Error::new(e.kind(), e.to_string()))),
        }
    }
}

#[cfg(test)]
mod tests {
    use qbase::frame::FrameType;

    use super::*;

    #[tokio::test]
    async fn test_datagram_reader_recv_buf() {
        let reader = Arc::new(Mutex::new(Ok(RawDatagramReader::new(1024))));

        let reader = DatagramReader(reader);

        let recv = tokio::spawn({
            let reader = reader.clone();
            async move {
                let n = reader.recv(&mut [0u8; 1024]).await.unwrap();
                assert_eq!(n, 11);
            }
        });

        reader
            .recv_datagram(DatagramFrame::new(None), Bytes::from_static(b"hello world"))
            .unwrap();

        recv.await.unwrap();
    }

    #[tokio::test]
    async fn test_datagram_reader_on_conn_error() {
        let reader = Arc::new(Mutex::new(Ok(RawDatagramReader::new(1024))));
        let reader = DatagramReader(reader);
        let error = Error::new(
            ErrorKind::ProtocolViolation,
            FrameType::Datagram(0),
            "protocol violation",
        );
        reader.on_conn_error(&error);

        let mut buf = [0u8; 1024];
        // let n = tokio::join!(blocking, reader.recv(&mut buf)).1.unwrap_err();
        let n = reader.recv(&mut buf).await.unwrap_err();
        assert_eq!(n.kind(), io::ErrorKind::BrokenPipe);
    }
}
