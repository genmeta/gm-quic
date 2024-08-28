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

/// The unique [`RawDatagramReader`] struct represents a reader for receiving datagrams frame from a connection.
///
/// the Application can read the received datagrams from the internal queue by calling the [`DatagramReader::recv`] method.
#[derive(Default, Debug)]
pub(crate) struct RawDatagramReader {
    /// the maximum size of the datagram that can be received.
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

pub(crate) type ArcDatagramReader = Arc<Mutex<io::Result<RawDatagramReader>>>;
/// The shared [`DatagramReader`] struct represents a reader for receiving datagrams frame from a connection.
///
/// the Application can read the received datagrams from the internal queue by calling the [`DatagramReader::recv`] method.
#[derive(Debug)]
pub struct DatagramReader(pub(super) ArcDatagramReader);

impl DatagramReader {
    /// Receives a datagram and push it into internal queue for Application to read.
    ///
    /// # Arguments
    ///
    /// * `frame` - The datagram frame.
    /// * `data` - The data contained in the datagram frame.
    ///
    /// # Returns
    ///
    /// Return [`Ok`] if the datagram is successfully received and processed.
    /// Return an [`Err`] if there is a protocol violation(the datagram size exceeds the maximum size).
    pub(crate) fn recv_datagram(
        &self,
        frame: &DatagramFrame,
        data: bytes::Bytes,
    ) -> Result<(), Error> {
        let reader = &mut self.0.lock().unwrap();
        let inner = reader.deref_mut();
        let Ok(reader) = inner else {
            return Ok(());
        };
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

    /// Handles a connection error.
    ///
    /// # Arguments
    ///
    /// * `error` - The error that occurred.
    ///
    /// # Note
    ///
    /// This method will wake up all the wakers that are waiting for the data to be read.
    ///
    /// if the connection is already closed, the new error will be ignored.
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

    /// Read the received data into a mutable slice.
    ///
    /// ``` rust, ignore
    /// pub async fn recv(&self, buf: & mut [u8]) -> io::Result<usize>
    /// ```
    ///
    /// # Arguments
    ///
    /// * `buf` - The mutable slice to receive the data into.
    ///
    /// # Returns
    ///
    /// Return a future that resolves to the number of bytes read.
    ///
    /// Return [`Err`] when the connection is closing or already closed
    ///
    /// # Note
    ///
    /// if the buffer is not large enough to hold the received data, the remaining data will be discarded.
    pub fn recv<'b>(&self, buf: &'b mut [u8]) -> ReadIntoSlice<'b> {
        let reader = self.0.clone();
        ReadIntoSlice { reader, buf }
    }

    /// Read the received data into a mutable buffer.
    ///
    /// ``` rust, ignore
    /// pub async fn recv_buf(&self, buf: & mut [u8]) -> io::Result<usize>
    /// ```
    ///
    /// # Arguments
    ///
    /// * `buf` - The mutable buffer to receive the data into.
    ///
    /// # Returns
    ///
    /// Return a future that resolves to the number of bytes read.
    ///
    /// Return [`Err`] when the connection is closing or already closed
    ///
    /// # Note
    ///
    /// if the buffer is not large enough to hold the received data, the behavior is defined by the implementation of [`BufMut::put`].
    pub fn recv_buf<'b, B: BufMut>(&self, buf: &'b mut B) -> ReadInfoBuf<'b, B> {
        let reader = self.0.clone();
        ReadInfoBuf { reader, buf }
    }

    /// return the transport parameters `max_datagram_frame_size` set by local
    ///
    /// # Returns
    ///
    /// Return [`Err`] when the connection is closing or already closed
    pub fn get_local_max_datagram_frame_size(&self) -> io::Result<usize> {
        let reader = self.0.lock().unwrap();
        match &*reader {
            Ok(reader) => Ok(reader.local_max_size),
            Err(error) => Err(io::Error::new(io::ErrorKind::BrokenPipe, error.to_string())),
        }
    }

    pub fn into_result(self) -> io::Result<Self> {
        if let Err(e) = &*self.0.lock().unwrap() {
            return Err(io::Error::new(e.kind(), e.to_string()));
        }
        Ok(self)
    }
}

/// the [`Future`] created by [`DatagramReader::recv`]
pub struct ReadIntoSlice<'a> {
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
                    reader.waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            },
            Err(e) => Poll::Ready(Err(io::Error::new(e.kind(), e.to_string()))),
        }
    }
}

/// the [`Future`] created by [`DatagramReader::recv_buf`]
pub struct ReadInfoBuf<'a, B> {
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
                    reader.waker = Some(cx.waker().clone());
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
            let reader = DatagramReader(reader.0.clone());
            async move {
                let n = reader.recv(&mut [0u8; 1024]).await.unwrap();
                assert_eq!(n, 11);
            }
        });

        reader
            .recv_datagram(
                &DatagramFrame::new(None),
                Bytes::from_static(b"hello world"),
            )
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
