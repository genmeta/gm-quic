use std::{
    collections::VecDeque,
    future::Future,
    io,
    ops::DerefMut,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{ready, Context, Poll, Waker},
};

use bytes::{BufMut, Bytes};
use qbase::{
    error::{Error, ErrorKind},
    frame::{BeFrame, DatagramFrame},
};

/// The [`RawDatagramReader`] struct represents a queue for receiving [`DatagramFrame`] frames from peer.
///
/// The protocol layer will push the received datagrams into the internal FIFO queue or set the internal queue to an error state
/// when a connection error has occurred. See [`DatagramIncoming`] for more.
///
/// The application can create a **unique** [`DatagramReader`] to read the received datagrams. See [`DatagramReader`] for more.
///
/// [`DatagramReader`] is created by [`DatagramIncoming::new_reader`], and they share the same [`RawDatagramReader`](wraped in [`ArcDatagramReader`]).
#[derive(Default, Debug)]
pub struct RawDatagramReader {
    /// The maximum size of the datagram that can be received.
    ///
    /// The value is set by the local protocol parameters [`max_datagram_frame_size`](https://www.rfc-editor.org/rfc/rfc9221.html#name-transport-parameter).
    ///
    /// If the size of the received datagram exceeds this value, a connection error occurs.
    local_max_size: usize,
    /// The internal queue for caching the received datagrams.
    queue: VecDeque<Bytes>,
    /// The waker for waking up the task that is waiting for the data to be read.
    ///
    /// When a datagram is received, the waker will be used to wake up the task.
    waker: Option<Waker>,
    /// The flag indicating whether the [`DatagramReader`] exists or not.
    ///
    /// See [`DatagramReader`] for more.
    reader_exist: bool,
}

impl RawDatagramReader {
    pub(crate) fn new(local_max_size: usize) -> Self {
        Self {
            local_max_size,
            queue: Default::default(),
            waker: Default::default(),
            reader_exist: false,
        }
    }
}

/// If a connection error occurs, the internal reader will be set to an error state.
/// See [`DatagramIncoming::on_conn_error`] for more.
pub type ArcDatagramReader = Arc<Mutex<Result<RawDatagramReader, Error>>>;

/// The [`DatagramIncoming`] struct represents a queue for the protocol layer to write the received datagrams.
///
/// When the protocol layer receives a [`DatagramFrame`], it will push it into the internal FIFO queue.
/// The application can read the received datagrams from the queue by creating a [`DatagramReader`].
///
/// When a connection error occurs, the error state will be set to the reader. See [`DatagramIncoming::on_conn_error`] for more.
#[derive(Debug, Clone)]
pub struct DatagramIncoming(pub(crate) ArcDatagramReader);

impl DatagramIncoming {
    /// Creates a new [`DatagramReader`] for the application to read the received datagrams.
    ///
    /// Because the internal datagram queue is a mpsc queue, the reader (consumer) is unique, only one reader can exist at the same time.
    /// If a reader already exists, the method will return an error.
    ///
    /// If a connection error occurs, the error will be set to the reader, and subsequent calls to this method will return an error.
    /// See [`DatagramIncoming::on_conn_error`] for more.
    pub fn new_reader(&self) -> io::Result<DatagramReader> {
        let mut guard = self.0.lock().unwrap();
        match guard.deref_mut() {
            Ok(raw) => {
                if raw.reader_exist {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "There has been a `DatagramReader`, see its docs for more",
                    ));
                }
                raw.reader_exist = true;
                Ok(DatagramReader(self.0.clone()))
            }
            Err(e) => Err(io::Error::from(e.clone())),
        }
    }

    /// Receives a datagram and pushes it into the internal FIFO queue for the application to read.
    ///
    /// If the size of the received datagram exceeds the maximum size set by the local protocol parameters `max_datagram_frame_size`,
    /// a connection error occurs.
    ///
    /// If the connection is closing or closed, the new datagram will be ignored.
    ///
    /// If there is a task waiting for the data to be read, the task will be woken up when the datagram is received.
    pub fn recv_datagram(&self, frame: &DatagramFrame, data: bytes::Bytes) -> Result<(), Error> {
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

    /// When a connection error occurs, the error will be set to the reader.
    ///
    /// Any subsequent calls to [`DatagramIncoming::new_reader`], [`DatagramReader::read`] and [`DatagramReader::read_buf`] will return an error.
    ///
    /// If there is a task waiting for the data to be read, the task will be woken up and return an error immediately.
    ///
    /// All the received datagrams will be discarded, and subsequent calls to [`DatagramIncoming::recv_datagram`] will be ignored.
    pub fn on_conn_error(&self, error: &Error) {
        let reader = &mut self.0.lock().unwrap();
        let inner = reader.deref_mut();
        if let Ok(reader) = inner {
            if let Some(waker) = reader.waker.take() {
                waker.wake();
            }
            *inner = Err(error.clone());
        }
    }
}

/// The [`DatagramReader`] struct represents a reader for the application to read the received datagrams.
///
/// The reader is created by the [`DatagramIncoming::new_reader`] method.
/// Because the internal datagram queue is a mpsc queue, the reader (consumer) is unique, only one reader can exist at the same time.
/// See [`DatagramIncoming::new_reader`] for more.
///
/// The application can read the received datagrams from the reader by calling the [`DatagramReader::read`] or [`DatagramReader::read_buf`] method.
///
/// These methods are asynchronous, they return a future that resolves to the number of bytes read into the buffer.
/// If the connection is closing or already closed, the future will yield an error.
///
/// Read their docs for more.
#[derive(Debug)]
pub struct DatagramReader(ArcDatagramReader);

impl DatagramReader {
    /// The internal implementation of the [`DatagramReader::recv`] method.
    ///
    /// If there has a datagram received but unread, this method will return [`Poll::Ready`] with
    /// the received datagram as [`Ok`]. Once the datagram is read, it will be removed from the queue,
    /// and the next call to this method will return the next datagram.
    ///
    /// If the connection is closing or already closed, this method will return [`Poll::Ready`] with
    /// an error as [`Err`].
    ///
    /// If the datagram is not ready, and the connection is active,the method will return [`Poll::Pending`]
    /// and set the waker for waking up the task when the datagram is received.
    pub fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<io::Result<Bytes>> {
        let mut reader = self.0.lock().unwrap();
        match reader.deref_mut() {
            Ok(reader) => match reader.queue.pop_front() {
                Some(bytes) => Poll::Ready(Ok(bytes)),
                None => {
                    reader.waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            },
            Err(e) => Poll::Ready(Err(io::Error::from(e.clone()))),
        }
    }

    /// Try to receive a datagram from peer.
    ///
    /// This method is asynchronous and returns a future that resolves to the received datagram.
    ///
    /// ``` rust, ignore
    /// pub async fn recv(&self) -> io::Result<Bytes>
    /// ```
    ///
    /// The future will yield the received datagram as [`Ok`].
    ///
    /// If the connection is closing or already closed, the future will yield an error as [`Err`].
    pub fn recv(&mut self) -> RecvDatagram {
        RecvDatagram { reader: self }
    }

    /// Reads the received data into a mutable slice.
    ///
    /// This method is asynchronous and returns a future that resolves to the number of bytes read.
    ///
    /// ``` rust, ignore
    /// pub async fn read(&self, buf: & mut [u8]) -> io::Result<usize>
    /// ```
    ///
    /// The future will yield the size of bytes read from the received datagram as [`Ok`].
    ///
    /// If the buffer is not large enough to hold the received data, the received data will be truncated.
    ///
    /// If the connection is closing or already closed, the future will yield an error as [`Err`].
    pub fn read<'b>(&'b mut self, buf: &'b mut [u8]) -> ReadIntoSlice<'b> {
        ReadIntoSlice { reader: self, buf }
    }

    /// Reads the received data into a mutable reference to [`bytes::BufMut`].
    ///
    /// This method is asynchronous and returns a future that resolves to the number of bytes read.
    ///
    /// ``` rust, ignore
    /// pub async fn read_buf(&self, buf: & mut [u8]) -> io::Result<usize>
    /// ```
    ///
    /// The future will yield the size of bytes read from the received datagram as [`Ok`].
    ///
    /// If the buffer is not large enough to hold the received data, the behavior is defined by the [`bytes::BufMut::put`] implementation.
    ///
    /// If the connection is closing or already closed, the future will yield an error as [`Err`].
    pub fn read_buf<'b, B: BufMut>(&'b mut self, buf: &'b mut B) -> ReadIntoBuf<'b, B> {
        ReadIntoBuf { reader: self, buf }
    }
}

/// Releases the reader when it is dropped, so that a new reader can be created.
impl Drop for DatagramReader {
    fn drop(&mut self) {
        let reader = &mut self.0.lock().unwrap();
        let inner = reader.deref_mut();
        if let Ok(reader) = inner {
            reader.reader_exist = false;
        }
    }
}

/// The [`Future`] created by [`DatagramReader::recv`], see [`DatagramReader::recv`] for more.
pub struct RecvDatagram<'a> {
    reader: &'a mut DatagramReader,
}

impl Future for RecvDatagram<'_> {
    type Output = io::Result<Bytes>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.reader.poll_recv(cx)
    }
}

/// the [`Future`] created by [`DatagramReader::read`], see [`DatagramReader::read`] for more.
pub struct ReadIntoSlice<'a> {
    reader: &'a mut DatagramReader,
    buf: &'a mut [u8],
}

impl Future for ReadIntoSlice<'_> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let s = self.get_mut();
        let bytes = ready!(s.reader.poll_recv(cx)?);

        let len = bytes.len().min(s.buf.len());
        s.buf[..len].copy_from_slice(&bytes[..len]);
        Poll::Ready(Ok(len))
    }
}

/// the [`Future`] created by [`DatagramReader::read_buf`], see [`DatagramReader::read_buf`] for more.
pub struct ReadIntoBuf<'a, B> {
    reader: &'a mut DatagramReader,
    buf: &'a mut B,
}

impl<B> Future for ReadIntoBuf<'_, B>
where
    B: BufMut,
{
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let s = self.get_mut();
        let bytes = ready!(s.reader.poll_recv(cx)?);

        let len = bytes.len();
        s.buf.put(bytes);
        Poll::Ready(Ok(len))
    }
}

#[cfg(test)]
mod tests {
    use qbase::frame::FrameType;

    use super::*;

    #[tokio::test]
    async fn test_datagram_reader_recv_buf() {
        let incoming = DatagramIncoming(Arc::new(Mutex::new(Ok(RawDatagramReader::new(1024)))));

        let recv = tokio::spawn({
            let mut reader = incoming.new_reader().unwrap();
            async move {
                let n = reader.read(&mut [0u8; 1024]).await.unwrap();
                assert_eq!(n, 11);
            }
        });

        incoming
            .recv_datagram(
                &DatagramFrame::new(None),
                Bytes::from_static(b"hello world"),
            )
            .unwrap();

        recv.await.unwrap();
    }

    #[tokio::test]
    async fn test_datagram_reader_on_conn_error() {
        let incoming = DatagramIncoming(Arc::new(Mutex::new(Ok(RawDatagramReader::new(1024)))));
        let error = Error::new(
            ErrorKind::ProtocolViolation,
            FrameType::Datagram(0),
            "protocol violation",
        );
        incoming.on_conn_error(&error);

        let new_reader = incoming.new_reader();
        assert!(new_reader.is_err());
        assert_eq!(new_reader.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    }
}
