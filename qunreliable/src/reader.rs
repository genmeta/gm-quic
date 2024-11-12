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

/// An asynchronous queue that caches received datagram frames from peer.
///
/// For protocol layer, this struct represents as the [`UnreliableIncoming`]. Once a datagram frame is received, the method
/// [`UnreliableIncoming::recv_datagram`] will be called to push the datagram frame into this queue.
///
/// For application layer, this struct represents as the [`UnreliableReader`] to read the received datagram frames from
/// this queue. [`UnreliableReader`] is created by [`UnreliableIncoming::new_reader`], they will share the same internal
/// queue.
///
/// Because of some trade off, only one [`UnreliableReader`] can exist at the same time, try to create a new reader when
/// there has been a reader will result an error. See [`UnreliableIncoming::new_reader`] for more.
#[derive(Default, Debug)]
pub struct ReceivedDatagramFrames {
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
    /// The flag indicating whether the [`UnreliableReader`] exists or not.
    ///
    /// See [`UnreliableIncoming::new_reader`] for more.
    reader_exist: bool,
}

impl ReceivedDatagramFrames {
    pub(crate) fn new(local_max_size: usize) -> Self {
        Self {
            local_max_size,
            queue: Default::default(),
            waker: Default::default(),
            reader_exist: false,
        }
    }
}

/// A wrapper of [`ReceivedDatagramFrames`] that can be shared between multiple [`UnreliableIncoming`]s and [`UnreliableReader`]s.
///
/// If a connection error occurs, the internal reader will be set to an error state.
/// See [`UnreliableIncoming::on_conn_error`] for more.
pub type ArcReceivedDatagramFrames = Arc<Mutex<Result<ReceivedDatagramFrames, Error>>>;

/// The struct for protocol layer to mange the incoming side of the datagram flow.
#[derive(Debug, Clone)]
pub struct UnreliableIncoming(pub(crate) ArcReceivedDatagramFrames);

impl UnreliableIncoming {
    /// Creates a new [`UnreliableReader`] for the application to read the received datagram frames.
    ///
    /// Returns an error when the connection is closing or already closed.
    ///
    /// Implementation a multiple consumer queue is complex, low performance, and its not a general use case, so there
    /// is only one reader can exist at the same time.
    pub fn new_reader(&self) -> io::Result<UnreliableReader> {
        let mut guard = self.0.lock().unwrap();
        match guard.deref_mut() {
            Ok(raw) => {
                if raw.reader_exist {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "There has been a `UnreliableReader`, see its docs for more",
                    ));
                }
                raw.reader_exist = true;
                Ok(UnreliableReader(self.0.clone()))
            }
            Err(e) => Err(io::Error::from(e.clone())),
        }
    }

    /// Receives a datagram frame and pushes it into the internal queue for the application to read.
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
    /// Any subsequent calls to [`UnreliableIncoming::new_reader`], [`UnreliableReader::poll_recv`], [`UnreliableReader::read`]
    /// and [`UnreliableReader::read_buf`] will return an error.
    ///
    /// If there is a task waiting for the data to be read, the task will be woken up and return an error immediately.
    ///
    /// All the received datagrams will be discarded, and subsequent calls to [`UnreliableIncoming::recv_datagram`] will be ignored.
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

/// The reader for the application to read the received [datagram frames].
///
/// Because of some trade off, only one [`UnreliableReader`] can exist at the same time, try to create a new reader when
/// there has been a reader will result an error. See [`UnreliableIncoming::new_reader`] for more.
///
/// [datagram frames]: https://www.rfc-editor.org/rfc/rfc9221.html
#[derive(Debug)]
pub struct UnreliableReader(ArcReceivedDatagramFrames);

impl UnreliableReader {
    // Poll to receive a [datagram frame] from peer.
    ///
    /// This is the internal implementation of the [`UnreliableReader::recv`] method.
    ///
    /// Be care of using this method, you have to ensure the reader is not dropped when the future is not resolved, or
    /// the reader will enter a damaged state, you cant use it anymore.
    ///
    /// While there has a datagram frame received but unread, this method will return [`Poll::Ready`] with the received
    /// datagram frame as [`Ok`] and pop it from the internal queue.
    ///
    /// If the connection is closing or already closed, this method will return [`Poll::Ready`] with an error as [`Err`].
    ///
    /// If the datagram is not ready, and the connection is active,the method will return [`Poll::Pending`] and set the
    /// waker for waking up the task when the datagram is received.
    ///
    /// [datagram frame]: https://www.rfc-editor.org/rfc/rfc9221.html
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

    /// Receive a [datagram frame] from peer.
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
    ///
    /// The future is *Cancel Safe*.
    ///
    /// [datagram frame]: https://www.rfc-editor.org/rfc/rfc9221.html
    pub fn recv(&mut self) -> RecvDatagram {
        RecvDatagram { reader: self }
    }

    /// Reads the received [datagram frame] into a mutable slice.
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
    ///
    /// The future is *Cancel Safe*.
    ///
    /// [datagram frame]: https://www.rfc-editor.org/rfc/rfc9221.html
    pub fn read<'b>(&'b mut self, buf: &'b mut [u8]) -> ReadIntoSlice<'b> {
        ReadIntoSlice { reader: self, buf }
    }

    /// Reads the received [datagram frame] into a mutable reference to [`bytes::BufMut`].
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
    ///
    /// The future is *Cancel Safe*.
    ///
    /// [datagram frame]: https://www.rfc-editor.org/rfc/rfc9221.html
    pub fn read_buf<'b, B: BufMut>(&'b mut self, buf: &'b mut B) -> ReadIntoBuf<'b, B> {
        ReadIntoBuf { reader: self, buf }
    }
}

/// Releases the reader when it is dropped, so that a new reader can be created.
impl Drop for UnreliableReader {
    fn drop(&mut self) {
        let reader = &mut self.0.lock().unwrap();
        let inner = reader.deref_mut();
        if let Ok(reader) = inner {
            reader.reader_exist = false;
        }
    }
}

/// The [`Future`] created by [`UnreliableReader::recv`], see [`UnreliableReader::recv`] for more.
pub struct RecvDatagram<'a> {
    reader: &'a mut UnreliableReader,
}

impl Future for RecvDatagram<'_> {
    type Output = io::Result<Bytes>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.reader.poll_recv(cx)
    }
}

impl Drop for RecvDatagram<'_> {
    fn drop(&mut self) {
        let mut reader = self.reader.0.lock().unwrap();
        if let Ok(reader) = reader.deref_mut() {
            if let Some(receiver) = reader.waker.take() {
                // Waker可能不来自这个Future，所以强制唤醒
                // 如果是本任务：无事发生
                // 如果不是本任务：有点性能损耗，但是这是你在乱用
                receiver.wake();
            }
        }
    }
}

/// the [`Future`] created by [`UnreliableReader::read`], see [`UnreliableReader::read`] for more.
pub struct ReadIntoSlice<'a> {
    reader: &'a mut UnreliableReader,
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

impl Drop for ReadIntoSlice<'_> {
    fn drop(&mut self) {
        let mut reader = self.reader.0.lock().unwrap();
        if let Ok(reader) = reader.deref_mut() {
            if let Some(receiver) = reader.waker.take() {
                receiver.wake();
            }
        }
    }
}

/// the [`Future`] created by [`UnreliableReader::read_buf`], see [`UnreliableReader::read_buf`] for more.
pub struct ReadIntoBuf<'a, B> {
    reader: &'a mut UnreliableReader,
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

impl<B> Drop for ReadIntoBuf<'_, B> {
    fn drop(&mut self) {
        let mut reader = self.reader.0.lock().unwrap();
        if let Ok(reader) = reader.deref_mut() {
            if let Some(receiver) = reader.waker.take() {
                receiver.wake();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use qbase::frame::FrameType;

    use super::*;

    #[tokio::test]
    async fn test_datagram_reader_recv_buf() {
        let incoming =
            UnreliableIncoming(Arc::new(Mutex::new(Ok(ReceivedDatagramFrames::new(1024)))));

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
        let incoming =
            UnreliableIncoming(Arc::new(Mutex::new(Ok(ReceivedDatagramFrames::new(1024)))));
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
