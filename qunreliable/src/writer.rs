use std::{
    collections::VecDeque,
    io,
    ops::DerefMut,
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use qbase::{
    error::Error,
    frame::{io::WriteDataFrame, BeFrame, DatagramFrame},
    varint::VarInt,
};

/// The [`RawDatagramWriter`] struct represents a queue for sending [`DatagramFrame`].
///
/// The transport layer will read the datagram from the queue and send it to the peer, or set the internal queue to an error state
/// when the connection is closing or already closed. See [`DatagramOutgoing`] for more details.
///
/// The application layer can create a [`DatagramWriter`] and push data into the queue by calling [`DatagramWriter::send`] or [`DatagramWriter::send_bytes`].
/// See [`DatagramWriter`] for more details.
///
/// [`DatagramWriter`] is created by [`DatagramOutgoing::new_writer`], and they share the same [`RawDatagramWriter`](wrapped in [`ArcDatagramWriter`]).
#[derive(Debug)]
pub struct RawDatagramWriter {
    /// The queue for storing the datagram frame to send.
    queue: VecDeque<Bytes>,
}

impl RawDatagramWriter {
    pub(crate) fn new() -> Self {
        Self {
            queue: Default::default(),
        }
    }
}

/// If a connection error occurs, the internal writer will be set to an error state.
/// See [`DatagramOutgoing::on_conn_error`] for more details.
pub type ArcDatagramWriter = Arc<Mutex<Result<RawDatagramWriter, Error>>>;

#[derive(Debug, Clone)]
pub struct DatagramOutgoing(pub(crate) ArcDatagramWriter);

impl DatagramOutgoing {
    /// Creates a new instance of [`DatagramWriter`].
    ///
    /// This method takes the remote transport parameters `max_datagram_frame_size`.
    ///
    /// Returns an error when the connection is closing or already closed.
    ///
    /// Be different from [`DatagramReader`], there can be multiple [`DatagramWriter`]s at the same time.
    ///
    /// [`DatagramReader`]: crate::reader::DatagramReader
    pub fn new_writer(&self, max_datagram_frame_size: u64) -> io::Result<DatagramWriter> {
        match self.0.lock().unwrap().deref_mut() {
            Ok(..) => Ok(DatagramWriter {
                writer: self.0.clone(),
                max_datagram_frame_size: max_datagram_frame_size as _,
            }),
            Err(e) => Err(io::Error::from(e.clone())),
        }
    }

    /// Attempts to encode the datagram frame into the buffer.
    ///
    /// If the datagram frame is successfully encoded, the method will return the datagram frame and the number of bytes written to the buffer.
    /// Otherwise, the method will return [`None`], and the buffer will not be modified.
    ///
    /// If the connection is closing or already closed, the method will return [`None`]. See [`DatagramOutgoing::on_conn_error`] for more details.
    ///
    /// If the internal queue is empty (no [`DatagramFrame`] needs to be sent), the method will return [`None`].
    ///
    /// # Encoding
    ///
    /// [`DatagramFrame`] has two types:
    /// - frame type `0x30`: The datagram frame without the data's length.
    ///
    /// The size of this form of frame is `1 byte` + `the size of the data`.
    ///
    /// - frame type `0x31`: The datagram frame with the data's length.
    ///
    /// The size of this form of frame is `1 byte` + `the size of the data's length` + `the size of the data`.
    ///
    /// The datagram won't be split into multiple frames. If the buffer is not enough to encode the datagram frame, the method will return [`None`].
    /// In this case, the buffer will not be modified, and the data will still be in the internal queue.
    ///
    /// This method tries to encode the [`DatagramFrame`] with the data's length first (frame type `0x31`).
    ///
    /// If the buffer is not enough to encode the length, it will encode the [`DatagramFrame`] without the data's length (frame type `0x30`).
    /// Because no frame can be put after the datagram frame without length, this method will put padding frames before to fill the buffer.
    /// In this case, the buffer will be filled.
    pub fn try_read_datagram(&self, mut buf: &mut [u8]) -> Option<(DatagramFrame, usize)> {
        let mut guard = self.0.lock().unwrap();
        let writer = guard.as_mut().ok()?;
        let datagram = writer.queue.front()?;

        let available = buf.len();

        let max_encoding_size = available.saturating_sub(datagram.len());
        if max_encoding_size == 0 {
            return None;
        }

        let datagram = writer.queue.pop_front()?;
        let frame_without_len = DatagramFrame::new(None);
        let frame_with_len = DatagramFrame::new(Some(VarInt::try_from(datagram.len()).unwrap()));
        match max_encoding_size {
            // Encode length
            n if n >= frame_with_len.encoding_size() => {
                buf.put_data_frame(&frame_with_len, &datagram);
                let written = frame_with_len.encoding_size() + datagram.len();
                Some((frame_with_len, written))
            }
            // Do not encode length, may need padding
            n => {
                debug_assert_eq!(frame_without_len.encoding_size(), 1);
                buf = &mut buf[n - frame_without_len.encoding_size()..];
                buf.put_data_frame(&frame_without_len, &datagram);
                let written = n + datagram.len();
                Some((frame_without_len, written))
            }
        }
    }

    /// When a connection error occurs, set the internal writer to an error state.
    ///
    /// Any subsequent calls to [`DatagramWriter::send`] or [`DatagramWriter::send_bytes`] will return an error.
    ///
    /// All datagrams in the internal queue will be dropped.
    pub fn on_conn_error(&self, error: &Error) {
        let writer = &mut self.0.lock().unwrap();
        if writer.is_ok() {
            **writer = Err(error.clone());
        }
    }
}

#[derive(Debug, Clone)]
pub struct DatagramWriter {
    writer: ArcDatagramWriter,
    /// The maximum size of the datagram frame that can be sent to the peer.
    ///
    /// The value is set by the remote peer, and the transport layer will use this value to limit the size of the datagram frame.
    ///
    /// If the size of the datagram frame exceeds this value, the transport layer will return an error.
    ///
    /// See [RFC](https://www.rfc-editor.org/rfc/rfc9221.html#name-transport-parameter) for more details.
    max_datagram_frame_size: usize,
}

impl DatagramWriter {
    /// Send bytes to the peer.
    ///
    /// The data will not be sent immediately; it will be pushed into the internal queue.
    /// The transport layer will read the datagram from the queue and send it to the peer.
    ///
    /// Returns [`Ok`] when the data is successfully pushed into the internal queue.
    /// Returns [`Err`] when the connection is closing or already closed.
    pub fn send_bytes(&self, data: Bytes) -> io::Result<()> {
        match self.writer.lock().unwrap().deref_mut() {
            Ok(writer) => {
                // Only consider the smallest encoding method: 1 byte
                if (1 + data.len()) > self.max_datagram_frame_size {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "datagram frame size exceeds the limit",
                    ));
                }
                writer.queue.push_back(data.clone());
                Ok(())
            }
            Err(e) => Err(io::Error::from(e.clone())),
        }
    }

    /// Send bytes to the peer.
    ///
    /// The data will not be sent immediately; it will be pushed into the internal queue.
    /// The transport layer will read the datagram from the queue and send it to the peer.
    ///
    /// Returns [`Ok`] when the data is successfully pushed into the internal queue.
    /// Returns [`Err`] when the connection is closing or already closed.
    pub fn send(&self, data: &[u8]) -> io::Result<()> {
        self.send_bytes(data.to_vec().into())
    }

    /// Returns the maximum size of the datagram frame that can be sent to the peer.
    /// Returns an error when the connection is closing or already closed.
    pub fn max_datagram_frame_size(&self) -> io::Result<usize> {
        match self.writer.lock().unwrap().deref_mut() {
            Ok(..) => Ok(self.max_datagram_frame_size),
            Err(e) => Err(io::Error::from(e.clone())),
        }
    }
}
#[cfg(test)]
mod tests {

    use qbase::{
        error::ErrorKind,
        frame::{io::WriteFrame, FrameType, PaddingFrame},
    };

    use super::*;

    #[test]
    fn test_datagram_writer_with_length() {
        let writer = Arc::new(Mutex::new(Ok(RawDatagramWriter::new())));
        let outgoing = DatagramOutgoing(writer);
        let writer = outgoing.new_writer(1024).unwrap();

        let data = Bytes::from_static(b"hello world");
        writer.send_bytes(data.clone()).unwrap();

        let mut buffer = [0; 1024];
        let expected_frame = DatagramFrame::new(Some(VarInt::try_from(data.len()).unwrap()));
        assert_eq!(
            outgoing.try_read_datagram(&mut buffer),
            Some((expected_frame, 1 + 1 + data.len()))
        );

        let mut expected_buffer = [0; 1024];
        {
            let mut expected_buffer = &mut expected_buffer[..];
            expected_buffer.put_data_frame(&expected_frame, &data);
        }
        assert_eq!(buffer, expected_buffer);
    }

    #[test]
    fn test_datagram_writer_without_length() {
        let writer = Arc::new(Mutex::new(Ok(RawDatagramWriter::new())));
        let outgoing = DatagramOutgoing(writer);
        let writer = outgoing.new_writer(1024).unwrap();

        let data = Bytes::from_static(b"hello world");
        writer.send_bytes(data.clone()).unwrap();

        let mut buffer = [0; 1024];
        assert_eq!(
            outgoing.try_read_datagram(&mut buffer[0..12]),
            Some((DatagramFrame::new(None), 12))
        );

        let mut expected_buffer = [0; 1024];
        {
            let mut expected_buffer = &mut expected_buffer[..];
            expected_buffer.put_data_frame(&DatagramFrame::new(None), &data);
        }
        assert_eq!(buffer, expected_buffer);
    }

    #[test]
    fn test_datagram_writer_unwritten() {
        let writer = Arc::new(Mutex::new(Ok(RawDatagramWriter::new())));
        let outgoing = DatagramOutgoing(writer);
        let writer = outgoing.new_writer(1024).unwrap();

        let data = Bytes::from_static(b"hello world");
        writer.send_bytes(data.clone()).unwrap();

        let mut buffer = [0; 1024];
        assert!(outgoing.try_read_datagram(&mut buffer[0..1]).is_none());

        let expected_buffer = [0; 1024];
        assert_eq!(buffer, expected_buffer);
    }

    #[test]
    fn test_datagram_writer_padding_first() {
        let writer = Arc::new(Mutex::new(Ok(RawDatagramWriter::new())));
        let outgoing = DatagramOutgoing(writer);
        let writer = outgoing.new_writer(1024).unwrap();

        // Will be encoded to 2 bytes
        let data = Bytes::from_static(&[b'a'; 2usize.pow(8 - 2)]);
        writer.send_bytes(data.clone()).unwrap();

        let mut buffer = [0; 1024];
        assert_eq!(
            outgoing.try_read_datagram(&mut buffer[..data.len() + 2]),
            Some((DatagramFrame::new(None), data.len() + 2))
        );

        let mut expected_buffer = [0; 1024];
        {
            let mut expected_buffer = &mut expected_buffer[..];
            expected_buffer.put_frame(&PaddingFrame);
            expected_buffer.put_data_frame(&DatagramFrame::new(None), &data);
        }

        assert_eq!(buffer, expected_buffer);
    }

    #[test]
    fn test_datagram_writer_exceeds_limit() {
        let writer = Arc::new(Mutex::new(Ok(RawDatagramWriter::new())));
        let outgoing = DatagramOutgoing(writer);
        let writer = outgoing.new_writer(0).unwrap();

        let data = Bytes::from_static(b"hello world");
        let result = writer.send_bytes(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_datagram_writer_on_conn_error() {
        let writer = Arc::new(Mutex::new(Ok(RawDatagramWriter::new())));
        let outgoing = DatagramOutgoing(writer);
        let writer = outgoing.new_writer(1024).unwrap();

        outgoing.on_conn_error(&Error::new(
            ErrorKind::ProtocolViolation,
            FrameType::Datagram(0),
            "test",
        ));
        let writer_guard = writer.writer.lock().unwrap();
        assert!(writer_guard.as_ref().is_err());
    }
}
