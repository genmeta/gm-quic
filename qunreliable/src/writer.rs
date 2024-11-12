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

/// The queue that caches the datagram frames to send.
///
/// For application layer, this represents as the [`UnreliableWriter`], which is used to send the [datagram frames] to
/// the peer.
///
/// [`UnreliableWriter`] is created by [`UnreliableOutgoing::new_writer`] and each QUIC Connection has only one queue.
/// All [`UnreliableWriter`]s share the same queue, you can create many [`UnreliableWriter`]s (or simply clone they) to
/// send the datagram frames at the same time.
///
/// For protocol layer, this represents as the [`UnreliableOutgoing`]. The [datagram frames] application want to send
/// will not be sent immediately; they will be pushed into this  queue. The protocol layer will read the datagram the
/// from the queue and send it to the peer.
///
///
/// [datagram frames]: https://www.rfc-editor.org/rfc/rfc9221.html
#[derive(Debug)]
pub struct DatagramFrameSink {
    /// The queue that stores the datagram frame to send.
    queue: VecDeque<Bytes>,
}

impl DatagramFrameSink {
    pub(crate) fn new() -> Self {
        Self {
            queue: Default::default(),
        }
    }
}

/// A wrapper of [`DatagramFrameSink`] that can be shared between multiple [`UnreliableWriter`]s and [`UnreliableOutgoing`]s.
///
/// If a connection error occurs, the internal state will be set to an error state. See [`UnreliableOutgoing::on_conn_error`]
/// for more details.
pub type ArcDatagramFrameSink = Arc<Mutex<Result<DatagramFrameSink, Error>>>;

/// The struct for protocol layer to mange the outgoing side of the datagram flow.
#[derive(Debug, Clone)]
pub struct UnreliableOutgoing(pub(crate) ArcDatagramFrameSink);

impl UnreliableOutgoing {
    /// Creates a new instance of [`UnreliableWriter`].
    ///
    /// Returns an error when the connection is closing or already closed.
    ///
    /// This method takes the remote transport parameters `max_datagram_frame_size`.
    ///
    /// Be different from [`UnreliableReader`], there can be multiple [`UnreliableWriter`]s at the same time.
    /// All of them share the same internal queue.
    ///
    /// [`UnreliableReader`]: crate::reader::UnreliableReader
    pub fn new_writer(&self, max_datagram_frame_size: u64) -> io::Result<UnreliableWriter> {
        match self.0.lock().unwrap().deref_mut() {
            Ok(..) => Ok(UnreliableWriter {
                writer: self.0.clone(),
                max_datagram_frame_size: max_datagram_frame_size as _,
            }),
            Err(e) => Err(io::Error::from(e.clone())),
        }
    }

    /// Attempts to encode the datagram frame into the buffer.
    ///
    /// If the datagram frame is successfully encoded, the method will return the datagram frame and the number of bytes
    /// written to the buffer. Otherwise, the method will return [`None`], and the buffer will not be modified.
    ///
    /// If the connection is closing or already closed, the method will return [`None`].
    /// See [`UnreliableOutgoing::on_conn_error`] for more details.
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
    /// The datagram won't be split into multiple frames. If the buffer is not enough to encode the datagram frame, the
    /// method will return [`None`]. In this case, the buffer will not be modified, and the data will still be in the
    /// internal queue.
    ///
    /// This method tries to encode the [`DatagramFrame`] with the data's length first (frame type `0x31`).
    ///
    /// If the buffer is not enough to encode the length, it will encode the [`DatagramFrame`] without the data's length
    /// (frame type `0x30`). Because no frame can be put after the datagram frame without length, this method will put
    /// padding frames before to fill the buffer. In this case, the buffer will be filled.
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

    /// When a connection error occurs, set the internal state to an error state.
    ///
    /// Any subsequent calls to [`UnreliableWriter::send`] or [`UnreliableWriter::send_bytes`] will return an error.
    /// All datagrams in the internal queue will be dropped and not sent to the peer.
    pub fn on_conn_error(&self, error: &Error) {
        let writer = &mut self.0.lock().unwrap();
        if writer.is_ok() {
            **writer = Err(error.clone());
        }
    }
}

/// The writer for application to send the [datagram frames] to the peer.
///
/// You can clone the writer or wrapper it in an [`Arc`] to send the datagram frames in many tasks.
///
/// [datagram frames]: https://www.rfc-editor.org/rfc/rfc9221.html
#[derive(Debug, Clone)]
pub struct UnreliableWriter {
    writer: ArcDatagramFrameSink,
    /// The maximum size of the datagram frame that can be sent to the peer.
    ///
    /// The value is set by the remote peer, and the protocol layer will use this value to limit the size of the datagram frame.
    ///
    /// If the size of the datagram frame exceeds this value, the protocol layer will return an error.
    ///
    /// See [RFC](https://www.rfc-editor.org/rfc/rfc9221.html#name-transport-parameter) for more details.
    max_datagram_frame_size: usize,
}

impl UnreliableWriter {
    /// Send unreliable data to the peer.
    ///
    /// The `data` will not be sent immediately, and the `data` sent may not be sent to the peer.
    ///
    /// If the peer dont support want to receive datagram frames, the method will return an error.
    ///
    /// The size of the datagram frame is limited by the `max_datagram_frame_size` transport parameter set by the peer.
    /// See [RFC](https://www.rfc-editor.org/rfc/rfc9221.html#name-transport-parameter) for more details about transport
    /// parameters.
    ///
    /// If the size of the `data` exceeds the limit, the method will return an error.
    ///
    /// You can call [`UnreliableWriter::max_datagram_frame_size`] to know the maximum size of the datagram frame you can
    /// send, read its documentation for more details.
    ///
    /// If the connection is closing or already closed, the method will also return an error.
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
                if self.max_datagram_frame_size == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "peer does not support RFC 9221: An Unreliable Datagram Extension to QUIC, or it dont want to receive datagram frames",
                    ));
                }
                writer.queue.push_back(data.clone());
                Ok(())
            }
            Err(e) => Err(io::Error::from(e.clone())),
        }
    }

    /// Send unreliable data to the peer.
    ///
    /// The `data` will not be sent immediately, and the `data` sent may not be sent to the peer.
    ///
    /// If the peer dont support want to receive datagram frames, the method will return an error.
    ///
    /// The size of the datagram frame is limited by the `max_datagram_frame_size` transport parameter set by the peer.
    /// See [RFC](https://www.rfc-editor.org/rfc/rfc9221.html#name-transport-parameter) for more details about transport
    /// parameters.
    ///
    /// If the size of the `data` exceeds the limit, the method will return an error.
    ///
    /// You can call [`UnreliableWriter::max_datagram_frame_size`] to know the maximum size of the datagram frame you can
    /// send, read its documentation for more details.
    ///
    /// If the connection is closing or already closed, the method will also return an error.
    pub fn send(&self, data: &[u8]) -> io::Result<()> {
        self.send_bytes(data.to_vec().into())
    }

    /// Returns the maximum size of the datagram frame that can be sent to the peer.
    ///
    /// If the connection is closing or already closed, the method will return an error.
    ///
    /// The value is a transport parameter set by the peer, and you cant send a datagram frame whose size exceeds this
    /// value.
    ///
    /// Because of the encoding, the size of the data you can send is less than this value, usually 1 byte less. Although
    /// its possiable to send a datagram frame with the size of `max_datagram_frame_size` - 1, its hardly to happen.     
    ///
    /// We recommend you to send unreliable data that the size is less or equal to `max_encoding_size` - `1` - `the size
    /// of the size of the data's length in varint form`. [varint] in definded in the QUIC RFC.
    ///
    /// Size 0 means the peer does not want to receive datagram frames, but it dont means the peer will not send datagram
    /// frames to you.
    ///
    /// [varint]: https://www.rfc-editor.org/rfc/rfc9000.html#integer-encoding
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
        let writer = Arc::new(Mutex::new(Ok(DatagramFrameSink::new())));
        let outgoing = UnreliableOutgoing(writer);
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
        let writer = Arc::new(Mutex::new(Ok(DatagramFrameSink::new())));
        let outgoing = UnreliableOutgoing(writer);
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
        let writer = Arc::new(Mutex::new(Ok(DatagramFrameSink::new())));
        let outgoing = UnreliableOutgoing(writer);
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
        let writer = Arc::new(Mutex::new(Ok(DatagramFrameSink::new())));
        let outgoing = UnreliableOutgoing(writer);
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
        let writer = Arc::new(Mutex::new(Ok(DatagramFrameSink::new())));
        let outgoing = UnreliableOutgoing(writer);
        let writer = outgoing.new_writer(0).unwrap();

        let data = Bytes::from_static(b"hello world");
        let result = writer.send_bytes(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_datagram_writer_on_conn_error() {
        let writer = Arc::new(Mutex::new(Ok(DatagramFrameSink::new())));
        let outgoing = UnreliableOutgoing(writer);
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
