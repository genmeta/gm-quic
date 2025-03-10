use std::{
    collections::VecDeque,
    io,
    ops::DerefMut,
    sync::{Arc, Mutex},
};

use bytes::{BufMut, Bytes};
use qbase::{
    error::Error,
    frame::{BeFrame, DatagramFrame},
    net::{DataWakers, SendLimiter},
    packet::MarshalDataFrame,
    varint::VarInt,
};

#[derive(Debug)]
struct RawDatagramWriter {
    /// The queue that stores the datagram frame to send.
    datagrams: VecDeque<Bytes>,
    data_wakers: DataWakers,
}

impl RawDatagramWriter {
    fn new(data_wakers: DataWakers) -> Self {
        Self {
            datagrams: VecDeque::new(),
            data_wakers,
        }
    }
}

/// The struct for protocol layer to mange the outgoing side of the datagram flow.
#[derive(Debug, Clone)]
pub struct DatagramOutgoing(Arc<Mutex<Result<RawDatagramWriter, Error>>>);

impl DatagramOutgoing {
    pub fn new(data_wakers: DataWakers) -> DatagramOutgoing {
        DatagramOutgoing(Arc::new(Mutex::new(Ok(RawDatagramWriter::new(
            data_wakers,
        )))))
    }

    /// Try to reate a new instance of [`DatagramWriter`].
    ///
    /// This method takes the remote transport parameters `max_datagram_frame_size`.
    ///
    /// Return an error if the connection is closing or already closed,
    /// or datagram is disenabled by peer(`max_datagram_frame_size` is `0`)
    pub fn new_writer(&self, max_datagram_frame_size: u64) -> io::Result<DatagramWriter> {
        let mut guard = self.0.lock().unwrap();
        let _writer = guard.as_mut().map_err(|e| e.clone())?;
        if max_datagram_frame_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Unreliable Datagram Extension was disenabled by peer's parameters",
            ));
        }
        Ok(DatagramWriter {
            writer: self.0.clone(),
            max_datagram_frame_size: max_datagram_frame_size as _,
        })
    }

    // Same logic with `try_load_data_into`, only used for test purpose.
    #[cfg(test)]
    fn try_read_datagram(&self, mut buf: &mut [u8]) -> Option<(DatagramFrame, usize)> {
        use qbase::frame::io::WriteDataFrame;

        let mut guard = self.0.lock().unwrap();
        let Ok(writer) = guard.as_mut() else {
            return None;
        };
        let datagram = writer.datagrams.front()?;
        let available = buf.remaining_mut();

        let max_encoding_size = available.saturating_sub(datagram.len());
        if max_encoding_size == 0 {
            return None;
        }

        let data = writer.datagrams.pop_front().expect("unreachable");
        let data_len = VarInt::try_from(data.len()).unwrap();
        let frame_without_len = DatagramFrame::new(false, data_len);
        let frame_with_len = DatagramFrame::new(true, data_len);
        let frame = match max_encoding_size {
            // Encode length
            n if n >= frame_with_len.encoding_size() => {
                buf.put_data_frame(&frame_with_len, &data);
                frame_with_len
            }
            // Do not encode length, may need padding
            n => {
                buf.put_bytes(0, n - frame_without_len.encoding_size());
                buf.put_data_frame(&frame_without_len, &data);
                frame_without_len
            }
        };
        Some((frame, available - buf.remaining_mut()))
    }

    /// Attempts to load the datagram frame into the packet.
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
    /// The datagram won't be split into multiple frames. If the remaining space of packet is not enough to encode the datagram frame,
    /// the datagram will not be loaded.
    ///
    /// This method tries to encode the [`DatagramFrame`] with the data's length first (frame type `0x31`).
    ///
    /// If remaining space of the packet is not enough to encode the length,
    /// it will encode the [`DatagramFrame`] without the data's length (frame type `0x30`).
    /// Because no frame can be put after the datagram frame without length,
    /// padding frames will be put before the datagram frame.
    /// In this case, the packet will be filled.
    pub fn try_load_data_into<P>(&self, packet: &mut P) -> Result<(), SendLimiter>
    where
        P: BufMut + MarshalDataFrame<DatagramFrame, Bytes>,
    {
        let mut guard = self.0.lock().unwrap();
        let Ok(writer) = guard.as_mut() else {
            return Err(SendLimiter::empty()); // connection closed
        };
        let Some(datagram) = writer.datagrams.front() else {
            return Err(SendLimiter::NO_UNLIMITED_DATA);
        };

        let available = packet.remaining_mut();

        let max_encoding_size = available.saturating_sub(datagram.len());
        if max_encoding_size == 0 {
            return Err(SendLimiter::BUFFER_TOO_SMALL);
        }

        let data = writer.datagrams.pop_front().expect("unreachable");
        let data_len = VarInt::try_from(data.len()).unwrap();
        let frame_without_len = DatagramFrame::new(false, data_len);
        let frame_with_len = DatagramFrame::new(true, data_len);
        match max_encoding_size {
            // Encode length
            n if n >= frame_with_len.encoding_size() => {
                packet.dump_frame_with_data(frame_with_len, data);
            }
            // Do not encode length, may need padding
            n => {
                packet.put_bytes(0, n - frame_without_len.encoding_size());
                packet.dump_frame_with_data(frame_without_len, data);
            }
        }
        Ok(())
    }

    /// When a connection error occurs, set the internal state to an error state.
    ///
    /// Any subsequent calls to [`DatagramWriter::send`] or [`DatagramWriter::send_bytes`] will return an error.
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
pub struct DatagramWriter {
    writer: Arc<Mutex<Result<RawDatagramWriter, Error>>>,
    /// The maximum size of the datagram frame that can be sent to the peer.
    ///
    /// The value is set by the remote peer, and the protocol layer will use this value to limit the size of the datagram frame.
    ///
    /// If the size of the datagram frame exceeds this value, the protocol layer will return an error.
    ///
    /// See [RFC](https://www.rfc-editor.org/rfc/rfc9221.html#name-transport-parameter) for more details.
    max_datagram_frame_size: usize,
}

impl DatagramWriter {
    /// Send unreliable data to the peer.
    ///
    /// The `data` will not be sent immediately, and the `data` sent is not guaranteed to be delivered.
    ///
    /// If the peer dont support want to receive datagram frames, the method will return an error.
    ///
    /// The size of the datagram frame is limited by the `max_datagram_frame_size` transport parameter set by the peer.
    /// See [RFC](https://www.rfc-editor.org/rfc/rfc9221.html#name-transport-parameter) for more details about transport
    /// parameters.
    ///
    /// If the size of the `data` exceeds the limit, the method will return an error.
    ///
    /// You can call [`DatagramWriter::max_datagram_frame_size`] to know the maximum size of the datagram frame you can
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
                writer.data_wakers.wake_all();
                writer.datagrams.push_back(data.clone());
                Ok(())
            }
            Err(e) => Err(io::Error::from(e.clone())),
        }
    }

    /// Send unreliable data to the peer.
    ///
    /// The `data` will not be sent immediately, and the `data` sent is not guaranteed to be delivered.
    ///
    /// The size of the datagram frame is limited by the `max_datagram_frame_size` transport parameter set by the peer.
    /// See [RFC](https://www.rfc-editor.org/rfc/rfc9221.html#name-transport-parameter) for more details about transport
    /// parameters.
    ///
    /// If the size of the `data` exceeds the limit, the method will return an error.
    ///
    /// You can call [`DatagramWriter::max_datagram_frame_size`] to know the maximum size of the datagram frame you can
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
    /// The value is a transport parameter set by the peer,
    /// and you cant send a datagram frame whose size exceeds this value.
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
        frame::{
            FrameType, PaddingFrame,
            io::{WriteDataFrame, WriteFrame},
        },
    };

    use super::*;

    #[test]
    fn test_datagram_writer_with_length() {
        let outgoing = DatagramOutgoing::new(Default::default());
        let writer = outgoing.new_writer(1024).unwrap();

        let data = Bytes::from_static(b"hello world");
        writer.send_bytes(data.clone()).unwrap();

        let mut buffer = [0; 1024];
        let expected_frame = DatagramFrame::new(true, VarInt::try_from(data.len()).unwrap());
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
        let outgoing = DatagramOutgoing::new(Default::default());
        let writer = outgoing.new_writer(1024).unwrap();

        let data = Bytes::from_static(b"hello world");
        writer.send_bytes(data.clone()).unwrap();

        let mut buffer = [0; 1024];
        assert_eq!(
            outgoing.try_read_datagram(&mut buffer[0..12]),
            Some((DatagramFrame::new(false, VarInt::from_u32(11)), 12))
        );

        let mut expected_buffer = [0; 1024];
        {
            let mut expected_buffer = &mut expected_buffer[..];
            expected_buffer.put_data_frame(&DatagramFrame::new(false, VarInt::from_u32(12)), &data);
        }
        assert_eq!(buffer, expected_buffer);
    }

    #[test]
    fn test_datagram_writer_unwritten() {
        let outgoing = DatagramOutgoing::new(Default::default());
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
        let outgoing = DatagramOutgoing::new(Default::default());
        let writer = outgoing.new_writer(1024).unwrap();

        // Will be encoded to 2 bytes
        let data = Bytes::from_static(&[b'a'; 2usize.pow(8 - 2)]);
        let data_len = VarInt::from_u32(data.len() as u32);
        writer.send_bytes(data.clone()).unwrap();

        let mut buffer = [0; 1024];
        assert_eq!(
            outgoing.try_read_datagram(&mut buffer[..data.len() + 2]),
            Some((DatagramFrame::new(false, data_len), data.len() + 2))
        );

        let mut expected_buffer = [0; 1024];
        {
            let mut expected_buffer = &mut expected_buffer[..];
            expected_buffer.put_frame(&PaddingFrame);
            expected_buffer.put_data_frame(&DatagramFrame::new(false, data_len), &data);
        }

        assert_eq!(buffer, expected_buffer);
    }

    #[test]
    fn test_datagram_writer_exceeds_limit() {
        let outgoing = DatagramOutgoing::new(Default::default());
        assert!(outgoing.new_writer(0).is_err());
    }

    #[test]
    fn test_datagram_writer_on_conn_error() {
        let outgoing = DatagramOutgoing::new(Default::default());
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
