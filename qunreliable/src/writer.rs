use std::{
    collections::VecDeque,
    io,
    ops::DerefMut,
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use qbase::{
    error::{Error, ErrorKind},
    frame::{io::WriteDatagramFrame, BeFrame, DatagramFrame, FrameType},
    util::TransportLimit,
    varint::VarInt,
};

#[derive(Debug)]
pub struct RawDatagramWriter {
    remote_max_size: usize,
    queue: VecDeque<Bytes>,
}

impl RawDatagramWriter {
    pub fn new(remote_max_size: usize) -> Self {
        Self {
            remote_max_size,
            queue: Default::default(),
        }
    }
}

pub type ArcDatagramWriter = Arc<Mutex<io::Result<RawDatagramWriter>>>;

#[derive(Debug, Clone)]
pub struct DatagramWriter(pub(super) ArcDatagramWriter);

impl DatagramWriter {
    pub(super) fn try_read_datagram(
        &self,
        limit: &mut TransportLimit,
        mut buf: &mut [u8],
    ) -> Option<(DatagramFrame, usize)> {
        let mut guard = self.0.lock().unwrap();
        let writer = guard.as_mut().ok()?;
        let datagram = writer.queue.front()?;

        let available = limit.available();

        let max_encoding_size = available.saturating_sub(datagram.len());
        if max_encoding_size == 0 {
            return None;
        }

        let datagram = writer.queue.pop_front()?;
        let frame_without_len = DatagramFrame::new(None);
        let frame_with_len = DatagramFrame::new(Some(VarInt::try_from(datagram.len()).unwrap()));
        match max_encoding_size {
            // 编码长度
            n if n >= frame_with_len.encoding_size() => {
                buf.put_datagram_frame(&frame_with_len, &datagram);
                let written = frame_with_len.encoding_size() + datagram.len();
                Some((frame_with_len, written))
            }
            // 不编码长度
            _ => {
                buf.put_datagram_frame(&frame_without_len, &datagram);
                Some((frame_without_len, 1 + datagram.len()))
            }
        }
    }

    pub(super) fn on_conn_error(&self, error: &Error) {
        let writer = &mut self.0.lock().unwrap();
        if writer.is_ok() {
            **writer = Err(io::Error::new(io::ErrorKind::BrokenPipe, error.to_string()));
        }
    }

    pub fn send_bytes(&self, data: Bytes) -> io::Result<()> {
        match self.0.lock().unwrap().deref_mut() {
            Ok(writer) => {
                // 这里只考虑最小的编码方式：也就是1字节
                if (1 + data.len()) > writer.remote_max_size {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "datagram frame size exceeds the limit",
                    ));
                }
                writer.queue.push_back(data);
                Ok(())
            }
            Err(e) => Err(io::Error::new(e.kind(), e.to_string())),
        }
    }

    pub fn send(&self, data: &[u8]) -> io::Result<()> {
        self.send_bytes(data.to_vec().into())
    }

    pub fn update_remote_max_datagram_frame_size(&self, size: usize) -> Result<(), Error> {
        let mut writer = self.0.lock().unwrap();
        let inner = writer.deref_mut();

        if let Ok(writer) = inner {
            if size < writer.remote_max_size {
                return Err(Error::new(
                    ErrorKind::ProtocolViolation,
                    FrameType::Datagram(0),
                    "datagram frame size cannot be reduced",
                ));
            }
            writer.remote_max_size = size;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_datagram_writer() {
        let writer = Arc::new(Mutex::new(Ok(RawDatagramWriter::new(1024))));
        let writer = DatagramWriter(writer);

        let data = Bytes::from_static(b"hello world");
        writer.send_bytes(data.clone()).unwrap();

        let (frame, written) = writer
            .try_read_datagram(
                &mut TransportLimit::new(None, usize::MAX, 0),
                &mut [0; 1024],
            )
            .unwrap();
        assert_eq!(frame.length, Some(VarInt::try_from(data.len()).unwrap()));
        assert_eq!(written, 1 + 1 + data.len());
    }

    #[test]
    fn test_datagram_writer_no_length() {
        let writer = Arc::new(Mutex::new(Ok(RawDatagramWriter::new(1024))));
        let writer = DatagramWriter(writer);

        let data = Bytes::from_static(b"hello world");
        writer.send_bytes(data.clone()).unwrap();
        assert_eq!(
            writer.try_read_datagram(
                &mut TransportLimit::new(None, usize::MAX, 0),
                &mut [0; 1 + 11]
            ),
            Some((DatagramFrame::new(None), 12))
        );
    }

    #[test]
    fn test_datagram_writer_un_written() {
        let writer = Arc::new(Mutex::new(Ok(RawDatagramWriter::new(1024))));
        let writer = DatagramWriter(writer);

        let data = Bytes::from_static(b"hello world");
        writer.send_bytes(data.clone()).unwrap();
        assert!(writer
            .try_read_datagram(&mut TransportLimit::new(None, usize::MAX, 0), &mut [0; 1])
            .is_none());
    }

    #[test]
    fn test_datagram_writer_exceeds_limit() {
        let writer = Arc::new(Mutex::new(Ok(RawDatagramWriter::new(10))));
        let writer = DatagramWriter(writer);

        let data = Bytes::from_static(b"hello world");
        let result = writer.send_bytes(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_datagram_writer_update_remote_max_datagram_frame_size() {
        let writer = Arc::new(Mutex::new(Ok(RawDatagramWriter::new(1024))));
        let writer = DatagramWriter(writer);

        writer.update_remote_max_datagram_frame_size(2048).unwrap();
        let writer_guard = writer.0.lock().unwrap();
        let writer = writer_guard.as_ref().unwrap();
        assert_eq!(writer.remote_max_size, 2048);
    }

    #[test]
    fn test_datagram_writer_reduce_remote_max_datagram_frame_size() {
        let writer = Arc::new(Mutex::new(Ok(RawDatagramWriter::new(1024))));
        let writer = DatagramWriter(writer);

        let result = writer.update_remote_max_datagram_frame_size(512);
        assert!(result.is_err());
    }

    #[test]
    fn test_datagram_writer_on_conn_error() {
        let writer = Arc::new(Mutex::new(Ok(RawDatagramWriter::new(1024))));
        let writer = DatagramWriter(writer);

        writer.on_conn_error(&Error::new(
            ErrorKind::ProtocolViolation,
            FrameType::Datagram(0),
            "test",
        ));
        let writer_guard = writer.0.lock().unwrap();
        assert!(writer_guard.as_ref().is_err());
    }
}
