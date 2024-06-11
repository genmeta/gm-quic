use super::{
    reader::{DatagramReader, RawDatagramReader},
    writer::{DatagramWriter, RawDatagramWriter},
};
use qbase::{
    error::{Error, ErrorKind},
    frame::{BeFrame, DatagramFrame},
};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct RawDatagramStream {
    max_datagram_frame_size: u64,
    reader: DatagramReader,
    writer: DatagramWriter,
}

impl RawDatagramStream {
    fn new(max_datagram_frame_size: u64) -> Self {
        let reader = RawDatagramReader::default();
        let writer = RawDatagramWriter::new(max_datagram_frame_size as _);

        Self {
            max_datagram_frame_size,
            reader: DatagramReader(Arc::new(Mutex::new(Ok(reader)))),
            writer: DatagramWriter(Arc::new(Mutex::new(Ok(writer)))),
        }
    }

    fn try_read_datagram(&self, buf: &mut [u8]) -> Option<(DatagramFrame, usize)> {
        self.writer.try_read_datagram(buf)
    }

    fn recv_datagram(&self, frame: DatagramFrame, body: bytes::Bytes) -> Result<(), Error> {
        if body.len() as u64 + 1 > self.max_datagram_frame_size {
            return Err(Error::new(
                ErrorKind::ProtocolViolation,
                frame.frame_type(),
                "datagram frame size exceeds the limit",
            ));
        }
        self.reader.recv_datagram(body);
        Ok(())
    }
}

#[derive(Default, Debug, Clone)]
pub enum DatagramStream {
    // 数据报流可能并没有启用
    #[default]
    Disenabled,
    Stream(RawDatagramStream),
}

impl DatagramStream {
    pub fn new(max_datagram_frame_size: u64) -> Self {
        if max_datagram_frame_size == 0 {
            Self::Disenabled
        } else {
            DatagramStream::Stream(RawDatagramStream::new(max_datagram_frame_size))
        }
    }

    pub fn try_read_datagram(&self, buf: &mut [u8]) -> Option<(DatagramFrame, usize)> {
        match self {
            DatagramStream::Disenabled => None,
            DatagramStream::Stream(s) => s.try_read_datagram(buf),
        }
    }

    pub fn recv_datagram(&self, frame: DatagramFrame, body: bytes::Bytes) -> Result<(), Error> {
        match self {
            DatagramStream::Disenabled => disenabled(&frame),
            DatagramStream::Stream(s) => s.recv_datagram(frame, body),
        }
    }

    pub fn rw(&self) -> Result<(DatagramReader, DatagramWriter), Error> {
        match self {
            DatagramStream::Disenabled => disenabled_datagram(),
            DatagramStream::Stream(s) => Ok((
                DatagramReader(s.reader.0.clone()),
                DatagramWriter(s.writer.0.clone()),
            )),
        }
    }

    pub(crate) fn on_conn_error(&self, error: &Error) {
        if let Self::Stream(ds) = self {
            ds.reader.on_conn_error(error);
            ds.writer.on_conn_error(error);
        }
    }
}

fn disenabled<T>(frame: &DatagramFrame) -> Result<T, Error> {
    Err(Error::new(
        ErrorKind::ProtocolViolation,
        frame.frame_type(),
        "DatagramFrame was disenabled",
    ))
}

fn disenabled_datagram<T>() -> Result<T, Error> {
    disenabled(&DatagramFrame { length: None })
}
