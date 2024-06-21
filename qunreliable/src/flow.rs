use std::sync::Arc;

use bytes::BufMut;
use qbase::{
    error::{Error, ErrorKind},
    frame::{BeFrame, DatagramFrame},
};
use tokio::sync::Mutex;

use super::{
    reader::{DatagramReader, RawDatagramReader},
    writer::{DatagramWriter, RawDatagramWriter},
};

#[derive(Debug, Clone)]
pub struct RawDatagramFlow {
    max_datagram_frame_size: u64,
    reader: DatagramReader,
    writer: DatagramWriter,
}

impl RawDatagramFlow {
    fn new(max_datagram_frame_size: u64) -> Self {
        let reader = RawDatagramReader::default();
        let writer = RawDatagramWriter::new(max_datagram_frame_size as _);

        Self {
            max_datagram_frame_size,
            reader: DatagramReader(Arc::new(Mutex::new(Ok(reader)))),
            writer: DatagramWriter(Arc::new(Mutex::new(Ok(writer)))),
        }
    }

    fn try_read_datagram(&self, buf: &mut impl BufMut) -> Option<DatagramFrame> {
        self.writer.try_read_datagram(buf)
    }

    fn recv_datagram(&self, frame: DatagramFrame, body: bytes::Bytes) -> Result<(), Error> {
        if (body.len() + frame.encoding_size()) as u64 > self.max_datagram_frame_size {
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
pub struct DatagramFlow {
    stream: Option<RawDatagramFlow>,
}

impl DatagramFlow {
    #[inline]
    pub fn new(max_datagram_frame_size: u64) -> Self {
        let stream = if max_datagram_frame_size == 0 {
            None
        } else {
            Some(RawDatagramFlow::new(max_datagram_frame_size))
        };
        Self { stream }
    }

    #[inline]
    pub fn try_read_datagram(&self, buf: &mut impl BufMut) -> Option<DatagramFrame> {
        self.stream.as_ref()?.try_read_datagram(buf)
    }

    #[inline]
    pub fn recv_datagram(&self, frame: DatagramFrame, body: bytes::Bytes) -> Result<(), Error> {
        self.stream
            .as_ref()
            .ok_or_else(|| disenabled(&frame))?
            .recv_datagram(frame, body)
    }

    #[inline]
    pub fn rw(&self) -> Result<(DatagramReader, DatagramWriter), Error> {
        let s = self.stream.as_ref().ok_or_else(disenabled_datagram)?;
        Ok((
            DatagramReader(s.reader.0.clone()),
            DatagramWriter(s.writer.0.clone()),
        ))
    }

    #[inline]
    pub fn on_conn_error(&self, error: &Error) {
        if let Some(s) = &self.stream {
            s.reader.on_conn_error(error);
            s.writer.on_conn_error(error);
        }
    }
}

fn disenabled(frame: &DatagramFrame) -> Error {
    Error::new(
        ErrorKind::ProtocolViolation,
        frame.frame_type(),
        "DatagramFrame was disenabled",
    )
}

fn disenabled_datagram() -> Error {
    disenabled(&DatagramFrame { length: None })
}
