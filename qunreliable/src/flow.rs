use std::sync::Arc;

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
    flow: Option<RawDatagramFlow>,
}

impl DatagramFlow {
    #[inline]
    pub fn new(max_datagram_frame_size: u64) -> Self {
        let flow = if max_datagram_frame_size == 0 {
            None
        } else {
            Some(RawDatagramFlow::new(max_datagram_frame_size))
        };
        Self { flow }
    }

    #[inline]
    pub fn try_read_datagram(&self, buf: &mut [u8]) -> Option<(DatagramFrame, usize)> {
        self.flow.as_ref()?.writer.try_read_datagram(buf)
    }

    #[inline]
    pub fn recv_datagram(&self, frame: DatagramFrame, body: bytes::Bytes) -> Result<(), Error> {
        self.flow
            .as_ref()
            .ok_or_else(|| disenabled(&frame))?
            .recv_datagram(frame, body)
    }

    #[inline]
    pub fn rw(&self) -> Result<(DatagramReader, DatagramWriter), Error> {
        let flow = self.flow.as_ref().ok_or_else(disenabled_datagram)?;
        Ok((
            DatagramReader(flow.reader.0.clone()),
            DatagramWriter(flow.writer.0.clone()),
        ))
    }

    #[inline]
    pub fn on_conn_error(&self, error: &Error) {
        if let Some(flow) = &self.flow {
            flow.reader.on_conn_error(error);
            flow.writer.on_conn_error(error);
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
