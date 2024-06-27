use std::{io, ops::DerefMut, sync::Arc};

use bytes::{BufMut, Bytes};
use qbase::{
    error::Error,
    frame::{io::WriteDatagramFrame, BeFrame, DatagramFrame},
    varint::VarInt,
};
use tokio::sync::Mutex;

use super::queue::DatagramQueue;

#[derive(Debug)]
pub struct RawDatagramWriter {
    max_size: usize,
    queue: DatagramQueue,
}

impl RawDatagramWriter {
    pub fn new(max_size: usize) -> Self {
        Self {
            max_size,
            queue: Default::default(),
        }
    }
}

pub type ArcDatagramWriter = Arc<Mutex<io::Result<RawDatagramWriter>>>;

#[derive(Debug, Clone)]
pub struct DatagramWriter(pub(super) ArcDatagramWriter);

impl DatagramWriter {
    pub(super) fn try_read_datagram(&self, mut buf: &mut [u8]) -> Option<(DatagramFrame, usize)> {
        let mut guard = self.0.blocking_lock();
        let writer = guard.as_mut().ok()?;
        let datagram = writer.queue.peek()?;

        let unwritten = buf.remaining_mut();
        if unwritten == 1 + datagram.len() {
            let frame = DatagramFrame::new(None);
            buf.put_datagram_frame(&frame, datagram);
            return Some((frame, unwritten - buf.remaining_mut()));
        }
        let frame = DatagramFrame::new(Some(VarInt::try_from(datagram.len()).unwrap()));
        if unwritten >= frame.encoding_size() + datagram.len() {
            buf.put_datagram_frame(&frame, datagram);
            Some((frame, unwritten - buf.remaining_mut()))
        } else {
            None
        }
    }

    pub(super) fn on_conn_error(&self, error: &Error) {
        let writer = &mut self.0.blocking_lock();
        let inner = writer.deref_mut();
        if inner.is_ok() {
            *inner = Err(io::Error::new(io::ErrorKind::BrokenPipe, error.to_string()));
        }
    }

    pub async fn send_bytes(&self, data: Bytes) -> io::Result<()> {
        match self.0.lock().await.deref_mut() {
            Ok(writer) => {
                if data.len() > writer.max_size {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "datagram frame size exceeds the limit",
                    ));
                }
                writer.queue.write(data);
                Ok(())
            }
            Err(e) => Err(io::Error::new(e.kind(), e.to_string())),
        }
    }

    pub async fn send(&self, data: &[u8]) -> io::Result<()> {
        self.send_bytes(data.to_vec().into()).await
    }
}
