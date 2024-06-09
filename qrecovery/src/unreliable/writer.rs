use std::{
    io,
    ops::DerefMut,
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use qbase::error::Error;

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
    pub(super) fn on_conn_error(&self, error: &Error) {
        let writer = &mut self.0.lock().unwrap();
        let inner = writer.deref_mut();
        if inner.is_ok() {
            *inner = Err(io::Error::new(io::ErrorKind::BrokenPipe, error.to_string()));
        }
    }

    // 看似异步，实际上完全是同步的...
    // TODO: 这里或许需要修改
    pub async fn send_bytes(&self, data: Bytes) -> io::Result<()> {
        match self.0.lock().unwrap().deref_mut() {
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
