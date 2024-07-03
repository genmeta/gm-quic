use std::sync::{Arc, RwLock};

use bytes::Bytes;
use futures::StreamExt;
use qbase::{error::Error, frame::DatagramFrame, util::ArcAsyncDeque};
use tokio::sync::{mpsc, Mutex};

use super::{
    reader::{DatagramReader, RawDatagramReader},
    writer::{DatagramWriter, RawDatagramWriter},
};

#[derive(Debug, Clone)]
pub struct RawDatagramFlow {
    reader: DatagramReader,
    writer: DatagramWriter,
}

impl RawDatagramFlow {
    fn new(local_max_datagram_frame_size: u64, remote_max_datagram_frame_size: u64) -> Self {
        let reader = RawDatagramReader::new(remote_max_datagram_frame_size as _);
        let writer = RawDatagramWriter::new(local_max_datagram_frame_size as _);

        Self {
            reader: DatagramReader(Arc::new(Mutex::new(Ok(reader)))),
            writer: DatagramWriter(Arc::new(Mutex::new(Ok(writer)))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DatagramFlow {
    raw_flow: Arc<RwLock<RawDatagramFlow>>,
}

impl DatagramFlow {
    #[inline]
    pub fn new(local_max_datagram_frame_size: u64, remote_max_datagram_frame_size: u64) -> Self {
        let flow = RawDatagramFlow::new(
            local_max_datagram_frame_size,
            remote_max_datagram_frame_size,
        );
        Self {
            raw_flow: Arc::new(RwLock::new(flow)),
        }
    }

    /// 如果对方在新的连接中缩小了max_data_frame_size，必须返回协议错误
    #[inline]
    pub fn update_remote_max_datagram_frame_size(&self, new_size: usize) -> Result<(), Error> {
        let flow = self.raw_flow.read().unwrap();
        flow.writer.update_remote_max_datagram_frame_size(new_size)
    }

    #[inline]
    pub fn try_read_datagram(&self, buf: &mut [u8]) -> Option<(DatagramFrame, usize)> {
        self.raw_flow.read().unwrap().writer.try_read_datagram(buf)
    }

    #[inline]
    pub fn recv_datagram(&self, frame: DatagramFrame, body: bytes::Bytes) -> Result<(), Error> {
        self.raw_flow
            .read()
            .unwrap()
            .reader
            .recv_datagram(frame, body)
    }

    #[inline]
    pub fn rw(&self) -> (DatagramReader, DatagramWriter) {
        let flow = self.raw_flow.read().unwrap();
        (
            DatagramReader(flow.reader.0.clone()),
            DatagramWriter(flow.writer.0.clone()),
        )
    }

    #[inline]
    pub fn on_conn_error(&self, error: &Error) {
        let raw_flow = self.raw_flow.read().unwrap();
        raw_flow.reader.on_conn_error(error);
        raw_flow.writer.on_conn_error(error);
    }

    #[inline]
    pub fn spawn_recv_datagram_frames(
        &self,
        error_tx: mpsc::UnboundedSender<Error>,
    ) -> ArcAsyncDeque<(DatagramFrame, Bytes)> {
        let (reader, _) = self.rw();
        let deque: ArcAsyncDeque<(DatagramFrame, Bytes)> = ArcAsyncDeque::new();
        tokio::spawn({
            let mut deque = deque.clone();
            async move {
                while let Some((frame, data)) = deque.next().await {
                    if let Err(error) = reader.recv_datagram(frame, data) {
                        _ = error_tx.send(error);
                    }
                }
            }
        });
        deque
    }
}
