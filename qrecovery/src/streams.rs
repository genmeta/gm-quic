use std::{
    fmt::Debug,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures::Future;
use qbase::{error::Error, frame::*, streamid::Role};

use crate::{recv::Reader, reliable::ArcReliableFrameQueue, send::Writer};

pub mod data;
pub mod listener;

#[derive(Debug, Clone)]
pub struct DataStreams(Arc<data::RawDataStreams>);

impl AsRef<DataStreams> for DataStreams {
    fn as_ref(&self) -> &DataStreams {
        self
    }
}

impl DataStreams {
    pub fn try_read_data(&self, buf: &mut [u8]) -> Option<(StreamFrame, usize)> {
        self.0.try_read_data(buf)
    }

    pub fn on_data_acked(&self, stream_frame: StreamFrame) {
        self.0.on_data_acked(stream_frame)
    }

    pub fn may_loss_data(&self, stream_frame: StreamFrame) {
        self.0.may_loss_data(stream_frame)
    }

    pub fn on_reset_acked(&self, reset_frame: ResetStreamFrame) {
        self.0.on_reset_acked(reset_frame)
    }

    pub fn recv_stream_control(&self, stream_ctl_frame: StreamCtlFrame) -> Result<(), Error> {
        self.0.recv_stream_control(stream_ctl_frame)
    }

    pub fn recv_data(&self, frame: StreamFrame, body: bytes::Bytes) -> Result<(), Error> {
        self.0.recv_data(frame, body)
    }

    pub fn on_conn_error(&self, err: &Error) {
        self.0.on_conn_error(err)
    }

    pub fn update_limit(&self, max_bi_streams: u64, max_uni_streams: u64) {
        self.0.update_limit(max_bi_streams, max_uni_streams)
    }
}

impl DataStreams {
    pub fn with_role_and_limit(
        role: Role,
        max_bi_streams: u64,
        max_uni_streams: u64,
        reliable_frame_queue: ArcReliableFrameQueue,
    ) -> Self {
        Self(Arc::new(data::RawDataStreams::with_role_and_limit(
            role,
            max_bi_streams,
            max_uni_streams,
            reliable_frame_queue,
        )))
    }

    pub async fn open_bi(&self) -> Result<Option<(Reader, Writer)>, Error> {
        BiDataStreamCreator {
            inner: self.0.clone(),
        }
        .await
    }

    pub async fn open_uni(&self) -> Result<Option<Writer>, Error> {
        UniDataStreamCreator {
            inner: self.0.clone(),
        }
        .await
    }

    pub fn listener(&self) -> listener::ArcListener {
        self.0.listener()
    }
}

struct BiDataStreamCreator {
    inner: Arc<data::RawDataStreams>,
}

impl Future for BiDataStreamCreator {
    type Output = Result<Option<(Reader, Writer)>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.poll_open_bi_stream(cx)
    }
}

struct UniDataStreamCreator {
    inner: Arc<data::RawDataStreams>,
}

impl Future for UniDataStreamCreator {
    type Output = Result<Option<Writer>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.poll_open_uni_stream(cx)
    }
}

#[cfg(test)]
mod tests {}
