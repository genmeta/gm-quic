use crate::{recv::Reader, reliable::ArcReliableFrameQueue, send::Writer};
use futures::Future;
use qbase::{error::Error, frame::*, streamid::Role};
use std::{
    fmt::Debug,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

/// For sending stream data
pub trait TransmitStream {
    /// read data to transmit
    fn try_read_data(&self, buf: &mut [u8]) -> Option<(StreamFrame, usize)>;

    fn on_data_acked(&self, stream_frame: StreamFrame);

    fn may_loss_data(&self, stream_frame: StreamFrame);

    fn on_reset_acked(&self, reset_frame: ResetStreamFrame);
}

pub trait ReceiveStream {
    fn recv_frame(&self, stream_ctl_frame: StreamCtlFrame) -> Result<(), Error>;

    fn recv_data(&self, stream_frame: StreamFrame, body: bytes::Bytes) -> Result<(), Error>;

    fn on_conn_error(&self, err: &Error);
}

pub mod data;
pub mod listener;
pub mod none;

#[derive(Debug, Clone)]
pub struct ArcDataStreams(Arc<data::RawDataStreams>);

impl TransmitStream for ArcDataStreams {
    fn try_read_data(&self, buf: &mut [u8]) -> Option<(StreamFrame, usize)> {
        self.0.try_read_data(buf)
    }

    fn on_data_acked(&self, stream_frame: StreamFrame) {
        self.0.on_data_acked(stream_frame)
    }

    fn may_loss_data(&self, stream_frame: StreamFrame) {
        self.0.may_loss_data(stream_frame)
    }

    fn on_reset_acked(&self, reset_frame: ResetStreamFrame) {
        self.0.on_reset_acked(reset_frame)
    }
}

impl ReceiveStream for ArcDataStreams {
    fn recv_frame(&self, stream_ctl_frame: StreamCtlFrame) -> Result<(), Error> {
        self.0.recv_frame(stream_ctl_frame)
    }

    fn recv_data(&self, stream_frame: StreamFrame, body: bytes::Bytes) -> Result<(), Error> {
        self.0.recv_data(stream_frame, body)
    }

    fn on_conn_error(&self, err: &Error) {
        self.0.on_conn_error(err)
    }
}

impl ArcDataStreams {
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

    pub fn open_bi(&self) -> BiDataStreamCreator {
        BiDataStreamCreator {
            inner: self.0.clone(),
        }
    }

    pub fn open_uni(&self) -> UniDataStreamCreator {
        UniDataStreamCreator {
            inner: self.0.clone(),
        }
    }

    #[inline]
    pub fn listener(&self) -> listener::ArcListener {
        self.0.listener()
    }
}

#[derive(Debug, Clone)]
pub struct BiDataStreamCreator {
    inner: Arc<data::RawDataStreams>,
}

impl Future for BiDataStreamCreator {
    type Output = Result<Option<(Reader, Writer)>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.poll_open_bi_stream(cx)
    }
}

#[derive(Debug, Clone)]
pub struct UniDataStreamCreator {
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
