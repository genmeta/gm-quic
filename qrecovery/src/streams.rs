use std::{
    fmt::Debug,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use deref_derive::Deref;
use futures::Future;
use qbase::{
    error::Error,
    frame::{ReceiveFrame, StreamCtlFrame, StreamFrame},
    streamid::Role,
};

use crate::{recv::Reader, reliable::ArcReliableFrameDeque, send::Writer};

pub mod crypto;
pub mod data;
pub mod listener;

#[derive(Debug, Clone, Deref)]
pub struct DataStreams(Arc<data::RawDataStreams>);

impl DataStreams {
    pub fn with_role_and_limit(
        role: Role,
        max_bi_streams: u64,
        max_uni_streams: u64,
        initial_max_stream_data_bidi_local: u64,
        initial_max_stream_data_bidi_remote: u64,
        initial_max_stream_data_uni: u64,
        reliable_frame_deque: ArcReliableFrameDeque,
    ) -> Self {
        Self(Arc::new(data::RawDataStreams::with_role_and_limit(
            role,
            max_bi_streams,
            max_uni_streams,
            initial_max_stream_data_bidi_local,
            initial_max_stream_data_bidi_remote,
            initial_max_stream_data_uni,
            reliable_frame_deque,
        )))
    }

    #[inline]
    pub fn open_bi(&self) -> BiDataStreamCreator {
        BiDataStreamCreator {
            inner: self.0.clone(),
        }
    }

    #[inline]
    pub fn open_uni(&self) -> UniDataStreamCreator {
        UniDataStreamCreator {
            inner: self.0.clone(),
        }
    }

    pub fn listener(&self) -> listener::ArcListener {
        self.0.listener()
    }
}

impl ReceiveFrame<StreamCtlFrame> for DataStreams {
    type Output = ();

    fn recv_frame(&mut self, frame: &StreamCtlFrame) -> Result<Self::Output, Error> {
        self.0.recv_stream_control(frame)
    }
}

impl ReceiveFrame<(StreamFrame, Bytes)> for DataStreams {
    type Output = usize;

    fn recv_frame(&mut self, frame: &(StreamFrame, Bytes)) -> Result<Self::Output, Error> {
        self.0.recv_data(frame)
    }
}

pub struct BiDataStreamCreator {
    inner: Arc<data::RawDataStreams>,
}

impl Future for BiDataStreamCreator {
    type Output = Result<Option<(Reader, Writer)>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.poll_open_bi_stream(cx)
    }
}

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
