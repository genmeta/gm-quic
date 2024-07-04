use std::{
    fmt::Debug,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use deref_derive::Deref;
use futures::Future;
use qbase::{error::Error, streamid::Role};

use crate::{recv::Reader, reliable::ArcReliableFrameQueue, send::Writer};

pub mod data;
pub mod listener;

#[derive(Debug, Clone, Deref)]
pub struct DataStreams(Arc<data::RawDataStreams>);

impl AsRef<DataStreams> for DataStreams {
    fn as_ref(&self) -> &DataStreams {
        self
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
