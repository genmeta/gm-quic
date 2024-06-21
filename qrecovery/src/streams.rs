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
pub struct ArcDataStreams(Arc<data::RawDataStreams>);

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
