use std::{
    fmt::Debug,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use deref_derive::Deref;
use listener::{AcceptBiStream, AcceptUniStream};
use qbase::{
    config::Parameters,
    error::Error,
    streamid::{Dir, Role},
};

use crate::{recv::Reader, reliable::ArcReliableFrameDeque, send::Writer};

pub mod crypto;
pub mod data;
pub mod listener;

#[derive(Debug, Clone, Deref)]
pub struct DataStreams(Arc<data::RawDataStreams>);

impl DataStreams {
    pub fn new(
        role: Role,
        local_params: &Parameters,
        reliable_frame_deque: ArcReliableFrameDeque,
    ) -> Self {
        let raw = data::RawDataStreams::new(role, local_params, reliable_frame_deque);

        Self(Arc::new(raw))
    }

    #[inline]
    pub fn open_bi<'a>(
        &'a self,
        local_params: &'a Parameters,
        remote_params: &'a Parameters,
    ) -> OpenBiStream<'a> {
        OpenBiStream {
            stream: self,
            local_params,
            remote_params,
        }
    }

    #[inline]
    pub fn open_uni<'a>(&'a self, remote_params: &'a Parameters) -> OpenUniStream<'a> {
        OpenUniStream {
            stream: self,
            remote_params,
        }
    }

    #[inline]
    pub fn accept_bi(&self) -> AcceptBiStream {
        self.0.accept_bi()
    }

    #[inline]
    pub fn accept_uni(&self) -> AcceptUniStream {
        self.0.accept_uni()
    }

    #[inline]
    pub fn listener(&self) -> listener::ArcListener {
        self.0.listener()
    }

    #[inline]
    pub fn premit_max_sid(&self, dir: Dir, val: u64) {
        self.0.premit_max_sid(dir, val);
    }
}

pub struct OpenBiStream<'a> {
    stream: &'a DataStreams,
    local_params: &'a Parameters,
    remote_params: &'a Parameters,
}

impl Future for OpenBiStream<'_> {
    type Output = Result<Option<(Reader, Writer)>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.stream
            .poll_open_bi_stream(cx, self.local_params, self.remote_params)
    }
}

pub struct OpenUniStream<'a> {
    stream: &'a DataStreams,
    remote_params: &'a Parameters,
}

impl Future for OpenUniStream<'_> {
    type Output = Result<Option<Writer>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.stream.poll_open_uni_stream(cx, self.remote_params)
    }
}

#[cfg(test)]
mod tests {}
