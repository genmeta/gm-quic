use std::{
    fmt::Debug,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use deref_derive::Deref;
use listener::{AcceptBiStream, AcceptUniStream};
use qbase::{
    config::Parameters,
    error::Error,
    frame::{ReceiveFrame, StreamCtlFrame, StreamFrame},
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
    pub fn open_bi(&self, snd_wnd_size: u64) -> OpenBiStream {
        OpenBiStream {
            inner: self.0.clone(),
            snd_wnd_size,
        }
    }

    #[inline]
    pub fn open_uni(&self, snd_wnd_size: u64) -> OpenUniStream {
        OpenUniStream {
            inner: self.0.clone(),
            snd_wnd_size,
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

pub struct OpenBiStream {
    inner: Arc<data::RawDataStreams>,
    snd_wnd_size: u64,
}

impl Future for OpenBiStream {
    type Output = Result<Option<(Reader, Writer)>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.poll_open_bi_stream(cx, self.snd_wnd_size)
    }
}

pub struct OpenUniStream {
    inner: Arc<data::RawDataStreams>,
    snd_wnd_size: u64,
}

impl Future for OpenUniStream {
    type Output = Result<Option<Writer>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.poll_open_uni_stream(cx, self.snd_wnd_size)
    }
}

#[cfg(test)]
mod tests {}
