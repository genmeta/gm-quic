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
    frame::{ReceiveFrame, SendFrame, StreamCtlFrame, StreamFrame},
    streamid::{Dir, Role},
};

use crate::{recv::Reader, send::Writer};

pub mod crypto;
pub mod data;
pub mod listener;

#[derive(Debug, Clone, Deref)]
pub struct DataStreams<T>(Arc<data::RawDataStreams<T>>)
where
    T: SendFrame<StreamCtlFrame> + Clone + Send + 'static;

impl<T> DataStreams<T>
where
    T: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    pub fn new(role: Role, local_params: &Parameters, ctrl_frames: T) -> Self {
        let raw = data::RawDataStreams::new(role, local_params, ctrl_frames);

        Self(Arc::new(raw))
    }

    #[inline]
    pub fn open_bi(&self, snd_wnd_size: u64) -> OpenBiStream<T> {
        OpenBiStream {
            inner: self.0.clone(),
            snd_wnd_size,
        }
    }

    #[inline]
    pub fn open_uni(&self, snd_wnd_size: u64) -> OpenUniStream<T> {
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

impl<T> ReceiveFrame<StreamCtlFrame> for DataStreams<T>
where
    T: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    type Output = ();

    fn recv_frame(&self, frame: &StreamCtlFrame) -> Result<Self::Output, Error> {
        self.0.recv_stream_control(frame)
    }
}

impl<T> ReceiveFrame<(StreamFrame, Bytes)> for DataStreams<T>
where
    T: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    type Output = usize;

    fn recv_frame(&self, frame: &(StreamFrame, Bytes)) -> Result<Self::Output, Error> {
        self.0.recv_data(frame)
    }
}

pub struct OpenBiStream<T>
where
    T: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    inner: Arc<data::RawDataStreams<T>>,
    snd_wnd_size: u64,
}

impl<T> Future for OpenBiStream<T>
where
    T: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    type Output = Result<Option<(Reader, Writer)>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.poll_open_bi_stream(cx, self.snd_wnd_size)
    }
}

pub struct OpenUniStream<T>
where
    T: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    inner: Arc<data::RawDataStreams<T>>,
    snd_wnd_size: u64,
}

impl<T> Future for OpenUniStream<T>
where
    T: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    type Output = Result<Option<Writer>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.poll_open_uni_stream(cx, self.snd_wnd_size)
    }
}

#[cfg(test)]
mod tests {}
