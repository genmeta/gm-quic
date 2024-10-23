//! The internal implementation of the QUIC stream.
//!
//! If you want to know how to create a stream, see the `QuicConnection` in another crate for more.
//!
//! If you want to know how to use a stream, see the [`Reader`] and [`Writer`] for more details.
//!
//! The structure in this module does not have the ability to actually send and receive frames, or
//! sense the loss or confirmation of frames. These functions are implemented by other modules. This
//! module provides the ability to generate frames, process frames, handle the frame lost and acked,
//! manage the state of all streams.
//!
//! [`DataStreams`] provides a large number of APIs for other blocks to call to achieve the above functions.
//! It corresponds to all streams on the connection.
//!
//! [`Incoming`] and[`Outgoing`] correspond to the input and output of a stream. They manage the sending and
//! receiving state machines and provide APIs for DataStream to use.
//!
//! [`Incoming`]: crate::recv::Incoming
//! [`Outgoing`]: crate::send::Outgoing
use std::{
    fmt::Debug,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use deref_derive::Deref;
pub use listener::{AcceptBiStream, AcceptUniStream};
use qbase::{
    error::Error,
    frame::{ReceiveFrame, SendFrame, StreamCtlFrame, StreamFrame},
    param::Parameters,
    sid::Role,
};
use thiserror::Error;

use crate::{recv::Reader, send::Writer};
mod io;
mod listener;
pub mod raw;

/// The wrapper of [`raw::DataStreams`], provides the abality of share between tasks.
///
/// See [`raw::DataStreams`] for more details.
#[derive(Debug, Clone, Deref)]
pub struct DataStreams<T>(Arc<raw::DataStreams<T>>)
where
    T: SendFrame<StreamCtlFrame> + Clone + Send + 'static;

impl<T> DataStreams<T>
where
    T: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    /// Creates a new instance of [`DataStreams`].
    ///
    /// The `ctrl_frames` is the frame sender, read [`raw::DataStreams`] for more details.
    pub fn new(role: Role, local_params: &Parameters, ctrl_frames: T) -> Self {
        let raw = raw::DataStreams::new(role, local_params, ctrl_frames);

        Self(Arc::new(raw))
    }

    /// Create a bidirectional stream, see the method of the same name on `QuicConnection` for more.
    #[inline]
    pub fn open_bi(&self, snd_wnd_size: u64) -> OpenBiStream<T> {
        OpenBiStream {
            inner: self,
            snd_wnd_size,
        }
    }

    /// Create a unidirectional stream, see the method of the same name on `QuicConnection` for more.
    #[inline]
    pub fn open_uni(&self, snd_wnd_size: u64) -> OpenUniStream<T> {
        OpenUniStream {
            inner: self,
            snd_wnd_size,
        }
    }

    /// Accpet a bidirectional stream, see the method of the same name on `QuicConnection` for more.
    #[inline]
    pub fn accept_bi(&self, snd_wnd_size: u64) -> AcceptBiStream {
        self.0.accept_bi(snd_wnd_size)
    }

    /// Accpet a unidirectional stream, see the method of the same name on `QuicConnection` for more.
    #[inline]
    pub fn accept_uni(&self) -> AcceptUniStream {
        self.0.accept_uni()
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

/// Future to open a bidirectional stream.
///
/// The creation of the stream is limited by the stream id. Once the stream id is available, the
/// future will complete immediately.
///
/// If a connection error occurred, the future will return an error.
///
/// Although this is a bidirectional stream, the peer will not be aware of this stream until we send
/// a frame on this stream.
pub struct OpenBiStream<'d, T>
where
    T: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    inner: &'d raw::DataStreams<T>,
    snd_wnd_size: u64,
}

impl<T> Future for OpenBiStream<'_, T>
where
    T: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    type Output = Result<Option<(Reader, Writer)>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.poll_open_bi_stream(cx, self.snd_wnd_size)
    }
}

/// Future to open a unidirectional stream.
///
/// The creation of the stream is limited by the stream id. Once the stream id is available, the
/// future will complete immediately.
///
/// If a connection error occurred, the future will return an error.
///
/// Note that the peer will not be aware of this stream until we send a frame on this stream.
pub struct OpenUniStream<'d, T>
where
    T: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    inner: &'d raw::DataStreams<T>,
    snd_wnd_size: u64,
}

impl<T> Future for OpenUniStream<'_, T>
where
    T: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    type Output = Result<Option<Writer>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.poll_open_uni_stream(cx, self.snd_wnd_size)
    }
}

#[derive(Debug, Error, Clone, Copy)]
#[error("the stream reset with error code {0}")]
pub struct StreamReset(pub u64);
