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
    net::{DataWakers, StreamWakers},
    param::CommonParameters,
    sid::{ControlConcurrency, Role, StreamId},
};

use crate::{recv::Reader, send::Writer};
mod io;
mod listener;
pub mod raw;

#[derive(Debug, Clone)]
pub struct Ext<T: Clone>(T);

impl<TX, F> SendFrame<F> for Ext<TX>
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
    F: Into<StreamCtlFrame>,
{
    fn send_frame<I: IntoIterator<Item = F>>(&self, iter: I) {
        self.0.send_frame(iter.into_iter().map(Into::into));
    }
}

/// Shared data streams, one for each connection.
///
/// App layer can use it to create and accept bidirectional or unidirectional streams.
/// QUIC layer will read frames and data from the streams and send them to peer,
/// and also write the frames and data received from peer to this data streams.
///
/// The `TX` is the frame sender, it should be able to send the [`StreamCtlFrame`], including:
/// - [`StreamCtlFrame::MaxStreamData`]
/// - [`StreamCtlFrame::MaxStreams`]
/// - [`StreamCtlFrame::StreamDataBlocked`]
/// - [`StreamCtlFrame::StreamsBlocked`]
/// - [`StreamCtlFrame::StopSending`]
/// - [`StreamCtlFrame::ResetStream`]
///
/// See [`raw::DataStreams`] for more details.
#[derive(Debug, Clone, Deref)]
pub struct DataStreams<TX>(Arc<raw::DataStreams<TX>>)
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static;

impl<TX> DataStreams<TX>
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    /// Creates a new instance of [`DataStreams`].
    ///
    /// The `ctrl_frames` is the frame sender, read [`raw::DataStreams`] for more details.
    pub fn new(
        role: Role,
        local_params: &CommonParameters,
        ctrl: Box<dyn ControlConcurrency>,
        ctrl_frames: TX,
        stream_wakers: StreamWakers,
        data_wakers: DataWakers,
    ) -> Self {
        Self(Arc::new(raw::DataStreams::new(
            role,
            local_params,
            ctrl,
            ctrl_frames,
            stream_wakers,
            data_wakers,
        )))
    }

    /// Create a bidirectional stream, see the method of the same name on `QuicConnection` for more.
    #[inline]
    pub fn open_bi(&self, snd_wnd_size: u64) -> OpenBiStream<TX> {
        OpenBiStream {
            inner: self,
            snd_wnd_size,
        }
    }

    /// Create a unidirectional stream, see the method of the same name on `QuicConnection` for more.
    #[inline]
    pub fn open_uni(&self, snd_wnd_size: u64) -> OpenUniStream<TX> {
        OpenUniStream {
            inner: self,
            snd_wnd_size,
        }
    }

    /// Accpet a bidirectional stream, see the method of the same name on `QuicConnection` for more.
    #[inline]
    pub fn accept_bi(&self, snd_wnd_size: u64) -> AcceptBiStream<Ext<TX>> {
        self.0.accept_bi(snd_wnd_size)
    }

    /// Accpet a unidirectional stream, see the method of the same name on `QuicConnection` for more.
    #[inline]
    pub fn accept_uni(&self) -> AcceptUniStream<Ext<TX>> {
        self.0.accept_uni()
    }
}

impl<TX> ReceiveFrame<StreamCtlFrame> for DataStreams<TX>
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    type Output = usize;

    fn recv_frame(&self, frame: &StreamCtlFrame) -> Result<Self::Output, Error> {
        self.0.recv_stream_control(frame)
    }
}

impl<TX> ReceiveFrame<(StreamFrame, Bytes)> for DataStreams<TX>
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
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
pub struct OpenBiStream<'d, TX>
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    inner: &'d raw::DataStreams<TX>,
    snd_wnd_size: u64,
}

impl<TX> Future for OpenBiStream<'_, TX>
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    type Output = Result<Option<(StreamId, (Reader<Ext<TX>>, Writer<Ext<TX>>))>, Error>;

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
pub struct OpenUniStream<'d, TX>
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    inner: &'d raw::DataStreams<TX>,
    snd_wnd_size: u64,
}

impl<TX> Future for OpenUniStream<'_, TX>
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    type Output = Result<Option<(StreamId, Writer<Ext<TX>>)>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.poll_open_uni_stream(cx, self.snd_wnd_size)
    }
}
