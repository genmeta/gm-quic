use crate::{recv::Reader, send::Writer};
use futures::Future;
use qbase::{error::Error, frame::*, streamid::Role};
use std::{
    collections::VecDeque,
    fmt::Debug,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

pub trait Output {
    type Outgoing: TransmitStream + Debug;

    fn output(&self) -> Self::Outgoing;
}

/// For sending stream data
pub trait TransmitStream {
    /// read data to transmit
    fn try_read_data(&mut self, buf: &mut [u8]) -> Option<(StreamFrame, usize)>;

    fn confirm_data_rcvd(&self, stream_frame: StreamFrame);

    fn may_loss_data(&self, stream_frame: StreamFrame);

    fn confirm_reset_rcvd(&self, reset_frame: ResetStreamFrame);
}

pub trait ReceiveStream {
    fn recv_frame(&self, stream_ctl_frame: StreamCtlFrame) -> Result<(), Error>;

    fn recv_data(&self, stream_frame: StreamFrame, body: bytes::Bytes) -> Result<(), Error>;

    fn conn_error(&self, err: &Error);
}

pub mod data;
pub mod listener;
pub mod none;

#[derive(Debug, Clone)]
pub struct ArcDataStreams(Arc<data::DataStreams>);

impl Output for ArcDataStreams {
    type Outgoing = data::ArcOutput;

    fn output(&self) -> Self::Outgoing {
        self.0.output()
    }
}

impl ReceiveStream for ArcDataStreams {
    fn recv_frame(&self, stream_ctl_frame: StreamCtlFrame) -> Result<(), Error> {
        self.0.recv_frame(stream_ctl_frame)
    }

    fn recv_data(&self, stream_frame: StreamFrame, body: bytes::Bytes) -> Result<(), Error> {
        self.0.recv_data(stream_frame, body)
    }

    fn conn_error(&self, err: &Error) {
        self.0.conn_error(err)
    }
}

impl ArcDataStreams {
    pub fn with_role_and_limit(
        role: Role,
        max_bi_streams: u64,
        max_uni_streams: u64,
        sending_frames: Arc<Mutex<VecDeque<ReliableFrame>>>,
    ) -> Self {
        Self(Arc::new(data::DataStreams::with_role_and_limit(
            role,
            max_bi_streams,
            max_uni_streams,
            sending_frames,
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
    inner: Arc<data::DataStreams>,
}

impl Future for BiDataStreamCreator {
    type Output = Result<Option<(Reader, Writer)>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.poll_open_bi_stream(cx)
    }
}

#[derive(Debug, Clone)]
pub struct UniDataStreamCreator {
    inner: Arc<data::DataStreams>,
}

impl Future for UniDataStreamCreator {
    type Output = Result<Option<Writer>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.poll_open_uni_stream(cx)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
