use super::AppStream;
use futures::Future;
use qbase::{
    error::Error,
    frame::*,
    streamid::{Dir, Role},
};
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

    pub fn new_bi(&self) -> ArcDataStreamCreator {
        ArcDataStreamCreator {
            inner: self.0.clone(),
            dir: Dir::Bi,
        }
    }

    pub fn new_uni(&self) -> ArcDataStreamCreator {
        ArcDataStreamCreator {
            inner: self.0.clone(),
            dir: Dir::Uni,
        }
    }

    #[inline]
    pub fn listener(&self) -> listener::ArcListener {
        self.0.listener()
    }
}

#[derive(Debug, Clone)]
pub struct ArcDataStreamCreator {
    inner: Arc<data::DataStreams>,
    dir: Dir,
}

impl Future for ArcDataStreamCreator {
    type Output = Option<AppStream>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.poll_create_stream(cx, self.dir)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
