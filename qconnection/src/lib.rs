pub mod events;
pub mod handshake;
pub mod path;
pub mod space;
pub mod termination;
pub mod tls;
pub mod tx;

pub mod prelude {
    pub use qbase::{frame::ConnectionCloseFrame, sid::StreamId, varint::VarInt};
    pub use qinterface::{
        path::{Endpoint, Pathway, Socket},
        router::QuicProto,
        QuicInterface,
    };
    pub use qunreliable::{UnreliableReader, UnreliableWriter};

    #[allow(unused_imports)]
    pub mod handy {
        pub use qinterface::handy::*;
    }

    pub use crate::{
        events::{EmitEvent, Event},
        Connection, StreamReader, StreamWriter,
    };
}

pub mod builder;

use std::{
    borrow::Cow,
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context, Poll},
    time::Duration,
};

use deref_derive::Deref;
use events::ArcEventBroker;
use path::ArcPaths;
use qbase::{
    cid, flow,
    frame::{ConnectionCloseFrame, ReliableFrame, SendFrame},
    param::{self, ArcParameters},
    sid::StreamId,
    token::ArcTokenRegistry,
};
use qinterface::{
    path::{Pathway, Socket},
    queue::RcvdPacketQueue,
    router::{QuicProto, RouterRegistry},
};
use qrecovery::{
    recv, reliable, send,
    streams::{self, Ext},
};
use qunreliable::{UnreliableReader, UnreliableWriter};
use space::Spaces;
use termination::Termination;
use tls::ArcTlsSession;
use tokio::{io::AsyncWrite, sync::Notify};

#[derive(Clone, Deref)]
pub struct ArcReliableFrameDeque {
    #[deref]
    inner: reliable::ArcReliableFrameDeque,
    notify: Arc<Notify>,
}

impl ArcReliableFrameDeque {
    pub fn with_capacity_and_notify(capacity: usize, notify: Arc<Notify>) -> Self {
        Self {
            inner: reliable::ArcReliableFrameDeque::with_capacity(capacity),
            notify,
        }
    }
}

impl<T> SendFrame<T> for ArcReliableFrameDeque
where
    T: Into<ReliableFrame>,
{
    fn send_frame<I: IntoIterator<Item = T>>(&self, iter: I) {
        self.inner.send_frame(iter.into_iter().map(Into::into));
        self.notify.notify_waiters();
    }
}

pub type ArcLocalCids = cid::ArcLocalCids<RouterRegistry<ArcReliableFrameDeque>>;
pub type ArcRemoteCids = cid::ArcRemoteCids<ArcReliableFrameDeque>;
pub type CidRegistry = cid::Registry<ArcLocalCids, ArcRemoteCids>;
pub type ArcDcidCell = cid::ArcCidCell<ArcReliableFrameDeque>;

pub type FlowController = flow::FlowController<ArcReliableFrameDeque>;
pub type Credit<'a> = flow::Credit<'a, ArcReliableFrameDeque>;

pub type Handshake = handshake::Handshake<ArcReliableFrameDeque>;
pub type RawHandshake = handshake::RawHandshake<ArcReliableFrameDeque>;

pub type DataStreams = streams::DataStreams<ArcReliableFrameDeque>;
pub type StreamReader = recv::Reader<Ext<ArcReliableFrameDeque>>;
type RawStreamWriter = send::Writer<Ext<ArcReliableFrameDeque>>;
pub type StreamWriter = Writer<send::Writer<Ext<ArcReliableFrameDeque>>>;

// rename(ask AI)
pub struct Writer<W> {
    raw_writer: W,
    send_notify: Arc<Notify>,
}

impl<W> Writer<W> {
    fn new(raw_writer: W, send_notify: Arc<Notify>) -> Self {
        Self {
            raw_writer,
            send_notify,
        }
    }
}

impl Writer<RawStreamWriter> {
    pub fn cancel(&mut self, err_code: u64) {
        self.raw_writer.cancel(err_code);
    }
}

impl<W: Unpin> Unpin for Writer<W> {}

impl<W> AsyncWrite for Writer<W>
where
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match Pin::new(&mut self.raw_writer).poll_write(cx, buf) {
            sent @ Poll::Ready(Ok(_n)) => {
                self.send_notify.notify_waiters();
                sent
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.raw_writer).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.send_notify.notify_waiters();
        Pin::new(&mut self.raw_writer).poll_shutdown(cx)
    }
}

#[derive(Clone)]
pub struct Components {
    parameters: ArcParameters,
    tls_session: ArcTlsSession,
    handshake: Handshake,
    token_registry: ArcTokenRegistry,
    cid_registry: CidRegistry,
    flow_ctrl: FlowController,
    spaces: Spaces,
    paths: ArcPaths,
    proto: Arc<QuicProto>,
    rcvd_pkt_q: Arc<RcvdPacketQueue>,
    send_notify: Arc<Notify>,
    event_broker: ArcEventBroker,
    defer_idle_timeout: Duration,
}

impl Components {
    pub fn open_bi_stream(
        &self,
    ) -> impl Future<Output = io::Result<Option<(StreamId, (StreamReader, StreamWriter))>>> + Send + use<>
    {
        let params = self.parameters.clone();
        let streams = self.spaces.data().streams().clone();
        let send_notify = self.send_notify.clone();
        async move {
            let param::Pair { remote, .. } = params.await?;
            let map_bi_stream =
                |(id, (reader, writer))| (id, (reader, Writer::new(writer, send_notify.clone())));
            Ok(streams
                .open_bi(remote.initial_max_stream_data_bidi_remote().into())
                .await?
                .map(map_bi_stream))
        }
    }

    pub fn open_uni_stream(
        &self,
    ) -> impl Future<Output = io::Result<Option<(StreamId, StreamWriter)>>> + Send + use<> {
        let params = self.parameters.clone();
        let streams = self.spaces.data().streams().clone();
        let send_notify = self.send_notify.clone();
        async move {
            let param::Pair { remote, .. } = params.await?;
            let map_uni_stream = |(id, writer)| (id, Writer::new(writer, send_notify.clone()));
            Ok(streams
                .open_uni(remote.initial_max_stream_data_uni().into())
                .await?
                .map(map_uni_stream))
        }
    }

    pub fn accept_bi_stream(
        &self,
    ) -> impl Future<Output = io::Result<Option<(StreamId, (StreamReader, StreamWriter))>>> + Send + use<>
    {
        let params = self.parameters.clone();
        let streams = self.spaces.data().streams().clone();
        let send_notify = self.send_notify.clone();
        async move {
            let param::Pair { remote, .. } = params.await?;
            let map_bi_stream =
                |(id, (reader, writer))| (id, (reader, Writer::new(writer, send_notify.clone())));
            let bi_stream = streams
                .accept_bi(remote.initial_max_stream_data_bidi_local().into())
                .await?;
            Ok(Some(map_bi_stream(bi_stream)))
        }
    }

    pub fn accept_uni_stream(
        &self,
    ) -> impl Future<Output = io::Result<Option<(StreamId, StreamReader)>>> + Send + use<> {
        let streams = self.spaces.data().streams().clone();
        async move { Ok(Some(streams.accept_uni().await?)) }
    }

    pub fn unreliable_reader(&self) -> io::Result<UnreliableReader> {
        self.spaces.data().datagrams().reader()
    }

    pub fn unreliable_writer(
        &self,
    ) -> impl Future<Output = io::Result<UnreliableWriter>> + Send + use<> {
        let params = self.parameters.clone();
        let datagrams = self.spaces.data().datagrams().clone();
        async move {
            let param::Pair { remote, .. } = params.await?;
            datagrams.writer(remote.max_datagram_frame_size().into())
        }
    }

    pub fn add_path(&self, socket: Socket, pathway: Pathway) {
        self.get_or_create_path(socket, pathway, false);
    }

    pub fn del_path(&self, pathway: &Pathway) {
        self.paths.remove(pathway);
    }
}

pub struct Connection(RwLock<Result<Components, Termination>>);

impl Connection {
    #[tracing::instrument(level = "info", skip(self))]
    pub fn enter_closing(&self, ccf: ConnectionCloseFrame) {
        let mut conn = self.0.write().unwrap();
        if let Ok(core_conn) = conn.as_mut() {
            *conn = Err(core_conn.clone().enter_closing(ccf));
        }
    }

    #[tracing::instrument(level = "info", skip(self))]
    pub fn enter_draining(&self, ccf: ConnectionCloseFrame) {
        let error = ccf.into();
        let mut conn = self.0.write().unwrap();
        match conn.as_mut() {
            Ok(core_conn) => *conn = Err(core_conn.clone().enter_draining(error)),
            Err(termination) => termination.enter_draining(),
        }
    }

    #[tracing::instrument(level = "trace", skip(self))]
    pub fn close(&self, reason: Cow<'static, str>, code: u64) {
        let error_code = code.try_into().unwrap();
        self.enter_closing(ConnectionCloseFrame::new_app(error_code, reason));
    }

    fn map<T>(&self, op: impl Fn(&Components) -> T) -> io::Result<T> {
        let guard = self.0.read().unwrap();
        guard
            .as_ref()
            .map(op)
            .map_err(|termination| termination.error().into())
    }

    #[tracing::instrument(level = "trace", skip(self))]
    pub async fn open_bi_stream(
        &self,
    ) -> io::Result<Option<(StreamId, (StreamReader, StreamWriter))>> {
        self.map(|core_conn| core_conn.open_bi_stream())?.await
    }

    #[tracing::instrument(level = "trace", skip(self))]
    pub async fn open_uni_stream(&self) -> io::Result<Option<(StreamId, StreamWriter)>> {
        self.map(|core_conn| core_conn.open_uni_stream())?.await
    }

    #[tracing::instrument(level = "trace", skip(self))]
    pub async fn accept_bi_stream(
        &self,
    ) -> io::Result<Option<(StreamId, (StreamReader, StreamWriter))>> {
        self.map(|core_conn| core_conn.accept_bi_stream())?.await
    }

    #[tracing::instrument(level = "trace", skip(self))]
    pub async fn accept_uni_stream(&self) -> io::Result<Option<(StreamId, StreamReader)>> {
        self.map(|core_conn| core_conn.accept_uni_stream())?.await
    }

    #[tracing::instrument(level = "trace", skip(self))]
    pub fn unreliable_reader(&self) -> io::Result<UnreliableReader> {
        self.map(|core_conn| core_conn.unreliable_reader())?
    }

    #[tracing::instrument(level = "trace", skip(self))]
    pub async fn unreliable_writer(&self) -> io::Result<UnreliableWriter> {
        self.map(|core_conn| core_conn.unreliable_writer())?.await
    }

    #[tracing::instrument(level = "trace", skip(self))]
    pub fn add_path(&self, socket: Socket, pathway: Pathway) -> io::Result<()> {
        self.map(|core_conn| core_conn.add_path(socket, pathway))
    }

    #[tracing::instrument(level = "trace", skip(self))]
    pub fn del_path(&self, pathway: &Pathway) -> io::Result<()> {
        self.map(|core_conn| core_conn.del_path(pathway))
    }

    pub fn is_active(&self) -> bool {
        self.0.read().unwrap().is_ok()
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        let state = self.0.read().unwrap();
        assert!(state.is_err(), "Connection must be closed before drop");
    }
}
