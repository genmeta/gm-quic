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
        path::{Endpoint, Pathway},
        router::{QuicListener, QuicProto},
        QuicInterface,
    };
    pub use qunreliable::{UnreliableReader, UnreliableWriter};

    pub mod handy {
        pub use qbase::sid::handy::*;
        pub use qinterface::handy::*;
    }

    pub use crate::{
        events::{EmitEvent, Event},
        Connection, StreamReader, StreamWriter,
    };
}

pub mod builder;

use std::{
    io,
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context, Poll},
};

use deref_derive::Deref;
use events::EmitEvent;
use path::Path;
use qbase::{
    cid, flow,
    frame::{ConnectionCloseFrame, ReliableFrame, SendFrame},
    param::{self, ArcParameters},
    sid::StreamId,
    token::ArcTokenRegistry,
};
use qinterface::{buffer::RcvdPacketBuffer, path::Pathway, router::RouterRegistry};
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

pub type ArcLocalCids = cid::local_cid2::ArcLocalCids<RouterRegistry<ArcReliableFrameDeque>>;
pub type ArcRemoteCids = cid::ArcRemoteCids<ArcReliableFrameDeque>;
pub type CidRegistry = cid::Registry<ArcLocalCids, ArcRemoteCids>;
pub type ArcDcidCell = cid::ArcCidCell<ArcReliableFrameDeque>;

pub type FlowController = flow::FlowController<ArcReliableFrameDeque>;
pub type Credit<'a> = flow::Credit<'a, ArcReliableFrameDeque>;

pub type Handshake = handshake::Handshake<ArcReliableFrameDeque>;
pub type RawHandshake = handshake::RawHandshake<ArcReliableFrameDeque>;
pub type ArcRcvdPacketBuffer = Arc<RcvdPacketBuffer>;

pub type DataStreams = streams::DataStreams<ArcReliableFrameDeque>;
pub type StreamReader = recv::Reader<Ext<ArcReliableFrameDeque>>;
type RawStreamWriter = send::Writer<Ext<ArcReliableFrameDeque>>;
pub type StreamWriter = Writer<send::Writer<Ext<ArcReliableFrameDeque>>>;

type ConnInterface = qinterface::conn::ConnInterface<Path>;
pub type ArcConnInterface = Arc<ConnInterface>;

type ClosingInterface = qinterface::closing::ClosingInterface;
pub type ArcClosingInterface = Arc<ClosingInterface>;

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
            sent @ Poll::Ready(Ok(n)) if n > 0 => {
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
    conn_iface: ArcConnInterface,
    send_notify: Arc<Notify>,
}

#[derive(Clone, Deref)]
pub struct CoreConnection {
    components: Components,
}

pub struct Connection(RwLock<Result<CoreConnection, Termination>>);

impl Connection {
    pub fn enter_closing<EE>(&self, ccf: ConnectionCloseFrame, event_broker: EE)
    where
        EE: EmitEvent + Send + Clone + 'static,
    {
        let mut conn = self.0.write().unwrap();
        if let Ok(core_conn) = conn.as_mut() {
            *conn = Err(core_conn.clone().enter_closing(ccf, event_broker));
        }
    }

    pub fn enter_draining<EE>(&self, ccf: ConnectionCloseFrame, event_broker: EE)
    where
        EE: EmitEvent + Send + Clone + 'static,
    {
        let error = ccf.into();
        let mut conn = self.0.write().unwrap();
        match conn.as_mut() {
            Ok(core_conn) => *conn = Err(core_conn.clone().enter_draining(error, event_broker)),
            Err(termination) => termination.enter_draining(),
        }
    }

    fn map<T>(&self, op: impl Fn(&CoreConnection) -> T) -> io::Result<T> {
        let guard = self.0.read().unwrap();
        guard
            .as_ref()
            .map(op)
            .map_err(|termination| termination.error().into())
    }

    pub async fn open_bi_stream(
        &self,
    ) -> io::Result<Option<(StreamId, (StreamReader, StreamWriter))>> {
        let (params, streams) = self.map(|core_conn| {
            (
                core_conn.components.parameters.clone(),
                core_conn.components.spaces.data().streams().clone(),
            )
        })?;
        let param::Pair { remote, .. } = params.await?;
        let result = streams
            .open_bi(remote.initial_max_stream_data_bidi_remote().into())
            .await?
            .map(|(id, (reader, writer))| {
                (
                    id,
                    (reader, StreamWriter::new(writer, Arc::new(Notify::new()))),
                )
            });
        Ok(result)
    }

    pub async fn open_uni_stream(&self) -> io::Result<Option<(StreamId, StreamWriter)>> {
        let (params, streams) = self.map(|core_conn| {
            (
                core_conn.components.parameters.clone(),
                core_conn.components.spaces.data().streams().clone(),
            )
        })?;

        let notify = Arc::new(Notify::new());
        let param::Pair { remote, .. } = params.await?;
        let result = streams
            .open_uni(remote.initial_max_stream_data_uni().into())
            .await?
            .map(|(id, writer)| (id, StreamWriter::new(writer, notify)));

        Ok(result)
    }

    pub async fn accept_bi_stream(
        &self,
    ) -> io::Result<Option<(StreamId, (StreamReader, StreamWriter))>> {
        let (params, streams) = self.map(|core_conn| {
            (
                core_conn.components.parameters.clone(),
                core_conn.components.spaces.data().streams().clone(),
            )
        })?;
        let param::Pair { remote, .. } = params.await?;
        let result = streams
            .accept_bi(remote.initial_max_stream_data_bidi_local().into())
            .await
            .map(|(sid, (reader, writer))| {
                (
                    sid,
                    (reader, StreamWriter::new(writer, Arc::new(Notify::new()))),
                )
            });
        Ok(Some(result?))
    }

    pub async fn accept_uni_stream(&self) -> io::Result<Option<(StreamId, StreamReader)>> {
        let (streams,) =
            self.map(|core_conn| (core_conn.components.spaces.data().streams().clone(),))?;
        let result = streams.accept_uni().await;
        Ok(Some(result?))
    }

    pub fn unreliable_reader(&self) -> io::Result<UnreliableReader> {
        self.map(|core_conn| core_conn.components.spaces.data().datagrams().reader())?
    }

    pub async fn unreliable_writer(&self) -> io::Result<UnreliableWriter> {
        let (params, datagrams) = self.map(|core_conn| {
            (
                core_conn.components.parameters.clone(),
                core_conn.components.spaces.data().datagrams().clone(),
            )
        })?;
        let param::Pair { remote, .. } = params.await?;
        datagrams.writer(remote.max_datagram_frame_size().into())
    }

    pub fn add_path(&self, pathway: Pathway) -> io::Result<()> {
        self.map(|core_conn| core_conn.add_path(pathway))
    }

    pub fn del_path(&self, pathway: &Pathway) -> io::Result<()> {
        self.map(|core_conn| core_conn.del_path(pathway))
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        let state = self.0.read().unwrap();
        assert!(state.is_err(), "Connection must be closed before drop");
    }
}
