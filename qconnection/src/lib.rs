pub mod events;
pub mod handshake;
pub mod path;
pub mod space;
pub mod state;
pub mod termination;
pub mod tls;
pub mod tx;

pub mod prelude {
    pub use qbase::{
        cid::ConnectionId,
        frame::ConnectionCloseFrame,
        net::route::*,
        sid::{ControlStreamsConcurrency, ProductStreamsConcurrencyController, StreamId},
        varint::VarInt,
    };
    pub use qinterface::{QuicInterface, router::QuicProto};
    #[cfg(feature = "unreliable")]
    pub use qunreliable::{DatagramReader, DatagramWriter};

    #[allow(unused_imports)]
    pub mod handy {
        pub use qinterface::handy::*;
    }

    pub use crate::{
        Connection, StreamReader, StreamWriter,
        events::{EmitEvent, Event},
        path::idle::HeartbeatConfig,
    };
}

pub mod builder;

use std::{
    borrow::Cow,
    future::Future,
    io,
    sync::{Arc, RwLock},
};

use events::ArcEventBroker;
use path::ArcPathContexts;
use prelude::HeartbeatConfig;
use qbase::{
    cid, flow,
    frame::{ConnectionCloseFrame, ReliableFrame},
    net::route::{Link, Pathway},
    param::{ArcParameters, ParameterId},
    sid::StreamId,
    token::ArcTokenRegistry,
    varint::VarInt,
};
use qinterface::{
    queue::RcvdPacketQueue,
    router::{QuicProto, RouterRegistry},
};
use qrecovery::{
    recv, reliable, send,
    streams::{self, Ext},
};
#[cfg(feature = "unreliable")]
use qunreliable::{DatagramReader, DatagramWriter};
use space::Spaces;
use state::ConnState;
use termination::Termination;
use tls::ArcTlsSession;

pub type ArcReliableFrameDeque = reliable::ArcReliableFrameDeque<ReliableFrame>;
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
pub type StreamWriter = send::Writer<Ext<ArcReliableFrameDeque>>;

#[derive(Clone)]
pub struct Components {
    parameters: ArcParameters,
    tls_session: ArcTlsSession,
    handshake: Handshake,
    token_registry: ArcTokenRegistry,
    cid_registry: CidRegistry,
    flow_ctrl: FlowController,
    spaces: Spaces,
    paths: ArcPathContexts,
    proto: Arc<QuicProto>,
    rcvd_pkt_q: Arc<RcvdPacketQueue>,
    defer_idle_timeout: HeartbeatConfig,
    event_broker: ArcEventBroker,
    state: ConnState,
}

impl Components {
    pub fn open_bi_stream(
        &self,
    ) -> impl Future<Output = io::Result<Option<(StreamId, (StreamReader, StreamWriter))>>> + Send + use<>
    {
        let params = self.parameters.clone();
        let streams = self.spaces.data().streams().clone();
        async move {
            let snd_wnd_size = params
                .get_remote_as::<VarInt>(ParameterId::InitialMaxStreamDataBidiRemote)
                .await?;
            Ok(streams.open_bi(snd_wnd_size.into_inner()).await?)
        }
    }

    pub fn open_uni_stream(
        &self,
    ) -> impl Future<Output = io::Result<Option<(StreamId, StreamWriter)>>> + Send + use<> {
        let params = self.parameters.clone();
        let streams = self.spaces.data().streams().clone();
        async move {
            let snd_wnd_size = params
                .get_remote_as::<VarInt>(ParameterId::InitialMaxStreamDataUni)
                .await?;
            Ok(streams.open_uni(snd_wnd_size.into_inner()).await?)
        }
    }

    pub fn accept_bi_stream(
        &self,
    ) -> impl Future<Output = io::Result<Option<(StreamId, (StreamReader, StreamWriter))>>> + Send + use<>
    {
        let params = self.parameters.clone();
        let streams = self.spaces.data().streams().clone();
        async move {
            let snd_wnd_size = params
                .get_remote_as::<VarInt>(ParameterId::InitialMaxStreamDataBidiLocal)
                .await?;
            Ok(Some(streams.accept_bi(snd_wnd_size.into_inner()).await?))
        }
    }

    pub fn accept_uni_stream(
        &self,
    ) -> impl Future<Output = io::Result<Option<(StreamId, StreamReader)>>> + Send + use<> {
        let streams = self.spaces.data().streams().clone();
        async move { Ok(Some(streams.accept_uni().await?)) }
    }

    #[cfg(feature = "unreliable")]
    pub fn unreliable_reader(&self) -> io::Result<DatagramReader> {
        self.spaces.data().datagrams().reader()
    }

    #[cfg(feature = "unreliable")]
    pub fn unreliable_writer(
        &self,
    ) -> impl Future<Output = io::Result<DatagramWriter>> + Send + use<> {
        let params = self.parameters.clone();
        let datagrams = self.spaces.data().datagrams().clone();
        async move {
            let max_datagram_frame_size = params
                .get_remote_as::<VarInt>(ParameterId::MaxDatagramFrameSize)
                .await?;
            datagrams.writer(max_datagram_frame_size.into_inner())
        }
    }

    pub fn add_path(&self, link: Link, pathway: Pathway) -> io::Result<()> {
        self.get_or_try_create_path(link, pathway, false)
            .map(|_| ())
    }

    pub fn del_path(&self, pathway: &Pathway) {
        self.paths.remove(pathway, "application removed");
    }

    pub fn origin_dcid(&self) -> io::Result<cid::ConnectionId> {
        Ok(self.parameters.get_origin_dcid()?)
    }
}

type ConnectionState = RwLock<Result<Components, Termination>>;

pub struct Connection {
    state: ConnectionState,
    qlog_span: qlog::telemetry::Span,
    tracing_span: tracing::Span,
}

impl Connection {
    fn map_state<T>(&self, op: impl FnOnce(&ConnectionState) -> T) -> T {
        let _qlog_span = self.qlog_span.enter();
        let _tracing_span = self.tracing_span.enter();
        op(&self.state)
    }

    fn try_map_components<T>(&self, op: impl Fn(&Components) -> T) -> io::Result<T> {
        self.map_state(|state| {
            state
                .read()
                .unwrap()
                .as_ref()
                .map(op)
                .map_err(|termination| termination.error().into())
        })
    }

    pub fn enter_closing(&self, ccf: ConnectionCloseFrame) {
        self.map_state(|state| {
            let mut conn = state.write().unwrap();
            if let Ok(components) = conn.as_mut() {
                *conn = Err(components.clone().enter_closing(ccf));
            }
        })
    }

    pub fn enter_draining(&self, ccf: ConnectionCloseFrame) {
        self.map_state(|state| {
            let mut conn = state.write().unwrap();
            match conn.as_mut() {
                Ok(core_conn) => *conn = Err(core_conn.clone().enter_draining(ccf)),
                Err(termination) => termination.enter_draining(),
            }
        })
    }

    pub fn close(&self, reason: Cow<'static, str>, code: u64) {
        let error_code = code.try_into().unwrap();
        self.enter_closing(ConnectionCloseFrame::new_app(error_code, reason));
    }

    pub async fn open_bi_stream(
        &self,
    ) -> io::Result<Option<(StreamId, (StreamReader, StreamWriter))>> {
        self.try_map_components(|core_conn| core_conn.open_bi_stream())?
            .await
    }

    pub async fn open_uni_stream(&self) -> io::Result<Option<(StreamId, StreamWriter)>> {
        self.try_map_components(|core_conn| core_conn.open_uni_stream())?
            .await
    }

    pub async fn accept_bi_stream(
        &self,
    ) -> io::Result<Option<(StreamId, (StreamReader, StreamWriter))>> {
        self.try_map_components(|core_conn| core_conn.accept_bi_stream())?
            .await
    }

    pub async fn accept_uni_stream(&self) -> io::Result<Option<(StreamId, StreamReader)>> {
        self.try_map_components(|core_conn| core_conn.accept_uni_stream())?
            .await
    }

    #[cfg(feature = "unreliable")]
    pub fn unreliable_reader(&self) -> io::Result<DatagramReader> {
        self.try_map_components(|core_conn| core_conn.unreliable_reader())?
    }

    #[cfg(feature = "unreliable")]
    pub async fn unreliable_writer(&self) -> io::Result<DatagramWriter> {
        self.try_map_components(|core_conn| core_conn.unreliable_writer())?
            .await
    }

    pub fn add_path(&self, link: Link, pathway: Pathway) -> io::Result<()> {
        self.try_map_components(|core_conn| core_conn.add_path(link, pathway))?
    }

    pub fn del_path(&self, pathway: &Pathway) -> io::Result<()> {
        self.try_map_components(|core_conn| core_conn.del_path(pathway))
    }

    pub fn is_active(&self) -> bool {
        self.try_map_components(|_| true).unwrap_or_default()
    }

    pub fn origin_dcid(&self) -> io::Result<cid::ConnectionId> {
        self.try_map_components(|core_conn| core_conn.origin_dcid())?
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        assert!(!self.is_active(), "Connection must be closed before drop");
    }
}
