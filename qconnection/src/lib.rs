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
        net::{address::*, route::*},
        sid::{ControlStreamsConcurrency, ProductStreamsConcurrencyController, StreamId},
        varint::VarInt,
    };
    pub use qinterface::QuicInterface;
    #[cfg(feature = "unreliable")]
    pub use qunreliable::{DatagramReader, DatagramWriter};

    #[allow(unused_imports)]
    pub mod handy {
        pub use qbase::{param::handy::*, sid::handy::*, token::handy::*};
        pub use qinterface::ifaces::handy::*;
    }

    pub use crate::{
        Connection, StreamReader, StreamWriter,
        events::{EmitEvent, Event},
        path::idle::HeartbeatConfig,
        tls::PeerCert,
    };
}

pub mod builder;

use std::{
    borrow::Cow,
    future::Future,
    io,
    sync::{Arc, RwLock},
};

use enum_dispatch::enum_dispatch;
use events::{ArcEventBroker, EmitEvent, Event};
use path::{ArcPathContexts, idle::HeartbeatConfig};
use qbase::{
    cid,
    error::Error,
    flow,
    frame::{ConnectionCloseFrame, CryptoFrame, ReliableFrame, StreamFrame},
    net::{
        address::BindAddr,
        route::{Link, Pathway},
    },
    param::{ArcParameters, ParameterId},
    sid::StreamId,
    token::ArcTokenRegistry,
};
use qevent::telemetry::Instrument;
use qinterface::{
    ifaces::QuicInterfaces,
    queue::RcvdPacketQueue,
    route::{Router, RouterEntry, RouterRegistry},
};
use qrecovery::{
    journal, recv, reliable, send,
    streams::{self, Ext},
};
#[cfg(feature = "unreliable")]
use qunreliable::{DatagramReader, DatagramWriter};
use space::Spaces;
use state::ConnState;
use termination::Termination;
use tls::{
    ArcClientName, ArcPeerCerts, ArcSendGate, ArcServerName, ArcTlsSession, ClientAuthers, PeerCert,
};
use tracing::Instrument as _;

/// The kind of frame which guaratend to be received by peer.
///
/// The bundle of [`StreamFrame`], [`CryptoFrame`] and [`ReliableFrame`].
#[derive(Debug, Clone, Eq, PartialEq)]
#[enum_dispatch(EncodeFrame, FrameFeture)]
pub enum GuaranteedFrame {
    Stream(StreamFrame),
    Crypto(CryptoFrame),
    Reliable(ReliableFrame),
}

/// For initial space, only reliable transmission of crypto frames is required.
pub type InitialJournal = journal::Journal<CryptoFrame>;
/// For handshake space, only reliable transmission of crypto frames is required.
pub type HandshakeJournal = journal::Journal<CryptoFrame>;
/// For data space, reliable transmission of [`GuaranteedFrame`] (crypto frames, stream frames and reliable frames) is required.
pub type DataJournal = journal::Journal<GuaranteedFrame>;

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
    interfaces: Arc<QuicInterfaces>,
    router: Arc<Router>,
    rcvd_pkt_q: Arc<RcvdPacketQueue>,
    defer_idle_timeout: HeartbeatConfig,
    event_broker: ArcEventBroker,
    conn_state: ConnState,

    peer_certs: ArcPeerCerts,
    server_name: ArcServerName,
    client_name: ArcClientName,
    specific: SpecificComponents,
}

#[derive(Clone)]
enum SpecificComponents {
    Client,
    Server(ServerComponents),
}

#[derive(Clone)]
struct ServerComponents {
    send_gate: ArcSendGate,
    client_authers: ClientAuthers,
    _odcid_router_entry: RouterEntry,
}

impl Components {
    pub fn open_bi_stream(
        &self,
    ) -> impl Future<Output = io::Result<Option<(StreamId, (StreamReader, StreamWriter))>>> + Send
    {
        let params = self.parameters.clone();
        let streams = self.spaces.data().streams().clone();
        async move {
            let snd_wnd_size = params
                .get_remote_as::<u64>(ParameterId::InitialMaxStreamDataBidiRemote)
                .await?;
            Ok(streams.open_bi(snd_wnd_size).await?)
        }
        .instrument_in_current()
        .in_current_span()
    }

    pub fn open_uni_stream(
        &self,
    ) -> impl Future<Output = io::Result<Option<(StreamId, StreamWriter)>>> + Send {
        let params = self.parameters.clone();
        let streams = self.spaces.data().streams().clone();
        async move {
            let snd_wnd_size = params
                .get_remote_as::<u64>(ParameterId::InitialMaxStreamDataUni)
                .await?;
            Ok(streams.open_uni(snd_wnd_size).await?)
        }
        .instrument_in_current()
        .in_current_span()
    }

    pub fn accept_bi_stream(
        &self,
    ) -> impl Future<Output = io::Result<Option<(StreamId, (StreamReader, StreamWriter))>>> + Send
    {
        let params = self.parameters.clone();
        let streams = self.spaces.data().streams().clone();
        async move {
            let snd_wnd_size = params
                .get_remote_as::<u64>(ParameterId::InitialMaxStreamDataBidiLocal)
                .await?;
            Ok(Some(streams.accept_bi(snd_wnd_size).await?))
        }
        .instrument_in_current()
        .in_current_span()
    }

    pub fn accept_uni_stream(
        &self,
    ) -> impl Future<Output = io::Result<Option<(StreamId, StreamReader)>>> + Send {
        let streams = self.spaces.data().streams().clone();
        async move { Ok(Some(streams.accept_uni().await?)) }
            .instrument_in_current()
            .in_current_span()
    }

    #[cfg(feature = "unreliable")]
    pub fn unreliable_reader(&self) -> io::Result<DatagramReader> {
        self.spaces.data().datagrams().reader()
    }

    #[cfg(feature = "unreliable")]
    pub fn unreliable_writer(&self) -> impl Future<Output = io::Result<DatagramWriter>> + Send {
        let params = self.parameters.clone();
        let datagrams = self.spaces.data().datagrams().clone();
        async move {
            let max_datagram_frame_size = params
                .get_remote_as::<u64>(ParameterId::MaxDatagramFrameSize)
                .await?;
            datagrams.writer(max_datagram_frame_size)
        }
        .instrument_in_current()
        .in_current_span()
    }

    pub fn add_path(&self, ifaca_addr: BindAddr, link: Link, pathway: Pathway) -> io::Result<()> {
        self.get_or_try_create_path(ifaca_addr, link, pathway, false)
            .map(|_| ())
    }

    pub fn del_path(&self, pathway: &Pathway) {
        self.paths.remove(pathway, "application removed");
    }

    pub fn peer_certs(&self) -> impl Future<Output = Result<Arc<PeerCert>, Error>> + Send {
        let peer_certs = self.peer_certs.clone();
        async move { peer_certs.get().await }
    }

    pub fn server_name(&self) -> impl Future<Output = Result<String, Error>> + Send {
        let server_name = self.server_name.clone();
        async move { server_name.get().await }
    }
}

type ConnectionState = RwLock<Result<Components, Termination>>;

pub struct Connection {
    state: ConnectionState,
    qlog_span: qevent::telemetry::Span,
    tracing_span: tracing::Span,
}

impl Connection {
    pub fn enter_closing(&self, ccf: ConnectionCloseFrame) {
        let _span = (self.qlog_span.enter(), self.tracing_span.enter());
        let mut conn = self.state.write().unwrap();
        if let Ok(components) = conn.as_mut() {
            *conn = Err(components.clone().enter_closing(ccf));
        }
    }

    pub fn enter_draining(&self, ccf: ConnectionCloseFrame) {
        let _span = (self.qlog_span.enter(), self.tracing_span.enter());
        let mut conn = self.state.write().unwrap();
        match conn.as_mut() {
            Ok(core_conn) => *conn = Err(core_conn.clone().enter_draining(ccf)),
            Err(termination) => termination.enter_draining(),
        }
    }

    pub fn close(&self, reason: impl Into<Cow<'static, str>>, code: u64) {
        let _span = (self.qlog_span.enter(), self.tracing_span.enter());

        let error_code = code.try_into().expect("application error code overflow");
        let ccf = ConnectionCloseFrame::new_app(error_code, reason);

        let mut conn = self.state.write().unwrap();
        if let Ok(components) = conn.as_mut() {
            components.event_broker.emit(Event::ApplicationClose);
            *conn = Err(components.clone().enter_closing(ccf));
        }
    }

    fn try_map_components<T>(&self, op: impl FnOnce(&Components) -> T) -> io::Result<T> {
        let _span = (self.qlog_span.enter(), self.tracing_span.enter());
        self.state
            .read()
            .unwrap()
            .as_ref()
            .map(op)
            .map_err(|termination| termination.error().into())
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

    pub fn add_path(&self, bind_addr: BindAddr, link: Link, pathway: Pathway) -> io::Result<()> {
        self.try_map_components(|core_conn| core_conn.add_path(bind_addr, link, pathway))?
    }

    pub fn del_path(&self, pathway: &Pathway) -> io::Result<()> {
        self.try_map_components(|core_conn| core_conn.del_path(pathway))
    }

    pub fn is_active(&self) -> bool {
        self.try_map_components(|_| true).unwrap_or_default()
    }

    pub fn origin_dcid(&self) -> io::Result<cid::ConnectionId> {
        self.try_map_components(|core_conn| Ok(core_conn.parameters.get_origin_dcid()?))?
    }

    pub async fn handshaked(&self) -> bool {
        if let Ok(f) = self.try_map_components(|core_conn| core_conn.conn_state.handshaked()) {
            return f.await;
        }
        false
    }

    pub async fn terminated(&self) {
        if let Ok(f) = self.try_map_components(|core_conn| core_conn.conn_state.terminated()) {
            f.await
        }
    }

    pub async fn peer_certs(&self) -> io::Result<Arc<PeerCert>> {
        Ok(self
            .try_map_components(|core_conn| core_conn.peer_certs())?
            .await?)
    }

    pub async fn server_name(&self) -> io::Result<String> {
        Ok(self
            .try_map_components(|core_conn| core_conn.server_name())?
            .await?)
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        if let Ok(origin_dcid) = self.origin_dcid() {
            tracing::warn!("Connection {origin_dcid:x} is still active when dropped",);
        }
    }
}
