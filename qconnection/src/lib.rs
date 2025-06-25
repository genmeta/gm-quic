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
        param::ParameterId,
        sid::{ControlStreamsConcurrency, ProductStreamsConcurrencyController, StreamId},
        varint::VarInt,
    };
    pub use qinterface::QuicIO;
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
    };
}

pub mod builder;

use std::{
    borrow::Cow,
    fmt::Debug,
    future::Future,
    io,
    ops::Deref,
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
    sid::{Role, StreamId},
    token::{ArcTokenRegistry, TokenRegistry},
};
use qevent::{
    quic::{Owner, connectivity::ConnectionClosed},
    telemetry::Instrument,
};
use qinterface::{
    ifaces::QuicInterfaces,
    queue::RcvdPacketQueue,
    route::{self, RouterEntry},
};
use qrecovery::{
    journal, recv, reliable, send,
    streams::{self, Ext},
};
#[cfg(feature = "unreliable")]
use qunreliable::{DatagramReader, DatagramWriter};
use space::Spaces;
use state::ArcConnState;
use termination::Termination;
use tls::ArcSendGate;
use tracing::Instrument as _;

use crate::{termination::Terminator, tls::ArcTlsHandshake};

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
pub type RouterRegistry = route::RouterRegistry<ArcReliableFrameDeque>;
pub type ArcLocalCids = cid::ArcLocalCids<RouterRegistry>;
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
    // TODO: delete this
    interfaces: Arc<QuicInterfaces>,
    rcvd_pkt_q: Arc<RcvdPacketQueue>,
    conn_state: ArcConnState,
    defer_idle_timeout: HeartbeatConfig,
    paths: ArcPathContexts,
    send_gate: ArcSendGate,
    tls_handshake: ArcTlsHandshake,
    quic_handshake: Handshake,
    parameters: ArcParameters,
    token_registry: ArcTokenRegistry,
    cid_registry: CidRegistry,
    spaces: Spaces,
    event_broker: ArcEventBroker,
    specific: SpecificComponents,
}

#[derive(Clone)]
pub enum SpecificComponents {
    Client {},
    Server { odcid_router_entry: RouterEntry },
}

impl Components {
    pub fn role(&self) -> Role {
        match self.specific {
            SpecificComponents::Client { .. } => Role::Client,
            SpecificComponents::Server { .. } => Role::Server,
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn open_bi_stream(
        &self,
    ) -> impl Future<Output = Result<Option<(StreamId, (StreamReader, StreamWriter))>, Error>> + Send
    {
        let data_space = self.spaces.data().clone();
        let terminated = self.conn_state.terminated();
        async move {
            if !data_space.is_zero_rtt_avaliable() {
                tokio::select! {
                    _ = data_space.one_rtt_ready() => {},
                    _ = terminated => {}
                }
            }
            data_space.streams().open_bi().await
        }
        .instrument_in_current()
        .in_current_span()
    }

    pub fn open_uni_stream(
        &self,
    ) -> impl Future<Output = Result<Option<(StreamId, StreamWriter)>, Error>> + Send {
        let data_space = self.spaces.data().clone();
        let terminated = self.conn_state.terminated();
        async move {
            if !data_space.is_zero_rtt_avaliable() {
                tokio::select! {
                    _ = data_space.one_rtt_ready() => {},
                    _ = terminated => {}
                }
            }
            data_space.streams().open_uni().await
        }
        .instrument_in_current()
        .in_current_span()
    }

    #[allow(clippy::type_complexity)]
    pub fn accept_bi_stream(
        &self,
    ) -> impl Future<Output = Result<(StreamId, (StreamReader, StreamWriter)), Error>> + Send {
        let streams = self.spaces.data().streams().clone();
        async move { streams.accept_bi().await }
            .instrument_in_current()
            .in_current_span()
    }

    pub fn accept_uni_stream(
        &self,
    ) -> impl Future<Output = Result<(StreamId, StreamReader), Error>> + Send {
        let streams = self.spaces.data().streams().clone();
        async move { streams.accept_uni().await }
            .instrument_in_current()
            .in_current_span()
    }

    #[cfg(feature = "unreliable")]
    #[deprecated]
    pub fn unreliable_reader(&self) -> io::Result<DatagramReader> {
        self.spaces.data().datagrams().reader()
    }

    #[cfg(feature = "unreliable")]
    #[deprecated]
    pub fn unreliable_writer(&self) -> impl Future<Output = io::Result<DatagramWriter>> + Send {
        let params = self.parameters.clone();
        let datagrams = self.spaces.data().datagrams().clone();
        async move {
            let max_datagram_frame_size = params
                .remote_ready()
                .await?
                .get_remote(ParameterId::MaxDatagramFrameSize)
                .expect("unreachable: default value will be got if the value unset");
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

    pub fn peer_certs(&self) -> impl Future<Output = Result<Option<Vec<u8>>, Error>> + Send {
        let tls_handshake = self.tls_handshake.clone();
        async move {
            match tls_handshake.info().await?.as_ref() {
                tls::TlsHandshakeInfo::Client { peer_cert, .. } => Ok(Some(peer_cert.to_vec())),
                tls::TlsHandshakeInfo::Server { peer_cert, .. } => Ok(peer_cert.clone()),
            }
        }
        .instrument_in_current()
        .in_current_span()
    }

    pub fn server_name(&self) -> impl Future<Output = Result<String, Error>> + Send {
        let token_registry = self.token_registry.clone();
        let tls_handshake = self.tls_handshake.clone();
        async move {
            if let TokenRegistry::Client((server_name, ..)) = token_registry.deref() {
                return Ok(server_name.clone());
            }
            match tls_handshake.info().await?.as_ref() {
                tls::TlsHandshakeInfo::Client { .. } => {
                    unreachable!("tls hs has different role with token registry")
                }
                tls::TlsHandshakeInfo::Server { server_name, .. } => Ok(server_name.clone()),
            }
        }
        .instrument_in_current()
        .in_current_span()
    }

    pub fn client_name(&self) -> impl Future<Output = Result<Option<String>, Error>> + Send {
        let parameters = self.parameters.clone();
        let tls_handshake = self.tls_handshake.clone();
        async move {
            {
                let parameters = parameters.lock_guard()?;
                if parameters.role() == Role::Client {
                    return Ok(parameters.get_local(ParameterId::ClientName));
                }
            }

            match tls_handshake.info().await?.as_ref() {
                tls::TlsHandshakeInfo::Client { .. } => {
                    unreachable!("tls hs has different role with token registry")
                }
                tls::TlsHandshakeInfo::Server { client_name, .. } => Ok(client_name.clone()),
            }
        }
        .instrument_in_current()
        .in_current_span()
    }
}

impl Components {
    pub fn enter_closing(self, ccf: ConnectionCloseFrame) -> Termination {
        qevent::event!(ConnectionClosed {
            owner: Owner::Local,
            ccf: &ccf // TODO: trigger
        });

        let error = ccf.clone().into();
        self.spaces.data().on_conn_error(&error);
        self.tls_handshake.on_conn_error(&error);
        self.parameters.on_conn_error(&error);

        tokio::spawn(
            {
                let pto_duration = self.paths.max_pto_duration().unwrap_or_default();
                let local_cids = self.cid_registry.local.clone();
                let rcvd_pkt_q = self.rcvd_pkt_q.clone();
                let event_broker = self.event_broker.clone();
                async move {
                    tokio::time::sleep(pto_duration).await;
                    local_cids.clear();
                    rcvd_pkt_q.close_all();
                    event_broker.emit(Event::Terminated);
                }
            }
            .instrument_in_current()
            .in_current_span(),
        );

        if self.send_gate.is_permitted() {
            let terminator = Arc::new(Terminator::new(ccf, &self));
            tokio::spawn(
                self.spaces
                    .close(terminator, self.rcvd_pkt_q.clone(), self.event_broker)
                    .instrument_in_current()
                    .in_current_span(),
            );
        }

        Termination::closing(error, self.cid_registry.local, self.rcvd_pkt_q)
    }

    pub fn enter_draining(self, ccf: ConnectionCloseFrame) -> Termination {
        qevent::event!(ConnectionClosed {
            owner: Owner::Local,
            ccf: &ccf // TODO: trigger
        });

        let error = ccf.clone().into();
        self.spaces.data().on_conn_error(&error);
        self.tls_handshake.on_conn_error(&error);
        self.parameters.on_conn_error(&error);

        tokio::spawn(
            {
                let pto_duration = self.paths.max_pto_duration().unwrap_or_default();
                let local_cids = self.cid_registry.local.clone();
                let rcvd_pkt_q = self.rcvd_pkt_q.clone();
                let event_broker = self.event_broker.clone();
                async move {
                    tokio::time::sleep(pto_duration).await;
                    local_cids.clear();
                    rcvd_pkt_q.close_all();
                    event_broker.emit(Event::Terminated);
                }
            }
            .instrument_in_current()
            .in_current_span(),
        );

        if self.send_gate.is_permitted() {
            let terminator = Arc::new(Terminator::new(ccf, &self));
            tokio::spawn(
                self.spaces
                    .drain(terminator, self.rcvd_pkt_q.clone())
                    .instrument_in_current()
                    .in_current_span(),
            );
        }

        Termination::draining(error, self.cid_registry.local)
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

    fn try_map_components<T>(&self, op: impl FnOnce(&Components) -> T) -> Result<T, Error> {
        let _span = (self.qlog_span.enter(), self.tracing_span.enter());
        self.state
            .read()
            .unwrap()
            .as_ref()
            .map(op)
            .map_err(|termination| termination.error())
    }

    pub async fn open_bi_stream(
        &self,
    ) -> Result<Option<(StreamId, (StreamReader, StreamWriter))>, Error> {
        self.try_map_components(|core_conn| core_conn.open_bi_stream())?
            .await
    }

    pub async fn open_uni_stream(&self) -> Result<Option<(StreamId, StreamWriter)>, Error> {
        self.try_map_components(|core_conn| core_conn.open_uni_stream())?
            .await
    }

    pub async fn accept_bi_stream(
        &self,
    ) -> Result<(StreamId, (StreamReader, StreamWriter)), Error> {
        self.try_map_components(|core_conn| core_conn.accept_bi_stream())?
            .await
    }

    pub async fn accept_uni_stream(&self) -> Result<(StreamId, StreamReader), Error> {
        self.try_map_components(|core_conn| core_conn.accept_uni_stream())?
            .await
    }

    #[cfg(feature = "unreliable")]
    #[deprecated]
    #[allow(deprecated)]
    pub fn unreliable_reader(&self) -> Result<io::Result<DatagramReader>, Error> {
        self.try_map_components(|core_conn| core_conn.unreliable_reader())
    }

    #[cfg(feature = "unreliable")]
    #[deprecated]
    #[allow(deprecated)]
    pub async fn unreliable_writer(&self) -> Result<io::Result<DatagramWriter>, Error> {
        Ok(self
            .try_map_components(|core_conn| core_conn.unreliable_writer())?
            .await)
    }

    pub fn add_path(
        &self,
        bind_addr: BindAddr,
        link: Link,
        pathway: Pathway,
    ) -> Result<io::Result<()>, Error> {
        self.try_map_components(|core_conn| core_conn.add_path(bind_addr, link, pathway))
    }

    pub fn del_path(&self, pathway: &Pathway) -> Result<(), Error> {
        self.try_map_components(|core_conn| core_conn.del_path(pathway))
    }

    pub fn is_active(&self) -> bool {
        self.try_map_components(|_| true).unwrap_or_default()
    }

    pub fn origin_dcid(&self) -> Result<cid::ConnectionId, Error> {
        self.try_map_components(|core_conn| core_conn.parameters.get_origin_dcid())?
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

    pub async fn peer_certs(&self) -> Result<Option<Vec<u8>>, Error> {
        self.try_map_components(|core_conn| core_conn.peer_certs())?
            .await
    }

    pub async fn server_name(&self) -> Result<String, Error> {
        self.try_map_components(|core_conn| core_conn.server_name())?
            .await
    }

    // 0xffee: String
    pub async fn client_name(&self) -> Result<Option<String>, Error> {
        self.try_map_components(|core_conn| core_conn.client_name())?
            .await
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        if let Ok(origin_dcid) = self.origin_dcid() {
            tracing::warn!("Connection {origin_dcid:x} is still active when dropped",);
        }
    }
}
