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
        error::{AppError, Error, ErrorKind, QuicError},
        frame::ConnectionCloseFrame,
        net::{addr::*, route::*},
        param::ParameterId,
        role::{Client, IntoRole, Role, Server},
        sid::{ControlStreamsConcurrency, ProductStreamsConcurrencyController, StreamId},
        varint::VarInt,
    };
    pub use qinterface::QuicIO;
    pub use qrecovery::{recv::StopSending, send::CancelStream, streams::error::StreamError};
    #[cfg(feature = "unreliable")]
    pub use qunreliable::{DatagramReader, DatagramWriter};

    pub mod handy {
        pub use qbase::{param::handy::*, sid::handy::*, token::handy::*};
        pub use qevent::telemetry::handy::*;
        pub use qinterface::{factory::handy::*, iface::handy::*};
    }

    pub use crate::{
        Connection, StreamReader, StreamWriter,
        tls::{AuthClient, ClientCertsVerifyResult, ClientNameVerifyResult},
    };
}

// Re-export dependencies
pub use ::{qbase, qevent, qinterface, qrecovery, qunreliable};

pub mod builder;

use std::{
    borrow::Cow,
    fmt::Debug,
    future::Future,
    io,
    ops::Deref,
    sync::{Arc, RwLock, atomic::AtomicBool},
};

use enum_dispatch::enum_dispatch;
use events::{ArcEventBroker, EmitEvent, Event};
use path::ArcPathContexts;
use qbase::{
    cid,
    error::{AppError, Error, ErrorKind, QuicError},
    flow,
    frame::{ConnectionCloseFrame, CryptoFrame, Frame, ReliableFrame, StreamFrame},
    net::{
        addr::BindUri,
        route::{EndpointAddr, Link, Pathway},
    },
    param::{ArcParameters, ParameterId},
    role::Role,
    sid::StreamId,
    time::ArcDeferIdleTimer,
    token::{ArcTokenRegistry, TokenRegistry},
};
use qevent::{
    quic::{Owner, connectivity::ConnectionClosed},
    telemetry::Instrument,
};
use qinterface::{
    iface::QuicInterfaces,
    queue::RcvdPacketQueue,
    route::{self, RouterEntry},
};
use qrecovery::{
    crypto::CryptoStream,
    journal, recv, reliable, send,
    streams::{self, Ext},
};
use qunreliable::DatagramFlow;
#[cfg(feature = "unreliable")]
use qunreliable::{DatagramReader, DatagramWriter};
use space::Spaces;
use state::ArcConnState;
use termination::Termination;
use tls::ArcSendLock;
use tracing::Instrument as _;

use crate::{
    path::error::{CreatePathFailure, PathDeactivated},
    termination::Terminator,
    tls::ArcTlsHandshake,
};

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

impl<'f, D> TryFrom<&'f Frame<D>> for GuaranteedFrame {
    type Error = &'f Frame<D>;

    fn try_from(frame: &'f Frame<D>) -> Result<Self, Self::Error> {
        Ok(match ReliableFrame::try_from(frame) {
            Ok(reliable) => Self::Reliable(reliable),
            Err(Frame::Crypto(crypto, _data)) => Self::Crypto(*crypto),
            Err(Frame::Stream(stream, _data)) => Self::Stream(*stream),
            Err(frame) => return Err(frame),
        })
    }
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
    defer_idle_timer: ArcDeferIdleTimer,
    paths: ArcPathContexts,
    send_lock: ArcSendLock,
    tls_handshake: ArcTlsHandshake,
    quic_handshake: Handshake,
    parameters: ArcParameters,
    token_registry: ArcTokenRegistry,
    cid_registry: CidRegistry,
    spaces: Spaces,
    crypto_streams: [CryptoStream; 3],
    reliable_frames: ArcReliableFrameDeque,
    data_streams: DataStreams,
    flow_ctrl: FlowController,
    datagram_flow: DatagramFlow,
    event_broker: ArcEventBroker,
    specific: SpecificComponents,
}

#[derive(Clone)]
pub enum SpecificComponents {
    Client {},
    Server {
        using_odcid: Arc<AtomicBool>,
        odcid_router_entry: Arc<RouterEntry>,
    },
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
        let is_zero_rtt_avaliable = self.spaces.data().is_zero_rtt_avaliable();
        let tls_handshake = self.tls_handshake.clone();
        let terminated = self.conn_state.terminated();
        let data_streams = self.data_streams.clone();
        let parameters = self.parameters.clone();
        async move {
            if !is_zero_rtt_avaliable {
                tokio::select! {
                    _ = tls_handshake.finished() => {},
                    _ = terminated => {}
                }
            }
            data_streams.open_bi(&parameters).await
        }
        .instrument_in_current()
        .in_current_span()
    }

    pub fn open_uni_stream(
        &self,
    ) -> impl Future<Output = Result<Option<(StreamId, StreamWriter)>, Error>> + Send {
        let is_zero_rtt_avaliable = self.spaces.data().is_zero_rtt_avaliable();
        let tls_handshake = self.tls_handshake.clone();
        let terminated = self.conn_state.terminated();
        let data_streams = self.data_streams.clone();
        let parameters = self.parameters.clone();
        async move {
            if !is_zero_rtt_avaliable {
                tokio::select! {
                    _ = tls_handshake.finished() => {},
                    _ = terminated => {}
                }
            }
            data_streams.open_uni(&parameters).await
        }
        .instrument_in_current()
        .in_current_span()
    }

    #[allow(clippy::type_complexity)]
    pub fn accept_bi_stream(
        &self,
    ) -> impl Future<Output = Result<(StreamId, (StreamReader, StreamWriter)), Error>> + Send {
        let data_streams = self.data_streams.clone();
        let parameters = self.parameters.clone();
        async move { data_streams.accept_bi(&parameters).await }
            .instrument_in_current()
            .in_current_span()
    }

    pub fn accept_uni_stream(
        &self,
    ) -> impl Future<Output = Result<(StreamId, StreamReader), Error>> + Send {
        let data_streams = self.data_streams.clone();
        async move { data_streams.accept_uni().await }
            .instrument_in_current()
            .in_current_span()
    }

    #[cfg(feature = "unreliable")]
    #[deprecated]
    pub fn unreliable_reader(&self) -> io::Result<DatagramReader> {
        self.datagram_flow.reader()
    }

    #[cfg(feature = "unreliable")]
    #[deprecated]
    pub fn unreliable_writer(&self) -> impl Future<Output = io::Result<DatagramWriter>> + Send {
        let params = self.parameters.clone();
        let datagram_flow = self.datagram_flow.clone();
        async move {
            let max_datagram_frame_size = params
                .remote_ready()
                .await?
                .get_remote(ParameterId::MaxDatagramFrameSize)
                .expect("unreachable: default value will be got if the value unset");
            datagram_flow.writer(max_datagram_frame_size)
        }
        .instrument_in_current()
        .in_current_span()
    }

    pub fn add_local_endpoint(&self, _bind: BindUri, _addr: EndpointAddr) {
        todo!("Implement this method to add a local endpoint.")
    }

    pub fn add_peer_endpoint(&self, _bind: BindUri, _addr: EndpointAddr) {
        todo!("Implement this method to add a peer endpoint.")
    }

    pub fn add_path(
        &self,
        bind_uri: BindUri,
        link: Link,
        pathway: Pathway,
    ) -> Result<(), CreatePathFailure> {
        self.get_or_try_create_path(bind_uri, link, pathway, false)
            .map(|_| ())
    }

    pub fn del_path(&self, pathway: &Pathway) {
        self.paths.remove(pathway, &PathDeactivated::App);
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
    pub fn enter_closing(self, error: Error) -> Termination {
        qevent::event!(ConnectionClosed {
            owner: Owner::Local,
            error: &error, // TODO: trigger
        });

        self.data_streams.on_conn_error(&error);
        self.datagram_flow.on_conn_error(&error);
        self.tls_handshake.on_conn_error(&error);
        self.parameters.on_conn_error(&error);

        tokio::spawn(
            {
                let pto_duration = self.paths.max_pto_duration().unwrap_or_default();
                let event_broker = self.event_broker.clone();
                async move {
                    tokio::time::sleep(pto_duration).await;
                    event_broker.emit(Event::Terminated);
                }
            }
            .instrument_in_current()
            .in_current_span(),
        );

        match self.send_lock.is_permitted() {
            // If permitted, we can send ccf packets.
            true => {
                let terminator = Arc::new(Terminator::new(error.clone().into(), &self));
                tokio::spawn(
                    self.spaces
                        .close(terminator, self.rcvd_pkt_q.clone(), self.event_broker)
                        .instrument_in_current()
                        .in_current_span(),
                );
            }
            // No need to send packets, just clear the paths.
            false => {
                // TODO: check the remote of close spaces
                self.paths.clear();
            }
        }

        Termination::closing(error, self.cid_registry.local, self.rcvd_pkt_q)
    }

    pub fn enter_draining(self, ccf: ConnectionCloseFrame) -> Termination {
        qevent::event!(ConnectionClosed {
            owner: Owner::Local,
            ccf: &ccf // TODO: trigger
        });

        let error = ccf.clone().into();
        self.data_streams.on_conn_error(&error);
        self.datagram_flow.on_conn_error(&error);
        self.tls_handshake.on_conn_error(&error);
        self.parameters.on_conn_error(&error);

        tokio::spawn(
            {
                let pto_duration = self.paths.max_pto_duration().unwrap_or_default();
                let event_broker = self.event_broker.clone();
                async move {
                    tokio::time::sleep(pto_duration).await;
                    event_broker.emit(Event::Terminated);
                }
            }
            .instrument_in_current()
            .in_current_span(),
        );

        match self.send_lock.is_permitted() {
            // If permitted, we can send ccf packets.
            true => {
                let terminator = Arc::new(Terminator::new(ccf, &self));
                tokio::spawn(
                    self.spaces
                        .drain(terminator, self.rcvd_pkt_q.clone())
                        .instrument_in_current()
                        .in_current_span(),
                );
            }
            // No need to send packets, just clear the paths.
            false => {
                self.paths.clear();
            }
        }

        // No need to receive packets, just close all queues.
        self.rcvd_pkt_q.close_all();
        Termination::draining(error, self.cid_registry.local)
    }
}

struct ConnectionState {
    state: RwLock<Result<Components, Termination>>,
    qlog_span: qevent::telemetry::Span,
    tracing_span: tracing::Span,
}

pub struct Connection(Arc<ConnectionState>);

impl ConnectionState {
    // called by event
    pub fn enter_closing(&self, error: QuicError) -> Result<(), Error> {
        let _span = (self.qlog_span.enter(), self.tracing_span.enter());
        let mut conn = self.state.write().unwrap();
        let core_conn = conn.as_ref().map_err(|t| t.error())?;

        *conn = Err(core_conn.clone().enter_closing(error.into()));
        Ok(())
    }

    pub fn application_close(
        &self,
        reason: impl Into<Cow<'static, str>>,
        code: u64,
    ) -> Result<(), Error> {
        let _span = (self.qlog_span.enter(), self.tracing_span.enter());
        let mut conn = self.state.write().unwrap();
        let core_conn = conn.as_ref().map_err(|t| t.error())?;

        let error_code = code.try_into().expect("application error code overflow");
        let error = AppError::new(error_code, reason);
        let event = Event::ApplicationClose(error.clone());
        core_conn.event_broker.emit(event);
        *conn = Err(core_conn.clone().enter_closing(error.into()));

        Ok(())
    }

    pub fn enter_draining(&self, ccf: ConnectionCloseFrame) -> bool {
        let _span = (self.qlog_span.enter(), self.tracing_span.enter());
        let mut conn = self.state.write().unwrap();
        match conn.as_mut() {
            Ok(core_conn) => {
                *conn = Err(core_conn.clone().enter_draining(ccf));
                true
            }
            Err(termination) => termination.enter_draining(),
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

    fn validate(&self) -> Result<(), Error> {
        let _span = (self.qlog_span.enter(), self.tracing_span.enter());
        let mut conn = self.state.write().unwrap();
        let core_conn = conn.as_ref().map_err(|e| e.error())?;
        let validate = 'validate: {
            if core_conn.paths.is_empty() {
                let error =
                    QuicError::with_default_fty(ErrorKind::NoViablePath, "No viable path exist");
                break 'validate Err(error);
            }
            Ok(())
        };
        if let Err(error) = validate {
            core_conn.event_broker.emit(Event::Failed(error.clone()));
            *conn = Err(core_conn.clone().enter_closing(error.into()));
        }
        Ok(())
    }
}

impl Connection {
    /// Close the connection with application close frame.
    ///
    /// Return error if the connection is already closed.
    pub fn close(&self, reason: impl Into<Cow<'static, str>>, code: u64) -> Result<(), Error> {
        self.0.application_close(reason, code)
    }

    pub async fn open_bi_stream(
        &self,
    ) -> Result<Option<(StreamId, (StreamReader, StreamWriter))>, Error> {
        self.0
            .try_map_components(|core_conn| core_conn.open_bi_stream())?
            .await
    }

    pub async fn open_uni_stream(&self) -> Result<Option<(StreamId, StreamWriter)>, Error> {
        self.0
            .try_map_components(|core_conn| core_conn.open_uni_stream())?
            .await
    }

    pub async fn accept_bi_stream(
        &self,
    ) -> Result<(StreamId, (StreamReader, StreamWriter)), Error> {
        self.0
            .try_map_components(|core_conn| core_conn.accept_bi_stream())?
            .await
    }

    pub async fn accept_uni_stream(&self) -> Result<(StreamId, StreamReader), Error> {
        self.0
            .try_map_components(|core_conn| core_conn.accept_uni_stream())?
            .await
    }

    #[cfg(feature = "unreliable")]
    #[deprecated]
    #[allow(deprecated)]
    pub fn unreliable_reader(&self) -> Result<io::Result<DatagramReader>, Error> {
        self.0
            .try_map_components(|core_conn| core_conn.unreliable_reader())
    }

    #[cfg(feature = "unreliable")]
    #[deprecated]
    #[allow(deprecated)]
    pub async fn unreliable_writer(&self) -> Result<io::Result<DatagramWriter>, Error> {
        Ok(self
            .0
            .try_map_components(|core_conn| core_conn.unreliable_writer())?
            .await)
    }

    pub fn add_path(
        &self,
        bind_uri: BindUri,
        link: Link,
        pathway: Pathway,
    ) -> Result<(), CreatePathFailure> {
        self.0
            .try_map_components(|core_conn| core_conn.add_path(bind_uri, link, pathway))
            .unwrap_or_else(|cc| Err(CreatePathFailure::ConnectionClosed(cc)))
    }

    pub fn del_path(&self, pathway: &Pathway) -> Result<(), Error> {
        self.0
            .try_map_components(|core_conn| core_conn.del_path(pathway))
    }

    pub fn origin_dcid(&self) -> Result<cid::ConnectionId, Error> {
        self.0
            .try_map_components(|core_conn| core_conn.cid_registry.origin_dcid())
    }

    pub async fn handshaked(&self) -> Result<(), Error> {
        self.0
            .try_map_components(|core_conn| core_conn.conn_state.handshaked())?
            .await
    }

    pub async fn terminated(&self) -> Error {
        match self
            .0
            .try_map_components(|core_conn| core_conn.conn_state.terminated())
        {
            Ok(f) => f.await,
            Err(error) => error,
        }
    }

    pub async fn peer_certs(&self) -> Result<Option<Vec<u8>>, Error> {
        self.0
            .try_map_components(|core_conn| core_conn.peer_certs())?
            .await
    }

    pub async fn server_name(&self) -> Result<String, Error> {
        self.0
            .try_map_components(|core_conn| core_conn.server_name())?
            .await
    }

    // 0xffee: String
    pub async fn client_name(&self) -> Result<Option<String>, Error> {
        self.0
            .try_map_components(|core_conn| core_conn.client_name())?
            .await
    }

    pub fn add_local_endpoint(&self, bind: BindUri, addr: EndpointAddr) -> Result<(), Error> {
        self.0
            .try_map_components(|core_conn| core_conn.add_local_endpoint(bind, addr))
    }

    pub fn add_peer_endpoint(&self, bind: BindUri, addr: EndpointAddr) -> Result<(), Error> {
        self.0
            .try_map_components(|core_conn| core_conn.add_peer_endpoint(bind, addr))
    }

    /// Check if the connection is still valid.
    ///
    /// Return error if no viable path exists, or the connection is closed.
    pub fn validate(&self) -> Result<(), Error> {
        self.0.validate()
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        if let Ok(origin_dcid) = self.origin_dcid() {
            if self.close("", 0).is_ok() {
                #[cfg(debug_assertions)]
                tracing::warn!(target: "quic", "Connection {origin_dcid:x} is still active when dropped, close it automatically.");
                #[cfg(not(debug_assertions))]
                tracing::debug!(target: "quic", "Connection {origin_dcid:x} is still active when dropped, close it automatically.");
            }
        }
    }
}
