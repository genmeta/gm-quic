use std::{
    future::Future,
    io,
    sync::{Arc, RwLock},
};

pub use qbase::{
    cid::{ConnectionId, GenUniqueCid, RetireCid},
    net::route::{Link, Pathway},
    packet::{
        DataHeader, Packet,
        header::{GetDcid, GetScid},
        long::DataHeader as LongHeader,
    },
    param::{ClientParameters, ServerParameters},
    sid::{ControlStreamsConcurrency, handy::*},
    token::{TokenProvider, TokenSink, handy::*},
};
use qbase::{
    error::Error,
    frame::ConnectionCloseFrame,
    net::{address::BindAddr, tx::ArcSendWakers},
    param::{ArcParameters, ParameterId},
    sid::{self, ProductStreamsConcurrencyController},
    token::ArcTokenRegistry,
    varint::VarInt,
};
use qcongestion::HandshakeStatus;
use qevent::{
    GroupID, VantagePointType,
    quic::{
        Owner,
        connectivity::{ConnectionClosed, PathAssigned},
        transport::ParametersSet,
    },
    telemetry::{Instrument, Log, Span},
};
use qinterface::{
    ifaces::QuicInterfaces,
    queue::RcvdPacketQueue,
    route::{Router, RouterRegistry},
};
pub use rustls::crypto::CryptoProvider;
use tracing::Instrument as _;

pub use crate::tls::AuthClient;
use crate::{
    ArcLocalCids, ArcReliableFrameDeque, ArcRemoteCids, CidRegistry, Components, Connection,
    FlowController, Handshake, RawHandshake, ServerComponents, SpecificComponents, Termination,
    events::{ArcEventBroker, EmitEvent, Event},
    path::{ArcPathContexts, Path},
    prelude::HeartbeatConfig,
    space::{self, Spaces, data::DataSpace, handshake::HandshakeSpace, initial::InitialSpace},
    state::ConnState,
    termination::Terminator,
    tls::{
        self, ArcClientName, ArcEndpointName, ArcPeerCerts, ArcSendGate, ArcServerName,
        ArcTlsSession, ArcZeroRtt, ClientAuthers, TlsSession,
    },
};

impl Connection {
    pub fn with_token_sink(
        server_name: String,
        token_sink: Arc<dyn TokenSink>,
    ) -> ClientFoundation {
        ClientFoundation {
            server: rustls::pki_types::ServerName::try_from(server_name.clone())
                .expect("server name is not valid"),
            token: token_sink.fetch_token(&server_name),
            token_registry: ArcTokenRegistry::with_sink(server_name.clone(), token_sink),
            server_name,
            client_params: ClientParameters::default(),
        }
    }

    pub fn with_token_provider(token_provider: Arc<dyn TokenProvider>) -> ServerFoundation {
        ServerFoundation {
            token_registry: ArcTokenRegistry::with_provider(token_provider),
            server_params: ServerParameters::default(),
            silent_rejection: false,
            client_authers: vec![],
        }
    }
}

pub struct ClientFoundation {
    server: rustls::pki_types::ServerName<'static>,
    token: Vec<u8>,
    token_registry: ArcTokenRegistry,
    client_params: ClientParameters,
    server_name: String,
}

impl ClientFoundation {
    pub fn with_parameters(self, client_params: ClientParameters) -> Self {
        ClientFoundation {
            client_params,
            ..self
        }
    }

    pub fn with_tls_config(
        self,
        tls_config: Arc<rustls::ClientConfig>,
    ) -> TlsReady<ClientFoundation, Arc<rustls::ClientConfig>> {
        TlsReady {
            foundation: self,
            tls_config,
            streams_ctrl: Box::new(sid::handy::DemandConcurrency),
        }
    }
}

pub struct ServerFoundation {
    token_registry: ArcTokenRegistry,
    server_params: ServerParameters,
    silent_rejection: bool,
    client_authers: ClientAuthers,
}

impl ServerFoundation {
    pub fn with_parameters(self, server_params: ServerParameters) -> Self {
        ServerFoundation {
            server_params,
            ..self
        }
    }

    pub fn with_silent_rejection(self, silent_rejection: bool) -> Self {
        ServerFoundation {
            silent_rejection,
            ..self
        }
    }

    pub fn with_client_authers(
        self,
        client_authers: impl IntoIterator<Item = Arc<dyn AuthClient>>,
    ) -> Self {
        ServerFoundation {
            client_authers: client_authers.into_iter().collect(),
            ..self
        }
    }

    pub fn with_tls_config(
        self,
        tls_config: Arc<rustls::ServerConfig>,
    ) -> TlsReady<ServerFoundation, Arc<rustls::ServerConfig>> {
        TlsReady {
            foundation: self,
            tls_config,
            streams_ctrl: Box::new(sid::handy::DemandConcurrency),
        }
    }
}

pub struct TlsReady<Foundation, Config> {
    foundation: Foundation,
    tls_config: Config,
    streams_ctrl: Box<dyn ControlStreamsConcurrency>,
}

fn initial_keys_with(
    crypto_provider: &Arc<CryptoProvider>,
    client_dcid: &ConnectionId,
    side: rustls::Side,
    version: rustls::quic::Version,
) -> rustls::quic::Keys {
    crypto_provider
        .cipher_suites
        .iter()
        .find_map(|cs| match (cs.suite(), cs.tls13()) {
            (rustls::CipherSuite::TLS13_AES_128_GCM_SHA256, Some(suite)) => {
                Some(suite.quic_suite())
            }
            _ => None,
        })
        .flatten()
        .expect("crypto provider does not provide supported cipher suite")
        .keys(client_dcid, side, version)
}

impl TlsReady<ClientFoundation, Arc<rustls::ClientConfig>> {
    pub fn with_streams_concurrency_strategy<F>(self, strategy_factory: &F) -> Self
    where
        F: ?Sized + ProductStreamsConcurrencyController,
    {
        let client_params = &self.foundation.client_params;
        let init_max_bidi_streams = client_params
            .get_as(ParameterId::InitialMaxStreamsBidi)
            .expect("unreachable: default value will be got if the value unset");
        let init_max_uni_streams = client_params
            .get_as(ParameterId::InitialMaxStreamsUni)
            .expect("unreachable: default value will be got if the value unset");
        TlsReady {
            streams_ctrl: strategy_factory.init(init_max_bidi_streams, init_max_uni_streams),
            ..self
        }
    }

    pub fn with_proto(
        self,
        router: Arc<Router>,
        interfaces: Arc<QuicInterfaces>,
    ) -> ProtoReady<ClientFoundation, Arc<rustls::ClientConfig>> {
        ProtoReady {
            foundation: self.foundation,
            tls_config: self.tls_config,
            streams_ctrl: self.streams_ctrl,
            router,
            interfaces,
            defer_idle_timeout: HeartbeatConfig::default(),
            zero_rtt: ArcZeroRtt::new(false),
        }
    }
}

impl TlsReady<ServerFoundation, Arc<rustls::ServerConfig>> {
    pub fn with_streams_concurrency_strategy<F>(self, strategy_factory: &F) -> Self
    where
        F: ?Sized + ProductStreamsConcurrencyController,
    {
        let server_params = &self.foundation.server_params;
        let init_max_bidi_streams = server_params
            .get_as(ParameterId::InitialMaxStreamsBidi)
            .expect("unreachable: default value will be got if the value unset");
        let init_max_uni_streams = server_params
            .get_as(ParameterId::InitialMaxStreamsUni)
            .expect("unreachable: default value will be got if the value unset");
        TlsReady {
            streams_ctrl: strategy_factory.init(init_max_bidi_streams, init_max_uni_streams),
            ..self
        }
    }

    pub fn with_proto(
        self,
        router: Arc<Router>,
        interfaces: Arc<QuicInterfaces>,
    ) -> ProtoReady<ServerFoundation, Arc<rustls::ServerConfig>> {
        ProtoReady {
            foundation: self.foundation,
            tls_config: self.tls_config,
            streams_ctrl: self.streams_ctrl,
            router,
            interfaces,
            defer_idle_timeout: HeartbeatConfig::default(),
            zero_rtt: ArcZeroRtt::new(false),
        }
    }
}

pub struct ProtoReady<Foundation, Config> {
    foundation: Foundation,
    tls_config: Config,
    streams_ctrl: Box<dyn ControlStreamsConcurrency>,
    router: Arc<Router>,
    interfaces: Arc<QuicInterfaces>,
    defer_idle_timeout: HeartbeatConfig,
    zero_rtt: ArcZeroRtt,
}

impl<Foundation, Config> ProtoReady<Foundation, Config> {
    pub fn defer_idle_timeout(self, config: HeartbeatConfig) -> Self {
        Self {
            defer_idle_timeout: config,
            ..self
        }
    }

    pub fn with_zero_rtt(self, enabled: bool) -> Self {
        ProtoReady {
            zero_rtt: ArcZeroRtt::new(enabled),
            ..self
        }
    }
}

impl ProtoReady<ClientFoundation, Arc<rustls::ClientConfig>> {
    pub fn with_cids(self, origin_dcid: ConnectionId) -> ComponentsReady {
        let mut client_params = self.foundation.client_params;

        let tx_wakers = ArcSendWakers::default();
        let reliable_frames = ArcReliableFrameDeque::with_capacity_and_wakers(8, tx_wakers.clone());

        let rcvd_pkt_q = Arc::new(RcvdPacketQueue::new());

        let router_registry: qinterface::route::RouterRegistry<ArcReliableFrameDeque> = self
            .router
            .registry(rcvd_pkt_q.clone(), reliable_frames.clone());
        let initial_scid = router_registry.gen_unique_cid();

        client_params
            .set(ParameterId::InitialSourceConnectionId, initial_scid)
            .unwrap();

        let cid_registry = CidRegistry::new(
            ArcLocalCids::new(initial_scid, router_registry),
            ArcRemoteCids::new(
                origin_dcid,
                client_params
                    .get_as(ParameterId::ActiveConnectionIdLimit)
                    .expect("unreachable: default value will be got if the value unset"),
                reliable_frames.clone(),
            ),
        );

        let initial_keys = initial_keys_with(
            self.tls_config.crypto_provider(),
            &origin_dcid,
            rustls::Side::Client,
            rustls::quic::Version::V1,
        );

        let max_ack_delay = client_params
            .get_as(ParameterId::MaxAckDelay)
            .expect("unreachable: default value will be got if the value unset");

        let client_name = ArcClientName::from(&client_params);

        let tls_session =
            TlsSession::new_client(self.foundation.server, self.tls_config, &client_params);

        let remembered_params = self
            .zero_rtt
            .is_enabled()
            .then(|| {
                    tls_session
                        .load_remembered_parameters()
                    .and_then(Result::ok)
            })
            .and_then(|opt| opt);

        let spaces = Spaces::new(
            InitialSpace::new(
                initial_keys.into(),
                self.foundation.token,
                tx_wakers.clone(),
            ),
            HandshakeSpace::new(tx_wakers.clone()),
            DataSpace::new(
                sid::Role::Client,
                reliable_frames.clone(),
                client_params.as_ref(),
                remembered_params.as_ref(),
                self.streams_ctrl,
                tx_wakers.clone(),
                max_ack_delay,
            ),
        );

        if self.zero_rtt.is_enabled() {
            tls_session.load_zero_rtt_keys(&spaces.data().zero_rtt_keys());
        }

        let flow_ctrl = FlowController::new(
            remembered_params
                .as_ref()
                .map(|remembered_params| {
                    remembered_params
                        .get_as(ParameterId::InitialMaxData)
                        .expect("unreachable: default value will be got if the value unset")
                })
                .unwrap_or(0),
            client_params
                .get_as(ParameterId::InitialMaxData)
                .expect("unreachable: default value will be got if the value unset"),
            reliable_frames.clone(),
            tx_wakers.clone(),
        );

        let parameters = ArcParameters::new_client(client_params, remembered_params, origin_dcid);
        let raw_handshake = RawHandshake::new(sid::Role::Client, reliable_frames.clone());

        ComponentsReady {
            interfaces: self.interfaces,
            parameters,
            tls_session: ArcTlsSession::new(tls_session),
            raw_handshake,
            token_registry: self.foundation.token_registry,
            cid_registry,
            flow_ctrl,
            spaces,
            rcvd_pkt_q,
            tx_wakers,
            defer_idle_timeout: self.defer_idle_timeout,
            client_name,
            server_name: ArcEndpointName::from(self.foundation.server_name),
            qlog_span: None,
            specific: SpecificComponents::Client {},
            zero_rtt: self.zero_rtt,
        }
    }
}

impl ProtoReady<ServerFoundation, Arc<rustls::ServerConfig>> {
    pub fn with_cids(
        self,
        origin_dcid: ConnectionId,
        client_scid: ConnectionId,
    ) -> ComponentsReady {
        let mut server_params = self.foundation.server_params;

        let tx_wakers = ArcSendWakers::default();
        let reliable_frames = ArcReliableFrameDeque::with_capacity_and_wakers(8, tx_wakers.clone());

        let rcvd_pkt_q = Arc::new(RcvdPacketQueue::new());

        let router_registry: RouterRegistry<ArcReliableFrameDeque> = self
            .router
            .registry(rcvd_pkt_q.clone(), reliable_frames.clone());
        let initial_scid = router_registry.gen_unique_cid();

        server_params
            .set(ParameterId::InitialSourceConnectionId, initial_scid)
            .unwrap();
        server_params
            .set(ParameterId::OriginalDestinationConnectionId, origin_dcid)
            .unwrap();
        let odcid_router_entry = self.router.insert(origin_dcid.into(), rcvd_pkt_q.clone());

        let cid_registry = CidRegistry::new(
            ArcLocalCids::new(initial_scid, router_registry),
            ArcRemoteCids::new(
                client_scid,
                server_params
                    .get_as(ParameterId::ActiveConnectionIdLimit)
                    .expect("unreachable: default value will be got if the value unset"),
                reliable_frames.clone(),
            ),
        );

        let initial_keys = initial_keys_with(
            self.tls_config.crypto_provider(),
            &origin_dcid,
            rustls::Side::Server,
            rustls::quic::Version::V1,
        );

        let flow_ctrl = FlowController::new(
            0,
            server_params
                .get_as(ParameterId::InitialMaxData)
                .expect("unreachable: default value will be got if the value unset"),
            reliable_frames.clone(),
            tx_wakers.clone(),
        );

        let max_ack_delay = server_params
            .get_as(ParameterId::MaxAckDelay)
            .expect("unreachable: default value will be got if the value unset");

        let tls_session =
            TlsSession::new_server(self.tls_config, &server_params, self.zero_rtt.is_enabled());

        let spaces = Spaces::new(
            InitialSpace::new(
                initial_keys.into(),
                Vec::with_capacity(0),
                tx_wakers.clone(),
            ),
            HandshakeSpace::new(tx_wakers.clone()),
            DataSpace::new(
                sid::Role::Server,
                reliable_frames.clone(),
                server_params.as_ref(),
                None,
                self.streams_ctrl,
                tx_wakers.clone(),
                max_ack_delay,
            ),
        );

        let parameters = ArcParameters::new_server(server_params);
        parameters
            .initial_scid_from_peer_need_equal(client_scid)
            .unwrap();

        let raw_handshake = RawHandshake::new(sid::Role::Server, reliable_frames.clone());

        ComponentsReady {
            interfaces: self.interfaces,
            parameters,
            tls_session: ArcTlsSession::new(tls_session),
            raw_handshake,
            token_registry: self.foundation.token_registry,
            cid_registry,
            flow_ctrl,
            spaces,
            rcvd_pkt_q,
            tx_wakers,
            defer_idle_timeout: self.defer_idle_timeout,
            client_name: ArcClientName::default(),
            server_name: ArcServerName::default(),
            qlog_span: None,
            specific: SpecificComponents::Server(ServerComponents {
                send_gate: if self.foundation.silent_rejection {
                    ArcSendGate::new()
                } else {
                    ArcSendGate::unrestricted()
                },
                client_authers: self.foundation.client_authers,
                odcid_router_entry,
            }),
            zero_rtt: self.zero_rtt,
        }
    }
}

pub struct ComponentsReady {
    interfaces: Arc<QuicInterfaces>,
    token_registry: ArcTokenRegistry,
    rcvd_pkt_q: Arc<RcvdPacketQueue>,
    cid_registry: CidRegistry,
    flow_ctrl: FlowController,
    spaces: Spaces,
    parameters: ArcParameters,
    tls_session: ArcTlsSession,
    raw_handshake: RawHandshake,
    defer_idle_timeout: HeartbeatConfig,
    tx_wakers: ArcSendWakers,
    client_name: ArcClientName,
    server_name: ArcServerName,
    specific: SpecificComponents,
    qlog_span: Option<Span>,
    zero_rtt: ArcZeroRtt,
}

impl ComponentsReady {
    pub fn with_qlog(mut self, logger: &(impl Log + ?Sized)) -> Self {
        let vantage_point_type = match self.raw_handshake.role() {
            sid::Role::Client => VantagePointType::Client,
            sid::Role::Server => VantagePointType::Server,
        };
        let origin_dcid = self.parameters.get_origin_dcid().unwrap();
        self.qlog_span = Some(logger.new_trace(vantage_point_type, origin_dcid.into()));
        self
    }

    pub fn run_with<EE>(self, event_broker: EE) -> Connection
    where
        EE: EmitEvent + Clone + Send + Sync + 'static,
    {
        // telemetry
        let role = self.raw_handshake.role();
        let group_id = GroupID::from(self.parameters.get_origin_dcid().unwrap());

        let tracing_span = tracing::info_span!("connection",%role, odcid = %group_id);
        let qlog_span = self
            .qlog_span
            .unwrap_or_else(|| qevent::span!(@current, group_id));

        let is_server = role == sid::Role::Server;
        let inform_cc = Arc::new(HandshakeStatus::new(is_server));
        let conn_state = ConnState::new();
        let event_broker = ArcEventBroker::new(conn_state.clone(), event_broker);
        let components = Components {
            interfaces: self.interfaces,
            parameters: self.parameters,
            tls_session: self.tls_session,
            handshake: Handshake::new(self.raw_handshake, inform_cc, event_broker.clone()),
            token_registry: self.token_registry,
            cid_registry: self.cid_registry,
            flow_ctrl: self.flow_ctrl,
            spaces: self.spaces,
            rcvd_pkt_q: self.rcvd_pkt_q,
            paths: ArcPathContexts::new(self.tx_wakers, event_broker.clone()),
            defer_idle_timeout: self.defer_idle_timeout,
            event_broker,
            conn_state,
            client_name: self.client_name,
            server_name: self.server_name,
            peer_certs: ArcPeerCerts::default(),
            specific: self.specific,
            zero_rtt: self.zero_rtt,
        };

        tracing_span.in_scope(|| {
            qlog_span.in_scope(|| {
                tokio::spawn(tls::keys_upgrade(&components));
                tokio::spawn(accept_transport_parameters(&components));
                tokio::spawn(handle_0rtt_rejection(&components));
                space::spawn_deliver_and_parse(&components);
            })
        });

        Connection {
            state: RwLock::new(Ok(components)),
            qlog_span,
            tracing_span,
        }
    }
}

fn accept_transport_parameters(components: &Components) -> impl Future<Output = ()> + Send {
    let params = components.parameters.clone();
    let streams = components.spaces.data().streams().clone();
    let cid_registry = components.cid_registry.clone();
    let flow_ctrl = components.flow_ctrl.clone();
    let role = components.handshake.role();
    let task = async move {
        use qbase::frame::{MaxStreamsFrame, ReceiveFrame, StreamCtlFrame};
        let remote_parameters = params.remote().await?;

        match role {
            sid::Role::Client => {
                qevent::event!(ParametersSet {
                    owner: Owner::Remote,
                    server_parameters: remote_parameters.as_ref(),
                })
            }
            sid::Role::Server => {
                qevent::event!(ParametersSet {
                    owner: Owner::Remote,
                    client_parameters: remote_parameters.as_ref(),
                })
            }
        };

        // pretend to receive the MAX_STREAM frames
        _ = streams.recv_frame(&StreamCtlFrame::MaxStreams(MaxStreamsFrame::Bi(
            remote_parameters
                .get_as::<VarInt>(ParameterId::InitialMaxStreamsBidi)
                .expect("unreachable: default value will be got if the value unset"),
        )));
        _ = streams.recv_frame(&StreamCtlFrame::MaxStreams(MaxStreamsFrame::Uni(
            remote_parameters
                .get_as::<VarInt>(ParameterId::InitialMaxStreamsUni)
                .expect("unreachable: default value will be got if the value unset"),
        )));

        flow_ctrl.reset_send_window(
            remote_parameters
                .get_as::<u64>(ParameterId::InitialMaxData)
                .expect("unreachable: default value will be got if the value unset"),
        );

        cid_registry.local.set_limit(
            remote_parameters
                .get_as::<u64>(ParameterId::ActiveConnectionIdLimit)
                .expect("unreachable: default value will be got if the value unset"),
        )?;

        Result::<_, Error>::Ok(())
    };
    let event_broker = components.event_broker.clone();
    async move {
        if let Err(Error::Quic(e)) = task.await {
            event_broker.emit(Event::Failed(e));
        }
    }
    .instrument_in_current()
    .in_current_span()
}

fn handle_0rtt_rejection(components: &Components) -> impl Future<Output = ()> + Send {
    let zero_rtt = components.zero_rtt.clone();
    let streams = components.spaces.data().streams().clone();
    async move {
        let Some(fut) = zero_rtt.is_accepted() else {
            return;
        };
        if matches!(fut.await, Ok(false)) {
            streams.on_0rtt_rejected();
        }
    }
    .instrument_in_current()
    .in_current_span()
}

impl Components {
    pub fn get_or_try_create_path(
        &self,
        bind_addr: BindAddr,
        link: Link,
        pathway: Pathway,
        is_probed: bool,
    ) -> io::Result<Arc<Path>> {
        let try_create = || {
            let interface = self
                .interfaces
                .get(&bind_addr)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "interface not found"))?;
            let max_ack_delay = self
                .parameters
                .local()?
                .get_as(ParameterId::MaxAckDelay)
                .expect("unreachable: default value will be got if the value unset");

            let do_validate = !self.conn_state.try_entry_attempted(self, link)?;
            qevent::event!(PathAssigned {
                path_id: pathway.to_string(),
                path_local: link.src(),
                path_remote: link.dst(),
            });

            let path = Arc::new(Path::new(
                interface,
                link,
                pathway,
                max_ack_delay,
                [
                    self.spaces.initial().clone(),
                    self.spaces.handshake().clone(),
                    self.spaces.data().clone(),
                ],
                self.handshake.status(),
            )?);

            if !is_probed {
                path.grant_anti_amplification();
            }

            let burst = path.new_burst(self);
            let idle_timeout = path.idle_timeout(self);

            let task = {
                let path = path.clone();
                let defer_idle_timeout = self.defer_idle_timeout;
                async move {
                    let validate = async {
                        if do_validate {
                            path.validate().await
                        } else {
                            path.skip_validation();
                            true
                        }
                    };
                    let reason: String = tokio::select! {
                        false = validate => "failed to validate".into(),
                        true = idle_timeout => "idle timeout".into(),
                        Err(e) = burst.launch() => format!("failed to send packets: {:?}", e),
                        _ = path.defer_idle_timeout(defer_idle_timeout) => "failed to defer idle timeout".into(),
                    };
                    Err(reason)
                }
            };

            let task =
                Instrument::instrument(task, qevent::span!(@current, path=pathway.to_string()))
                    .instrument_in_current();

            tracing::info!(%pathway, %link, is_probed, do_validate, "add new path:");
            Ok((path, task))
        };
        self.paths.get_or_try_create_with(pathway, try_create)
    }
}

impl Components {
    // 对于server，第一条路径也通过add_path添加
    pub fn enter_closing(self, ccf: ConnectionCloseFrame) -> Termination {
        qevent::event!(ConnectionClosed {
            owner: Owner::Local,
            ccf: &ccf // TODO: trigger
        });
        let error = ccf.clone().into();
        self.spaces.data().on_conn_error(&error);
        self.flow_ctrl.on_conn_error(&error);
        self.tls_session.on_conn_error(&error);
        self.parameters.on_conn_error(&error);
        self.server_name.on_conn_error(&error);
        self.peer_certs.on_conn_error(&error);

        tokio::spawn({
            let local_cids = self.cid_registry.local.clone();
            let event_broker = self.event_broker.clone();
            let pto_duration = self.paths.max_pto_duration().unwrap_or_default();
            async move {
                tokio::time::sleep(pto_duration * 3).await;
                local_cids.clear();
                event_broker.emit(Event::Terminated);
            }
            .instrument_in_current()
            .in_current_span()
        });

        let terminator = Arc::new(Terminator::new(ccf, &self));

        // for server, send ccf only if the send gate is permitted.
        if !matches!(self.specific, SpecificComponents::Server(ref s) if !s.send_gate.is_permitted())
        {
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
        self.flow_ctrl.on_conn_error(&error);
        self.tls_session.on_conn_error(&error);
        self.parameters.on_conn_error(&error);
        self.server_name.on_conn_error(&error);
        self.peer_certs.on_conn_error(&error);

        tokio::spawn({
            let local_cids = self.cid_registry.local.clone();
            let event_broker = self.event_broker.clone();
            let pto_duration = self.paths.max_pto_duration().unwrap_or_default();
            async move {
                tokio::time::sleep(pto_duration * 3).await;
                local_cids.clear();
                event_broker.emit(Event::Terminated);
            }
            .instrument_in_current()
            .in_current_span()
        });

        // for server, send ccf only if the send gate is permitted.
        if !matches!(self.specific, SpecificComponents::Server(ref s) if !s.send_gate.is_permitted())
        {
            let terminator = Arc::new(Terminator::new(ccf, &self));
            tokio::spawn(
                self.spaces
                    .drain(terminator, self.rcvd_pkt_q)
                    .instrument_in_current()
                    .in_current_span(),
            );
        }

        Termination::draining(error, self.cid_registry.local)
    }
}
