use std::{
    ops::Deref,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

pub use qbase::{
    cid::ConnectionId,
    packet::{
        DataHeader, OneRttHeader, Packet,
        header::{GetDcid, GetScid},
        long::DataHeader as LongHeader,
    },
    param::{ClientParameters, ServerParameters},
    sid::{ControlStreamsConcurrency, ProductStreamsConcurrencyController},
    token::{TokenProvider, TokenSink},
};
use qbase::{
    cid::GenUniqueCid,
    error::{Error, ErrorKind, QuicError},
    net::tx::{ArcSendWakers, Signals},
    param::{ArcParameters, ParameterId, Parameters},
    role::Role,
    sid::handy::DemandConcurrency,
    time::ArcDeferIdleTimer,
    token::{ArcTokenRegistry, TokenRegistry},
};
use qcongestion::HandshakeStatus;
use qevent::{
    GroupID,
    quic::{
        Owner,
        transport::{ParametersRestored, ParametersSet},
    },
    telemetry::{Instrument, Log, handy::NoopLogger},
};
pub use qinterface::route::{Router, Way};
use qinterface::{iface::QuicInterfaces, queue::RcvdPacketQueue};
use rustls::crypto::CryptoProvider;
pub use rustls::{ClientConfig as TlsClientConfig, ServerConfig as TlsServerConfig};
use tokio::time;
use tracing::Instrument as _;

pub use crate::tls::{AuthClient, ClientAuthers};
use crate::{
    ArcLocalCids, ArcReliableFrameDeque, ArcRemoteCids, CidRegistry, Components, Connection,
    Handshake, RawHandshake, RouterRegistry, SpecificComponents,
    events::{ArcEventBroker, Event},
    path::ArcPathContexts,
    prelude::EmitEvent,
    space::{
        Spaces, data::DataSpace, handshake::HandshakeSpace, initial::InitialSpace,
        spawn_deliver_and_parse,
    },
    state::ArcConnState,
    tls::{
        ArcSendLock, ArcTlsHandshake, ClientTlsSession, ServerTlsSession, TlsHandshakeInfo,
        TlsSession,
    },
};

impl Connection {
    pub fn new_client(server_name: String, token_sink: Arc<dyn TokenSink>) -> ClientFoundation {
        ClientFoundation {
            server_name: server_name.clone(),
            token_registry: ArcTokenRegistry::with_sink(server_name.clone(), token_sink),
            client_params: ClientParameters::default(),
        }
    }

    pub fn new_server(token_provider: Arc<dyn TokenProvider>) -> ServerFoundation {
        ServerFoundation {
            token_registry: ArcTokenRegistry::with_provider(token_provider),
            server_params: ServerParameters::default(),
            anti_port_scan: false,
            client_authers: ClientAuthers::default(),
        }
    }
}

pub struct ClientFoundation {
    server_name: String,
    token_registry: ArcTokenRegistry,
    client_params: ClientParameters,
}

impl ClientFoundation {
    pub fn with_parameters(mut self, params: ClientParameters) -> Self {
        self.client_params = params;
        self
    }
}

pub struct ServerFoundation {
    token_registry: ArcTokenRegistry,
    server_params: ServerParameters,
    anti_port_scan: bool,
    client_authers: ClientAuthers,
}

impl ServerFoundation {
    pub fn with_parameters(mut self, params: ServerParameters) -> Self {
        self.server_params = params;
        self
    }

    pub fn with_anti_port_scan(mut self, enabled: bool) -> Self {
        self.anti_port_scan = enabled;
        self
    }

    pub fn with_client_authers(mut self, authers: ClientAuthers) -> Self {
        self.client_authers = authers;
        self
    }
}

pub struct ConnectionFoundation<Foundation, TlsConfig> {
    foundation: Foundation,
    tls_config: TlsConfig,

    ifaces: Arc<QuicInterfaces>,
    router: Arc<Router>,
    streams_ctrl: Box<dyn ControlStreamsConcurrency>,
    defer_idle_timeout: Duration,
}

pub type ClientConnectionFoundation = ConnectionFoundation<ClientFoundation, TlsClientConfig>;
pub type ServerConnectionFoundation = ConnectionFoundation<ServerFoundation, TlsServerConfig>;

impl ClientFoundation {
    pub fn with_tls_config(
        self,
        tls_config: TlsClientConfig,
    ) -> ConnectionFoundation<Self, TlsClientConfig> {
        ConnectionFoundation {
            foundation: self,
            tls_config,
            ifaces: QuicInterfaces::global().clone(),
            router: Router::global().clone(),
            streams_ctrl: Box::new(DemandConcurrency), // ZST cause no alloc
            defer_idle_timeout: Duration::ZERO,
        }
    }
}

impl ConnectionFoundation<ClientFoundation, TlsClientConfig> {
    pub fn with_streams_concurrency_strategy<F>(self, strategy_factory: &F) -> Self
    where
        F: ProductStreamsConcurrencyController + ?Sized,
    {
        let client_params = &self.foundation.client_params;
        let init_max_bidi_streams = client_params
            .get(ParameterId::InitialMaxStreamsBidi)
            .expect("unreachable: default value will be got if the value unset");
        let init_max_uni_streams = client_params
            .get(ParameterId::InitialMaxStreamsUni)
            .expect("unreachable: default value will be got if the value unset");
        ConnectionFoundation {
            streams_ctrl: strategy_factory.init(init_max_bidi_streams, init_max_uni_streams),
            ..self
        }
    }

    pub fn with_zero_rtt(mut self, enabled: bool) -> Self {
        self.tls_config.enable_early_data = enabled;
        self
    }
}

impl ServerFoundation {
    pub fn with_tls_config(
        self,
        tls_config: TlsServerConfig,
    ) -> ConnectionFoundation<Self, TlsServerConfig> {
        ConnectionFoundation {
            foundation: self,
            tls_config,
            ifaces: QuicInterfaces::global().clone(),
            router: Router::global().clone(),
            streams_ctrl: Box::new(DemandConcurrency), // ZST cause no alloc
            defer_idle_timeout: Duration::ZERO,
        }
    }
}

impl ConnectionFoundation<ServerFoundation, TlsServerConfig> {
    pub fn with_streams_concurrency_strategy<F>(self, strategy_factory: &F) -> Self
    where
        F: ProductStreamsConcurrencyController + ?Sized,
    {
        let server_params = &self.foundation.server_params;
        let init_max_bidi_streams = server_params
            .get(ParameterId::InitialMaxStreamsBidi)
            .expect("unreachable: default value will be got if the value unset");
        let init_max_uni_streams = server_params
            .get(ParameterId::InitialMaxStreamsUni)
            .expect("unreachable: default value will be got if the value unset");
        ConnectionFoundation {
            streams_ctrl: strategy_factory.init(init_max_bidi_streams, init_max_uni_streams),
            ..self
        }
    }

    pub fn with_zero_rtt(mut self, enabled: bool) -> Self {
        match enabled {
            true => self.tls_config.max_early_data_size = 0xffffffff,
            false => self.tls_config.max_early_data_size = 0,
        }
        self
    }
}

impl<Foundation, TlsConfig> ConnectionFoundation<Foundation, TlsConfig> {
    pub fn with_defer_idle_timeout(mut self, timeout: Duration) -> Self {
        self.defer_idle_timeout = timeout;
        self
    }
}

fn initial_keys_with(
    crypto_provider: &Arc<CryptoProvider>,
    origin_dcid: &ConnectionId,
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
        .keys(origin_dcid, side, version)
}

impl ConnectionFoundation<ClientFoundation, TlsClientConfig> {
    pub fn with_cids(self, origin_dcid: ConnectionId) -> PendingConnection {
        let initial_keys = initial_keys_with(
            self.tls_config.crypto_provider(),
            &origin_dcid,
            rustls::Side::Client,
            crate::tls::QUIC_VERSION,
        );

        let rcvd_pkt_q = Arc::new(RcvdPacketQueue::new());

        let tx_wakers = ArcSendWakers::default();
        let reliable_frames = ArcReliableFrameDeque::with_capacity_and_wakers(8, tx_wakers.clone());

        let router_registry = self
            .router
            .registry_on_issuing_scid(rcvd_pkt_q.clone(), reliable_frames.clone());
        let initial_scid = router_registry.gen_unique_cid();

        let mut clinet_params = self.foundation.client_params;
        _ = clinet_params.set(ParameterId::InitialSourceConnectionId, initial_scid);

        let tls_session = ClientTlsSession::init(
            self.foundation.server_name.clone(),
            Arc::new(self.tls_config),
            &clinet_params,
        )
        .expect("Failed to initialize TLS handshake");

        // if zero rtt enabled && loadede remembered parameters && zero rtt keys is available
        let (data_space, parameters) = match tls_session.load_zero_rtt() {
            Some((remembered_parameters, zero_rtt_keys)) => {
                let data_space = DataSpace::new(
                    Role::Client,
                    &clinet_params,
                    Some(&remembered_parameters),
                    self.streams_ctrl,
                    reliable_frames.clone(),
                    tx_wakers.clone(),
                );
                qevent::event!(ParametersRestored {
                    client_parameters: &remembered_parameters,
                });
                data_space.zero_rtt_keys().set_keys(zero_rtt_keys);
                let parameters =
                    Parameters::new_client(clinet_params, Some(remembered_parameters), origin_dcid);
                (data_space, parameters)
            }
            None => {
                let data_space = DataSpace::new(
                    Role::Client,
                    &clinet_params,
                    None,
                    self.streams_ctrl,
                    reliable_frames.clone(),
                    tx_wakers.clone(),
                );
                let parameters = Parameters::new_client(clinet_params, None, origin_dcid);
                (data_space, parameters)
            }
        };

        PendingConnection {
            interfaces: self.ifaces,
            rcvd_pkt_q,
            defer_idle_timeout: self.defer_idle_timeout,
            role: Role::Client,
            origin_dcid,
            initial_scid,
            tx_wakers,
            send_lock: ArcSendLock::unrestricted(),
            reliable_frames,
            router_registry,
            parameters,
            token_registry: self.foundation.token_registry,
            tls_session: TlsSession::Client(tls_session),
            initial_keys,
            data_space,
            sepcific: SpecificComponents::Client {},
            qlogger: Arc::new(NoopLogger),
        }
    }
}

impl ConnectionFoundation<ServerFoundation, TlsServerConfig> {
    pub fn with_cids(self, origin_dcid: ConnectionId) -> PendingConnection {
        let initial_keys = initial_keys_with(
            self.tls_config.crypto_provider(),
            &origin_dcid,
            rustls::Side::Server,
            crate::tls::QUIC_VERSION,
        );

        let rcvd_pkt_q = Arc::new(RcvdPacketQueue::new());

        let tx_wakers = ArcSendWakers::default();
        let reliable_frames = ArcReliableFrameDeque::with_capacity_and_wakers(8, tx_wakers.clone());

        let router_registry = self
            .router
            .registry_on_issuing_scid(rcvd_pkt_q.clone(), reliable_frames.clone());
        let initial_scid = router_registry.gen_unique_cid();
        let odcid_router_entry = self.router.insert(origin_dcid.into(), rcvd_pkt_q.clone());

        let mut server_params = self.foundation.server_params;
        _ = server_params.set(ParameterId::InitialSourceConnectionId, initial_scid);
        _ = server_params.set(ParameterId::OriginalDestinationConnectionId, origin_dcid);

        let tls_session = ServerTlsSession::init(
            Arc::new(self.tls_config),
            &server_params,
            self.foundation.client_authers,
            self.foundation.anti_port_scan,
        )
        .expect("Failed to initialize TLS handshake"); // TODO: tls创建的错误处理

        let data_space = DataSpace::new(
            Role::Server,
            &server_params,
            None,
            self.streams_ctrl,
            reliable_frames.clone(),
            tx_wakers.clone(),
        );

        PendingConnection {
            interfaces: self.ifaces,
            rcvd_pkt_q,
            defer_idle_timeout: self.defer_idle_timeout,
            role: Role::Server,
            origin_dcid,
            initial_scid,
            tx_wakers,
            send_lock: tls_session.send_lock().clone(),
            reliable_frames,
            router_registry,
            parameters: Parameters::new_server(server_params),
            token_registry: self.foundation.token_registry,
            tls_session: TlsSession::Server(tls_session),
            initial_keys,
            data_space,
            sepcific: SpecificComponents::Server {
                odcid_router_entry: Arc::new(odcid_router_entry),
                using_odcid: Arc::new(AtomicBool::new(true)),
            },
            qlogger: Arc::new(NoopLogger),
        }
    }
}

pub struct PendingConnection {
    interfaces: Arc<QuicInterfaces>,
    rcvd_pkt_q: Arc<RcvdPacketQueue>,
    defer_idle_timeout: Duration,
    role: Role,
    origin_dcid: ConnectionId,
    initial_scid: ConnectionId,
    send_lock: ArcSendLock,
    tx_wakers: ArcSendWakers,
    reliable_frames: ArcReliableFrameDeque,
    router_registry: RouterRegistry,
    parameters: Parameters,
    token_registry: ArcTokenRegistry,
    tls_session: TlsSession,
    initial_keys: rustls::quic::Keys,
    data_space: DataSpace,
    sepcific: SpecificComponents,
    qlogger: Arc<dyn Log>,
}

impl PendingConnection {
    pub fn with_qlog(mut self, qlogger: Arc<dyn Log>) -> Self {
        self.qlogger = qlogger;
        self
    }

    pub fn run(self, event_broker: impl EmitEvent + 'static) -> Connection {
        let group_id = GroupID::from(self.origin_dcid);
        let qlog_span = self.qlogger.new_trace(self.role.into(), group_id.clone());
        let tracing_span = tracing::info_span!("connection", role = %self.role, odcid = %group_id);
        let _span = (qlog_span.enter(), tracing_span.clone().entered());

        let conn_state = ArcConnState::new();
        let event_broker = ArcEventBroker::new(conn_state.clone(), event_broker);

        let initial_token = match self.token_registry.deref() {
            TokenRegistry::Client((server_name, token_sink)) => token_sink.fetch_token(server_name),
            TokenRegistry::Server(..) => vec![],
        };
        let spaces = Spaces::new(
            InitialSpace::new(
                self.initial_keys.into(),
                initial_token,
                self.tx_wakers.clone(),
            ),
            HandshakeSpace::new(self.tx_wakers.clone()),
            self.data_space,
        );

        let quic_handshake = Handshake::new(
            RawHandshake::new(self.role, self.reliable_frames.clone()),
            Arc::new(HandshakeStatus::new(self.role == Role::Server)),
            event_broker.clone(),
        );

        let local_cids = ArcLocalCids::new(self.initial_scid, self.router_registry);
        let remote_cids = ArcRemoteCids::new(
            self.parameters
                .get_local(ParameterId::ActiveConnectionIdLimit)
                .expect("unreachable: default value will be got if the value unset"),
            self.reliable_frames.clone(),
        );
        let cid_registry = CidRegistry::new(self.role, self.origin_dcid, local_cids, remote_cids);

        let components = Components {
            interfaces: self.interfaces,
            rcvd_pkt_q: self.rcvd_pkt_q,
            conn_state,
            defer_idle_timer: ArcDeferIdleTimer::new(self.defer_idle_timeout),
            paths: ArcPathContexts::new(self.tx_wakers.clone(), event_broker.clone()),
            send_lock: self.send_lock,
            tls_handshake: ArcTlsHandshake::new(self.tls_session),
            quic_handshake,
            parameters: ArcParameters::from(self.parameters),
            token_registry: self.token_registry,
            cid_registry,
            spaces,
            event_broker,
            specific: self.sepcific,
        };

        spawn_tls_handshake(&components, self.tx_wakers.clone());
        spawn_deliver_and_parse(&components);

        Connection {
            state: Ok(components).into(),
            qlog_span,
            tracing_span,
        }
    }
}

fn spawn_tls_handshake(components: &Components, tx_wakers: ArcSendWakers) {
    let task = components.tls_handshake.clone().launch(
        components.parameters.clone(),
        components.quic_handshake.clone(),
        [
            components.spaces.initial().crypto_stream().clone(),
            components.spaces.handshake().crypto_stream().clone(),
            components.spaces.data().crypto_stream().clone(),
        ],
        (
            components.spaces.handshake().keys(),
            components.spaces.data().zero_rtt_keys(),
            components.spaces.data().one_rtt_keys(),
        ),
        on_tls_handshake_done(
            components.parameters.clone(),
            components.spaces.data().clone(),
            components.cid_registry.local.clone(),
            tx_wakers,
        ),
    );

    let event_broker = components.event_broker.clone();
    let task = async move {
        if let Err(Error::Quic(e)) = task.await {
            event_broker.emit(Event::Failed(e));
        }
    };

    tokio::spawn(task.instrument_in_current().in_current_span());

    let event_broker = components.event_broker.clone();
    let paths = components.paths.clone();
    let tls_handshake = components.tls_handshake.clone();
    let task = async move {
        {
            if time::timeout(Duration::from_secs(25), tls_handshake.finished())
                .await
                .is_err()
            {
                paths.clear();
                event_broker.emit(Event::Failed(QuicError::with_default_fty(
                    ErrorKind::NoViablePath,
                    "TLS handshake timeout after 25 seconds",
                )));
            }
        }
    };

    tokio::spawn(task.instrument_in_current().in_current_span());
}

fn on_tls_handshake_done(
    parameters: ArcParameters,
    data_space: Arc<DataSpace>,
    local_cids: ArcLocalCids,
    tx_wakers: ArcSendWakers,
) -> impl FnOnce(&TlsHandshakeInfo) -> Result<(), Error> + Send {
    move |info| {
        let zero_rtt_rejected = info
            .zero_rtt_accepted()
            .map(|accepted| !accepted)
            .unwrap_or(false);

        let parameters = parameters.lock_guard()?;

        if zero_rtt_rejected {
            debug_assert_eq!(parameters.role(), Role::Client);
            tracing::warn!("0-RTT is not enabled, or not accepted by the server.");
        }

        match parameters.role() {
            Role::Client => qevent::event!(ParametersSet {
                owner: Owner::Remote,
                server_parameters: parameters
                    .server()
                    .expect("client and server parameters has been ready"),
            }),
            Role::Server => qevent::event!(ParametersSet {
                owner: Owner::Remote,
                client_parameters: parameters
                    .client()
                    .expect("client and server parameters has been ready"),
            }),
        }

        // accept InitialMaxStreamsBidi, InitialMaxStreamUni,
        // InitialMaxStreamDataBidiLocal, InitialMaxStreamDataBidiRemote, InitialMaxStreamDataUni,
        match parameters.role() {
            Role::Client => data_space.streams().revise_params(
                zero_rtt_rejected,
                parameters
                    .server()
                    .expect("client and server parameters has been ready"),
            ),
            Role::Server => data_space.streams().revise_params(
                zero_rtt_rejected,
                parameters
                    .client()
                    .expect("client and server parameters has been ready"),
            ),
        };
        // accept InitialMaxData:
        data_space.flow_ctrl().sender.revise_max_data(
            zero_rtt_rejected,
            parameters
                .get_remote(ParameterId::InitialMaxData)
                .expect("unreachable: default value will be got if the value unset"),
        );
        // accept ActiveConnectionIdLimit
        local_cids.set_limit(
            parameters
                .get_remote(ParameterId::ActiveConnectionIdLimit)
                .expect("unreachable: default value will be got if the value unset"),
        )?;
        data_space.journal().of_rcvd_packets().revise_max_ack_delay(
            parameters
                .get_remote(ParameterId::MaxAckDelay)
                .expect("unreachable: default value will be got if the value unset"),
        );

        tx_wakers.wake_all_by(Signals::TLS_FIN);

        Result::<_, Error>::Ok(())
    }
}
