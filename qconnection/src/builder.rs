use std::{
    borrow::Cow,
    future::Future,
    ops::Deref,
    sync::{Arc, RwLock},
    time::Duration,
};

pub use qbase::{
    cid::{ConnectionId, GenUniqueCid, RetireCid},
    packet::{
        DataHeader, Packet,
        header::{GetDcid, GetScid},
        long::DataHeader as LongHeader,
    },
    param::{ClientParameters, CommonParameters, ServerParameters},
    sid::{ControlConcurrency, handy::*},
    token::{TokenProvider, TokenSink, handy::*},
};
use qbase::{
    frame::ConnectionCloseFrame,
    param::{self, ArcParameters},
    sid,
    token::ArcTokenRegistry,
};
use qcongestion::{ArcCC, CongestionAlgorithm};
use qinterface::{
    path::{Netway, Pathway},
    queue::RcvdPacketQueue,
    router::QuicProto,
};
use qlog::{
    GroupID, VantagePointType,
    quic::{
        Owner,
        connectivity::{
            ConnectionClosed, ConnectionStateUpdated, GranularConnectionStates, PathAssigned,
        },
        transport::ParametersSet,
    },
    telemetry::{Instrument, Log, Span},
};
pub use rustls::crypto::CryptoProvider;
use tokio::sync::Notify;
use tracing::Instrument as _;

use crate::{
    ArcLocalCids, ArcReliableFrameDeque, ArcRemoteCids, CidRegistry, Components, Connection,
    FlowController, Handshake, RawHandshake, Termination,
    events::{ArcEventBroker, EmitEvent, Event},
    path::{ArcPaths, Path, PathContext},
    prelude::HeartbeatConfig,
    space::{self, Spaces, data::DataSpace, handshake::HandshakeSpace, initial::InitialSpace},
    state::ConnState,
    termination::ClosingState,
    tls::{self, ArcTlsSession},
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
            token_registry: ArcTokenRegistry::with_sink(server_name, token_sink),
            client_params: ClientParameters::default(),
            remembered: None,
        }
    }

    pub fn with_token_provider(token_provider: Arc<dyn TokenProvider>) -> ServerFoundation {
        ServerFoundation {
            token_registry: ArcTokenRegistry::with_provider(token_provider),
            server_params: ServerParameters::default(),
        }
    }
}

pub struct ClientFoundation {
    server: rustls::pki_types::ServerName<'static>,
    token: Vec<u8>,
    token_registry: ArcTokenRegistry,
    client_params: ClientParameters,
    remembered: Option<CommonParameters>,
}

impl ClientFoundation {
    pub fn with_parameters(
        self,
        client_params: ClientParameters,
        remembered: Option<CommonParameters>,
    ) -> Self {
        ClientFoundation {
            client_params,
            remembered,
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
}

impl ServerFoundation {
    pub fn with_parameters(self, server_params: ServerParameters) -> Self {
        ServerFoundation {
            server_params,
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
    streams_ctrl: Box<dyn ControlConcurrency>,
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
    pub fn with_streams_ctrl(
        self,
        gen_streams_ctrl: impl FnOnce(u64, u64) -> Box<dyn ControlConcurrency> + Send + Sync,
    ) -> Self {
        let client_params = &self.foundation.client_params;
        let max_bidi_streams = client_params.initial_max_streams_bidi().into_inner();
        let max_uni_streams = client_params.initial_max_streams_uni().into_inner();
        TlsReady {
            streams_ctrl: gen_streams_ctrl(max_bidi_streams, max_uni_streams),
            ..self
        }
    }

    pub fn with_proto(
        self,
        proto: Arc<QuicProto>,
    ) -> ProtoReady<ClientFoundation, Arc<rustls::ClientConfig>> {
        ProtoReady {
            foundation: self.foundation,
            tls_config: self.tls_config,
            streams_ctrl: self.streams_ctrl,
            proto,
            defer_idle_timeout: HeartbeatConfig::default(),
        }
    }
}

impl TlsReady<ServerFoundation, Arc<rustls::ServerConfig>> {
    pub fn with_streams_ctrl(
        self,
        gen_streams_ctrl: impl FnOnce(u64, u64) -> Box<dyn ControlConcurrency> + Send + Sync,
    ) -> Self {
        let server_params = &self.foundation.server_params;
        let max_bidi_streams = server_params.initial_max_streams_bidi().into_inner();
        let max_uni_streams = server_params.initial_max_streams_uni().into_inner();
        TlsReady {
            streams_ctrl: gen_streams_ctrl(max_bidi_streams, max_uni_streams),
            ..self
        }
    }

    pub fn with_proto(
        self,
        proto: Arc<QuicProto>,
    ) -> ProtoReady<ServerFoundation, Arc<rustls::ServerConfig>> {
        ProtoReady {
            foundation: self.foundation,
            tls_config: self.tls_config,
            streams_ctrl: self.streams_ctrl,
            proto,
            defer_idle_timeout: HeartbeatConfig::default(),
        }
    }
}

pub struct ProtoReady<Foundation, Config> {
    foundation: Foundation,
    tls_config: Config,
    streams_ctrl: Box<dyn ControlConcurrency>,
    proto: Arc<QuicProto>,
    defer_idle_timeout: HeartbeatConfig,
}

impl<Foundation, Config> ProtoReady<Foundation, Config> {
    pub fn defer_idle_timeout(self, config: HeartbeatConfig) -> Self {
        Self {
            defer_idle_timeout: config,
            ..self
        }
    }
}

impl ProtoReady<ClientFoundation, Arc<rustls::ClientConfig>> {
    pub fn with_cids(mut self, random_initial_dcid: ConnectionId) -> ComponentsReady {
        let client_params = &mut self.foundation.client_params;
        let remembered = &self.foundation.remembered;

        let sendable = Arc::new(Notify::new());
        let reliable_frames = ArcReliableFrameDeque::with_capacity_and_notify(8, sendable.clone());

        let rcvd_pkt_q = Arc::new(RcvdPacketQueue::new());

        let router_registry: qinterface::router::RouterRegistry<ArcReliableFrameDeque> = self
            .proto
            .registry(rcvd_pkt_q.clone(), reliable_frames.clone());
        let initial_scid = router_registry.gen_unique_cid();

        client_params.set_initial_source_connection_id(initial_scid);
        let parameters = ArcParameters::new_client(*client_params, *remembered);
        parameters.original_dcid_from_server_need_equal(random_initial_dcid);

        let initial_keys = initial_keys_with(
            self.tls_config.crypto_provider(),
            &random_initial_dcid,
            rustls::Side::Client,
            rustls::quic::Version::V1,
        );

        let tls_session =
            ArcTlsSession::new_client(self.foundation.server, self.tls_config, &parameters);

        let raw_handshake = RawHandshake::new(sid::Role::Client, reliable_frames.clone());

        let cid_registry = CidRegistry::new(
            ArcLocalCids::new(initial_scid, router_registry),
            ArcRemoteCids::new(
                random_initial_dcid,
                client_params.active_connection_id_limit().into(),
                reliable_frames.clone(),
            ),
        );

        let flow_ctrl = FlowController::new(
            remembered.map_or(0, |p| p.initial_max_data().into_inner()),
            client_params.initial_max_data().into_inner(),
            reliable_frames.clone(),
        );

        let spaces = Spaces::new(
            InitialSpace::new(initial_keys, self.foundation.token, sendable.clone()),
            HandshakeSpace::new(sendable.clone()),
            DataSpace::new(
                sid::Role::Client,
                reliable_frames.clone(),
                client_params,
                self.streams_ctrl,
                sendable.clone(),
            ),
        );

        ComponentsReady {
            parameters,
            tls_session,
            raw_handshake,
            token_registry: self.foundation.token_registry,
            cid_registry,
            flow_ctrl,
            spaces,
            proto: self.proto,
            rcvd_pkt_q,
            sendable,
            defer_idle_timeout: self.defer_idle_timeout,
            span: None,
        }
    }
}

impl ProtoReady<ServerFoundation, Arc<rustls::ServerConfig>> {
    pub fn with_cids(
        mut self,
        original_dcid: ConnectionId,
        client_scid: ConnectionId,
    ) -> ComponentsReady {
        let server_params = &mut self.foundation.server_params;
        let sendable = Arc::new(Notify::new());
        let reliable_frames = ArcReliableFrameDeque::with_capacity_and_notify(8, sendable.clone());

        let rcvd_pkt_q = Arc::new(RcvdPacketQueue::new());

        let issued_cids = reliable_frames.clone();
        let router_registry: qinterface::router::RouterRegistry<ArcReliableFrameDeque> =
            self.proto.registry(rcvd_pkt_q.clone(), issued_cids);

        let initial_scid = router_registry.gen_unique_cid();
        server_params.set_initial_source_connection_id(initial_scid);

        self.proto
            .add_router_entry(original_dcid.into(), rcvd_pkt_q.clone());
        server_params.set_original_destination_connection_id(original_dcid);
        let parameters = ArcParameters::new_server(*server_params);
        parameters.initial_scid_from_peer_need_equal(client_scid);

        let initial_keys = initial_keys_with(
            self.tls_config.crypto_provider(),
            &original_dcid,
            rustls::Side::Server,
            rustls::quic::Version::V1,
        );
        let tls_session = ArcTlsSession::new_server(self.tls_config, &parameters);

        let raw_handshake = RawHandshake::new(sid::Role::Server, reliable_frames.clone());

        let cid_registry = CidRegistry::new(
            ArcLocalCids::new(initial_scid, router_registry),
            ArcRemoteCids::new(
                client_scid,
                server_params.active_connection_id_limit().into(),
                reliable_frames.clone(),
            ),
        );

        let flow_ctrl = FlowController::new(
            0,
            server_params.initial_max_data().into_inner(),
            reliable_frames.clone(),
        );

        let spaces = Spaces::new(
            InitialSpace::new(initial_keys, Vec::with_capacity(0), sendable.clone()),
            HandshakeSpace::new(sendable.clone()),
            DataSpace::new(
                sid::Role::Server,
                reliable_frames.clone(),
                server_params,
                self.streams_ctrl,
                sendable.clone(),
            ),
        );

        ComponentsReady {
            parameters,
            tls_session,
            raw_handshake,
            token_registry: self.foundation.token_registry,
            cid_registry,
            flow_ctrl,
            spaces,
            proto: self.proto,
            rcvd_pkt_q,
            sendable,
            defer_idle_timeout: self.defer_idle_timeout,
            span: None,
        }
    }
}

pub struct ComponentsReady {
    parameters: ArcParameters,
    tls_session: ArcTlsSession,
    raw_handshake: RawHandshake,
    token_registry: ArcTokenRegistry,
    cid_registry: CidRegistry,
    flow_ctrl: FlowController,
    spaces: Spaces,
    proto: Arc<QuicProto>,
    rcvd_pkt_q: Arc<RcvdPacketQueue>,
    defer_idle_timeout: HeartbeatConfig,
    sendable: Arc<Notify>,
    span: Option<Span>,
}

impl ComponentsReady {
    pub fn with_qlog(mut self, logger: &(impl Log + ?Sized)) -> Self {
        let vantage_point_type = match self.raw_handshake.role() {
            sid::Role::Client => VantagePointType::Client,
            sid::Role::Server => VantagePointType::Server,
        };
        let origin_dcid = self.parameters.get_origin_dcid().unwrap();
        self.span = Some(logger.new_trace(vantage_point_type, origin_dcid.into()));
        self
    }

    pub fn run_with<EE>(self, event_broker: EE) -> Connection
    where
        EE: EmitEvent + Clone + Send + Sync + 'static,
    {
        let group_id = GroupID::from(self.parameters.get_origin_dcid().unwrap());
        let span = self.span.unwrap_or_else(|| qlog::span!(@current, group_id));
        let event_broker = ArcEventBroker::new(event_broker);
        let components = Components {
            parameters: self.parameters,
            tls_session: self.tls_session,
            handshake: Handshake::new(self.raw_handshake, event_broker.clone()),
            token_registry: self.token_registry,
            cid_registry: self.cid_registry,
            flow_ctrl: self.flow_ctrl,
            spaces: self.spaces,
            proto: self.proto,
            rcvd_pkt_q: self.rcvd_pkt_q,
            paths: ArcPaths::new(event_broker.clone()),
            send_notify: self.sendable,
            defer_idle_timeout: self.defer_idle_timeout,
            event_broker,
            state: ConnState::new(),
            span: span.clone(),
        };

        span.in_scope(|| {
            tokio::spawn(tls::keys_upgrade(&components));
            tokio::spawn(accpet_transport_parameters(&components));
            space::spawn_deliver_and_parse(&components);
        });

        Connection(RwLock::new(Ok(components)))
    }
}

fn accpet_transport_parameters(components: &Components) -> impl Future<Output = ()> + Send + use<> {
    let params = components.parameters.clone();
    let streams = components.spaces.data().streams().clone();
    let cid_registry = components.cid_registry.clone();
    let flow_ctrl = components.flow_ctrl.clone();
    let event_broker = components.event_broker.clone();
    let role = components.handshake.role();
    async move {
        use qbase::frame::{MaxStreamsFrame, ReceiveFrame, StreamCtlFrame};
        if let Ok(param::Pair { remote, .. }) = params.clone().await {
            match role {
                sid::Role::Client => qlog::event!(ParametersSet {
                    owner: Owner::Remote,
                    server_parameters: params.server().expect("unreachable"),
                }),
                sid::Role::Server => qlog::event!(ParametersSet {
                    owner: Owner::Local,
                    client_parameters: params.client().expect("unreachable"),
                }),
            }

            // pretend to receive the MAX_STREAM frames
            _ = streams.recv_frame(&StreamCtlFrame::MaxStreams(MaxStreamsFrame::Bi(
                remote.initial_max_streams_bidi(),
            )));
            _ = streams.recv_frame(&StreamCtlFrame::MaxStreams(MaxStreamsFrame::Uni(
                remote.initial_max_streams_uni(),
            )));

            flow_ctrl.reset_send_window(remote.initial_max_data().into_inner());

            let active_cid_limit = remote.active_connection_id_limit().into();
            if let Err(e) = cid_registry.local.set_limit(active_cid_limit) {
                event_broker.emit(Event::Failed(e));
            }
        }
    }
    .instrument_in_current()
    .in_current_span()
}

impl Components {
    pub fn get_or_create_path(
        &self,
        netway: Netway,
        pathway: Pathway,
        is_probed: bool,
    ) -> Option<Arc<Path>> {
        match self.paths.entry(pathway) {
            dashmap::Entry::Occupied(occupied_entry) => Some(occupied_entry.get().deref().clone()),
            dashmap::Entry::Vacant(vacant_entry) => {
                let do_validate = !self.state.try_entry_attempted(self, netway);
                qlog::event!(PathAssigned {
                    path_id: pathway.to_string(),
                    path_local: netway.src(),
                    path_remote: netway.dst(),
                });
                let max_ack_delay = self.parameters.local()?.max_ack_delay().into_inner();

                let cc = ArcCC::new(
                    CongestionAlgorithm::NewReno,
                    Duration::from_micros(max_ack_delay as _),
                    [
                        self.spaces.initial().clone(),
                        self.spaces.handshake().clone(),
                        self.spaces.data().clone(),
                    ],
                    Box::new(self.handshake.clone()),
                );

                let path = Arc::new(Path::new(&self.proto, netway, pathway, cc)?);

                if !is_probed {
                    path.grant_anti_amplifier();
                }

                let burst = path.new_burst(self);
                let idle_timeout = path.idle_timeout(self);

                let task = {
                    let path = path.clone();
                    let paths = self.paths.clone();
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
                        let reason: Cow<'static, str> = tokio::select! {
                            false = validate => "failed to validate".into(),
                            _ = idle_timeout => "idle timeout".into(),
                            Err(e) = burst.launch() => format!("failed to send packets: {}", e).into(),
                            _ = path.defer_idle_timeout(defer_idle_timeout) => "failed to defer idle timeout".into(),
                        };
                        // same as [`Components::del_path`]
                        paths.remove(&pathway, reason.as_ref());
                    }
                };

                let task =
                    Instrument::instrument(task, qlog::span!(@current, path=pathway.to_string()))
                        .instrument_in_current();

                vacant_entry.insert(PathContext::new(
                    path.clone(),
                    tokio::spawn(task).abort_handle(),
                ));
                tracing::info!(%pathway, %netway,is_probed,do_validate, "created new path");
                Some(path)
            }
        }
    }
}

impl Components {
    // 对于server，第一条路径也通过add_path添加
    pub fn enter_closing(self, ccf: ConnectionCloseFrame) -> Termination {
        let _enter = self.span.enter();
        qlog::event!(ConnectionClosed {
            owner: Owner::Local,
            ccf: &ccf // TODO: trigger
        });
        qlog::event!(ConnectionStateUpdated {
            ?old: self.state.load(),
            new: GranularConnectionStates::Closing,
        });

        let error = ccf.clone().into();
        self.spaces.data().on_conn_error(&error);
        self.flow_ctrl.on_conn_error(&error);
        self.tls_session.on_conn_error(&error);
        if self.handshake.role() == sid::Role::Server {
            let local_parameters = self.parameters.server().unwrap();
            let origin_dcid = local_parameters.original_destination_connection_id();
            self.proto.del_router_entry(&origin_dcid.into());
        }
        self.parameters.on_conn_error(&error);
        let closing_state = Arc::new(ClosingState::new(ccf, &self));

        tokio::spawn({
            let local_cids = self.cid_registry.local.clone();
            let event_broker = self.event_broker.clone();
            let pto_duration = self.paths.max_pto_duration().unwrap_or_default();
            async move {
                tokio::time::sleep(pto_duration * 3).await;
                local_cids.clear();
                event_broker.emit(Event::Terminated);
                qlog::event!(ConnectionStateUpdated {
                    old: GranularConnectionStates::Closing,
                    new: GranularConnectionStates::Closed,
                });
            }
            .instrument_in_current()
            .in_current_span()
        });

        self.spaces
            .close(closing_state.clone(), self.event_broker.clone());

        Termination::closing(error, self.cid_registry.local, closing_state)
    }

    pub fn enter_draining(self, ccf: ConnectionCloseFrame) -> Termination {
        let _enter = self.span.enter();
        qlog::event!(ConnectionClosed {
            owner: Owner::Local,
            ccf: &ccf // TODO: trigger
        });
        qlog::event!(ConnectionStateUpdated {
            ?old: self.state.load(),
            new: GranularConnectionStates::Draining,
        });

        let error = ccf.into();
        self.spaces.data().on_conn_error(&error);
        self.flow_ctrl.on_conn_error(&error);
        self.tls_session.on_conn_error(&error);
        if self.handshake.role() == sid::Role::Server {
            let local_parameters = self.parameters.server().unwrap();
            let origin_dcid = local_parameters.original_destination_connection_id();
            self.proto.del_router_entry(&origin_dcid.into());
        }
        self.parameters.on_conn_error(&error);

        tokio::spawn({
            let local_cids = self.cid_registry.local.clone();
            let event_broker = self.event_broker.clone();
            let pto_duration = self.paths.max_pto_duration().unwrap_or_default();
            async move {
                tokio::time::sleep(pto_duration * 3).await;
                local_cids.clear();
                event_broker.emit(Event::Terminated);
                qlog::event!(ConnectionStateUpdated {
                    old: GranularConnectionStates::Draining,
                    new: GranularConnectionStates::Closed,
                });
            }
            .instrument_in_current()
            .in_current_span()
        });

        self.rcvd_pkt_q.close_all();
        Termination::draining(error, self.cid_registry.local)
    }
}
