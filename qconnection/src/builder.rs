use std::{
    future::Future,
    io,
    sync::{Arc, RwLock},
    time::Duration,
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
    net::{address::AbstractAddr, tx::ArcSendWakers},
    param::{ArcParameters, ParameterId, RememberedParameters},
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
use qinterface::{queue::RcvdPacketQueue, router::QuicProto};
pub use rustls::crypto::CryptoProvider;
use tracing::Instrument as _;

use crate::{
    ArcLocalCids, ArcReliableFrameDeque, ArcRemoteCids, CidRegistry, Components, Connection,
    FlowController, Handshake, RawHandshake, Termination,
    events::{ArcEventBroker, EmitEvent, Event},
    path::{ArcPathContexts, Path},
    prelude::HeartbeatConfig,
    space::{self, Spaces, data::DataSpace, handshake::HandshakeSpace, initial::InitialSpace},
    state::ConnState,
    termination::Terminator,
    tls::{self, ArcPeerCerts, ArcServerName, ArcTlsSession},
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
    server_name: String,
    remembered: Option<RememberedParameters>,
}

impl ClientFoundation {
    pub fn with_parameters(
        self,
        client_params: ClientParameters,
        remembered: Option<RememberedParameters>,
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
        let init_max_bidi_streams = client_params.initial_max_streams_bidi().into_inner();
        let init_max_uni_streams = client_params.initial_max_streams_uni().into_inner();
        TlsReady {
            streams_ctrl: strategy_factory.init(init_max_bidi_streams, init_max_uni_streams),
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
    pub fn with_streams_concurrency_strategy<F>(self, strategy_factory: &F) -> Self
    where
        F: ?Sized + ProductStreamsConcurrencyController,
    {
        let server_params = &self.foundation.server_params;
        let init_max_bidi_streams = server_params.initial_max_streams_bidi().into_inner();
        let init_max_uni_streams = server_params.initial_max_streams_uni().into_inner();
        TlsReady {
            streams_ctrl: strategy_factory.init(init_max_bidi_streams, init_max_uni_streams),
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
    streams_ctrl: Box<dyn ControlStreamsConcurrency>,
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
    pub fn with_cids(self, origin_dcid: ConnectionId) -> ComponentsReady {
        let mut client_params = self.foundation.client_params;
        let remembered = self.foundation.remembered;

        let tx_wakers = ArcSendWakers::default();
        let reliable_frames = ArcReliableFrameDeque::with_capacity_and_wakers(8, tx_wakers.clone());

        let rcvd_pkt_q = Arc::new(RcvdPacketQueue::new());

        let router_registry: qinterface::router::RouterRegistry<ArcReliableFrameDeque> = self
            .proto
            .registry(rcvd_pkt_q.clone(), reliable_frames.clone());
        let initial_scid = router_registry.gen_unique_cid();

        client_params.set_initial_source_connection_id(initial_scid);

        let cid_registry = CidRegistry::new(
            ArcLocalCids::new(initial_scid, router_registry),
            ArcRemoteCids::new(
                origin_dcid,
                client_params.active_connection_id_limit().into(),
                reliable_frames.clone(),
            ),
        );

        let initial_keys = initial_keys_with(
            self.tls_config.crypto_provider(),
            &origin_dcid,
            rustls::Side::Client,
            rustls::quic::Version::V1,
        );

        let flow_ctrl = FlowController::new(
            0, // TODO: 0rtt
            client_params.initial_max_data().into_inner(),
            reliable_frames.clone(),
            tx_wakers.clone(),
        );

        let max_ack_delay = client_params.max_ack_delay();

        let spaces = Spaces::new(
            InitialSpace::new(initial_keys, self.foundation.token, tx_wakers.clone()),
            HandshakeSpace::new(tx_wakers.clone()),
            DataSpace::new(
                sid::Role::Client,
                reliable_frames.clone(),
                &client_params,
                self.streams_ctrl,
                tx_wakers.clone(),
                max_ack_delay,
            ),
        );

        let parameters = ArcParameters::new_client(client_params, remembered, origin_dcid);

        let tls_session =
            ArcTlsSession::new_client(self.foundation.server, self.tls_config, &parameters);

        let raw_handshake = RawHandshake::new(sid::Role::Client, reliable_frames.clone());

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
            tx_wakers,
            defer_idle_timeout: self.defer_idle_timeout,
            server_name: ArcServerName::from(self.foundation.server_name),
            qlog_span: None,
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

        let router_registry: qinterface::router::RouterRegistry<ArcReliableFrameDeque> = self
            .proto
            .registry(rcvd_pkt_q.clone(), reliable_frames.clone());
        let initial_scid = router_registry.gen_unique_cid();

        server_params.set_initial_source_connection_id(initial_scid);
        self.proto
            .add_router_entry(origin_dcid.into(), rcvd_pkt_q.clone());
        server_params.set_original_destination_connection_id(origin_dcid);

        let cid_registry = CidRegistry::new(
            ArcLocalCids::new(initial_scid, router_registry),
            ArcRemoteCids::new(
                client_scid,
                server_params.active_connection_id_limit().into(),
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
            server_params.initial_max_data().into_inner(),
            reliable_frames.clone(),
            tx_wakers.clone(),
        );

        let max_ack_delay = server_params.max_ack_delay();
        let spaces = Spaces::new(
            InitialSpace::new(initial_keys, Vec::with_capacity(0), tx_wakers.clone()),
            HandshakeSpace::new(tx_wakers.clone()),
            DataSpace::new(
                sid::Role::Server,
                reliable_frames.clone(),
                &server_params,
                self.streams_ctrl,
                tx_wakers.clone(),
                max_ack_delay,
            ),
        );

        let parameters = ArcParameters::new_server(server_params);
        _ = parameters.initial_scid_from_peer_need_equal(client_scid);

        let tls_session = ArcTlsSession::new_server(self.tls_config, &parameters);

        let raw_handshake = RawHandshake::new(sid::Role::Server, reliable_frames.clone());

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
            tx_wakers,
            defer_idle_timeout: self.defer_idle_timeout,
            server_name: ArcServerName::default(),
            qlog_span: None,
        }
    }
}

pub struct ComponentsReady {
    proto: Arc<QuicProto>,
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
    qlog_span: Option<Span>,

    server_name: ArcServerName,
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
            parameters: self.parameters,
            tls_session: self.tls_session,
            handshake: Handshake::new(self.raw_handshake, inform_cc, event_broker.clone()),
            token_registry: self.token_registry,
            cid_registry: self.cid_registry,
            flow_ctrl: self.flow_ctrl,
            spaces: self.spaces,
            proto: self.proto,
            rcvd_pkt_q: self.rcvd_pkt_q,
            paths: ArcPathContexts::new(self.tx_wakers, event_broker.clone()),
            defer_idle_timeout: self.defer_idle_timeout,
            event_broker,
            conn_state,
            peer_certs: ArcPeerCerts::default(),
            server_name: self.server_name,
        };

        tracing_span.in_scope(|| {
            qlog_span.in_scope(|| {
                tokio::spawn(tls::keys_upgrade(&components));
                tokio::spawn(accept_transport_parameters(&components));
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
        params.ready().await?;

        match role {
            sid::Role::Client => params.map_server_parameters(|p| {
                qevent::event!(ParametersSet {
                    owner: Owner::Remote,
                    server_parameters: p,
                })
            }),
            sid::Role::Server => params.map_client_parameters(|p| {
                qevent::event!(ParametersSet {
                    owner: Owner::Remote,
                    client_parameters: p,
                })
            }),
        }

        // pretend to receive the MAX_STREAM frames
        _ = streams.recv_frame(&StreamCtlFrame::MaxStreams(MaxStreamsFrame::Bi(
            params
                .get_remote_as::<VarInt>(ParameterId::InitialMaxStreamsBidi)
                .await?,
        )));
        _ = streams.recv_frame(&StreamCtlFrame::MaxStreams(MaxStreamsFrame::Uni(
            params
                .get_remote_as::<VarInt>(ParameterId::InitialMaxStreamsUni)
                .await?,
        )));

        flow_ctrl.reset_send_window(
            params
                .get_remote_as::<u64>(ParameterId::InitialMaxData)
                .await?,
        );

        cid_registry.local.set_limit(
            params
                .get_remote_as::<u64>(ParameterId::ActiveConnectionIdLimit)
                .await?,
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

impl Components {
    pub fn get_or_try_create_path(
        &self,
        iface_addr: AbstractAddr,
        link: Link,
        pathway: Pathway,
        is_probed: bool,
    ) -> io::Result<Arc<Path>> {
        let try_create = || {
            let do_validate = !self.conn_state.try_entry_attempted(self, link)?;
            qevent::event!(PathAssigned {
                path_id: pathway.to_string(),
                path_local: link.src(),
                path_remote: link.dst(),
            });
            let max_ack_delay = self
                .parameters
                .get_local_as::<Duration>(ParameterId::MaxAckDelay)?;

            let path = Arc::new(Path::new(
                &self.proto,
                iface_addr,
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
                        _ = idle_timeout => "idle timeout".into(),
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
        if self.handshake.role() == sid::Role::Server {
            let origin_dcid = self
                .parameters
                .get_origin_dcid()
                .expect("connection not close yet");
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
            }
            .instrument_in_current()
            .in_current_span()
        });

        let terminator = Arc::new(Terminator::new(ccf, &self));
        tokio::spawn(
            self.spaces
                .close(terminator, self.rcvd_pkt_q.clone(), self.event_broker)
                .instrument_in_current()
                .in_current_span(),
        );

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
        if self.handshake.role() == sid::Role::Server {
            let origin_dcid = self
                .parameters
                .get_origin_dcid()
                .expect("connection not close yet");
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
            }
            .instrument_in_current()
            .in_current_span()
        });

        let terminator = Arc::new(Terminator::new(ccf, &self));
        tokio::spawn(
            self.spaces
                .drain(terminator, self.rcvd_pkt_q)
                .instrument_in_current()
                .in_current_span(),
        );

        Termination::draining(error, self.cid_registry.local)
    }
}
