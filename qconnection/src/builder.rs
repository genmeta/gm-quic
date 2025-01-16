use std::{
    future::Future,
    sync::{Arc, RwLock},
    time::Duration,
};

pub use qbase::{
    cid::{ConnectionId, GenUniqueCid, RetireCid},
    packet::{
        header::{GetDcid, GetScid},
        long::DataHeader as LongHeader,
        DataHeader, Packet,
    },
    param::{ClientParameters, CommonParameters, ServerParameters},
    sid::{handy::*, ControlConcurrency},
    token::{handy::*, TokenProvider, TokenSink},
};
use qbase::{
    error::{Error, ErrorKind},
    frame::ConnectionCloseFrame,
    param::{self, ArcParameters},
    sid,
    token::ArcTokenRegistry,
    Epoch,
};
use qcongestion::{ArcCC, CongestionAlgorithm, CongestionControl};
use qinterface::{
    conn::{ConnInterface, PathContext},
    path::Pathway,
    router::QuicProto,
};
pub use rustls::crypto::CryptoProvider;
use tokio::sync::Notify;

use crate::{
    events::{EmitEvent, Event},
    path::{Path, PathKind},
    space::{self, data::DataSpace, handshake::HandshakeSpace, initial::InitialSpace, Spaces},
    tls::{self, ArcTlsSession},
    ArcConnInterface, ArcLocalCids, ArcReliableFrameDeque, ArcRemoteCids, CidRegistry, Components,
    Connection, CoreConnection, FlowController, Handshake, RawHandshake, Termination,
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

    pub fn with_interface(
        mut self,
        proto: Arc<QuicProto>,
        random_initial_dcid: ConnectionId,
    ) -> ComponentsReady {
        let client_params = &mut self.foundation.client_params;
        let remembered = &self.foundation.remembered;

        let send_notify = Arc::new(Notify::new());
        let reliable_frames =
            ArcReliableFrameDeque::with_capacity_and_notify(8, send_notify.clone());

        let conn_iface = Arc::new(ConnInterface::new(proto.clone()));

        let router_registry: qinterface::router::RouterRegistry<ArcReliableFrameDeque> = proto
            .registry(
                conn_iface.received_packets_buffer().clone(),
                reliable_frames.clone(),
            );
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
            InitialSpace::new(initial_keys, self.foundation.token),
            HandshakeSpace::new(),
            DataSpace::new(
                sid::Role::Client,
                reliable_frames.clone(),
                client_params,
                self.streams_ctrl,
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
            conn_iface,
            send_notify,
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

    pub fn with_interface(
        mut self,
        proto: Arc<QuicProto>,
        original_dcid: ConnectionId,
        client_scid: ConnectionId,
    ) -> ComponentsReady {
        let server_params = &mut self.foundation.server_params;
        let send_notify = Arc::new(Notify::new());
        let reliable_frames =
            ArcReliableFrameDeque::with_capacity_and_notify(8, send_notify.clone());

        let conn_iface = Arc::new(ConnInterface::new(proto.clone()));

        let issued_cids = reliable_frames.clone();
        let router_registry: qinterface::router::RouterRegistry<ArcReliableFrameDeque> =
            proto.registry(conn_iface.received_packets_buffer().clone(), issued_cids);

        let initial_scid = router_registry.gen_unique_cid();
        server_params.set_initial_source_connection_id(initial_scid);

        proto.register(
            original_dcid.into(),
            conn_iface.received_packets_buffer().clone(),
        );
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
            InitialSpace::new(initial_keys, Vec::with_capacity(0)),
            HandshakeSpace::new(),
            DataSpace::new(
                sid::Role::Server,
                reliable_frames.clone(),
                server_params,
                self.streams_ctrl,
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
            conn_iface,
            send_notify,
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
    conn_iface: ArcConnInterface,
    send_notify: Arc<Notify>,
}

impl ComponentsReady {
    pub fn run_with<EE>(self, event_broker: EE) -> Connection
    where
        EE: EmitEvent + Clone + Send + Sync + 'static,
    {
        let event_broker = Arc::new(event_broker);
        let handshake = Handshake::new(self.raw_handshake, event_broker.clone());

        let components = Components {
            parameters: self.parameters,
            tls_session: self.tls_session,
            handshake,
            token_registry: self.token_registry,
            cid_registry: self.cid_registry,
            flow_ctrl: self.flow_ctrl,
            spaces: self.spaces,
            conn_iface: self.conn_iface,
            send_notify: self.send_notify,
            event_broker,
        };

        tokio::spawn(tls::keys_upgrade(&components));

        tokio::spawn(accpet_transport_parameters(&components));

        space::launch_deliver_and_parse(&components);

        Connection(RwLock::new(Ok(CoreConnection { components })))
    }
}

fn accpet_transport_parameters(components: &Components) -> impl Future<Output = ()> + Send {
    let params = components.parameters.clone();
    let streams = components.spaces.data().streams().clone();
    let cid_registry = components.cid_registry.clone();
    let flow_ctrl = components.flow_ctrl.clone();
    let event_broker = components.event_broker.clone();
    async move {
        use qbase::frame::{MaxStreamsFrame, ReceiveFrame, StreamCtlFrame};
        if let Ok(param::Pair { local: _, remote }) = params.await {
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
}

impl Components {
    pub fn try_create_path(&self, pathway: Pathway, is_probed: bool) -> Option<PathContext<Path>> {
        let max_ack_delay = self.parameters.local()?.max_ack_delay().into_inner();

        let cc = ArcCC::new(
            CongestionAlgorithm::Bbr,
            Duration::from_micros(max_ack_delay as _),
            [
                self.spaces.initial().clone(),
                self.spaces.handshake().clone(),
                self.spaces.data().clone(),
            ],
            Box::new(self.handshake.clone()),
        );

        let conn_iface = self.conn_iface.clone();
        let is_initial = conn_iface.try_create_initial_path();
        let kind = PathKind::new(is_initial, is_probed);
        let path = Arc::new(Path::new(pathway, cc, kind, conn_iface.clone()));

        if !kind.is_probed() {
            path.grant_anti_amplifier();
        }

        let burst = path.new_burst(self);
        let guard = path.new_guard(self);
        let ticker = path.new_ticker();

        let event_broker = self.event_broker.clone();
        let task = tokio::spawn(async move {
            tokio::select! {
                _ = burst.launch() => {},
                _ = guard.launch() => {},
                _ = ticker.launch() => {}
            }
            conn_iface.paths().remove(&pathway);
            if conn_iface.paths().is_empty() {
                event_broker.emit(Event::Failed(Error::with_default_fty(
                    ErrorKind::NoViablePath,
                    "no viable path exist",
                )));
            }
        });
        Some(PathContext::new(path, task.abort_handle()))
    }
}

impl CoreConnection {
    // 对于server，第一条路径也通过add_path添加

    pub fn enter_closing(self, ccf: ConnectionCloseFrame) -> Termination {
        let error = ccf.clone().into();
        self.spaces.data().on_conn_error(&error);
        self.components.flow_ctrl.on_conn_error(&error);
        self.components.tls_session.on_conn_error(&error);
        if self.components.handshake.role() == sid::Role::Server {
            let local_parameters = self.components.parameters.server().unwrap();
            let origin_dcid = local_parameters.original_destination_connection_id();
            self.conn_iface.router_if().unregister(&origin_dcid.into());
        }
        self.components.parameters.on_conn_error(&error);
        let closing_iface = Arc::new(self.conn_iface.close(ccf, &self.components.cid_registry));

        tokio::spawn({
            let local_cids = self.cid_registry.local.clone();
            let event_broker = self.event_broker.clone();
            let pto_duration = self
                .conn_iface
                .paths()
                .iter()
                .map(|p| p.cc().pto_time(Epoch::Data))
                .max()
                .unwrap_or_default();
            async move {
                tokio::time::sleep(pto_duration).await;
                local_cids.clear();
                event_broker.emit(Event::Terminated);
            }
        });

        self.components
            .spaces
            .close(closing_iface.clone(), &self.components.event_broker);

        Termination::closing(error, self.components.cid_registry.local, closing_iface)
    }

    pub fn enter_draining(self, error: Error) -> Termination {
        self.spaces.data().on_conn_error(&error);
        self.components.flow_ctrl.on_conn_error(&error);
        self.components.tls_session.on_conn_error(&error);
        if self.components.handshake.role() == sid::Role::Server {
            let local_parameters = self.components.parameters.server().unwrap();
            let origin_dcid = local_parameters.original_destination_connection_id();
            self.conn_iface.router_if().unregister(&origin_dcid.into());
        }
        self.components.parameters.on_conn_error(&error);

        tokio::spawn({
            let local_cids = self.cid_registry.local.clone();
            let event_broker = self.event_broker.clone();
            let pto_duration = self
                .conn_iface
                .paths()
                .iter()
                .map(|p| p.cc().pto_time(Epoch::Data))
                .max()
                .unwrap_or_default();
            async move {
                tokio::time::sleep(pto_duration).await;
                local_cids.clear();
                event_broker.emit(Event::Terminated);
            }
        });

        self.conn_iface.received_packets_buffer().close_all();
        Termination::draining(error, self.components.cid_registry.local)
    }
}
