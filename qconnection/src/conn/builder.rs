use std::sync::Arc;

use futures::channel::mpsc;
use qbase::{
    cid::ConnectionId,
    param::{ArcParameters, ClientParameters, CommonParameters, ServerParameters},
    sid::{handy, ControlConcurrency, Role},
    token::{ArcTokenRegistry, TokenProvider, TokenSink},
};
use rustls::crypto::CryptoProvider;
use tokio::{sync::Notify, task::JoinHandle};

use crate::{path::Paths, router::Router, tls::ArcTlsSession};

use super::{
    space::{DataSpace, HandshakeSpace, InitialSpace},
    ArcLocalCids, ArcRemoteCids, CidRegistry, FlowController, Handshake, RcvdPackets,
};

/// 一个连接的核心，客户端、服务端通用
/// 能够处理收到的包，能够发送数据包，能够打开流、接受流
pub struct CoreConnection {
    components: Components,
    notify: Arc<Notify>,
    join_handles: [JoinHandle<RcvdPackets>; 4],
}

impl CoreConnection {
    pub fn with_token_sink(
        server_name: String,
        token_sink: Arc<dyn TokenSink>,
    ) -> ClientFoundation {
        let Ok(server) = rustls::pki_types::ServerName::try_from(server_name.clone()) else {
            panic!("server_name is not valid")
        };
        let token = token_sink.fetch_token(&server_name);

        ClientFoundation {
            server,
            token,
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
            streams_ctrl: Box::new(handy::DemandConcurrency),
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
            streams_ctrl: Box::new(handy::DemandConcurrency),
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
        .unwrap()
        .keys(&client_dcid, side, version)
}

impl TlsReady<ClientFoundation, Arc<rustls::ClientConfig>> {
    pub fn with_streams_ctrl(
        self,
        gen_streams_ctrl: &Box<dyn Fn(u64, u64) -> Box<dyn ControlConcurrency> + Send + Sync>,
    ) -> Self {
        let client_params = &self.foundation.client_params;
        let max_bidi_streams = client_params.initial_max_streams_bidi().into_inner();
        let max_uni_streams = client_params.initial_max_streams_uni().into_inner();
        TlsReady {
            streams_ctrl: gen_streams_ctrl(max_bidi_streams, max_uni_streams),
            ..self
        }
    }

    pub fn with_cids(
        mut self,
        chosen_initial_scid: ConnectionId,
        random_initial_dcid: ConnectionId,
    ) -> SpaceReady {
        let client_params = &mut self.foundation.client_params;
        let remembered = &self.foundation.remembered;

        let local_initial_max_data = client_params.initial_max_data().into_inner();
        let peer_initial_max_data = remembered.map_or(0, |p| p.initial_max_data().into_inner());

        let data_space = DataSpace::new(Role::Client, client_params, self.streams_ctrl);
        let reliable_frames = &data_space.reliable_frames;
        let handshake = Handshake::new(Role::Client, reliable_frames.clone());
        let flow_ctrl = FlowController::new(
            peer_initial_max_data,
            local_initial_max_data,
            reliable_frames.clone(),
        );

        client_params.set_initial_source_connection_id(chosen_initial_scid);
        let parameters = ArcParameters::new_client(client_params, remembered);
        parameters.original_dcid_from_server_need_equal(random_initial_dcid);

        let initial_keys = initial_keys_with(
            self.tls_config.crypto_provider(),
            &random_initial_dcid,
            rustls::Side::Client,
            rustls::quic::Version::V1,
        );
        let tls_session =
            ArcTlsSession::new_client(self.foundation.server, self.tls_config, &parameters);

        SpaceReady {
            initial_dcid: random_initial_dcid,
            parameters,
            tls_session,
            handshake,
            token_registry: self.foundation.token_registry,
            flow_ctrl,
            paths: Paths::default(),
            initial_space: InitialSpace::new(initial_keys, self.foundation.token),
            hs_space: HandshakeSpace::default(),
            data_space,
        }
    }
}

impl TlsReady<ServerFoundation, Arc<rustls::ServerConfig>> {
    pub fn with_streams_ctrl(
        self,
        gen_streams_ctrl: &Box<dyn Fn(u64, u64) -> Box<dyn ControlConcurrency> + Send + Sync>,
    ) -> Self {
        let server_params = &self.foundation.server_params;
        let max_bidi_streams = server_params.initial_max_streams_bidi().into_inner();
        let max_uni_streams = server_params.initial_max_streams_uni().into_inner();
        TlsReady {
            streams_ctrl: gen_streams_ctrl(max_bidi_streams, max_uni_streams),
            ..self
        }
    }

    pub fn with_cids(
        mut self,
        chosen_initial_scid: ConnectionId,
        original_dcid: ConnectionId,
        client_scid: ConnectionId,
    ) -> SpaceReady {
        let server_params = &mut self.foundation.server_params;
        let local_initial_max_data = server_params.initial_max_data().into_inner();

        let data_space = DataSpace::new(Role::Server, server_params, self.streams_ctrl);
        let reliable_frames = &data_space.reliable_frames;
        let handshake = Handshake::new(Role::Server, reliable_frames.clone());
        let flow_ctrl = FlowController::new(0, local_initial_max_data, reliable_frames.clone());

        server_params.set_initial_source_connection_id(chosen_initial_scid);
        server_params.set_original_destination_connection_id(original_dcid);
        let parameters = ArcParameters::new_server(server_params);
        parameters.initial_scid_from_peer_need_equal(client_scid);

        let initial_keys = initial_keys_with(
            self.tls_config.crypto_provider(),
            &original_dcid,
            rustls::Side::Server,
            rustls::quic::Version::V1,
        );
        let tls_session = ArcTlsSession::new_server(self.tls_config, &parameters);

        SpaceReady {
            initial_dcid: client_scid,
            parameters,
            tls_session,
            handshake,
            token_registry: self.foundation.token_registry,
            flow_ctrl,
            paths: Paths::default(),
            initial_space: InitialSpace::new(initial_keys, Vec::with_capacity(0)),
            hs_space: HandshakeSpace::default(),
            data_space,
        }
    }
}

pub struct SpaceReady {
    initial_dcid: ConnectionId,
    parameters: ArcParameters,
    tls_session: ArcTlsSession,
    handshake: Handshake,
    token_registry: ArcTokenRegistry,
    flow_ctrl: FlowController,
    paths: Paths,
    initial_space: InitialSpace,
    hs_space: HandshakeSpace,
    data_space: DataSpace,
}

impl SpaceReady {
    pub fn run_with(self) -> CoreConnection {
        let (initial_packets_entry, rcvd_initial_packets) = mpsc::unbounded();
        let (zero_rtt_packets_entry, rcvd_0rtt_packets) = mpsc::unbounded();
        let (hs_packets_entry, rcvd_hs_packets) = mpsc::unbounded();
        let (one_rtt_packets_entry, rcvd_1rtt_packets) = mpsc::unbounded();

        let local_params = self.parameters.local().unwrap();
        let reliable_frames = &self.data_space.reliable_frames;
        let initial_scid = local_params.initial_source_connection_id();
        let router_registry = Router::registry(
            initial_scid,
            reliable_frames.clone(),
            [
                initial_packets_entry,
                zero_rtt_packets_entry,
                hs_packets_entry,
                one_rtt_packets_entry,
            ],
        );
        let local_cids = ArcLocalCids::new(initial_scid, router_registry);
        let remote_cids = ArcRemoteCids::new(
            self.initial_dcid,
            local_params.active_connection_id_limit().into(),
            reliable_frames.clone(),
        );
        let cid_registry = CidRegistry::new(local_cids, remote_cids);

        let notify = Arc::new(Notify::new());

        todo!()
        /*
        CoreConnection {
            components,
            notify,
            join_handles,
        }
        */
    }
}

pub struct Components {
    parameters: ArcParameters,
    tls_session: ArcTlsSession,
    handshake: Handshake,
    token_registry: ArcTokenRegistry,
    cid_registry: CidRegistry,
    flow_ctrl: FlowController,
    paths: Paths,
    initial_space: InitialSpace,
    hs_space: HandshakeSpace,
    data_space: DataSpace,
}
