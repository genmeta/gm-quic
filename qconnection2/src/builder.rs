use std::sync::Arc;

pub use qbase::{
    cid::ConnectionId,
    param::{ClientParameters, CommonParameters, ServerParameters},
    sid::ControlConcurrency,
    token::{TokenProvider, TokenSink},
};
use qbase::{param, sid, token};
use qrecovery::reliable;
pub use rustls::{self, crypto::CryptoProvider};

use crate::{
    conn,
    dying::{closing, draining},
    event, path, router,
    space::{data, handshake, initial},
    tls,
};

/// 一个连接的核心，客户端、服务端通用
/// 能够处理收到的包，能够发送数据包，能够打开流、接受流
pub struct CoreConnection {
    pub(crate) spaces: Spaces,
    pub(crate) components: Components,
    pub(crate) paths: Arc<path::Paths>,
    // TOOD: if -> iface
    pub(crate) conn_if: Arc<router::ConnInterface>,
}

#[derive(Clone)]
pub struct Components {
    pub(crate) parameters: param::ArcParameters,
    pub(crate) tls_session: tls::ArcTlsSession,
    pub(crate) handshake: conn::Handshake,
    pub(crate) token_registry: token::ArcTokenRegistry,
    pub(crate) cid_registry: conn::CidRegistry,
    pub(crate) flow_ctrl: conn::FlowController,
}

#[derive(Clone)]
pub struct Spaces {
    pub(crate) initial: initial::Space,
    pub(crate) handshake: handshake::Space,
    pub(crate) data: data::Space,
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
            token_registry: token::ArcTokenRegistry::with_sink(server_name, token_sink),
            client_params: ClientParameters::default(),
            remembered: None,
        }
    }

    pub fn with_token_provider(token_provider: Arc<dyn TokenProvider>) -> ServerFoundation {
        ServerFoundation {
            token_registry: token::ArcTokenRegistry::with_provider(token_provider),
            server_params: ServerParameters::default(),
        }
    }
}

pub struct ClientFoundation {
    server: rustls::pki_types::ServerName<'static>,
    token: Vec<u8>,
    token_registry: token::ArcTokenRegistry,
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
    token_registry: token::ArcTokenRegistry,
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

    pub fn with_cids(
        mut self,
        chosen_initial_scid: ConnectionId,
        random_initial_dcid: ConnectionId,
    ) -> SpaceReady {
        let client_params = &mut self.foundation.client_params;
        let remembered = &self.foundation.remembered;

        let local_initial_max_data = client_params.initial_max_data().into_inner();
        let peer_initial_max_data = remembered.map_or(0, |p| p.initial_max_data().into_inner());

        let reliable_frames = reliable::ArcReliableFrameDeque::with_capacity(8);
        let data_space = data::Space::new(
            sid::Role::Client,
            reliable_frames.clone(),
            client_params,
            self.streams_ctrl,
        );

        let handshake = conn::Handshake::new(sid::Role::Client, reliable_frames.clone());
        let flow_ctrl = conn::FlowController::new(
            peer_initial_max_data,
            local_initial_max_data,
            reliable_frames.clone(),
        );

        client_params.set_initial_source_connection_id(chosen_initial_scid);
        let parameters = param::ArcParameters::new_client(*client_params, *remembered);
        parameters.original_dcid_from_server_need_equal(random_initial_dcid);

        let initial_keys = initial_keys_with(
            self.tls_config.crypto_provider(),
            &random_initial_dcid,
            rustls::Side::Client,
            rustls::quic::Version::V1,
        );
        let tls_session =
            tls::ArcTlsSession::new_client(self.foundation.server, self.tls_config, &parameters);

        let spaces = Spaces {
            initial: initial::Space::new(initial_keys, self.foundation.token),
            handshake: handshake::Space::new(),
            data: data_space,
        };

        SpaceReady {
            initial_dcid: random_initial_dcid,
            parameters,
            tls_session,
            handshake,
            token_registry: self.foundation.token_registry,
            flow_ctrl,
            reliable_frames,
            spaces,
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

    pub fn with_cids(
        mut self,
        chosen_initial_scid: ConnectionId,
        original_dcid: ConnectionId,
        client_scid: ConnectionId,
    ) -> SpaceReady {
        let server_params = &mut self.foundation.server_params;
        let local_initial_max_data = server_params.initial_max_data().into_inner();

        let reliable_frames = reliable::ArcReliableFrameDeque::with_capacity(8);
        let data_space = data::Space::new(
            sid::Role::Client,
            reliable_frames.clone(),
            server_params,
            self.streams_ctrl,
        );
        let handshake = conn::Handshake::new(sid::Role::Server, reliable_frames.clone());
        let flow_ctrl =
            conn::FlowController::new(0, local_initial_max_data, reliable_frames.clone());

        server_params.set_initial_source_connection_id(chosen_initial_scid);
        server_params.set_original_destination_connection_id(original_dcid);
        let parameters = param::ArcParameters::new_server(*server_params);
        parameters.initial_scid_from_peer_need_equal(client_scid);

        let initial_keys = initial_keys_with(
            self.tls_config.crypto_provider(),
            &original_dcid,
            rustls::Side::Server,
            rustls::quic::Version::V1,
        );
        let tls_session = tls::ArcTlsSession::new_server(self.tls_config, &parameters);

        let spaces = Spaces {
            initial: initial::Space::new(initial_keys, Vec::with_capacity(0)),
            handshake: handshake::Space::new(),
            data: data_space,
        };

        SpaceReady {
            initial_dcid: client_scid,
            parameters,
            tls_session,
            handshake,
            token_registry: self.foundation.token_registry,
            flow_ctrl,
            reliable_frames,
            spaces,
        }
    }
}

pub struct SpaceReady {
    initial_dcid: ConnectionId,
    parameters: param::ArcParameters,
    tls_session: tls::ArcTlsSession,
    handshake: conn::Handshake,
    token_registry: token::ArcTokenRegistry,
    flow_ctrl: conn::FlowController,
    reliable_frames: reliable::ArcReliableFrameDeque,
    spaces: Spaces,
}

impl SpaceReady {
    pub fn run_with(
        self,
        proto: Arc<router::QuicProto>,
        event_broker: event::EventBroker,
    ) -> CoreConnection {
        let local_params = self.parameters.local().unwrap();
        let initial_scid = local_params.initial_source_connection_id();

        let (on_new_path, mut new_paths) = futures::channel::mpsc::unbounded();
        let new_path = Box::new(move |pathway| {
            _ = on_new_path.unbounded_send(pathway);
            Ok(())
        });

        let conn_if = Arc::new(router::ConnInterface::new(proto.clone(), new_path as _));

        let router_registry =
            proto.registry(conn_if.clone(), initial_scid, self.reliable_frames.clone());
        let local_cids = conn::ArcLocalCids::new(initial_scid, router_registry);
        let remote_cids = conn::ArcRemoteCids::new(
            self.initial_dcid,
            local_params.active_connection_id_limit().into(),
            self.reliable_frames.clone(),
        );
        let cid_registry = conn::CidRegistry::new(local_cids, remote_cids);

        self.tls_session.keys_upgrade(
            [
                self.spaces.initial.crypto_stream(),
                self.spaces.handshake.crypto_stream(),
                self.spaces.data.crypto_stream(),
            ],
            self.spaces.handshake.keys().clone(),
            self.spaces.data.one_rtt_keys().clone(),
            self.handshake.clone(),
            self.parameters.clone(),
            event_broker.clone(),
        );

        tokio::spawn({
            let params = self.parameters.clone();
            let streams = self.spaces.data.streams().clone();
            let cid_registry = cid_registry.clone();
            let flow_ctrl = self.flow_ctrl.clone();
            let event_broker = event_broker.clone();
            async move {
                use qbase::frame::{MaxStreamsFrame, ReceiveFrame, StreamCtlFrame};

                use crate::util::subscribe::Subscribe;
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
                        _ = event_broker.deliver(e.into());
                    }
                }
            }
        });

        let components = Components {
            parameters: self.parameters,
            tls_session: self.tls_session,
            handshake: self.handshake,
            token_registry: self.token_registry,
            cid_registry,
            flow_ctrl: self.flow_ctrl,
        };

        let path_creator = path::Path::creator(
            conn_if.clone(),
            initial_scid,
            self.spaces.clone(),
            components.clone(),
            event_broker.clone(),
        );

        let paths = Arc::new(path::Paths::new_with(path_creator, event_broker));

        tokio::spawn({
            let paths = paths.clone();
            async move {
                use futures::StreamExt;
                while let Some(new_path) = new_paths.next().await {
                    paths.add_path(new_path);
                }
            }
        });

        CoreConnection {
            spaces: self.spaces,
            conn_if,
            components,
            paths,
        }
    }
}

impl CoreConnection {
    pub(crate) fn entry_closing(
        self,
        error: &qbase::error::Error,
        event_broker: event::EventBroker,
    ) -> closing::Connection {
        self.spaces.data.streams().on_conn_error(error);
        self.spaces.data.datagrams().on_conn_error(error);
        self.components.flow_ctrl.on_conn_error(error);
        self.components.parameters.on_conn_error(error);
        self.components.tls_session.on_conn_error(error);
        self.paths.on_conn_error(error);

        let ccf = error.clone().into();
        let handshake_space = {
            // try { $tt } (the unstable try block feature) ≈ (||{ $tt })()
            let ccf_packet = (|| {
                let scid = self.components.cid_registry.local.initial_scid()?;
                let dcid = self.components.cid_registry.remote.latest_dcid()?;
                let mut buf = [0; qcongestion::MSS];
                let pkt = self
                    .spaces
                    .handshake
                    .try_assemble_ccf_packet(scid, dcid, &ccf, &mut buf)?;
                Some(bytes::Bytes::copy_from_slice(&pkt))
            })();
            let ccf_packet = ccf_packet.unwrap_or_default();
            let event_broker = event_broker.clone();
            self.spaces.handshake.close(ccf_packet, event_broker)
        };
        let data_space = {
            let ccf_packet = (|| {
                let dcid = self.components.cid_registry.remote.latest_dcid()?;
                let mut buf = [0; qcongestion::MSS];
                let pkt = self
                    .spaces
                    .data
                    .try_assemble_ccf_packet(dcid, &ccf, &mut buf)?;
                Some(bytes::Bytes::copy_from_slice(&pkt))
            })();
            let ccf_packet = ccf_packet.unwrap_or_default();
            let event_broker = event_broker.clone();
            self.spaces.data.close(ccf_packet, event_broker)
        };
        let closing_spaces = closing::Spaces {
            handshake: handshake_space,
            data: data_space,
        };

        let router_if = self.conn_if.router_if();
        closing::Connection::new(
            router_if.clone(),
            self.components.cid_registry,
            closing_spaces,
        )
    }

    pub(crate) fn enter_draining(self, error: &qbase::error::Error) -> draining::Connection {
        self.spaces.data.streams().on_conn_error(error);
        self.spaces.data.datagrams().on_conn_error(error);
        self.components.flow_ctrl.on_conn_error(error);
        self.components.parameters.on_conn_error(error);
        self.components.tls_session.on_conn_error(error);
        self.paths.on_conn_error(error);

        let router_if = self.conn_if.router_if();
        draining::Connection::new(router_if.clone(), self.components.cid_registry)
    }
}
