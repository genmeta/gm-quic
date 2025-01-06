use std::{
    io,
    sync::{Arc, Mutex},
    time::Duration,
};

use futures::{Stream, StreamExt};
pub use qbase::{
    cid::ConnectionId,
    param::{ClientParameters, CommonParameters, ServerParameters},
    sid::ControlConcurrency,
    token::{TokenProvider, TokenSink},
};
use qbase::{
    error::Error,
    frame::ConnectionCloseFrame,
    param::{self, ArcParameters},
    sid,
    token::ArcTokenRegistry,
};
use qcongestion::{ArcCC, CongestionAlgorithm};
use qrecovery::reliable::ArcReliableFrameDeque;
pub use rustls::crypto::CryptoProvider;
use tokio::time::Instant;

use crate::{
    events::{EmitEvent, Event},
    path::{entry::PacketEntry, ArcPaths, Path, Pathway},
    router::{ConnInterface, QuicProto},
    space::{DataSpace, HandshakeSpace, InitialSpace, Spaces},
    tls::ArcTlsSession,
    ArcLocalCids, ArcRemoteCids, CidRegistry, Components, Connection, CoreConnection, DataStreams,
    FlowController, Handshake, Termination,
};

impl Connection {
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

    pub fn with_cids(
        mut self,
        chosen_initial_scid: ConnectionId,
        random_initial_dcid: ConnectionId,
    ) -> SpaceReady {
        let client_params = &mut self.foundation.client_params;
        let remembered = &self.foundation.remembered;

        let local_initial_max_data = client_params.initial_max_data().into_inner();
        let peer_initial_max_data = remembered.map_or(0, |p| p.initial_max_data().into_inner());

        let reliable_frames = ArcReliableFrameDeque::with_capacity(8);
        let data_space = DataSpace::new(
            sid::Role::Client,
            reliable_frames.clone(),
            client_params,
            self.streams_ctrl,
        );

        let handshake = Handshake::new(sid::Role::Client, reliable_frames.clone());
        let flow_ctrl = FlowController::new(
            peer_initial_max_data,
            local_initial_max_data,
            reliable_frames.clone(),
        );

        client_params.set_initial_source_connection_id(chosen_initial_scid);
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

        let spaces = Spaces {
            initial: InitialSpace::new(initial_keys, self.foundation.token),
            handshake: HandshakeSpace::new(),
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

        let reliable_frames = ArcReliableFrameDeque::with_capacity(8);
        let data_space = DataSpace::new(
            sid::Role::Client,
            reliable_frames.clone(),
            server_params,
            self.streams_ctrl,
        );
        let handshake = Handshake::new(sid::Role::Server, reliable_frames.clone());
        let flow_ctrl = FlowController::new(0, local_initial_max_data, reliable_frames.clone());

        server_params.set_initial_source_connection_id(chosen_initial_scid);
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

        let spaces = Spaces {
            initial: InitialSpace::new(initial_keys, Vec::with_capacity(0)),
            handshake: HandshakeSpace::new(),
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
    parameters: ArcParameters,
    tls_session: ArcTlsSession,
    handshake: Handshake,
    token_registry: ArcTokenRegistry,
    flow_ctrl: FlowController,
    reliable_frames: ArcReliableFrameDeque,
    spaces: Spaces,
}

impl SpaceReady {
    pub fn run_with<EE>(self, proto: Arc<QuicProto>, event_broker: EE) -> Connection
    where
        EE: EmitEvent + Clone + Send + 'static,
    {
        let local_params = self.parameters.local().unwrap();
        let initial_scid = local_params.initial_source_connection_id();

        let (on_probed_path, probed_paths) = futures::channel::mpsc::unbounded();

        let conn_iface = Arc::new(ConnInterface::new(proto.clone(), on_probed_path));

        let router_registry = proto.registry(
            conn_iface.clone(),
            initial_scid,
            self.reliable_frames.clone(),
        );
        let local_cids = ArcLocalCids::new(initial_scid, router_registry);
        let remote_cids = ArcRemoteCids::new(
            self.initial_dcid,
            local_params.active_connection_id_limit().into(),
            self.reliable_frames.clone(),
        );
        let cid_registry = CidRegistry::new(local_cids, remote_cids);

        self.tls_session.keys_upgrade(
            [
                &self.spaces.initial.crypto_stream,
                &self.spaces.handshake.crypto_stream,
                &self.spaces.data.crypto_stream,
            ],
            self.spaces.handshake.keys.clone(),
            self.spaces.data.one_rtt_keys.clone(),
            self.handshake.clone(),
            self.parameters.clone(),
            event_broker.clone(),
        );

        tokio::spawn({
            accpet_transport_parameters(
                self.parameters.clone(),
                self.spaces.data.streams.clone(),
                cid_registry.clone(),
                self.flow_ctrl.clone(),
                event_broker.clone(),
            )
        });

        let components = Components {
            parameters: self.parameters,
            tls_session: self.tls_session,
            handshake: self.handshake,
            token_registry: self.token_registry,
            cid_registry,
            flow_ctrl: self.flow_ctrl,
        };

        let paths = ArcPaths::new();

        let packet_entry = Arc::new(PacketEntry::new());

        self.spaces.initial.build(
            packet_entry.initial.receiver(),
            &paths,
            &components,
            event_broker.clone(),
        );
        self.spaces.handshake.build(
            packet_entry.handshake.receiver(),
            &paths,
            event_broker.clone(),
        );
        self.spaces.data.build(
            &paths,
            &components,
            packet_entry.zero_rtt.receiver(),
            packet_entry.one_rtt.receiver(),
            event_broker.clone(),
        );

        tokio::spawn({
            accept_probed_paths(
                probed_paths,
                components.clone(),
                self.spaces.clone(),
                packet_entry.clone(),
                conn_iface.clone(),
                paths.clone(),
            )
        });

        // tokio::spawn({
        //     let paths = paths.clone();
        //     async move {
        //         use futures::StreamExt;
        //         while let Some(new_path) = probed_paths.next().await {
        //             paths.add_path(new_path);
        //         }
        //     }
        // });

        Connection(
            Ok(CoreConnection {
                spaces: self.spaces,
                conn_iface,
                components,
                packet_entry,
                paths,
            })
            .into(),
        )
    }
}

async fn accpet_transport_parameters<EE>(
    params: ArcParameters,
    streams: DataStreams,
    cid_registry: CidRegistry,
    flow_ctrl: FlowController,
    event_broker: EE,
) where
    EE: EmitEvent + Clone + Send + 'static,
{
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

// 叫accept好吗？
async fn accept_probed_paths(
    mut probed_paths: impl Stream<Item = Pathway> + Unpin,
    components: Components,
    spaces: Spaces,
    packet_entry: Arc<PacketEntry>,
    conn_iface: Arc<ConnInterface>,
    paths: ArcPaths,
) {
    while let Some(new_pathway) = probed_paths.next().await {
        paths.entry(new_pathway).or_insert_with(|| {
            let cc = ArcCC::new(
                CongestionAlgorithm::Bbr,
                Duration::from_micros(100),
                [
                    Box::new(spaces.initial.tracker().clone()),
                    Box::new(spaces.handshake.tracker().clone()),
                    Box::new(spaces.data.tracker().clone()),
                ],
                components.handshake.clone(),
            );
            let path = Arc::new(Path::new(new_pathway, cc, conn_iface.clone()));

            let mut rcvd_packets = conn_iface.register(new_pathway);
            let packet_entry = packet_entry.clone();
            let recv_task = tokio::spawn(async move {
                while let Some(new_packet) = rcvd_packets.next().await {
                    if !packet_entry.deliver(new_packet, new_pathway).await {
                        break;
                    }
                }
            });

            let send_fut = {
                let dcid = components.cid_registry.remote.apply_dcid();
                let flow_ctrl = components.flow_ctrl.clone();
                // 探测到的路径不可能是第一条路径，就不给它发送i0h包的能力
                let space = spaces.data.clone();
                path.new_one_rtt_burst(dcid, flow_ctrl, space).launch()
            };

            tokio::spawn({
                let path = path.clone();
                let paths = paths.clone();
                let conn_iface = conn_iface.clone();
                async move {
                    tokio::select! {
                        // path validate faild
                        false = path.validate() => {}
                        // recv task terminate(connection terminate)
                        _ = recv_task => {}
                        // connection or network path terminate
                        _ = send_fut => {}
                    }
                    paths.del(&new_pathway);
                    // TODO: way & pathway, 不统一，之后改改
                    conn_iface.unregister(&new_pathway);
                }
            });

            path
        });
    }
}

impl CoreConnection {
    // 对于server，第一条路径也通过add_path添加
    pub fn add_path(&self, pathway: Pathway) {
        self.paths.entry(pathway).or_insert_with(|| {
            let cc = ArcCC::new(
                CongestionAlgorithm::Bbr,
                Duration::from_micros(100),
                [
                    Box::new(self.spaces.initial.tracker().clone()),
                    Box::new(self.spaces.handshake.tracker().clone()),
                    Box::new(self.spaces.data.tracker().clone()),
                ],
                self.components.handshake.clone(),
            );
            let path = Arc::new(Path::new(pathway, cc, self.conn_iface.clone()));

            let mut rcvd_packets = self.conn_iface.register(pathway);
            let packet_entry = self.packet_entry.clone();
            let recv_task = tokio::spawn(async move {
                while let Some(new_packet) = rcvd_packets.next().await {
                    if !packet_entry.deliver(new_packet, pathway).await {
                        break;
                    }
                }
            });

            let send_fut = {
                let path = path.clone();
                let dcid = self.components.cid_registry.remote.apply_dcid();
                let flow_ctrl = self.components.flow_ctrl.clone();
                let initial_scid = self.components.cid_registry.local.initial_scid();
                let is_client = self.components.handshake.role() == sid::Role::Client;
                let spaces = self.spaces.clone();
                async move {
                    match initial_scid {
                        Some(scid) => {
                            // rfc9000 21.1.1.1:
                            // Note: The anti-amplification limit only applies when an endpoint responds to packets
                            // received from an unvalidated address. The anti-amplification limit does not apply to
                            // clients when establishing a new connection or when initiating connection migration.
                            if is_client {
                                //  clients when establishing a new connection
                                path.grant_anti_amplifier();
                            }
                            path.new_all_level_burst(scid, dcid, flow_ctrl, spaces)
                                .launch()
                                .await
                        }
                        None => {
                            // "initiating connection migration"
                            path.grant_anti_amplifier();
                            path.new_one_rtt_burst(dcid, flow_ctrl, spaces.data)
                                .launch()
                                .await
                        }
                    }
                }
            };

            tokio::spawn({
                let path = path.clone();
                let paths = self.paths.clone();
                let conn_iface = self.conn_iface.clone();
                async move {
                    tokio::select! {
                        // path validate faild
                        false = path.validate() => {}
                        // recv task terminate(connection terminate)
                        _ = recv_task => {}
                        // connection or network path terminate
                        _ = send_fut => {}
                    }
                    paths.del(&pathway);
                    conn_iface.unregister(&pathway);
                }
            });

            path
        });
    }

    pub(crate) fn enter_closing<EE>(self, error: Error, event_broker: EE) -> Termination
    where
        EE: EmitEvent + Send + Clone + 'static,
    {
        self.spaces.data.streams.on_conn_error(&error);
        self.spaces.data.datagrams.on_conn_error(&error);
        self.components.flow_ctrl.on_conn_error(&error);
        self.components.parameters.on_conn_error(&error);
        self.components.tls_session.on_conn_error(&error);
        self.components.cid_registry.local.freeze();
        self.conn_iface.disable_probing();
        self.paths.clear();

        tokio::spawn({
            let event_broker = event_broker.clone();
            let pto_duration = self.paths.max_pto_duration().unwrap_or_default();
            async move {
                tokio::time::sleep(pto_duration).await;
                event_broker.emit(Event::Terminated);
            }
        });

        struct ReceivingStatistics {
            last_recv_time: Instant,
            rcvd_packets: usize,
        }

        impl ReceivingStatistics {
            fn should_send(&mut self) -> bool {
                let last_recv_time = core::mem::replace(&mut self.last_recv_time, Instant::now());
                self.rcvd_packets += 1;
                last_recv_time.elapsed() > Duration::from_secs(1) || self.rcvd_packets % 3 == 0
            }
        }

        let statistics = Arc::new(Mutex::new(ReceivingStatistics {
            last_recv_time: Instant::now(),
            rcvd_packets: 0,
        }));

        let scid = self.components.cid_registry.local.initial_scid();
        let dcid = self.components.cid_registry.remote.latest_dcid();
        let ccf: Arc<ConnectionCloseFrame> = Arc::new(error.clone().into());

        self.packet_entry.one_rtt.close();

        match self.spaces.initial.close() {
            None => self.packet_entry.initial.close(),
            Some(space) => {
                let mut packets = self.packet_entry.initial.receiver();
                let ccf = ccf.clone();
                let event_broker = event_broker.clone();
                let statistics = statistics.clone();
                let conn_iface = self.conn_iface.clone();
                tokio::spawn(async move {
                    while let Some((packet, pathway)) = packets.next().await {
                        if let Some(ccf) = space.deliver(packet) {
                            event_broker.emit(Event::Closed(ccf));
                        }
                        if statistics.lock().unwrap().should_send() {
                            let (Some(scid), Some(dcid)) = (scid, dcid) else {
                                continue;
                            };
                            let Ok(send_capability) = conn_iface.send_capability(pathway) else {
                                continue;
                            };
                            let max_segment_size = send_capability.max_segment_size as usize;
                            let reversed_size = send_capability.reversed_size as usize;
                            let mut buffer = vec![0; max_segment_size];
                            let buf = &mut buffer[reversed_size..];
                            // None -> buffer too small, hardly possible
                            if let Some(packet) =
                                space.try_assemble_ccf_packet(scid, dcid, ccf.as_ref(), buf)
                            {
                                let packets =
                                    &[io::IoSlice::new(&buffer[..reversed_size + packet.size()])];
                                _ = conn_iface
                                    .send_packets(packets, pathway, pathway.dst())
                                    .await;
                            };
                        }
                    }
                });
            }
        }

        self.packet_entry.zero_rtt.close();

        match self.spaces.handshake.close() {
            None => self.packet_entry.handshake.close(),
            Some(space) => {
                let mut packets = self.packet_entry.handshake.receiver();
                let ccf = ccf.clone();
                let event_broker = event_broker.clone();
                let statistics = statistics.clone();
                let conn_iface = self.conn_iface.clone();
                tokio::spawn(async move {
                    while let Some((packet, pathway)) = packets.next().await {
                        if let Some(ccf) = space.deliver(packet) {
                            event_broker.emit(Event::Closed(ccf));
                        }
                        if statistics.lock().unwrap().should_send() {
                            let (Some(scid), Some(dcid)) = (scid, dcid) else {
                                continue;
                            };
                            let Ok(send_capability) = conn_iface.send_capability(pathway) else {
                                continue;
                            };
                            let max_segment_size = send_capability.max_segment_size as usize;
                            let reversed_size = send_capability.reversed_size as usize;
                            let mut buffer = vec![0; max_segment_size];
                            let buf = &mut buffer[reversed_size..];
                            // None -> buffer too small, hardly possible
                            if let Some(packet) =
                                space.try_assemble_ccf_packet(scid, dcid, ccf.as_ref(), buf)
                            {
                                let packets =
                                    &[io::IoSlice::new(&buffer[..reversed_size + packet.size()])];
                                _ = conn_iface
                                    .send_packets(packets, pathway, pathway.dst())
                                    .await;
                            };
                        }
                    }
                });
            }
        }

        match self.spaces.data.close() {
            None => todo!(),
            Some(space) => {
                let mut packets = self.packet_entry.one_rtt.receiver();
                let ccf = ccf.clone();
                let event_broker = event_broker.clone();
                let statistics = statistics.clone();
                let conn_iface = self.conn_iface.clone();
                tokio::spawn(async move {
                    while let Some((packet, pathway)) = packets.next().await {
                        if let Some(ccf) = space.deliver(packet) {
                            event_broker.emit(Event::Closed(ccf));
                        }
                        if statistics.lock().unwrap().should_send() {
                            let Some(dcid) = dcid else {
                                continue;
                            };
                            let Ok(send_capability) = conn_iface.send_capability(pathway) else {
                                continue;
                            };
                            let max_segment_size = send_capability.max_segment_size as usize;
                            let reversed_size = send_capability.reversed_size as usize;
                            let mut buffer = vec![0; max_segment_size];
                            let buf = &mut buffer[reversed_size..];
                            // None -> buffer too small, hardly possible
                            if let Some(packet) =
                                space.try_assemble_ccf_packet(dcid, ccf.as_ref(), buf)
                            {
                                let packets =
                                    &[io::IoSlice::new(&buffer[..reversed_size + packet.size()])];
                                _ = conn_iface
                                    .send_packets(packets, pathway, pathway.dst())
                                    .await;
                            };
                        }
                    }
                });
            }
        }

        Termination {
            error,
            cid_registry: self.components.cid_registry,
            conn_iface: self.conn_iface,
            packet_entry: self.packet_entry,
            is_draining: false,
        }
    }

    pub(crate) fn enter_draining<EE>(self, error: Error, event_broker: EE) -> Termination
    where
        EE: EmitEvent + Send + Clone + 'static,
    {
        self.spaces.data.streams.on_conn_error(&error);
        self.spaces.data.datagrams.on_conn_error(&error);
        self.components.flow_ctrl.on_conn_error(&error);
        self.components.parameters.on_conn_error(&error);
        self.components.tls_session.on_conn_error(&error);
        self.components.cid_registry.local.freeze();
        self.conn_iface.disable_probing();
        self.paths.clear();

        tokio::spawn({
            let event_broker = event_broker.clone();
            let pto_duration = self.paths.max_pto_duration().unwrap_or_default();
            async move {
                tokio::time::sleep(pto_duration).await;
                event_broker.emit(Event::Terminated);
            }
        });

        self.packet_entry.initial.close();
        self.packet_entry.handshake.close();
        self.packet_entry.zero_rtt.close();
        self.packet_entry.one_rtt.close();

        Termination {
            error,
            cid_registry: self.components.cid_registry,
            conn_iface: self.conn_iface,
            packet_entry: self.packet_entry,
            is_draining: false,
        }
    }
}

// impl CoreConnection {
//     pub(crate) fn entry_closing(
//         self,
//         error: &qbase::error::Error,
//         event_broker: event::EventBroker,
//     ) -> closing::Connection {
//         self.spaces.data.streams().on_conn_error(error);
//         self.spaces.data.datagrams().on_conn_error(error);
//         self.components.flow_ctrl.on_conn_error(error);
//         self.components.parameters.on_conn_error(error);
//         self.components.tls_session.on_conn_error(error);
//         self.paths.on_conn_error(error);

//         let ccf = error.clone().into();
//         let handshake_space = {
//             // try { $tt } (the unstable try block feature) ≈ (||{ $tt })()
//             let ccf_packet = (|| {
//                 let scid = self.components.cid_registry.local.initial_scid()?;
//                 let dcid = self.components.cid_registry.remote.latest_dcid()?;
//                 let mut buf = [0; qcongestion::MSS];
//                 let pkt = self
//                     .spaces
//                     .handshake
//                     .try_assemble_ccf_packet(scid, dcid, &ccf, &mut buf)?;
//                 Some(bytes::Bytes::copy_from_slice(&pkt))
//             })();
//             let ccf_packet = ccf_packet.unwrap_or_default();
//             let event_broker = event_broker.clone();
//             self.spaces.handshake.close(ccf_packet, event_broker)
//         };
//         let data_space = {
//             let ccf_packet = (|| {
//                 let dcid = self.components.cid_registry.remote.latest_dcid()?;
//                 let mut buf = [0; qcongestion::MSS];
//                 let pkt = self
//                     .spaces
//                     .data
//                     .try_assemble_ccf_packet(dcid, &ccf, &mut buf)?;
//                 Some(bytes::Bytes::copy_from_slice(&pkt))
//             })();
//             let ccf_packet = ccf_packet.unwrap_or_default();
//             let event_broker = event_broker.clone();
//             self.spaces.data.close(ccf_packet, event_broker)
//         };
//         let closing_spaces = closing::Spaces {
//             handshake: handshake_space,
//             data: data_space,
//         };

//         let router_if = self.conn_if.router_if();
//         closing::Connection::new(
//             router_if.clone(),
//             self.components.cid_registry,
//             closing_spaces,
//         )
//     }

//     pub(crate) fn enter_draining(self, error: &qbase::error::Error) -> draining::Connection {
//         self.spaces.data.streams().on_conn_error(error);
//         self.spaces.data.datagrams().on_conn_error(error);
//         self.components.flow_ctrl.on_conn_error(error);
//         self.components.parameters.on_conn_error(error);
//         self.components.tls_session.on_conn_error(error);
//         self.paths.on_conn_error(error);

//         let router_if = self.conn_if.router_if();
//         draining::Connection::new(router_if.clone(), self.components.cid_registry)
//     }
// }
