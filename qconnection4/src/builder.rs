use std::sync::{Arc, RwLock};

use futures::{Stream, StreamExt};
pub use qbase::{
    cid::{ConnectionId, GenUniqueCid, RetireCid},
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
use qinterface::{conn::ConnInterface, path::Pathway, router::QuicProto};
pub use rustls::crypto::CryptoProvider;
use tokio::sync::Notify;

use crate::{
    events::{EmitEvent, Event},
    path::{ArcPaths, RcvdPacketBuffer},
    space::{
        data::{self, DataSpace},
        handshake::{self, HandshakeSpace},
        initial::{self, InitialSpace},
        Spaces,
    },
    tls::ArcTlsSession,
    ArcLocalCids, ArcRcvdPacketBuffer, ArcReliableFrameDeque, ArcRemoteCids, CidRegistry,
    Components, Connection, CoreConnection, DataStreams, FlowController, Handshake, RawHandshake,
    Termination,
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

    pub fn with_cids(mut self, random_initial_dcid: ConnectionId) -> SpaceReady {
        let client_params = &mut self.foundation.client_params;
        let remembered = &self.foundation.remembered;

        let local_initial_max_data = client_params.initial_max_data().into_inner();
        let peer_initial_max_data = remembered.map_or(0, |p| p.initial_max_data().into_inner());

        let notify = Arc::new(Notify::new());
        let reliable_frames = ArcReliableFrameDeque::with_capacity_and_notify(8, notify.clone());
        let data_space = DataSpace::new(
            sid::Role::Client,
            reliable_frames.clone(),
            client_params,
            self.streams_ctrl,
        );

        let handshake = RawHandshake::new(sid::Role::Client, reliable_frames.clone());
        let flow_ctrl = FlowController::new(
            peer_initial_max_data,
            local_initial_max_data,
            reliable_frames.clone(),
        );

        // client_params.set_initial_source_connection_id(chosen_initial_scid);
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

        let spaces = Spaces::new(
            InitialSpace::new(initial_keys, self.foundation.token),
            HandshakeSpace::new(),
            data_space,
        );

        SpaceReady {
            initial_dcid: random_initial_dcid,
            parameters,
            tls_session,
            handshake,
            token_registry: self.foundation.token_registry,
            flow_ctrl,
            reliable_frames,
            spaces,
            notify,
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
        original_dcid: ConnectionId,
        client_scid: ConnectionId,
    ) -> SpaceReady {
        let server_params = &mut self.foundation.server_params;
        let local_initial_max_data = server_params.initial_max_data().into_inner();

        let notify = Arc::new(Notify::new());
        let reliable_frames = ArcReliableFrameDeque::with_capacity_and_notify(8, notify.clone());
        let data_space = DataSpace::new(
            sid::Role::Client,
            reliable_frames.clone(),
            server_params,
            self.streams_ctrl,
        );
        let handshake = RawHandshake::new(sid::Role::Server, reliable_frames.clone());
        let flow_ctrl = FlowController::new(0, local_initial_max_data, reliable_frames.clone());

        // server_params.set_initial_source_connection_id(chosen_initial_scid);
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

        let spaces = Spaces::new(
            InitialSpace::new(initial_keys, Vec::with_capacity(0)),
            HandshakeSpace::new(),
            data_space,
        );

        SpaceReady {
            initial_dcid: client_scid,
            parameters,
            tls_session,
            handshake,
            token_registry: self.foundation.token_registry,
            flow_ctrl,
            reliable_frames,
            spaces,
            notify,
        }
    }
}

pub struct SpaceReady {
    initial_dcid: ConnectionId,
    parameters: ArcParameters,
    tls_session: ArcTlsSession,
    handshake: RawHandshake,
    token_registry: ArcTokenRegistry,
    flow_ctrl: FlowController,
    reliable_frames: ArcReliableFrameDeque,
    spaces: Spaces,
    // TODO: 当路径发送任务没数据可发时，则等待这个通知；
    //       绝不可进入下次循环，尝试发送数据仍无数据可发，会陷入死循环
    //       相应地，当数据写入，或者重传时，要唤醒该通知
    notify: Arc<Notify>,
}

impl SpaceReady {
    pub fn run_with<EE>(self, proto: Arc<QuicProto>, event_broker: EE) -> Connection
    where
        EE: EmitEvent + Clone + Send + Sync + 'static,
    {
        let local_params = self.parameters.local().unwrap();
        let initial_scid = local_params.initial_source_connection_id();

        let (probed_path_tx, probed_path_rx) = futures::channel::mpsc::unbounded();
        let conn_iface = Arc::new(ConnInterface::new(proto.clone(), probed_path_tx));

        let issued_cids = self.reliable_frames.clone();
        let router_registry = proto.registry(conn_iface.clone(), issued_cids);
        self.parameters
            .set_initial_scid(router_registry.gen_unique_cid());
        let local_cids = ArcLocalCids::new(initial_scid, router_registry);

        let active_cid_limit = local_params.active_connection_id_limit().into();
        let retired_cids = self.reliable_frames.clone();
        let remote_cids = ArcRemoteCids::new(self.initial_dcid, active_cid_limit, retired_cids);

        let cid_registry = CidRegistry::new(local_cids, remote_cids);

        let handshake = Handshake::new(self.handshake, Arc::new(event_broker.clone()));

        self.tls_session.keys_upgrade(
            [
                self.spaces.initial().crypto_stream(),
                self.spaces.handshake().crypto_stream(),
                &self.spaces.data().crypto_stream,
            ],
            self.spaces.handshake().keys(),
            self.spaces.data().one_rtt_keys(),
            handshake.clone(),
            self.parameters.clone(),
            event_broker.clone(),
        );

        tokio::spawn({
            accpet_transport_parameters(
                self.parameters.clone(),
                self.spaces.data().streams.clone(),
                cid_registry.clone(),
                self.flow_ctrl.clone(),
                event_broker.clone(),
            )
        });

        let components = Components {
            parameters: self.parameters,
            tls_session: self.tls_session,
            handshake,
            token_registry: self.token_registry,
            cid_registry,
            flow_ctrl: self.flow_ctrl,
        };

        let paths = ArcPaths::new();

        let rvd_pkt_buf = Arc::new(RcvdPacketBuffer::new());

        initial::launch_deliver_and_parse(
            rvd_pkt_buf.initial().receiver(),
            self.spaces.initial().clone(),
            paths.clone(),
            conn_iface.clone(),
            &components,
            event_broker.clone(),
        );
        handshake::launch_deliver_and_parse(
            rvd_pkt_buf.handshake().receiver(),
            self.spaces.handshake().clone(),
            paths.clone(),
            conn_iface.clone(),
            &components,
            event_broker.clone(),
        );
        data::launch_deliver_and_parse(
            rvd_pkt_buf.zero_rtt().receiver(),
            rvd_pkt_buf.one_rtt().receiver(),
            self.spaces.data().clone(),
            paths.clone(),
            &components,
            event_broker.clone(),
        );

        tokio::spawn({
            accept_probed_paths(
                probed_path_rx,
                components.clone(),
                self.spaces.clone(),
                rvd_pkt_buf.clone(),
                conn_iface.clone(),
                paths.clone(),
            )
        });

        Connection(RwLock::new(Ok(CoreConnection {
            spaces: self.spaces,
            conn_iface,
            components,
            rvd_pkt_buf,
            paths,
        })))
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
    rvd_pkt_buf: ArcRcvdPacketBuffer,
    conn_iface: Arc<ConnInterface>,
    paths: ArcPaths,
) {
    while let Some(pathway) = probed_paths.next().await {
        paths.entry(pathway).or_insert_with(|| {
            // let cc = ArcCC::new(
            //     CongestionAlgorithm::Bbr,
            //     Duration::from_micros(100),
            //     [
            //         Box::new(spaces.initial.tracker().clone()),
            //         Box::new(spaces.handshake.tracker().clone()),
            //         Box::new(spaces.data.tracker().clone()),
            //     ],
            //     components.handshake.clone(),
            // );
            // let path = Arc::new(Path::new(pathway, cc, conn_iface.clone()));

            // let mut rcvd_packets = conn_iface.register(pathway);
            // let packet_entry = packet_entry.clone();
            // let recv_task = tokio::spawn(async move {
            //     while let Some(new_packet) = rcvd_packets.next().await {
            //         packet_entry.deliver(new_packet, pathway).await
            //     }
            // });

            // let send_fut = {
            //     let dcid = components.cid_registry.remote.apply_dcid();
            //     let flow_ctrl = components.flow_ctrl.clone();
            //     // 探测到的路径不可能是第一条路径，就不给它发送i0h包的能力
            //     let space = spaces.data.clone();
            //     path.new_one_rtt_burst(dcid, flow_ctrl, space).launch()
            // };

            // let task = tokio::spawn({
            //     let path = path.clone();
            //     let paths = paths.clone();
            //     let conn_iface = conn_iface.clone();
            //     async move {
            //         tokio::select! {
            //             // path validate faild
            //             false = path.validate() => {}
            //             // recv task terminate(connection terminate)
            //             _ = recv_task => {}
            //             // connection or network path terminate
            //             _ = send_fut => {}
            //         }
            //         paths.del(&pathway);
            //         conn_iface.unregister(&pathway);
            //     }
            // });

            // PathGuard::new(path, task.abort_handle())
            todo!()
        });
    }
}

impl CoreConnection {
    // 对于server，第一条路径也通过add_path添加
    pub fn add_path(&self, pathway: Pathway) {
        // self.paths.entry(pathway).or_insert_with(|| {
        //     let cc = ArcCC::new(
        //         CongestionAlgorithm::Bbr,
        //         Duration::from_micros(100),
        //         [
        //             Box::new(self.spaces.initial.tracker().clone()),
        //             Box::new(self.spaces.handshake.tracker().clone()),
        //             Box::new(self.spaces.data.tracker().clone()),
        //         ],
        //         self.components.handshake.clone(),
        //     );
        //     let path = Arc::new(Path::new(pathway, cc, self.conn_iface.clone()));

        //     let mut rcvd_packets = self.conn_iface.register(pathway);
        //     let packet_entry = self.packet_entry.clone();
        //     let recv_task = tokio::spawn(async move {
        //         while let Some(new_packet) = rcvd_packets.next().await {
        //             packet_entry.deliver(new_packet, pathway).await;
        //         }
        //     });

        //     let send_fut = {
        //         let path = path.clone();
        //         let dcid = self.components.cid_registry.remote.apply_dcid();
        //         let flow_ctrl = self.components.flow_ctrl.clone();
        //         let initial_scid = self.components.cid_registry.local.initial_scid();
        //         let is_client = self.components.handshake.role() == sid::Role::Client;
        //         let spaces = self.spaces.clone();
        //         async move {
        //             match initial_scid {
        //                 Some(scid) => {
        //                     // rfc9000 21.1.1.1:
        //                     // Note: The anti-amplification limit only applies when an endpoint responds to packets
        //                     // received from an unvalidated address. The anti-amplification limit does not apply to
        //                     // clients when establishing a new connection or when initiating connection migration.
        //                     if is_client {
        //                         //  clients when establishing a new connection
        //                         path.grant_anti_amplifier();
        //                     }
        //                     path.new_all_level_burst(scid, dcid, flow_ctrl, spaces)
        //                         .launch()
        //                         .await
        //                 }
        //                 None => {
        //                     // "initiating connection migration"
        //                     path.grant_anti_amplifier();
        //                     path.new_one_rtt_burst(dcid, flow_ctrl, spaces.data)
        //                         .launch()
        //                         .await
        //                 }
        //             }
        //         }
        //     };

        //     let task = tokio::spawn({
        //         let path = path.clone();
        //         let paths = self.paths.clone();
        //         let conn_iface = self.conn_iface.clone();
        //         async move {
        //             tokio::select! {
        //                 // path validate faild
        //                 false = path.validate() => {}
        //                 // recv task terminate(connection terminate)
        //                 _ = recv_task => {}
        //                 // connection or network path terminate
        //                 _ = send_fut => {}
        //             }
        //             paths.del(&pathway);
        //             conn_iface.unregister(&pathway);
        //         }
        //     });

        //     PathGuard::new(path, task.abort_handle())
        // });
    }

    pub fn del_path(&self, pathway: Pathway) {
        self.paths.del(&pathway);
    }

    pub fn enter_closing<EE>(self, ccf: ConnectionCloseFrame, event_broker: EE) -> Termination
    where
        EE: EmitEvent + Send + Clone + 'static,
    {
        let error = ccf.clone().into();
        self.spaces.data().streams.on_conn_error(&error);
        self.spaces.data().datagrams.on_conn_error(&error);
        self.components.flow_ctrl.on_conn_error(&error);
        self.components.tls_session.on_conn_error(&error);
        if self.components.handshake.role() == sid::Role::Server {
            let local_parameters = self.components.parameters.server().unwrap();
            let origin_dcid = local_parameters.original_destination_connection_id();
            self.conn_iface.router_if().unregister(&origin_dcid.into());
        }
        self.components.parameters.on_conn_error(&error);
        self.paths.clear();

        tokio::spawn({
            let event_broker = event_broker.clone();
            let pto_duration = self.paths.max_pto_duration().unwrap_or_default();
            async move {
                tokio::time::sleep(pto_duration).await;
                event_broker.emit(Event::Terminated);
            }
        });

        self.spaces.close(
            &self.rvd_pkt_buf,
            Arc::new(self.conn_iface.close(ccf, &self.components.cid_registry)),
            &event_broker,
        );

        Termination::closing(error, self.components.cid_registry.local, self.rvd_pkt_buf)
    }

    pub fn enter_draining<EE>(self, error: Error, event_broker: EE) -> Termination
    where
        EE: EmitEvent + Send + Clone + 'static,
    {
        self.spaces.data().streams.on_conn_error(&error);
        self.spaces.data().datagrams.on_conn_error(&error);
        self.components.flow_ctrl.on_conn_error(&error);
        self.components.tls_session.on_conn_error(&error);
        if self.components.handshake.role() == sid::Role::Server {
            let local_parameters = self.components.parameters.server().unwrap();
            let origin_dcid = local_parameters.original_destination_connection_id();
            self.conn_iface.router_if().unregister(&origin_dcid.into());
        }
        self.components.parameters.on_conn_error(&error);
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

        self.rvd_pkt_buf.close();
        Termination::draining(error, self.components.cid_registry.local)
    }
}
