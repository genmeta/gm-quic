use std::sync::{Arc, Mutex};

use futures::channel::mpsc;
use qbase::{
    cid::ConnectionId, flow::FlowController, handshake::Handshake, packet::keys::ArcKeys,
    streamid::Role,
};
use qrecovery::{reliable::ArcReliableFrameDeque, streams::DataStreams};
use qunreliable::DatagramFlow;
use rustls::quic::Keys;
use tokio::{sync::Notify, task::JoinHandle};

use super::{
    scope::{data::DataScope, handshake::HandshakeScope, initial::InitialScope},
    ArcLocalCids, ArcRemoteCids, CidRegistry, RcvdPackets, TokenRegistry,
};
use crate::{
    error::ConnError,
    path::{ArcPath, ArcPathes, Pathway, RawPath},
    router::ROUTER,
    tls::{ArcTlsSession, GetParameters},
};

pub struct RawConnection {
    pub server_name: String,
    pub pathes: ArcPathes,
    pub cid_registry: CidRegistry,
    pub token_registry: TokenRegistry,
    // handshake done的信号
    pub handshake: Handshake<ArcReliableFrameDeque>,
    pub flow_ctrl: FlowController,
    pub error: ConnError,

    pub reliable_frames: ArcReliableFrameDeque,
    pub streams: DataStreams,
    pub datagrams: DatagramFlow,

    pub initial: InitialScope,
    pub hs: HandshakeScope,
    pub data: DataScope,
    pub notify: Arc<Notify>, // Notifier for closing the packet receiving task
    pub join_handles: [JoinHandle<RcvdPackets>; 4],

    pub params: GetParameters,
}

impl RawConnection {
    fn gen_cid() -> ConnectionId {
        ConnectionId::random_gen_with_mark(8, 0x80, 0x7F)
    }

    pub fn new(
        role: Role,
        server_name: String,
        tls_session: ArcTlsSession,
        scid: ConnectionId,
        initial_keys: Keys,
    ) -> Self {
        let (initial_packets_entry, rcvd_initial_packets) = mpsc::unbounded();
        let (zero_rtt_packets_entry, rcvd_0rtt_packets) = mpsc::unbounded();
        let (hs_packets_entry, rcvd_hs_packets) = mpsc::unbounded();
        let (one_rtt_packets_entry, rcvd_1rtt_packets) = mpsc::unbounded();

        let reliable_frames = ArcReliableFrameDeque::with_capacity(0);
        let initial = InitialScope::new(ArcKeys::with_keys(initial_keys));
        let hs = HandshakeScope::default();
        let data = DataScope::default();

        // TODO: Token Skin 和 Token Provider 由外面传提供，不需要在此创建
        let token_registry = if role == Role::Client {
            TokenRegistry::new_client(server_name.clone(), initial.clone())
        } else {
            TokenRegistry::new_server(server_name.clone(), reliable_frames.clone())
        };
        let router_registry = ROUTER.registry(
            token_registry.clone(),
            reliable_frames.clone(),
            [
                initial_packets_entry.clone(),
                zero_rtt_packets_entry.clone(),
                hs_packets_entry.clone(),
                one_rtt_packets_entry.clone(),
            ],
        );
        let local_cids = ArcLocalCids::new(Self::gen_cid, scid, router_registry);
        let remote_cids = ArcRemoteCids::with_limit(2, reliable_frames.clone());
        let cid_registry = CidRegistry::new(local_cids, remote_cids);
        let handshake = Handshake::new(role, reliable_frames.clone());
        let flow_ctrl = FlowController::with_initial(0, 0);
        let conn_error = ConnError::default();

        let streams = DataStreams::with_role_and_limit(
            role,
            // 流数量
            0,
            0,
            // 对我方创建的双向流的限制
            0,
            // 对方创建的双向流的限制
            0,
            // 对对方创建的单向流的限制
            0,
            reliable_frames.clone(),
        );
        let datagrams = DatagramFlow::new(0, 0);

        let pathes = ArcPathes::new(Box::new({
            let cid_registry = cid_registry.clone();
            let flow_ctrl = flow_ctrl.clone();
            let handshake = handshake.clone();
            let gen_readers = {
                let initial = initial.clone();
                let hs = hs.clone();
                let data = data.clone();
                let reliable_frames = reliable_frames.clone();
                let streams = streams.clone();
                let datagrams = datagrams.clone();
                let token = match &token_registry {
                    TokenRegistry::Client(client) => client.initial_token.clone(),
                    _ => Arc::new(Mutex::new(Vec::new())),
                };
                move |path: &RawPath| {
                    (
                        initial.reader(token.clone()),
                        hs.reader(),
                        data.reader(
                            path.challenge_sndbuf(),
                            path.response_sndbuf(),
                            reliable_frames.clone(),
                            streams.clone(),
                            datagrams.clone(),
                        ),
                    )
                }
            };
            move |pathway, usc| {
                let scid = cid_registry.local.active_cids()[0];
                let dcid = cid_registry.remote.apply_cid();
                let path = ArcPath::new(usc.clone(), scid, dcid);

                if !handshake.is_handshake_done() {
                    if role == Role::Client {
                        path.anti_amplifier.grant();
                    }
                } else {
                    path.begin_validation();
                }
                path.begin_sending(pathway, &flow_ctrl, &gen_readers);
                path
            }
        }));

        let notify = Arc::new(Notify::new());
        let join_initial = initial.build(
            rcvd_initial_packets,
            &pathes,
            &notify,
            &conn_error,
            token_registry.clone(),
        );
        let join_hs = hs.build(rcvd_hs_packets, &pathes, &notify, &conn_error);
        let (join_0rtt, join_1rtt) = data.build(
            &pathes,
            &handshake,
            &streams,
            &datagrams,
            &cid_registry,
            &flow_ctrl,
            &notify,
            &conn_error,
            rcvd_0rtt_packets,
            rcvd_1rtt_packets,
            token_registry.clone(),
        );
        let join_handles = [join_initial, join_0rtt, join_hs, join_1rtt];

        let get_params = tls_session.keys_upgrade(
            [
                &initial.crypto_stream,
                &hs.crypto_stream,
                &data.crypto_stream,
            ],
            hs.keys.clone(),
            data.one_rtt_keys.clone(),
            conn_error.clone(),
        );

        Self {
            server_name,
            pathes,
            cid_registry,
            token_registry,
            handshake,
            flow_ctrl,
            streams,
            reliable_frames,
            datagrams,
            initial,
            hs,
            data,
            notify,
            join_handles,
            error: conn_error,
            params: get_params,
        }
    }

    pub fn update_path_recv_time(&self, pathway: Pathway) {
        if let Some(path) = self.pathes.try_get(&pathway).try_unwrap() {
            path.update_recv_time();
        }
    }
}
