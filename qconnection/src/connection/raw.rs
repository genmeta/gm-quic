use std::sync::{Arc, Mutex};

use futures::channel::mpsc;
use qbase::{
    flow::FlowController,
    handshake::Handshake,
    packet::keys::ArcKeys,
    streamid::Role,
    token::{TokenProvider, TokenSink},
};
use qrecovery::{reliable::ArcReliableFrameDeque, streams::DataStreams};
use qunreliable::DatagramFlow;
use tokio::{sync::Notify, task::JoinHandle};

use super::{
    scope::{data::DataScope, handshake::HandshakeScope, initial::InitialScope},
    CidRegistry, RcvdPackets,
};
use crate::{
    error::ConnError,
    path::{ArcPath, ArcPathes, RawPath},
    router::ArcRouter,
    tls::{ArcTlsSession, GetParameters},
};

pub struct RawConnection {
    pub pathes: ArcPathes,
    pub cid_registry: CidRegistry,
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

    pub token: Arc<Mutex<Vec<u8>>>,
    pub params: GetParameters,
}

impl RawConnection {
    pub fn new(
        role: Role,
        tls_session: ArcTlsSession,
        router: ArcRouter,
        mut token_skin: Option<TokenSink>,
        token_provider: Option<TokenProvider>,
    ) -> Self {
        let (initial_packets_entry, rcvd_initial_packets) = mpsc::unbounded();
        let (zero_rtt_packets_entry, rcvd_0rtt_packets) = mpsc::unbounded();
        let (hs_packets_entry, rcvd_hs_packets) = mpsc::unbounded();
        let (one_rtt_packets_entry, rcvd_1rtt_packets) = mpsc::unbounded();

        let reliable_frames = ArcReliableFrameDeque::with_capacity(0);
        let initial = InitialScope::new(ArcKeys::new_pending());
        let hs = HandshakeScope::default();
        let data = DataScope::default();

        let router_registry = router.registry(
            reliable_frames.clone(),
            [
                initial_packets_entry.clone(),
                zero_rtt_packets_entry.clone(),
                hs_packets_entry.clone(),
                one_rtt_packets_entry.clone(),
            ],
        );

        let cid_registry = CidRegistry::new(8, router_registry, reliable_frames.clone(), 2);
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

        let token = match &mut token_skin {
            Some(token_sink) => token_sink.get_token().unwrap_or_else(Vec::new),
            None => Vec::new(),
        };

        let token = Arc::new(Mutex::new(token));

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
                let token = token.clone();
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
            reliable_frames.clone(),
            token_provider,
            &conn_error,
        );
        let join_hs = hs.build(rcvd_hs_packets, &pathes, &notify, &conn_error);
        let (join_0rtt, join_1rtt) = data.build(
            &router,
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
            token_skin,
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
            pathes,
            cid_registry,
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
            token,
        }
    }

    pub fn retry(&self, token: Vec<u8>) {
        *self.token.lock().unwrap() = token;
        let largest = self.initial.space.sent_packets().receive().largest_pn();
        for pn in 0..largest {
            let _ = self.initial.space.sent_packets().receive().may_loss_pkt(pn);
        }
    }
}
