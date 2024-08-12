use std::sync::Arc;

use futures::channel::mpsc;
use qbase::{flow::FlowController, handshake::Handshake, packet::keys::ArcKeys, streamid::Role};
use qrecovery::{reliable::ArcReliableFrameDeque, streams::DataStreams};
use qunreliable::DatagramFlow;
use tokio::{sync::Notify, task::JoinHandle};

use super::{
    scope::{data::DataScope, handshake::HandshakeScope, initial::InitialScope},
    CidRegistry, RcvdPackets,
};
use crate::{
    address_validator::ArcNewTokens,
    error::ConnError,
    path::{ArcPathes, RawPath},
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

    pub params: GetParameters,
}

impl RawConnection {
    pub fn new(role: Role, tls_session: ArcTlsSession, router: ArcRouter) -> Self {
        let (initial_packets_entry, rcvd_initial_packets) = mpsc::unbounded();
        let (zero_rtt_packets_entry, rcvd_0rtt_packets) = mpsc::unbounded();
        let (hs_packets_entry, rcvd_hs_packets) = mpsc::unbounded();
        let (one_rtt_packets_entry, rcvd_1rtt_packets) = mpsc::unbounded();
        let (retry_packets_entry, rcvd_retry_packets) = mpsc::unbounded();

        let reliable_frames = ArcReliableFrameDeque::with_capacity(0);
        let router_registry = router.registry(
            reliable_frames.clone(),
            [
                initial_packets_entry.clone(),
                zero_rtt_packets_entry.clone(),
                hs_packets_entry.clone(),
                one_rtt_packets_entry.clone(),
            ],
            retry_packets_entry.clone(),
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

        let initial = InitialScope::new(ArcKeys::new_pending());
        let hs = HandshakeScope::new();
        let data = DataScope::new();

        let pathes = ArcPathes::new(Box::new({
            let remote_cids = cid_registry.remote.clone();
            let flow_ctrl = flow_ctrl.clone();
            let gen_readers = {
                let initial = initial.clone();
                let hs = hs.clone();
                let data = data.clone();
                let reliable_frames = reliable_frames.clone();
                let streams = streams.clone();
                let datagrams = datagrams.clone();
                move |path: &RawPath| {
                    (
                        initial.reader_with_token(Vec::new()),
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
                let dcid = remote_cids.apply_cid();
                let path = RawPath::new(usc.clone(), dcid);
                path.begin_validation();
                path.begin_sending(pathway, &flow_ctrl, &gen_readers);
                path
            }
        }));

        let notify = Arc::new(Notify::new());
        let join_initial = initial.build(rcvd_initial_packets, &pathes, &notify, &conn_error);
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
        }
    }
}
