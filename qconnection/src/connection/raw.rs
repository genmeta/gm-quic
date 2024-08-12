use std::sync::{Arc, Mutex};

use futures::channel::mpsc;
use qbase::{
    flow::FlowController,
    handshake::Handshake,
    packet::{keys::ArcKeys, SpinBit},
    streamid::Role,
};
use qrecovery::{reliable::ArcReliableFrameDeque, streams::DataStreams};
use qunreliable::DatagramFlow;

use super::{
    scope::{data::DataScope, handshake::HandshakeScope, initial::InitialScope},
    CidRegistry,
};
use crate::{
    error::ConnError,
    path::{ArcPathes, RawPath},
    router::ArcRouter,
    tls::{ArcTlsSession, GetParameters},
};

#[derive(Clone)]
pub struct RawConnection {
    pub pathes: ArcPathes,
    pub cid_registry: CidRegistry,
    // handshake done的信号
    pub handshake: Handshake<ArcReliableFrameDeque>,
    pub flow_ctrl: FlowController,
    pub spin: Arc<Mutex<SpinBit>>,
    pub error: ConnError,

    pub initial: InitialScope,
    pub hs: HandshakeScope,
    pub data: DataScope,

    pub reliable_frames: ArcReliableFrameDeque,
    pub streams: DataStreams,
    pub datagrams: DatagramFlow,

    pub params: GetParameters,
}

impl RawConnection {
    pub fn new(role: Role, tls_session: ArcTlsSession, router: ArcRouter) -> Self {
        let (initial_packets_entry, rcvd_initial_packets) = mpsc::unbounded();
        let (zero_rtt_packets_entry, rcvd_0rtt_packets) = mpsc::unbounded();
        let (hs_packets_entry, rcvd_hs_packets) = mpsc::unbounded();
        let (one_rtt_packets_entry, rcvd_1rtt_packets) = mpsc::unbounded();

        let reliable_frames = ArcReliableFrameDeque::with_capacity(0);
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
        let spin = Arc::new(Mutex::new(SpinBit::Zero));
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

        let initial = InitialScope::new(ArcKeys::new_pending(), initial_packets_entry);
        let hs = HandshakeScope::new(hs_packets_entry);
        let data = DataScope::new(zero_rtt_packets_entry, one_rtt_packets_entry);

        let pathes = ArcPathes::new(Box::new({
            let remote_cids = cid_registry.remote.clone();
            move |_pathway, usc| {
                let dcid = remote_cids.apply_cid();
                let path = RawPath::new(usc.clone(), dcid);
                // TODO: 启动发包任务
                path
            }
        }));

        initial.build(rcvd_initial_packets, &pathes, &conn_error);
        hs.build(rcvd_hs_packets, &pathes, &conn_error);
        data.build(
            &pathes,
            &handshake,
            &streams,
            &datagrams,
            &cid_registry,
            &flow_ctrl,
            &conn_error,
            rcvd_0rtt_packets,
            rcvd_1rtt_packets,
        );

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
            initial,
            hs,
            data,
            streams,
            reliable_frames,
            datagrams,
            spin,
            error: conn_error,
            params: get_params,
        }
    }
}
