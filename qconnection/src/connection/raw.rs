use std::{
    ops::Deref,
    sync::{Arc, Mutex},
};

use futures::channel::mpsc;
use qbase::{
    cid::ConnectionId,
    flow::FlowController,
    frame::{MaxStreamsFrame, ReceiveFrame, StreamCtlFrame},
    packet::keys::ArcKeys,
    param::Parameters,
    streamid::Role,
    token::{ArcTokenRegistry, TokenRegistry},
};
use qcongestion::{MayLoss, RetirePktRecord};
use qrecovery::reliable::ArcReliableFrameDeque;
use qunreliable::DatagramFlow;
use rustls::quic::Keys;
use tokio::{sync::Notify, task::JoinHandle};

use super::{
    parameters::ConnParameters,
    scope::{
        data::{DataMayLoss, DataScope},
        handshake::{HandshakeMayloss, HandshakeScope},
        initial::{InitialMayLoss, InitialScope},
    },
    ArcLocalCids, ArcRemoteCids, CidRegistry, DataStreams, Handshake, RcvdPackets,
};
use crate::{
    error::ConnError,
    path::{pathway::Pathway, ArcPath, ArcPathes, RawPath},
    router::Router,
    tls::ArcTlsSession,
};

pub struct RawConnection {
    pub initial_scid: ConnectionId,
    pub token: Arc<Mutex<Vec<u8>>>,
    pub pathes: ArcPathes,
    pub cid_registry: CidRegistry,
    // handshake done的信号
    pub handshake: Handshake,
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

    pub tls_session: ArcTlsSession,
    pub params: ConnParameters,
}

impl RawConnection {
    pub fn new(
        role: Role,
        local_params: Parameters,
        tls_session: ArcTlsSession,
        initial_scid: ConnectionId,
        initial_dcid: ConnectionId,
        initial_keys: Keys,
        token_registry: ArcTokenRegistry,
    ) -> Self {
        let (initial_packets_entry, rcvd_initial_packets) = mpsc::unbounded();
        let (zero_rtt_packets_entry, rcvd_0rtt_packets) = mpsc::unbounded();
        let (hs_packets_entry, rcvd_hs_packets) = mpsc::unbounded();
        let (one_rtt_packets_entry, rcvd_1rtt_packets) = mpsc::unbounded();

        let reliable_frames = ArcReliableFrameDeque::with_capacity(0);
        let initial = InitialScope::new(ArcKeys::with_keys(initial_keys));
        let hs = HandshakeScope::default();
        let data = DataScope::default();

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
            initial_dcid,
            local_params.active_connection_id_limit().into(),
            reliable_frames.clone(),
        );
        let cid_registry = CidRegistry::new(local_cids, remote_cids);
        let handshake = Handshake::new(role, reliable_frames.clone());
        let flow_ctrl = FlowController::with_parameter(65535, 65535);
        let conn_error = ConnError::default();

        let streams = DataStreams::new(role, &local_params, reliable_frames.clone());
        let datagrams = DatagramFlow::new(0);

        let token = match token_registry.deref() {
            TokenRegistry::Client((server_name, client)) => {
                Arc::new(Mutex::new(client.get_token(server_name)))
            }
            TokenRegistry::Server(_) => Arc::new(Mutex::new(vec![])),
        };
        let path_creator = Box::new({
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

            let initial = initial.clone();
            let hs = hs.clone();
            let data = data.clone();

            let initial_may_loss =
                InitialMayLoss::new(initial.space.clone(), initial.crypto_stream.outgoing());
            let hs_may_loss = HandshakeMayloss::new(hs.space.clone(), hs.crypto_stream.outgoing());
            let data_may_loss = DataMayLoss::new(
                data.space.clone(),
                reliable_frames.clone(),
                streams.clone(),
                data.crypto_stream.outgoing(),
            );

            move |pathway, usc| {
                let scid = cid_registry.local.active_cids()[0];
                let dcid = cid_registry.remote.apply_dcid();
                let loss: [Box<dyn MayLoss>; 3] = [
                    Box::new(initial_may_loss.clone()),
                    Box::new(hs_may_loss.clone()),
                    Box::new(data_may_loss.clone()),
                ];
                let retire: [Box<dyn RetirePktRecord>; 3] = [
                    Box::new(initial.clone()),
                    Box::new(hs.clone()),
                    Box::new(data.clone()),
                ];

                let path = ArcPath::new(usc, scid, dcid, loss, retire);
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
        });
        let on_no_path = Arc::new({
            let conn_error = conn_error.clone();
            move || {
                conn_error.no_viable_path();
            }
        });
        let pathes = ArcPathes::new(path_creator, on_no_path);

        let validate = {
            let tls_session = tls_session.clone();
            let token_registry = token_registry.clone();
            move |initial_token: &[u8], path: ArcPath| {
                if let TokenRegistry::Server(provider) = token_registry.deref() {
                    if let Some(server_name) = tls_session.server_name() {
                        if provider.validate_token(server_name, initial_token) {
                            path.anti_amplifier.grant();
                        }
                    }
                }
            }
        };

        let notify = Arc::new(Notify::new());
        let join_initial = initial.build(
            rcvd_initial_packets,
            &pathes,
            &cid_registry.remote,
            &notify,
            &conn_error,
            validate,
        );

        let join_hs = hs.build(rcvd_hs_packets, &pathes, &notify, &conn_error);

        let remote_params = tls_session.keys_upgrade(
            [
                &initial.crypto_stream,
                &hs.crypto_stream,
                &data.crypto_stream,
            ],
            hs.keys.clone(),
            data.one_rtt_keys.clone(),
            conn_error.clone(),
            handshake.clone(),
        );

        let params = ConnParameters::new(local_params.into(), remote_params.clone());
        tokio::spawn({
            let streams = streams.clone();
            let conn_error = conn_error.clone();
            let cid_registry = cid_registry.clone();
            async move {
                let remote_params = remote_params.read().await;
                let Ok(remote_params) = remote_params else {
                    return;
                };

                _ = streams.recv_frame(&StreamCtlFrame::MaxStreams(MaxStreamsFrame::Bi(
                    remote_params.initial_max_streams_bidi(),
                )));
                _ = streams.recv_frame(&StreamCtlFrame::MaxStreams(MaxStreamsFrame::Uni(
                    remote_params.initial_max_streams_uni(),
                )));

                let active_cid_limit = remote_params.active_connection_id_limit().into();
                if let Err(e) = cid_registry.local.set_limit(active_cid_limit) {
                    conn_error.on_error(e);
                }
            }
        });

        let (join_0rtt, join_1rtt) = data.build(
            &pathes,
            &handshake,
            &reliable_frames,
            &streams,
            &datagrams,
            &cid_registry,
            &flow_ctrl,
            &notify,
            &conn_error,
            rcvd_0rtt_packets,
            rcvd_1rtt_packets,
            token_registry,
        );
        let join_handles = [join_initial, join_0rtt, join_hs, join_1rtt];

        Self {
            initial_scid,
            token,
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
            params,
            tls_session,
        }
    }

    pub fn update_path_recv_time(&self, pathway: Pathway) {
        if let Some(path) = self.pathes.try_get(&pathway).try_unwrap() {
            path.update_recv_time();
        }
    }
}
