use std::{
    ops::Deref,
    sync::{Arc, Mutex},
    time::Duration,
};

use futures::channel::mpsc;
use qbase::{
    cid::ConnectionId,
    error::Error,
    frame::{MaxStreamsFrame, ReceiveFrame, StreamCtlFrame},
    packet::{
        header::long::{RetryHeader, VersionNegotiationHeader},
        keys::{ArcKeys, ArcOneRttKeys},
    },
    param::Parameters,
    sid::{ControlConcurrency, Role},
    token::{ArcTokenRegistry, TokenRegistry},
    Epoch,
};
use qcongestion::{ArcCC, CongestionAlgorithm, CongestionControl};
use rustls::quic::Keys;
use tokio::{sync::Notify, task::JoinHandle};

use super::{
    parameters::ConnParameters,
    space::{
        data::{DataSpace, DataTracker},
        handshake::{HandshakeSpace, HandshakeTracker},
        initial::{InitialSpace, InitialTracker},
    },
    ArcLocalCids, ArcRemoteCids, CidRegistry, FlowController, Handshake, RcvdPackets,
};
use crate::{
    error::ConnError,
    path::{ArcPath, ArcPaths, Path, Paths, Pathway},
    router::Router,
    tls::ArcTlsSession,
};

pub struct Connection {
    // TOOD?: hide these fields
    pub(super) initial_scid: ConnectionId,
    pub(super) token: Arc<Mutex<Vec<u8>>>,
    pub(super) paths: ArcPaths,
    pub(super) cid_registry: CidRegistry,
    pub(super) flow_ctrl: FlowController,
    pub(super) error: ConnError,

    pub(super) initial: InitialSpace,
    pub(super) hs: HandshakeSpace,
    pub(super) data: DataSpace,
    pub(super) notify: Arc<Notify>, // Notifier for closing the packet receiving task
    pub(super) join_handles: [JoinHandle<RcvdPackets>; 4],

    pub(super) tls_session: ArcTlsSession,
    pub(super) params: ConnParameters,
}

impl Connection {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        role: Role,
        local_params: Parameters,
        tls_session: ArcTlsSession,
        initial_scid: ConnectionId,
        initial_dcid: ConnectionId,
        initial_keys: Keys,
        streams_ctrl: Box<dyn ControlConcurrency>,
        token_registry: ArcTokenRegistry,
    ) -> Self {
        let (initial_packets_entry, rcvd_initial_packets) = mpsc::unbounded();
        let (zero_rtt_packets_entry, rcvd_0rtt_packets) = mpsc::unbounded();
        let (hs_packets_entry, rcvd_hs_packets) = mpsc::unbounded();
        let (one_rtt_packets_entry, rcvd_1rtt_packets) = mpsc::unbounded();

        let initial = InitialSpace::new(ArcKeys::with_keys(initial_keys));
        let hs = HandshakeSpace::default();
        let data = DataSpace::new(role, &local_params, streams_ctrl);
        let reliable_frames = &data.reliable_frames;
        let streams = &data.streams;
        let datagrams = &data.datagrams;

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
        let flow_ctrl = FlowController::new(65535, 65535, reliable_frames.clone());
        let conn_error = ConnError::default();

        let token = match token_registry.deref() {
            TokenRegistry::Client((server_name, client)) => {
                Arc::new(Mutex::new(client.fetch_token(server_name)))
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
                move |path: &Path| {
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

            let initial_tracker =
                InitialTracker::new(initial.journal.clone(), initial.crypto_stream.outgoing());
            let hs_tracker = HandshakeTracker::new(hs.journal.clone(), hs.crypto_stream.outgoing());
            let data_tracker = DataTracker::new(
                data.journal.clone(),
                reliable_frames.clone(),
                streams.clone(),
                data.crypto_stream.outgoing(),
            );

            move |pathway, usc| {
                let scid = cid_registry.local.active_cids()[0];
                let dcid = cid_registry.remote.apply_dcid();

                let cc = ArcCC::new(
                    CongestionAlgorithm::Bbr,
                    Duration::from_millis(100),
                    [
                        Box::new(initial_tracker.clone()),
                        Box::new(hs_tracker.clone()),
                        Box::new(data_tracker.clone()),
                    ],
                    handshake.clone(),
                );

                let path = Path::new(usc, scid, dcid, cc);
                if !handshake.is_handshake_done() {
                    if role == Role::Client {
                        path.grant_anti_amplifier();
                    }
                } else {
                    path.begin_validation();
                }
                path.begin_sending(pathway, &flow_ctrl, &gen_readers);
                Arc::new(path)
            }
        });
        let on_no_path = Arc::new({
            let conn_error = conn_error.clone();
            move || {
                conn_error.no_viable_path();
            }
        });
        let paths = Paths::new(path_creator, on_no_path).into();

        let validate = {
            let tls_session = tls_session.clone();
            let token_registry = token_registry.clone();
            move |initial_token: &[u8], path: ArcPath| {
                if let TokenRegistry::Server(provider) = token_registry.deref() {
                    if let Some(server_name) = tls_session.server_name() {
                        if provider.verify_token(server_name, initial_token) {
                            path.grant_anti_amplifier();
                        }
                    }
                }
            }
        };

        let notify = Arc::new(Notify::new());
        let join_initial = initial.build(
            rcvd_initial_packets,
            &paths,
            &cid_registry.remote,
            &notify,
            &conn_error,
            validate,
        );

        let join_hs = hs.build(rcvd_hs_packets, &paths, &notify, &conn_error);

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

                // pretend to receive the MAX_STREAM frames
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
            &paths,
            &handshake,
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
            paths,
            cid_registry,
            flow_ctrl,
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
    pub fn max_pto_duration(&self) -> Option<Duration> {
        self.paths
            .iter()
            .map(|path| path.cc().pto_time(Epoch::Data))
            .max()
    }

    pub fn abort_with_error(&self, error: &Error) {
        self.data.on_conn_error(error);
        self.flow_ctrl.on_conn_error(error);
        self.params.on_conn_error(error);
        self.tls_session.abort();
        self.notify.notify_waiters();
    }

    pub fn update_path_recv_time(&self, pathway: Pathway) {
        if let Some(path) = self.paths.try_get(&pathway).try_unwrap() {
            path.update_recv_time();
        }
    }
}

/// Try to join two futures, return `None` if any of them is `None`.
///
// While Try trait is unstable, tokio&futures dont provide such a function
pub async fn try_join<T, U>(
    a: impl core::future::Future<Output = Option<T>> + Unpin,
    b: impl core::future::Future<Output = Option<U>> + Unpin,
) -> Option<(T, U)> {
    use futures::future::Either;
    match futures::future::select(a, b).await {
        Either::Left((a, b)) => Some((a?, b.await?)),
        Either::Right((b, a)) => Some((a.await?, b?)),
    }
}

impl Connection {
    pub fn packet_entry(
        &self,
    ) -> impl Fn(qbase::packet::Packet, Pathway, crate::usc::ArcUsc) + Send + Sync + 'static {
        use futures::StreamExt;
        let error_tracker = self.error.clone();

        // retry and version negotiation
        let retry_entry = self.retry_packet_entry();
        let vn_entry = self.vn_packet_entry();

        // initial space
        let (initial_entry, mut rcvd_initial) = mpsc::unbounded();
        let dispatch_frame = self.initial.frame_entry(&error_tracker);
        let packet_entry = self.initial.packet_entry(
            self.paths.clone(),
            self.cid_registry.remote.clone(),
            error_tracker.clone(),
            |_, _| unimplemented!(), // can only be accessed in `new`
            dispatch_frame,
        );

        let key: ArcKeys = ArcKeys::new_pending(); // can only be accessed in `new`
        tokio::spawn(async move {
            while let Some((bundle, keys)) =
                try_join(rcvd_initial.next(), key.get_remote_keys()).await
            {
                packet_entry(bundle, keys.as_ref());
            }
        });

        // handshake space
        let (handshake_entry, mut rcvd_handshake) = mpsc::unbounded();
        let dispatch_frame = self.hs.frame_entry(&error_tracker);
        let packet_entry =
            self.hs
                .packet_entry(self.paths.clone(), error_tracker.clone(), dispatch_frame);

        let key: ArcKeys = ArcKeys::new_pending(); // can only be accessed in `new`
        tokio::spawn(async move {
            while let Some((bundle, keys)) =
                try_join(rcvd_handshake.next(), key.get_remote_keys()).await
            {
                packet_entry(bundle, keys.as_ref());
            }
        });

        // data space
        let dispatch_frame = self.data.frame_entry(
            &error_tracker,
            &Handshake::new_client(), // can only be accessed in `new`
            &self.cid_registry,
            &self.flow_ctrl,
            &ArcTokenRegistry::default_provider(), // can only be accessed in `new`
        );

        // zero rtt
        let (zero_rtt_entry, mut rcvd_zero_rtt) = mpsc::unbounded();
        let zero_rtt_packet_entry = self.data.zero_rtt_packets_entry(
            self.paths.clone(),
            error_tracker.clone(),
            dispatch_frame.clone(),
        );

        let key: ArcKeys = ArcKeys::new_pending(); // can only be accessed in `new`
        tokio::spawn(async move {
            while let Some((bundle, keys)) =
                try_join(rcvd_zero_rtt.next(), key.get_remote_keys()).await
            {
                zero_rtt_packet_entry(bundle, keys.as_ref());
            }
        });

        // one rtt
        let (one_rtt_entry, mut rcvd_one_rtt) = mpsc::unbounded();
        let one_rtt_packet_entry = self.data.one_rtt_packets_entry(
            self.paths.clone(),
            error_tracker.clone(),
            dispatch_frame,
        );

        let key: ArcOneRttKeys = ArcOneRttKeys::new_pending(); // can only be accessed in `new`
        tokio::spawn(async move {
            while let Some((bundle, (hpk, pk))) =
                try_join(rcvd_one_rtt.next(), key.get_remote_keys()).await
            {
                one_rtt_packet_entry(bundle, (&*hpk, &pk));
            }
        });

        use qbase::packet::{header, DataHeader, Packet};
        move |packet, pathway, usc| match packet {
            Packet::VN(vn) => vn_entry(vn, pathway),
            Packet::Retry(retry) => retry_entry(retry, pathway),
            Packet::Data(data_packet) => match data_packet.header {
                DataHeader::Long(header::DataHeader::Initial(initial)) => {
                    let packet = (initial, data_packet.bytes, data_packet.offset);
                    _ = initial_entry.unbounded_send((packet, pathway, usc))
                }
                DataHeader::Long(header::DataHeader::Handshake(handshake)) => {
                    let packet = (handshake, data_packet.bytes, data_packet.offset);
                    _ = handshake_entry.unbounded_send((packet, pathway, usc))
                }
                DataHeader::Long(header::DataHeader::ZeroRtt(zero_rtt)) => {
                    let packet = (zero_rtt, data_packet.bytes, data_packet.offset);
                    _ = zero_rtt_entry.unbounded_send((packet, pathway, usc))
                }
                DataHeader::Short(one_rtt) => {
                    let packet = (one_rtt, data_packet.bytes, data_packet.offset);
                    _ = one_rtt_entry.unbounded_send((packet, pathway, usc))
                }
            },
        }
    }

    pub fn retry_packet_entry(&self) -> impl Fn(RetryHeader, Pathway) + Send + 'static {
        let paths = self.paths.clone();
        let token = self.token.clone();
        let remote_cids = self.cid_registry.remote.clone();
        let initial = self.initial.clone();
        move |retry, pathway| {
            paths.update_path_recv_time(pathway);

            *token.lock().unwrap() = retry.token.to_vec();
            remote_cids.revise_initial_dcid(retry.scid);
            let sent_record = initial.journal.sent();
            let mut guard = sent_record.recv();
            for i in 0..guard.largest_pn() {
                for frame in guard.may_loss_pkt(i) {
                    initial.crypto_stream.outgoing().may_loss_data(&frame);
                }
            }
        }
    }

    pub fn vn_packet_entry(&self) -> impl Fn(VersionNegotiationHeader, Pathway) + Send + 'static {
        let paths = self.paths.clone();
        move |_vn, pathway| {
            paths.update_path_recv_time(pathway);

            // TODO: actually handle the VN packet
        }
    }
}
