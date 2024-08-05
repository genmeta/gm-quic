use std::sync::{Arc, Mutex};

use dashmap::DashMap;
use futures::channel::mpsc;
use qbase::{
    flow::FlowController,
    handshake::Handshake,
    packet::{keys::ArcKeys, SpacePacket, SpinBit},
    streamid::Role,
};
use qrecovery::{reliable::ArcReliableFrameDeque, space::DataSpace, streams::DataStreams};
use qudp::ArcUsc;
use qunreliable::DatagramFlow;

use super::{
    scope::{data::DataScope, handshake::HandshakeScope, initial::InitialScope},
    CidRegistry,
};
use crate::{
    error::ConnError,
    path::{ArcPath, Pathway},
    router::ArcRouter,
    tls::ArcTlsSession,
};

#[derive(Clone)]
pub struct RawConnection {
    pub pathes: DashMap<Pathway, ArcPath>,
    pub cid_registry: CidRegistry,
    // handshake done的信号
    pub handshake: Handshake,
    pub flow_ctrl: FlowController,
    pub spin: Arc<Mutex<SpinBit>>,
    pub error: ConnError,

    pub initial: InitialScope,
    pub hs: HandshakeScope,
    pub data: DataScope,

    pub reliable_frames: ArcReliableFrameDeque,
    pub streams: DataStreams,
    pub datagrams: DatagramFlow,
}

impl RawConnection {
    pub fn new(role: Role, _tls_session: ArcTlsSession, router: ArcRouter) -> Self {
        let reliable_frames = ArcReliableFrameDeque::with_capacity(0);

        let pathes = DashMap::new();
        let cid_registry = CidRegistry::new(8, reliable_frames.clone(), router, 2);
        let handshake = Handshake::with_role(role);
        let flow_ctrl = FlowController::with_initial(0, 0);
        let spin = Arc::new(Mutex::new(SpinBit::Off));
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

        let (initial_packets_entry, rcvd_initial_packets) = mpsc::unbounded();
        let (hs_packets_entry, rcvd_hs_packets) = mpsc::unbounded();
        let (zero_rtt_packets_entry, rcvd_0rtt_packets) = mpsc::unbounded();
        let (one_rtt_packets_entry, rcvd_1rtt_packets) = mpsc::unbounded();

        let initial = InitialScope::new(ArcKeys::new_pending(), initial_packets_entry);
        let hs = HandshakeScope::new(hs_packets_entry);
        let data = DataScope::new(zero_rtt_packets_entry, one_rtt_packets_entry);

        initial.build(rcvd_initial_packets, conn_error.clone());
        hs.build(rcvd_hs_packets, conn_error.clone());
        data.build(
            &handshake,
            &streams,
            &datagrams,
            &cid_registry,
            &flow_ctrl,
            rcvd_0rtt_packets,
            rcvd_1rtt_packets,
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
        }
    }

    pub fn recv_packet_via_path(&self, packet: SpacePacket, path: ArcPath) {
        match packet {
            SpacePacket::Initial(packet) => {
                _ = self.initial.packets_entry.unbounded_send((packet, path))
            }
            SpacePacket::Handshake(packet) => {
                _ = self.hs.packets_entry.unbounded_send((packet, path))
            }
            SpacePacket::ZeroRtt(packet) => {
                _ = self
                    .data
                    .zero_rtt_packets_entry
                    .unbounded_send((packet, path))
            }
            SpacePacket::OneRtt(packet) => {
                _ = self
                    .data
                    .one_rtt_packets_entry
                    .unbounded_send((packet, path))
            }
        }
    }

    pub fn get_path(&self, pathway: Pathway, usc: &ArcUsc) -> ArcPath {
        self.pathes
            .entry(pathway)
            .or_insert_with(|| {
                let path = ArcPath::new(usc.clone(), pathway, self);
                self.pathes.insert(pathway, path.clone());

                tokio::spawn({
                    let path = path.clone();
                    let connection = self.clone();
                    async move {
                        path.has_been_inactivated().await;
                        connection.pathes.remove(&pathway);
                    }
                });
                path
            })
            .value()
            .clone()
    }

    pub fn enter_closing(&self) -> (DashMap<Pathway, ArcPath>, CidRegistry, DataSpace) {
        (
            self.pathes.clone(),
            self.cid_registry.clone(),
            self.data.space.clone(),
        )
    }
}
