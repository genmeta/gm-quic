use std::sync::{Arc, Mutex};

use dashmap::DashMap;
use futures::channel::mpsc;
use qbase::{
    cid::Registry,
    flow::FlowController,
    handshake::Handshake,
    packet::{keys::ArcKeys, SpacePacket, SpinBit},
    streamid::Role,
};
use qrecovery::{reliable::ArcReliableFrameDeque, space::DataSpace, streams::DataStreams};
use qudp::ArcUsc;
use qunreliable::DatagramFlow;

use super::scope::{data::DataScope, handshake::HandshakeScope, initial::InitialScope};
use crate::{
    error::ConnError,
    path::{ArcPath, Pathway},
    tls::ArcTlsSession,
};

pub struct RawConnection {
    pub pathes: DashMap<Pathway, ArcPath>,
    pub cid_registry: Registry,
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
    pub fn new(role: Role, _tls_session: ArcTlsSession) -> Self {
        let pathes = DashMap::new();
        let cid_registry = Registry::new(2);
        let handshake = Handshake::with_role(role);
        let flow_control = FlowController::with_initial(0, 0);
        let spin = Arc::new(Mutex::new(SpinBit::Off));
        let conn_error = ConnError::default();

        let reliable_frames = ArcReliableFrameDeque::with_capacity(0);
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
            &flow_control,
            rcvd_0rtt_packets,
            rcvd_1rtt_packets,
            conn_error.clone(),
        );

        Self {
            pathes,
            cid_registry,
            handshake,
            flow_ctrl: flow_control,
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
                let _ = (pathway, usc);
                unimplemented!()
            })
            .value()
            .clone()
    }

    pub fn enter_closing(&self) -> (DashMap<Pathway, ArcPath>, Registry, DataSpace) {
        (
            self.pathes.clone(),
            self.cid_registry.clone(),
            self.data.space.clone(),
        )
    }
}
