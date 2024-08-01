use std::sync::{Arc, Mutex};

use dashmap::DashMap;
use futures::{channel::mpsc, StreamExt};
use qbase::{
    cid::Registry,
    flow::FlowController,
    handshake::Handshake,
    packet::{
        keys::{ArcKeys, ArcOneRttKeys},
        SpacePacket, SpinBit,
    },
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
    pathes: DashMap<Pathway, ArcPath>,
    cid_registry: Registry,
    // handshake done的信号
    handshake: Handshake,
    flow_ctrl: FlowController,
    spin: Arc<Mutex<SpinBit>>,
    error: ConnError,

    initial: InitialScope,
    hs: HandshakeScope,
    data: DataScope,

    reliable_frames: ArcReliableFrameDeque,
    streams: DataStreams,
    datagrams: DatagramFlow,
}

impl RawConnection {
    // TOOD: 传输参数实际上不是一开始就可以设置好的，而是在握手过程中逐渐完善的
    pub fn new(role: Role, tls_session: ArcTlsSession) -> Self {
        let pathes = DashMap::new();
        let cid_registry = Registry::new(2);
        let handshake = Handshake::with_role(role);
        let flow_ctrl = FlowController::with_initial(0, 0);
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
            handshake.clone(),
            streams.clone(),
            datagrams.clone(),
            &cid_registry,
            &flow_ctrl,
            rcvd_0rtt_packets,
            rcvd_1rtt_packets,
            conn_error.clone(),
        );

        let (parameters_entry, mut rcvd_transport_parameters) = mpsc::channel(1);
        tls_session.keys_upgrade(
            [
                &initial.crypto_stream,
                &hs.crypto_stream,
                &data.crypto_stream,
            ],
            hs.keys.clone(),
            data.one_rtt_keys.clone(),
            parameters_entry,
        );

        tokio::spawn({
            let conn_error = conn_error.clone();
            let streams = streams.clone();
            let flow_ctrl = flow_ctrl.clone();
            let datagrams = datagrams.clone();
            async move {
                let parameter = rcvd_transport_parameters.next().await.unwrap();
                if let Err(e) = datagrams.apply_transport_parameters(&parameter) {
                    conn_error.on_error(e)
                };
                streams.apply_transport_parameters(&parameter);
                flow_ctrl.apply_transport_parameters(&parameter);
            }
        });

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
                let _ = (pathway, usc);
                unimplemented!()
            })
            .value()
            .clone()
    }

    pub fn enter_closing(
        &self,
    ) -> (
        DashMap<Pathway, ArcPath>,
        Registry,
        DataSpace,
        ArcOneRttKeys,
    ) {
        (
            self.pathes.clone(),
            self.cid_registry.clone(),
            self.data.space.clone(),
            self.data.one_rtt_keys.clone(),
        )
    }
}
