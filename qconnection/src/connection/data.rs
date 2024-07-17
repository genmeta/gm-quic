use qbase::{
    error::Error,
    frame::ConnectionCloseFrame,
    packet::{
        keys::{ArcKeys, ArcOneRttKeys},
        HandshakePacket, InitialPacket, OneRttPacket, SpacePacket, SpinBit, ZeroRttPacket,
    },
};
use qrecovery::space::{DataSpace, HandshakeSpace, InitialSpace};
use qunreliable::DatagramFlow;
use tokio::sync::{mpsc, oneshot};

use super::state::ConnectionState;
use crate::{
    controller::ArcFlowController,
    path::{ArcPath, PathState},
};

type PacketQueue<T> = mpsc::UnboundedSender<(T, ArcPath)>;

pub enum ConnectionStateData {
    Initial {
        init_pkt_queue: PacketQueue<InitialPacket>,
        init_keys: ArcKeys,
        init_space: InitialSpace,

        hs_pkt_queue: PacketQueue<HandshakePacket>,
        hs_keys: ArcKeys,
        hs_space: HandshakeSpace,

        zero_rtt_pkt_queue: PacketQueue<ZeroRttPacket>,
        zero_rtt_keys: ArcKeys,

        one_rtt_pkt_queue: PacketQueue<OneRttPacket>,
        one_rtt_keys: ArcOneRttKeys,
        data_space: DataSpace,
        flow_ctrl: ArcFlowController,
        spin: SpinBit,

        datagram_flow: DatagramFlow,

        conn_err_tx: Option<oneshot::Sender<Error>>,
        rcvd_ccf_tx: Option<oneshot::Sender<ConnectionCloseFrame>>,
    },
    Handshaking {
        hs_pkt_queue: PacketQueue<HandshakePacket>,
        hs_keys: ArcKeys,
        hs_space: HandshakeSpace,

        zero_rtt_pkt_queue: PacketQueue<ZeroRttPacket>,
        zero_rtt_keys: ArcKeys,

        one_rtt_pkt_queue: PacketQueue<OneRttPacket>,
        one_rtt_keys: ArcOneRttKeys,
        data_space: DataSpace,
        flow_ctrl: ArcFlowController,
        spin: SpinBit,

        datagram_flow: DatagramFlow,

        conn_err_tx: Option<oneshot::Sender<Error>>,
        rcvd_ccf_tx: Option<oneshot::Sender<ConnectionCloseFrame>>,
    },
    Normal {
        one_rtt_pkt_queue: PacketQueue<OneRttPacket>,
        one_rtt_keys: ArcOneRttKeys,
        data_space: DataSpace,
        flow_ctrl: ArcFlowController,
        spin: SpinBit,

        datagram_flow: DatagramFlow,

        conn_err_tx: Option<oneshot::Sender<Error>>,
        rcvd_ccf_tx: Option<oneshot::Sender<ConnectionCloseFrame>>,
    },
    Closing {
        packet: (),
        rcvd_ccf_tx: Option<oneshot::Sender<ConnectionCloseFrame>>,
    },
    Draining {},
    Invalid,
}

impl ConnectionStateData {
    pub(super) fn cur_state(&self) -> ConnectionState {
        match self {
            ConnectionStateData::Initial { .. } => ConnectionState::Initial,
            ConnectionStateData::Handshaking { .. } => ConnectionState::Handshaking,
            ConnectionStateData::Normal { .. } => ConnectionState::Normal,
            ConnectionStateData::Closing { .. } => ConnectionState::Closing,
            ConnectionStateData::Draining {} => ConnectionState::Draining,
            ConnectionStateData::Invalid => ConnectionState::Closed,
        }
    }

    pub fn receive_packet_via(&self, ptk: SpacePacket, path: ArcPath) {
        match ptk {
            SpacePacket::Initial(pkt) => {
                if let ConnectionStateData::Initial { init_pkt_queue, .. } = self {
                    let _ = init_pkt_queue.send((pkt, path));
                }
            }
            SpacePacket::Handshake(pkt) => {
                if let ConnectionStateData::Handshaking { hs_pkt_queue, .. }
                | ConnectionStateData::Initial { hs_pkt_queue, .. } = self
                {
                    _ = hs_pkt_queue.send((pkt, path));
                }
            }
            SpacePacket::ZeroRtt(pkt) => {
                if let ConnectionStateData::Handshaking {
                    zero_rtt_pkt_queue, ..
                }
                | ConnectionStateData::Initial {
                    zero_rtt_pkt_queue, ..
                } = self
                {
                    _ = zero_rtt_pkt_queue.send((pkt, path));
                }
            }
            SpacePacket::OneRtt(pkt) => {
                if let ConnectionStateData::Initial {
                    one_rtt_pkt_queue, ..
                }
                | ConnectionStateData::Handshaking {
                    one_rtt_pkt_queue, ..
                }
                | ConnectionStateData::Normal {
                    one_rtt_pkt_queue, ..
                } = self
                {
                    _ = one_rtt_pkt_queue.send((pkt, path));
                }
            }
        }
    }

    pub fn create_path_state(&self) -> Option<PathState> {
        match self {
            ConnectionStateData::Initial {
                init_keys,
                init_space,
                hs_keys,
                hs_space,
                one_rtt_keys,
                data_space,
                flow_ctrl,
                spin,
                datagram_flow,
                ..
            } => Some(PathState::Initial {
                init_keys: init_keys.clone(),
                init_space: init_space.clone(),
                hs_keys: hs_keys.clone(),
                hs_space: hs_space.clone(),
                one_rtt_keys: one_rtt_keys.clone(),
                data_space: data_space.clone(),
                flow_ctrl: flow_ctrl.clone(),
                spin: *spin,
                datagram_flow: datagram_flow.clone(),
            }),
            ConnectionStateData::Handshaking {
                hs_keys,
                hs_space,
                one_rtt_keys,
                data_space,
                flow_ctrl,
                spin,
                datagram_flow,
                ..
            } => Some(PathState::Handshaking {
                hs_keys: hs_keys.clone(),
                hs_space: hs_space.clone(),
                one_rtt_keys: one_rtt_keys.clone(),
                data_space: data_space.clone(),
                flow_ctrl: flow_ctrl.clone(),
                spin: *spin,
                datagram_flow: datagram_flow.clone(),
            }),
            ConnectionStateData::Normal {
                one_rtt_keys,
                data_space,
                flow_ctrl,
                spin,
                datagram_flow,
                ..
            } => Some(PathState::Normal {
                one_rtt_keys: one_rtt_keys.clone(),
                data_space: data_space.clone(),
                flow_ctrl: flow_ctrl.clone(),
                spin: *spin,
                datagram_flow: datagram_flow.clone(),
            }),
            _ => None,
        }
    }
}

// impl ConnectionStateData {
//     fn cur_state(&self) -> ConnectionState {
//         match self {
//             ConnectionStateData::Initial { .. } => ConnectionState::Initial,
//             ConnectionStateData::Handshake { .. } => ConnectionState::Handshake,
//             ConnectionStateData::Normal { .. } => ConnectionState::Normal,
//             ConnectionStateData::Closing { .. } => ConnectionState::Closing,
//             ConnectionStateData::Draining { .. } => ConnectionState::Draining,
//             ConnectionStateData::Closed => ConnectionState::Closed,
//         }
//     }
// }
