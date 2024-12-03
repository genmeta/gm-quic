use qbase::{
    cid::ConnectionId,
    flow,
    packet::keys::ArcKeys,
    param::Parameters,
    sid::{ControlConcurrency, Role},
    token::ArcTokenRegistry,
};
use qrecovery::reliable;
use rustls::quic::Keys;

use crate::{path::ArcPaths, tls::ArcTlsSession};

use super::{
    parameters::ConnParameters,
    space::{initial, DataSpace, HandshakeSpace, InitialSpace},
    ArcLocalCids, ArcRemoteCids, CidRegistry, FlowController, Handshake,
};

/// 一个连接的核心，客户端、服务端通用
/// 能够处理收到的包，能够发送数据包，能够打开流、接受流
pub struct CoreConnection {
    // 连接参数
    params: ConnParameters,
    handshake: Handshake,
    // 连接级流量控制
    flow_ctrl: FlowController,
    // 所有路径集合，每个路径单独的拥塞控制
    // paths: ArcPaths,
    // tls握手
    tls_session: ArcTlsSession,
    // 三个空间
    initial: InitialSpace,
    hs: HandshakeSpace,
    data: DataSpace,
}

impl CoreConnection {
    pub fn client(
        parameters: Parameters,
        streams_ctrl: Box<dyn ControlConcurrency>,
        token: Option<Vec<u8>>,
    ) -> ClientConnectionBuilder {
        let initial = InitialSpace::default();
        let hs = HandshakeSpace::default();
        let data = DataSpace::new(Role::Client, &parameters, streams_ctrl);

        let reliable_frames = &data.reliable_frames;
        let handshake = Handshake::new(Role::Client, reliable_frames.clone());
        let flow_ctrl = FlowController::new(65535, 65535, reliable_frames.clone());

        // let paths = ArcPaths::new();
        ClientConnectionBuilder {
            params: ConnParameters::new(parameters, token),
            handshake,
            flow_ctrl,
            initial,
            hs,
            data,
        }
    }

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
        let initial = InitialSpace::new(ArcKeys::with_keys(initial_keys));
        let hs = HandshakeSpace::default();
        let data = DataSpace::new(role, &local_params, streams_ctrl);

        let handshake = Handshake::new(role, reliable_frames.clone());
        let flow_ctrl = FlowController::new(65535, 65535, reliable_frames.clone());
    }
}


pub struct ClientConnectionBuilder {
    params: ConnParameters,
    handshake: Handshake,
    flow_ctrl: FlowController,
    initial: InitialSpace,
    hs: HandshakeSpace,
    data: DataSpace,
}