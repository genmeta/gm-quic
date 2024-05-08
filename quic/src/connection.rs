use bytes::BytesMut;
use qbase::packet::{HandshakeHeader, InitialHeader, OneRttHeader, ZeroRTTHeader};
use qrecovery::space::{
    DataSpace, HandshakeSpace, InitailSpace, OneRttDataSpace, ZeroRttDataSpace,
};

/// Key material for use in QUIC packet spaces
///
/// QUIC uses 4 different sets of keys (and progressive key updates for long-running connections):
///
/// * Initial: these can be created from [`Keys::initial()`]
/// * 0-RTT keys: can be retrieved from [`ConnectionCommon::zero_rtt_keys()`]
/// * Handshake: these are returned from [`ConnectionCommon::write_hs()`] after `ClientHello` and
///   `ServerHello` messages have been exchanged
/// * 1-RTT keys: these are returned from [`ConnectionCommon::write_hs()`] after the handshake is done
///
/// Once the 1-RTT keys have been exchanged, either side may initiate a key update. Progressive
/// update keys can be obtained from the [`Secrets`] returned in [`KeyChange::OneRtt`]. Note that
/// only packet keys are updated by key updates; header protection keys remain the same.

/// 所以，先从Keys::initial()获得initial_keys，这是在endpoint层，都可以默认存在的
/// 收到init数据包，用initial_keys去除包头保护，解密包体，写给initial空间，然后从initial空间的crypto流中读出数据，写入
/// 调用write_hs()，获得handshake keys,

/// 收到handshake数据包，用handshake keys去除包头保护，解密包体，写给handshake空间，然后从handshake空间的额crypto流中读出数据，写入
/// 调用write_hs()，获得1-rtt keys，
/// 从ConnectionCommon::zero_rtt_keys()获取zero_rtt_keys,
pub struct Connection {
    initial_space: InitailSpace,
    handshake_space: HandshakeSpace,
    data_space: DataSpace,
}

impl Connection {
    pub fn receive_initial_packet(&mut self, header: InitialHeader, packet: BytesMut) {
        // todo
    }

    pub fn receive_handshake_packet(&mut self, header: HandshakeHeader, packet: BytesMut) {
        // todo
    }

    pub fn receive_zero_rtt_packet(&mut self, header: ZeroRTTHeader, packet: BytesMut) {
        // todo
    }

    pub fn receive_one_rtt_packet(&mut self, header: OneRttHeader, packet: BytesMut) {
        // todo
    }
}
