use crate::{crypto::TlsIO, ReceiveProtectedPacket};
use qbase::packet::{KeyPhaseBit, OneRttPacket, SpacePacket, SpinBit};
use qrecovery::{
    rtt::Rtt,
    space::{OneRttDataSpace, TransmitHalf},
};
use rustls::quic::Secrets;

/// 稳定期的连接，只包含1RTT空间，只处理1RTT数据包
pub struct StableConnection {
    tls_session: TlsIO,
    tx: TransmitHalf<OneRttDataSpace>,

    spin: SpinBit,
    key_phase: KeyPhaseBit,
    secrets: Secrets,
    // 暂时性的，rtt应该跟path相关
    rtt: Rtt,
}

impl ReceiveProtectedPacket for StableConnection {
    fn receive_protected_packet(&mut self, protected_packet: SpacePacket) {
        match protected_packet {
            SpacePacket::OneRtt(packet) => {}
            _other => {
                // just ignore
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
