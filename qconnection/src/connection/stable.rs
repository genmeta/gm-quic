use crate::crypto::TlsIO;
use qbase::packet::{KeyPhaseBit, SpinBit};
use qrecovery::{rtt::Rtt, space::OneRttDataSpace};
use rustls::quic::Secrets;

/// 稳定期的连接，只包含1RTT空间，只处理1RTT数据包
pub struct StableConnection {
    tls_session: TlsIO,
    // tx: TransmitHalf<OneRttDataSpace>,
    spin: SpinBit,
    key_phase: KeyPhaseBit,
    secrets: Secrets,
    // 暂时性的，rtt应该跟path相关
    rtt: Rtt,
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
