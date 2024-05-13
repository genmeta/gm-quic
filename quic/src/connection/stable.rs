use crate::{crypto::TlsIO, ReceiveProtectedPacket};
use qbase::packet::{KeyPhaseToggle, ProtectedPacket, SpinToggle};
use qrecovery::{
    rtt::Rtt,
    space::{OneRttDataSpace, ReceiveHalf, ReceivePacket, TransmitHalf},
};
use rustls::quic::Secrets;

/// 稳定期的连接，只包含1RTT空间，只处理1RTT数据包
pub struct StableConnection {
    tls_session: TlsIO,
    tx: TransmitHalf<OneRttDataSpace>,
    rx: ReceiveHalf<OneRttDataSpace>,

    spin: SpinToggle,
    key_phase: KeyPhaseToggle,
    secrets: Secrets,
    // 暂时性的，rtt应该跟path相关
    rtt: Rtt,
}

impl ReceiveProtectedPacket for StableConnection {
    /// 再收到1RTT数据包，直接让ReceiveHalf处理
    fn receive_protected_packet(&mut self, protected_packet: ProtectedPacket) {
        match protected_packet {
            ProtectedPacket::OneRtt(packet) => {
                // todo: 需要处理ConnectionFrame以及错误
                let _ = self.rx.receive_packet(packet, &mut self.rtt);
            }
            _other => {
                // just ignore
            }
        }
    }
}
