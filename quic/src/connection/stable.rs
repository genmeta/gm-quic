use crate::{crypto::TlsIO, rx_queue::RxQueue, ReceiveProtectedPacket};
use qbase::packet::{KeyPhaseToggle, ProtectedOneRttPacket, ProtectedPacket, SpinToggle};
use qrecovery::{
    rtt::Rtt,
    space::{OneRttDataSpace, ReceiveHalf, ReceivePacket, TransmitHalf},
};
use rustls::quic::Secrets;

/// 稳定期的连接，只包含1RTT空间，只处理1RTT数据包
pub struct StableConnection {
    tls_session: TlsIO,
    tx: TransmitHalf<OneRttDataSpace>,
    rx_queue: RxQueue<ProtectedOneRttPacket>,

    spin: SpinToggle,
    key_phase: KeyPhaseToggle,
    secrets: Secrets,
    // 暂时性的，rtt应该跟path相关
    rtt: Rtt,
}

impl ReceiveProtectedPacket for StableConnection {
    fn receive_protected_packet(&mut self, protected_packet: ProtectedPacket) {
        match protected_packet {
            ProtectedPacket::OneRtt(packet) => {
                self.rx_queue.push(packet);
            }
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
