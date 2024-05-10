use super::crypto::TlsSession;
use bytes::BytesMut;
use qbase::{
    error::Error,
    frame::ConnectionFrame,
    packet::{
        ext::decrypt_packet, KeyPhaseToggle, ProtectedInitialHeader, ProtectedOneRttHeader,
        ProtectedZeroRTTHeader, SpinToggle,
    },
};
use qrecovery::{
    rtt::Rtt,
    space::{DataSpace, HandshakeSpace, InitialSpace, Receive},
};
use rustls::quic::Keys;

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
    tls_session: TlsSession,
    initial_keys: Keys,
    handshake_keys: Keys,
    zero_rtt_keys: Keys,
    one_rtt_keys: Keys,

    initial_space: InitialSpace,
    handshake_space: HandshakeSpace,
    data_space: DataSpace,

    // 暂时性的，rtt应该跟path相关
    rtt: Rtt,

    spin: SpinToggle,
    key_phase: KeyPhaseToggle,
}

impl Connection {
    pub fn receive_initial_packet(
        &mut self,
        header: ProtectedInitialHeader,
        packet: BytesMut,
        pn_offset: usize,
    ) -> Result<(), Error> {
        let (pn, body) = decrypt_packet(header, packet, pn_offset, 0, &self.initial_keys.remote)?;
        for frame in self.initial_space.receive(pn, body, &mut self.rtt)? {
            match frame {
                ConnectionFrame::Close(frame) => {
                    if frame.frame_type.is_some() {
                        return Err(Error::new(
                            qbase::error::ErrorKind::ProtocolViolation,
                            frame.frame_type.unwrap(),
                            "The initial space does not allow the application layer to close the connection."
                        ));
                    }
                    todo!("close connection")
                }
                _ => unreachable!("no signaling frame in initial space"),
            }
        }
        Ok(())
    }

    pub fn receive_handshake_packet(
        &mut self,
        header: ProtectedInitialHeader,
        packet: BytesMut,
        pn_offset: usize,
    ) -> Result<(), Error> {
        let (pn, body) = decrypt_packet(header, packet, pn_offset, 0, &self.handshake_keys.remote)?;
        for frame in self.initial_space.receive(pn, body, &mut self.rtt)? {
            match frame {
                ConnectionFrame::Close(frame) => {
                    if frame.frame_type.is_some() {
                        return Err(Error::new(
                            qbase::error::ErrorKind::ProtocolViolation,
                            frame.frame_type.unwrap(),
                            "The handshake space does not allow the application layer to close the connection."
                        ));
                    }
                    todo!("close connection")
                }
                _ => unreachable!("no signaling frame in initial space"),
            }
        }
        Ok(())
    }

    pub fn receive_zero_rtt_packet(&mut self, header: ProtectedZeroRTTHeader, packet: BytesMut) {
        // todo
    }

    pub fn receive_one_rtt_packet(&mut self, header: ProtectedOneRttHeader, packet: BytesMut) {
        // todo
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4)
    }
}
