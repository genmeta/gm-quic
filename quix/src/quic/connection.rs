use std::{
    ops::{Index, IndexMut},
    slice::SliceIndex,
};

use bytes::Bytes;
use qbase::config::TransportParameters;
use rustls::Side;

use super::{
    crypto::Keys,
    crypto::{tls_session::TlsSession, KeyPair, PacketKey, ZeroRttCrypto},
    error::TransportError,
    frames,
    packet::SpaceId,
};

pub(crate) struct Connection {
    tls: Box<TlsSession>,
    space_crypto: [Option<Keys>; 3],
    zero_rtt_crypto: Option<ZeroRttCrypto>,
    next_crypto: Option<KeyPair<Box<dyn PacketKey>>>,
    highest_space: SpaceId,
    side: Side,
    handshake_done: bool,
}

impl Connection {
    // 客户端主动发起tls握手
    fn tls_handshake(&mut self) {
        // todo: offset 应该是Space 维护
        let offset = 0;
        loop {
            let space = self.highest_space;
            let mut outgoing = Vec::new();
            if let Some(crypto) = self.tls.write_handshake(&mut outgoing) {
                match space {
                    SpaceId::Initial => {
                        self.upgrade_crypto(SpaceId::Handshake, crypto);
                    }
                    SpaceId::Handshake => {
                        self.upgrade_crypto(SpaceId::Data, crypto);
                    }
                    _ => unreachable!("got updated secrets during 1-RTT"),
                }
            }
            if outgoing.is_empty() {
                if space == self.highest_space {
                    break;
                } else {
                    // Keys updated, check for more data to send
                    continue;
                }
            }
            let outgoing = Bytes::from(outgoing);
            let frame = frames::Crypto {
                offset,
                data: outgoing,
            };
            // 把帧交给 Space 发送
        }
    }

    fn init_0rtt(&mut self) {
        let client_tls = match self.tls.as_mut() {
            TlsSession::Client(ref mut x) => x,
            _ => return,
        };

        let (header, packet) = match client_tls.early_crypto() {
            Some(x) => x,
            None => return,
        };
        if self.side == Side::Client {
            match client_tls.transport_parameters() {
                Ok(params) => {
                    let params = params
                        .expect("crypto layer didn't supply transport parameters with ticket");
                    todo!("set params")
                }
                Err(e) => {
                    return;
                }
            }
        }
        self.zero_rtt_crypto = Some(ZeroRttCrypto { header, packet });
    }

    // 更新密钥
    fn upgrade_crypto(&mut self, space: SpaceId, crypto: Keys) {
        debug_assert!(
            self.space_crypto[space as usize].is_none(),
            "already reached packet space {space:?}"
        );
        if space == SpaceId::Data {
            self.next_crypto = Some(
                self.tls
                    .next_1rtt_keys()
                    .expect("handshake should be complete"),
            );
        }

        self.space_crypto[space as usize] = Some(crypto);
        debug_assert!(space as usize > self.highest_space as usize);
        self.highest_space = space;
        if space == SpaceId::Data && self.side == Side::Client {
            // 一旦客户端启用了1-RTT密钥，它必须不能（MUST NOT）再发送0-RTT包。
            self.zero_rtt_crypto = None;
        }
    }

    fn read_crypto(
        &mut self,
        space: SpaceId,
        crypto: &frames::Crypto,
        payload_len: usize,
    ) -> Result<(), TransportError> {
        let expected = if self.handshake_done {
            SpaceId::Data
        } else if self.highest_space == SpaceId::Initial {
            SpaceId::Initial
        } else {
            // server 收到 client 的第一个包后，最高密级为 Data
            // 但在 Handshake done 之前仍然期望收到 Handshake 空间的 CRYPTO帧
            SpaceId::Handshake
        };

        debug_assert!(space <= expected, "received out-of-order CRYPTO data");

        if self.tls.read_handshake(&crypto.data[..payload_len])? {
            self.handshake_done = true;
        }
        Ok(())
    }
}
