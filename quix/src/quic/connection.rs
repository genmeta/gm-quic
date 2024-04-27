use std::{
    future::Future,
    ops::{Index, IndexMut},
    pin::Pin,
    slice::SliceIndex,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use bytes::Bytes;
use libc::BUFSIZ;
use qbase::config::TransportParameters;
use rustls::{internal::msgs::handshake, Connection, Side};

use super::{
    cid::ConnectionId,
    crypto::{tls_session::server_config, Keys},
    crypto::{
        tls_session::{client_config, TlsSession},
        KeyPair, PacketKey, ZeroRttCrypto,
    },
    error::{Error, TransportError},
    frames,
    packet::SpaceId,
};

pub(crate) struct Crypto {
    tls: Box<TlsSession>,
    space_crypto: [Option<Keys>; 3],
    zero_rtt_crypto: Option<ZeroRttCrypto>,
    next_crypto: Option<KeyPair<Box<dyn PacketKey>>>,
    highest_space: SpaceId,
    side: Side,
    handshake_done: bool,
    start_hanshake: bool,
}

struct HandshakeData {
    pub protocol: Option<Vec<u8>>,
    pub server_name: Option<String>,
}

impl Crypto {
    fn new_client(
        roots: rustls::RootCertStore,
        version: u32,
        server_name: &str,
        init_cid: &ConnectionId,
    ) -> Result<Self, Error> {
        let mut client_config = Arc::new(client_config(roots));
        let tls = TlsSession::start_client_session(
            client_config,
            version,
            server_name,
            &TransportParameters::default(),
        )?;

        let init_key = TlsSession::initial_keys(version, init_cid, Side::Client)?;
        let tls = Box::new(tls);
        Ok(Self {
            tls,
            space_crypto: [Some(init_key), None, None],
            zero_rtt_crypto: None,
            next_crypto: None,
            highest_space: SpaceId::Initial,
            side: Side::Client,
            handshake_done: false,
            start_hanshake: false,
        })
    }

    fn new_server(
        version: u32,
        cert_chain: Vec<rustls::Certificate>,
        key: rustls::PrivateKey,
    ) -> Result<Self, Error> {
        let server_config =
            server_config(cert_chain, key).map_err(|_| Error::InvaildServerConfig)?;
        let server_config = Arc::new(server_config);

        let tls = TlsSession::start_server_session(
            server_config,
            version,
            &TransportParameters::default(),
        )?;
        let tls = Box::new(tls);
        Ok(Self {
            tls,
            space_crypto: [None, None, None],
            zero_rtt_crypto: None,
            next_crypto: None,
            highest_space: SpaceId::Initial,
            side: Side::Server,
            handshake_done: false,
            start_hanshake: false,
        })
    }

    fn handshake_data(&mut self) -> Poll<HandshakeData> {
        match self.tls.is_handshaking() {
            true => Poll::Pending,
            false => {
                let inner = match &self.tls.as_ref() {
                    TlsSession::Client(ref x) => &x.inner,
                    TlsSession::Server(ref x) => &x.inner,
                };
                let server_name = match inner {
                    rustls::quic::Connection::Client(_) => None,
                    rustls::quic::Connection::Server(ref session) => session.server_name(),
                };
                if inner.alpn_protocol().is_some() {
                    let name = if let Some(name) = server_name {
                        Some(name.to_string())
                    } else {
                        None
                    };

                    Poll::Ready(HandshakeData {
                        protocol: inner.alpn_protocol().map(|x| x.to_vec()),
                        server_name: name,
                    })
                } else {
                    Poll::Pending
                }
            }
        }
    }

    async fn get_tls_data(&mut self) -> Poll<(Vec<u8>, Option<Keys>)> {
        let mut outgoing = &mut Vec::new();
        if let Some(keys) = self.tls.get_crypto(&mut outgoing) {
            match self.highest_space {
                SpaceId::Initial => {
                    self.upgrade_crypto(SpaceId::Handshake, keys);
                }
                SpaceId::Handshake => {
                    self.upgrade_crypto(SpaceId::Data, keys);
                }
                _ => unreachable!("got updated secrets during 1-RTT"),
            }
        }

        if outgoing.is_empty() {
            return Poll::Pending;
        }
        return Poll::Ready((outgoing.to_vec(), None));
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

    /// 服务端向TLS提供客户端的握手字节来启动tls握手
    /// 每次调用 write_tls_data 之后都要调用 get_tls_data
    fn write_tls_data(&mut self, space: SpaceId, buf: &[u8]) -> Result<(), TransportError> {
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

        // 把数据写给 tls
        self.tls.write_crypto(buf)?;
        Ok(())
    }
}
