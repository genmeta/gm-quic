use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
};

use qbase::config::TransportParameters;
use rustls::Side;
use tokio::io::{AsyncRead, AsyncWrite};

use super::{
    cid::ConnectionId,
    crypto::{tls_session::server_config, Keys},
    crypto::{
        tls_session::{client_config, TlsSession},
        KeyPair, PacketKey, ZeroRttCrypto,
    },
    error::Error,
    packet::SpaceId,
};

pub(crate) struct Crypto {
    tls: Box<TlsSession>,
    read_waker: Option<Waker>,
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
        let client_config = Arc::new(client_config(roots));
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
            read_waker: None,
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
            read_waker: None,
        })
    }

    fn poll_handshake_data(&mut self) -> Poll<HandshakeData> {
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
                    let name = server_name.map(|name| name.to_string());

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
}

impl AsyncRead for Crypto {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        assert!(self.read_waker.is_none());

        let tls = self.tls.as_mut();
        let outgoing = &mut Vec::new();
        if let Some(keys) = tls.get_crypto(outgoing) {
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
            self.read_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        buf.put_slice(outgoing);
        if let Some(waker) = self.read_waker.take() {
            waker.wake();
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Crypto {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.tls.as_mut().write_crypto(buf) {
            Ok(_) => Poll::Ready(Ok(buf.len())),
            Err(e) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    /// 不会真正关闭 tls，生成 close_notify warning alert,
    /// 需要调用 poll_read 读出来通过 crypto 流发送出去  
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.tls.as_mut().shutdown() {
            Ok(_) => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))),
        }
    }
}
