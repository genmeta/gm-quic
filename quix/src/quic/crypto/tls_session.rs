use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use qbase::{
    cid::ConnectionId,
    config::{self, TransportParameters},
};
use ring::aead;
use rustls::{
    client::InvalidDnsNameError,
    quic::{Connection, KeyChange, Secrets, Version},
    ClientConfig, ServerConfig, Side,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::quic::error::Error::UnsupportedVersion;
use crate::quic::error::{Error, TransportError, TransportErrorCode};

use super::{HeaderKey, KeyPair, Keys, PacketKey};
use crate::quic::error::Error::InvalidDnsName;

/// 当从收到 crypto 数据时
/// 1. 如果是当前 tls 密级，将数据排序到输入流中，如果有新的数据可用，按照顺序传递给 tls
/// 2. 如果来自之前的密级，则该数据包不得包含超出该流中先前接收的数据末尾的数据，否则产生一个 PROTOCOL_VIOLATION类型的连接错误
/// 3. 如果数据包来自一个新的加密级别，那么它将被TLS保存以备以后处理。 一旦TLS转向接收来自这个加密级别的数据，就可以将保存的数据提供给TLS。
///    当TLS为更高的加密级别提供密钥时，如果有前一个加密级别的数据没有被TLS消耗掉，这必须作为PROTOCOL_VIOLATION类型的连接错误处理。
pub enum TlsSession {
    Client(ClientSession),
    Server(ServerSession),
}

pub struct ClientSession {
    version: Version,
    next_secrets: Option<Secrets>,
    pub inner: Connection,
}

pub struct ServerSession {
    version: Version,
    pub inner: Connection,
    protocol: Option<Vec<u8>>,
    next_secrets: Option<Secrets>,
    name: Option<String>,
}

impl TlsSession {
    pub fn start_client_session(
        config: Arc<ClientConfig>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<TlsSession, Error> {
        let version = interpret_version(version)?;
        Ok(TlsSession::Client(ClientSession {
            version,
            next_secrets: None,
            inner: rustls::quic::Connection::Client(
                rustls::quic::ClientConnection::new(
                    config,
                    version,
                    server_name.try_into().map_err(|_| InvalidDnsName)?,
                    params.to_vec(),
                )
                .unwrap(),
            ),
        }))
    }

    pub fn start_server_session(
        config: Arc<ServerConfig>,
        version: u32,
        params: &TransportParameters,
    ) -> Result<TlsSession, Error> {
        let version = interpret_version(version)?;
        Ok(TlsSession::Server(ServerSession {
            version,
            inner: rustls::quic::Connection::Server(
                rustls::quic::ServerConnection::new(config, version, params.to_vec()).unwrap(),
            ),
            next_secrets: None,
            protocol: None,
            name: None,
        }))
    }

    /// 生成 inital keys
    /// initial_secret = HKDF-Extract(initial_salt,client_dst_connection_id)
    /// client_initial_secret = HKDF-Expand-Label(initial_secret,"client in", "",Hash.length)
    /// server_initial_secret = HKDF-Expand-Label(initial_secret,"server in", "",Hash.length)
    pub fn initial_keys(
        version: u32,
        dst_cid: &ConnectionId,
        side: Side,
    ) -> Result<Keys, crate::quic::error::Error> {
        let version = interpret_version(version)?;
        let keys = rustls::quic::Keys::initial(version, dst_cid, side.into());
        Ok(Keys {
            header: KeyPair {
                local: Box::new(keys.local.header),
                remote: Box::new(keys.remote.header),
            },
            packet: KeyPair {
                local: Box::new(keys.local.packet),
                remote: Box::new(keys.remote.packet),
            },
        })
    }

    /// 在TLS协议栈报告握手完成时，才认为TLS握手完成。
    /// 当TLS协议栈发送了Finished消息，并校验了对端的Finished消息，TLS协议栈才会报告握手完成。
    pub fn is_handshaking(&self) -> bool {
        match self {
            TlsSession::Client(s) => s.inner.is_handshaking(),
            TlsSession::Server(s) => s.inner.is_handshaking(),
        }
    }

    /// 每次TLS被提供新的数据时，都会向TLS请求新的握手字节。 即每次调用 read_shandshke 后，都要调用一下 write_handshake
    /// 如果收到的握手信息不完整或者没有数据要发送，TLS可能不会提供任何字节。
    /// 握手完成后，QUIC只需要向TLS提供CRYPTO流中到达的任何数据。与握手过程中使用的方式相同，在提供收到的数据后，会向TLS请求新的数据。
    pub fn write_crypto(&mut self, buf: &[u8]) -> Result<(), TransportError> {
        let inner = match self {
            TlsSession::Client(s) => &mut s.inner,
            TlsSession::Server(s) => &mut s.inner,
        };
        inner.read_hs(buf).map_err(|e| {
            if let Some(alert) = inner.alert() {
                TransportError {
                    code: TransportErrorCode::crypto(alert.get_u8()),
                    frame: None,
                    reason: e.to_string(),
                }
            } else {
                TransportError::PROTOCOL_VIOLATION(format!("TLS error: {e}"))
            }
        })?;
        Ok(())
    }

    /// TLS产生的每个数据块都与TLS当前使用的密钥集相关联。
    /// 如果QUIC需要重新传输该数据，即使TLS已经更新到更新的密钥，它也必须使用相同的密钥。
    pub fn get_crypto(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        let inner = match self {
            TlsSession::Client(s) => &mut s.inner,
            TlsSession::Server(s) => &mut s.inner,
        };

        let keys = match inner.write_hs(buf)? {
            KeyChange::Handshake { keys } => keys,
            KeyChange::OneRtt { keys, next } => {
                match self {
                    TlsSession::Client(s) => s.next_secrets = Some(next),
                    TlsSession::Server(s) => s.next_secrets = Some(next),
                }
                keys
            }
        };

        Some(Keys {
            header: KeyPair {
                local: Box::new(keys.local.header),
                remote: Box::new(keys.remote.header),
            },
            packet: KeyPair {
                local: Box::new(keys.local.packet),
                remote: Box::new(keys.remote.packet),
            },
        })
    }

    pub fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        let mut secrets = match self {
            TlsSession::Client(s) => s.next_secrets.take()?,
            TlsSession::Server(s) => s.next_secrets.take()?,
        };

        let keys = secrets.next_packet_keys();
        Some(KeyPair {
            local: Box::new(keys.local),
            remote: Box::new(keys.remote),
        })
    }

    /// Queues a close_notify warning alert to be sent in the next
    /// [`Connection::write_tls`] call.  This informs the peer that the
    /// connection is being closed.
    pub fn shutdown(&mut self) -> Result<(), TransportError> {
        let inner = match self {
            TlsSession::Client(s) => &mut s.inner,
            TlsSession::Server(s) => &mut s.inner,
        };
        inner.send_close_notify();
        Ok(())
    }
}

impl ClientSession {
    // 获取 0-RTT 密钥
    pub fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        let keys = self.inner.zero_rtt_keys()?;
        Some((Box::new(keys.header), Box::new(keys.packet)))
    }

    pub fn early_data_accepted(&self) -> Option<bool> {
        match self.inner {
            Connection::Client(ref session) => Some(session.is_early_data_accepted()),
            _ => None,
        }
    }

    pub fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        match self.inner.quic_transport_parameters() {
            None => Ok(None),
            Some(buf) => match TransportParameters::read(&mut io::Cursor::new(buf)) {
                Ok(params) => Ok(Some(params)),
                Err(e) => Err(TransportError::PROTOCOL_VIOLATION(format!(
                    "failed to parse transport parameters: {e}"
                ))),
            },
        }
    }
}

impl ServerSession {
    fn retry_tag(&self, version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        let version = interpret_version(version).unwrap();
        let (nonce, key) = match version {
            Version::V1 => (RETRY_INTEGRITY_NONCE_V1, RETRY_INTEGRITY_KEY_V1),
            Version::V1Draft => (RETRY_INTEGRITY_NONCE_DRAFT, RETRY_INTEGRITY_KEY_DRAFT),
            _ => unreachable!(),
        };

        let mut pseudo_packet = Vec::with_capacity(packet.len() + orig_dst_cid.len() + 1);
        pseudo_packet.push(orig_dst_cid.len() as u8);
        pseudo_packet.extend_from_slice(orig_dst_cid);
        pseudo_packet.extend_from_slice(packet);

        let nonce = aead::Nonce::assume_unique_for_key(nonce);
        let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &key).unwrap());

        let tag = key
            .seal_in_place_separate_tag(nonce, aead::Aad::from(pseudo_packet), &mut [])
            .unwrap();
        let mut result = [0; 16];
        result.copy_from_slice(tag.as_ref());
        result
    }

    fn protocol(&self) -> Option<&[u8]> {
        self.protocol.as_ref().map(Vec::as_slice)
    }

    fn name(&self) -> Option<&str> {
        self.name.as_ref().map(String::as_str)
    }
}

fn interpret_version(version: u32) -> Result<Version, crate::quic::error::Error> {
    match version {
        0xff00_001d..=0xff00_0020 => Ok(Version::V1Draft),
        0x0000_0001 | 0xff00_0021..=0xff00_0022 => Ok(Version::V1),
        _ => Err(UnsupportedVersion),
    }
}

const RETRY_INTEGRITY_KEY_DRAFT: [u8; 16] = [
    0xcc, 0xce, 0x18, 0x7e, 0xd0, 0x9a, 0x09, 0xd0, 0x57, 0x28, 0x15, 0x5a, 0x6c, 0xb9, 0x6b, 0xe1,
];
const RETRY_INTEGRITY_NONCE_DRAFT: [u8; 12] = [
    0xe5, 0x49, 0x30, 0xf9, 0x7f, 0x21, 0x36, 0xf0, 0x53, 0x0a, 0x8c, 0x1c,
];

const RETRY_INTEGRITY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
const RETRY_INTEGRITY_NONCE_V1: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

/// Initialize a sane QUIC-compatible TLS client configuration
///
/// QUIC requires that TLS 1.3 be enabled. Advanced users can use any [`rustls::ClientConfig`] that
/// satisfies this requirement.
pub(crate) fn client_config(roots: rustls::RootCertStore) -> rustls::ClientConfig {
    let mut cfg = rustls::ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.enable_early_data = true;
    cfg
}

/// Initialize a sane QUIC-compatible TLS server configuration
///
/// QUIC requires that TLS 1.3 be enabled, and that the maximum early data size is either 0 or
/// `u32::MAX`. Advanced users can use any [`rustls::ServerConfig`] that satisfies these
/// requirements.
pub(crate) fn server_config(
    cert_chain: Vec<rustls::Certificate>,
    key: rustls::PrivateKey,
) -> Result<rustls::ServerConfig, rustls::Error> {
    let mut cfg = rustls::ServerConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;
    cfg.max_early_data_size = u32::MAX;
    Ok(cfg)
}
