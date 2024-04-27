use std::{io, sync::Arc};

use qbase::config::{self, TransportParameters};
use ring::aead;
use rustls::{
    client::InvalidDnsNameError,
    quic::{Connection, KeyChange, Secrets, Version},
    ClientConfig, ServerConfig, Side,
};

use crate::quic::error::{Error, TransportError, TransportErrorCode};
use crate::quic::{cid::ConnectionId, error::Error::UnsupportedVersion};

use super::{HeaderKey, KeyPair, Keys, PacketKey};
use crate::quic::error::Error::InvalidDnsName;

pub enum TlsSession {
    Client(ClientSession),
    Server(ServerSession),
}

pub struct ClientSession {
    version: Version,
    next_secrets: Option<Secrets>,
    inner: Connection,
}

pub struct ServerSession {
    version: Version,
    inner: Connection,
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

    pub fn is_handshaking(&self) -> bool {
        match self {
            TlsSession::Client(s) => s.inner.is_handshaking(),
            TlsSession::Server(s) => s.inner.is_handshaking(),
        }
    }

    // 读取 crypto 握手数据，第一次握手完成后返回 true
    pub fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
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

        let have_server_name = match inner {
            Connection::Client(_) => false,
            Connection::Server(ref session) => session.server_name().is_some(),
        };
        if inner.alpn_protocol().is_some() || have_server_name || !self.is_handshaking() {
            return Ok(true);
        }
        Ok(false)
    }

    pub fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
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
