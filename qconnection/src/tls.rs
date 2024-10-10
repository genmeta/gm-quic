use std::{
    ops::DerefMut,
    sync::{Arc, Mutex},
};

use qbase::{
    cid::ConnectionId,
    config::{
        ext::{be_parameters, WriteParameters},
        Parameters,
    },
    error::{Error, ErrorKind},
    packet::keys::{ArcKeys, ArcOneRttKeys},
    streamid::Role,
};
use qrecovery::{crypto::CryptoStream, space::Epoch};
use rustls::{crypto::CryptoProvider, quic::Keys, Side};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Notify,
};

use crate::{
    connection::{parameters::RemoteParameters, Handshake},
    error::ConnError,
};

#[derive(Debug, Error, Clone, Copy)]
#[error("TLS session is aborted")]
pub struct Aborted;

type TlsConnection = rustls::quic::Connection;

#[derive(Debug, Clone)]
pub struct ArcTlsSession(Arc<Mutex<Result<TlsConnection, Aborted>>>);

impl ArcTlsSession {
    const QUIC_VERSION: rustls::quic::Version = rustls::quic::Version::V1;

    pub fn new_client(
        server_name: rustls::pki_types::ServerName<'static>,
        tls_config: Arc<rustls::ClientConfig>,
        parameters: &Parameters,
    ) -> Self {
        let mut params_bytes = Vec::new();
        params_bytes.put_parameters(parameters);

        let client_connection = rustls::quic::ClientConnection::new(
            tls_config,
            Self::QUIC_VERSION,
            server_name,
            params_bytes,
        );
        let connection = rustls::quic::Connection::Client(client_connection.unwrap());
        Self(Arc::new(Mutex::new(Ok(connection))))
    }

    pub fn new_server(tls_config: Arc<rustls::ServerConfig>, parameters: &Parameters) -> Self {
        let mut params = Vec::new();
        params.put_parameters(parameters);

        let server_connection =
            rustls::quic::ServerConnection::new(tls_config, Self::QUIC_VERSION, params).unwrap();
        let connection = rustls::quic::Connection::Server(server_connection);
        Self(Arc::new(Mutex::new(Ok(connection))))
    }

    pub fn initial_keys(crypto_provider: &CryptoProvider, side: Side, cid: ConnectionId) -> Keys {
        let suite = crypto_provider
            .cipher_suites
            .iter()
            .find_map(|cs| match (cs.suite(), cs.tls13()) {
                (rustls::CipherSuite::TLS13_AES_128_GCM_SHA256, Some(suite)) => {
                    Some(suite.quic_suite())
                }
                _ => None,
            })
            .flatten()
            .unwrap();
        suite.keys(&cid, side, rustls::quic::Version::V1)
    }

    pub fn abort(&self) {
        *self.0.lock().unwrap() = Err(Aborted);
    }

    /// 自托管密钥升级
    pub fn keys_upgrade(
        &self,
        crypto_streams: [&CryptoStream; 3],
        handshake_keys: ArcKeys,
        one_rtt_keys: ArcOneRttKeys,
        conn_error: ConnError,
        handshake: Handshake,
    ) -> RemoteParameters {
        let remote_params = RemoteParameters::new();
        let tls_wants_read = Arc::new(Notify::new());
        tls_wants_read.notify_one();

        let for_each_epoch = |epoch: Epoch| {
            let mut crypto_stream_reader = crypto_streams[epoch].reader();
            let tls_session = self.clone();
            let conn_error = conn_error.clone();
            let tls_wants_read = tls_wants_read.clone();

            tokio::spawn(async move {
                let mut read_buf = [0u8; 1500];
                while let Ok(read) = crypto_stream_reader.read(&mut read_buf[..]).await {
                    let mut guard = tls_session.0.lock().unwrap();
                    let tls_connection = match guard.deref_mut() {
                        Ok(tls_session) => tls_session,
                        Err(_aborted) => break,
                    };

                    log::trace!("read {read} bytes from crypto stream (epoch {epoch:?})");
                    if let Err(e) = tls_connection.read_hs(&read_buf[..read]) {
                        let error_kind = match tls_connection.alert() {
                            Some(alert) => ErrorKind::Crypto(alert.into()),
                            None => ErrorKind::ProtocolViolation,
                        };
                        let reason = format!("TLS error: {e}");
                        conn_error.on_error(Error::with_default_fty(error_kind, reason));
                        break;
                    }

                    tls_wants_read.notify_one();
                }
            })
        };

        tokio::spawn({
            let tls_session = self.clone();
            let remote_params = remote_params.clone();

            let mut crypto_stream_writers =
                Epoch::EPOCHS.map(|epoch| crypto_streams[epoch].writer());
            let crypto_stream_readers = Epoch::EPOCHS.map(for_each_epoch);

            async move {
                let mut write_buf = Vec::with_capacity(1500);
                let mut cur_epoch = Epoch::Initial;
                loop {
                    tls_wants_read.notified().await;

                    let (transport_parameters, key_upgrade, is_handshaking) = {
                        let mut guard = tls_session.0.lock().unwrap();
                        let tls_connection = match guard.deref_mut() {
                            Ok(tls_session) => tls_session,
                            Err(_aborted) => break,
                        };
                        let transport_parameters = get_transport_parameters(tls_connection);
                        write_buf.clear();
                        let key_upgrade = tls_connection.write_hs(&mut write_buf);
                        let is_handshaking = tls_connection.is_handshaking();
                        (transport_parameters, key_upgrade, is_handshaking)
                    };

                    if let Some(params) = transport_parameters {
                        match params {
                            Ok(params) => remote_params.write(params.into()),
                            // when the transport parameters are invalid, the connection has closed.
                            // Err(error) => conn_error.on_error(error),
                            Err(_conn_error) => break,
                        }
                    }

                    if !write_buf.is_empty() {
                        log::trace!(
                            "write {} bytes to tls connection (epoch {cur_epoch:?})",
                            write_buf.len(),
                        );
                        if let Err(e) = crypto_stream_writers[cur_epoch].write(&write_buf).await {
                            let error = Error::with_default_fty(ErrorKind::Internal, e.to_string());
                            conn_error.on_error(error);
                            break;
                        }
                    }

                    if let Some(key_change) = key_upgrade {
                        match key_change {
                            rustls::quic::KeyChange::Handshake { keys } => {
                                log::trace!("handshake keys updated");
                                handshake_keys.set_keys(keys);
                                cur_epoch = Epoch::Handshake;
                            }
                            rustls::quic::KeyChange::OneRtt { keys, next } => {
                                log::trace!("1-RTT keys updated");
                                one_rtt_keys.set_keys(keys, next);
                                cur_epoch = Epoch::Data;
                            }
                        }
                        tls_wants_read.notify_one();
                    }

                    if !is_handshaking && handshake.role() == Role::Server {
                        handshake.done();
                    }
                }

                for reader in crypto_stream_readers {
                    reader.abort();
                }
            }
        });

        remote_params
    }

    pub fn server_name(&self) -> Option<String> {
        match self.0.lock().unwrap().as_ref() {
            Ok(TlsConnection::Server(server_conn)) => server_conn.server_name().map(Into::into),
            Ok(TlsConnection::Client(_)) | Err(_) => None,
        }
    }
}

fn get_transport_parameters(tls_conn: &TlsConnection) -> Option<Result<Parameters, Error>> {
    let raw = tls_conn.quic_transport_parameters()?;
    let params = match be_parameters(raw) {
        Ok((_, params)) => params,
        Err(e) => {
            return Some(Err(Error::with_default_fty(
                ErrorKind::Internal,
                e.to_string(),
            )))
        }
    };
    if let Err(reason) = params.validate() {
        return Some(Err(Error::with_default_fty(
            ErrorKind::TransportParameter,
            reason,
        )));
    }
    Some(Ok(params))
}
