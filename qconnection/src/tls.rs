use core::{
    ops::DerefMut,
    task::{Context, Poll, Waker},
};
use std::sync::{Arc, Mutex};

use qbase::{
    cid::ConnectionId,
    error::{Error, ErrorKind},
    packet::keys::{ArcKeys, ArcOneRttKeys},
    param::{
        codec::{be_parameters, WriteParameters},
        Parameters,
    },
};
use qrecovery::{crypto::CryptoStream, journal::Epoch};
use rustls::{
    crypto::CryptoProvider,
    quic::{KeyChange, Keys},
    Side,
};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    conn::{parameters::RemoteParameters, Handshake},
    error::ConnError,
};

#[derive(Debug, Error, Clone, Copy)]
#[error("TLS session is aborted")]
pub struct Aborted;

type TlsConnection = rustls::quic::Connection;

#[derive(Debug)]
struct TlsSession {
    tls_conn: TlsConnection,
    read_waker: Option<Waker>,
    /// Optimize: avoid reading transport parameters repeatedly, because the rustls willnot consume
    /// the bytes of transport parameters after reading them.
    params_read: bool,
}

impl From<TlsConnection> for TlsSession {
    fn from(tls_conn: TlsConnection) -> Self {
        Self {
            tls_conn,
            read_waker: None,
            params_read: false,
        }
    }
}

impl TlsSession {
    fn wake_read(&mut self) {
        if let Some(waker) = self.read_waker.as_ref() {
            waker.wake_by_ref();
        }
    }

    fn write(&mut self, buf: &[u8]) -> Result<(), rustls::Error> {
        self.tls_conn.read_hs(buf)
    }

    fn read(&mut self, buf: &mut Vec<u8>) -> Option<KeyChange> {
        self.tls_conn.write_hs(buf)
    }

    fn get_transport_parameters(&mut self) -> Option<Result<Parameters, Error>> {
        if self.params_read {
            return None;
        }
        let raw = self.tls_conn.quic_transport_parameters()?;
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
        self.params_read = true;
        Some(Ok(params))
    }

    fn alert(&self) -> Option<rustls::AlertDescription> {
        self.tls_conn.alert()
    }

    fn is_handshaking(&self) -> bool {
        self.tls_conn.is_handshaking()
    }

    fn server_name(&self) -> Option<&str> {
        match &self.tls_conn {
            TlsConnection::Server(server_conn) => server_conn.server_name(),
            TlsConnection::Client(_) => None,
        }
    }
}

struct ReadTls<'r> {
    tls_conn: &'r Mutex<Result<TlsSession, Aborted>>,
    buffer: &'r mut Vec<u8>,
    read_params: bool,
}

impl futures::Future for ReadTls<'_> {
    type Output = Result<(Option<KeyChange>, Option<Result<Parameters, Error>>, bool), Aborted>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut guard = this.tls_conn.lock().unwrap();
        let tls_conn = match guard.deref_mut() {
            Ok(tls_conn) => tls_conn,
            Err(_aborted) => return Poll::Ready(Err(Aborted)),
        };

        let key_change = tls_conn.read(this.buffer);
        if key_change.is_none() && this.buffer.is_empty() {
            tls_conn.read_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }

        let remote_params = if this.read_params {
            tls_conn.get_transport_parameters()
        } else {
            None
        };

        let is_handshaking = tls_conn.is_handshaking();

        Poll::Ready(Ok((key_change, remote_params, is_handshaking)))
    }
}

/// The shared TLS session for QUIC's TLS handshake.
///
/// This is a wrapper around the [`rustls::quic::Connection`], which is a QUIC-specific TLS connection.
#[derive(Debug, Clone)]
pub struct ArcTlsSession(Arc<Mutex<Result<TlsSession, Aborted>>>);

impl ArcTlsSession {
    /// The QUIC version used by the TLS session.
    const QUIC_VERSION: rustls::quic::Version = rustls::quic::Version::V1;

    /// Create a new client-side TLS session.
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
        Self(Arc::new(Mutex::new(Ok(connection.into()))))
    }

    /// Create a new server-side TLS session.
    pub fn new_server(tls_config: Arc<rustls::ServerConfig>, parameters: &Parameters) -> Self {
        let mut params = Vec::new();
        params.put_parameters(parameters);

        let server_connection =
            rustls::quic::ServerConnection::new(tls_config, Self::QUIC_VERSION, params).unwrap();
        let connection = rustls::quic::Connection::Server(server_connection);
        Self(Arc::new(Mutex::new(Ok(connection.into()))))
    }

    /// Generate the keys for the initial packet protection.
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

    /// Abort the TLS session, the handshaking will be stopped if it is not completed.
    pub fn abort(&self) {
        let mut guard = self.0.lock().unwrap();
        if let Ok(raw_tls) = guard.deref_mut() {
            if let Some(waker) = raw_tls.read_waker.take() {
                waker.wake();
            }
            *guard = Err(Aborted);
        }
    }

    fn read<'r>(&'r self, buf: &'r mut Vec<u8>, read_params: bool) -> ReadTls<'r> {
        buf.clear();
        ReadTls {
            tls_conn: &self.0,
            buffer: buf,
            read_params,
        }
    }

    /// Start the TLS handshake, automatically upgrade the keys, and transmit tls data.
    ///
    /// The [`CryptoStream`]s are provide for TLS connection to transmit the encrypted data.
    ///
    /// The [`ArcKeys`] and [`ArcOneRttKeys`] will be set when the keys are upgraded.
    ///
    /// The [`ConnError`] is used to notify the other components that a connection error occurred
    /// in the process of the handshake.
    ///
    /// The [`Handshake`] is used to notify the other components that the handshake is completed,
    /// for server, it should send the [`HandshakeDoneFrame`] to the client.
    ///
    /// Return a [`RemoteParameters`] that can be used to asynchronously get the peer's transport
    /// parameters.
    ///
    /// [`HandshakeDoneFrame`]: qbase::frame::HandshakeDoneFrame
    pub fn keys_upgrade(
        &self,
        crypto_streams: [&CryptoStream; 3],
        handshake_keys: ArcKeys,
        one_rtt_keys: ArcOneRttKeys,
        conn_error: ConnError,
        handshake: Handshake,
    ) -> RemoteParameters {
        let remote_params = RemoteParameters::new();

        let for_each_epoch = |epoch: Epoch| {
            let mut crypto_stream_reader = crypto_streams[epoch].reader();
            let tls_session = self.clone();
            let conn_error = conn_error.clone();

            tokio::spawn(async move {
                let mut read_buf = [0u8; 1500];
                while let Ok(read) = crypto_stream_reader.read(&mut read_buf[..]).await {
                    let mut guard = tls_session.0.lock().unwrap();
                    let tls_connection = match guard.deref_mut() {
                        Ok(tls_session) => tls_session,
                        Err(_aborted) => break,
                    };

                    if let Err(e) = tls_connection.write(&read_buf[..read]) {
                        let error_kind = match tls_connection.alert() {
                            Some(alert) => ErrorKind::Crypto(alert.into()),
                            None => ErrorKind::ProtocolViolation,
                        };
                        let reason = format!("TLS error: {e}");
                        conn_error.on_error(Error::with_default_fty(error_kind, reason));
                        break;
                    }

                    tls_connection.wake_read();
                }
            })
        };

        tokio::spawn({
            let tls_session = self.clone();
            let remote_params = remote_params.clone();

            let mut crypto_stream_writers =
                Epoch::EPOCHS.map(|epoch| crypto_streams[epoch].writer());
            let crypto_stream_read_tasks = Epoch::EPOCHS.map(for_each_epoch);

            async move {
                let mut send_buf = Vec::with_capacity(1500);
                let mut cur_epoch = Epoch::Initial;
                loop {
                    let read_params = !remote_params.is_ready();
                    let read_result = tls_session.read(&mut send_buf, read_params).await;
                    let (key_upgrade, params, is_handshaking) = match read_result {
                        Ok(results) => results,
                        Err(_aborted) => break,
                    };

                    if let Some(params) = params {
                        match params {
                            Ok(params) => remote_params.write(params.into()),
                            Err(params_error) => {
                                conn_error.on_error(params_error);
                                break;
                            }
                        }
                    }

                    if !send_buf.is_empty() {
                        let write_result =
                            crypto_stream_writers[cur_epoch].write_all(&send_buf).await;
                        if let Err(e) = write_result {
                            let error = Error::with_default_fty(ErrorKind::Internal, e.to_string());
                            conn_error.on_error(error);
                            break;
                        }
                    }

                    if let Some(key_change) = key_upgrade {
                        match key_change {
                            rustls::quic::KeyChange::Handshake { keys } => {
                                handshake_keys.set_keys(keys);
                                cur_epoch = Epoch::Handshake;
                            }
                            rustls::quic::KeyChange::OneRtt { keys, next } => {
                                one_rtt_keys.set_keys(keys, next);
                                cur_epoch = Epoch::Data;
                            }
                        }
                    }

                    if !is_handshaking {
                        if let Handshake::Server(server_handshake) = &handshake {
                            server_handshake.done();
                        }
                    }
                }

                for read_task in crypto_stream_read_tasks {
                    read_task.abort();
                }
            }
        });

        remote_params
    }

    /// For server, retrieves the server name, if any, used to select the certificate and private key.
    ///
    /// For client, returns [`None`].
    ///
    /// read [`rustls::quic::ServerConnection::server_name`] for more.
    pub fn server_name(&self) -> Option<String> {
        self.0
            .lock()
            .unwrap()
            .as_ref()
            .ok()
            .and_then(TlsSession::server_name)
            .map(ToString::to_string)
    }
}
