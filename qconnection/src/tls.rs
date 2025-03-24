use core::{
    ops::DerefMut,
    task::{Context, Poll, Waker},
};
use std::{
    future::Future,
    sync::{Arc, Mutex},
};

use qbase::{
    Epoch,
    error::{Error, ErrorKind},
    param::ArcParameters,
};
use qlog::telemetry::Instrument;
use qrecovery::crypto::CryptoStream;
use rustls::quic::KeyChange;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::Instrument as _;

use crate::{Components, Handshake, events::Event, prelude::EmitEvent};

type TlsConnection = rustls::quic::Connection;

#[derive(Debug)]
struct TlsSession {
    tls_conn: TlsConnection,
    read_waker: Option<Waker>,
}

impl From<TlsConnection> for TlsSession {
    fn from(tls_conn: TlsConnection) -> Self {
        Self {
            tls_conn,
            read_waker: None,
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

    fn try_get_parameters(&mut self, params: &ArcParameters) -> Result<(), Error> {
        if !params.has_rcvd_remote_params() {
            if let Some(raw) = self.tls_conn.quic_transport_parameters() {
                params.recv_remote_params(raw)?;
            }
        }
        Ok(())
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

struct ReadAndProcess<'r> {
    tls_conn: &'r Mutex<Result<TlsSession, Error>>,
    messages: &'r mut Vec<u8>,
    parameters: &'r ArcParameters,
    handshake: &'r Handshake,
}

impl futures::Future for ReadAndProcess<'_> {
    type Output = Result<Option<KeyChange>, Error>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut guard = this.tls_conn.lock().unwrap();
        let tls_conn = match guard.deref_mut() {
            Ok(tls_conn) => tls_conn,
            Err(e) => return Poll::Ready(Err(e.clone())),
        };

        let key_change = tls_conn.read(this.messages);
        if key_change.is_none() && this.messages.is_empty() {
            tls_conn.read_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }

        if !tls_conn.is_handshaking() {
            this.handshake.done();
        }

        tls_conn.try_get_parameters(this.parameters)?;

        Poll::Ready(Ok(key_change))
    }
}

/// The shared TLS session for QUIC's TLS handshake.
///
/// This is a wrapper around the [`rustls::quic::Connection`], which is a QUIC-specific TLS connection.
#[derive(Debug, Clone)]
pub struct ArcTlsSession(Arc<Mutex<Result<TlsSession, Error>>>);

impl ArcTlsSession {
    /// The QUIC version used by the TLS session.
    const QUIC_VERSION: rustls::quic::Version = rustls::quic::Version::V1;

    /// Create a new client-side TLS session.
    pub fn new_client(
        server_name: rustls::pki_types::ServerName<'static>,
        tls_config: Arc<rustls::ClientConfig>,
        parameters: &ArcParameters,
    ) -> Self {
        let mut params = Vec::with_capacity(1024);
        parameters.load_local_params_into(&mut params);

        let client_connection = rustls::quic::ClientConnection::new(
            tls_config,
            Self::QUIC_VERSION,
            server_name,
            params,
        );
        let connection = rustls::quic::Connection::Client(client_connection.unwrap());
        Self(Arc::new(Mutex::new(Ok(connection.into()))))
    }

    /// Create a new server-side TLS session.
    pub fn new_server(tls_config: Arc<rustls::ServerConfig>, parameters: &ArcParameters) -> Self {
        let mut params = Vec::with_capacity(1024);
        parameters.load_local_params_into(&mut params);

        let server_connection =
            rustls::quic::ServerConnection::new(tls_config, Self::QUIC_VERSION, params).unwrap();
        let connection = rustls::quic::Connection::Server(server_connection);
        Self(Arc::new(Mutex::new(Ok(connection.into()))))
    }

    /// Abort the TLS session, the handshaking will be stopped if it is not completed.
    pub fn on_conn_error(&self, error: &Error) {
        let mut guard = self.0.lock().unwrap();
        if let Ok(raw_tls) = guard.deref_mut() {
            if let Some(waker) = raw_tls.read_waker.take() {
                waker.wake();
            }
            *guard = Err(error.clone());
        }
    }

    fn read_and_process<'r>(
        &'r self,
        buf: &'r mut Vec<u8>,
        parameters: &'r ArcParameters,
        handshake: &'r Handshake,
    ) -> ReadAndProcess<'r> {
        buf.clear();
        ReadAndProcess {
            tls_conn: &self.0,
            messages: buf,
            parameters,
            handshake,
        }
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

/// Start the TLS handshake, automatically upgrade the keys, and transmit tls data.
pub fn keys_upgrade(components: &Components) -> impl Future<Output = ()> + Send + use<> {
    let crypto_streams: [&CryptoStream; 3] = [
        components.spaces.initial().crypto_stream(),
        components.spaces.handshake().crypto_stream(),
        components.spaces.data().crypto_stream(),
    ];

    let epoch_read_task = |epoch: Epoch| {
        let mut crypto_stream_reader = crypto_streams[epoch].reader();
        let tls_session = components.tls_session.clone();
        let broker = components.event_broker.clone();

        tokio::spawn(
            async move {
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
                        broker.emit(Event::Failed(Error::with_default_fty(error_kind, reason)));
                        break;
                    }

                    tls_connection.wake_read();
                }
            }
            .instrument_in_current()
            .in_current_span(),
        )
    };

    let epoch_crypto_writer = |epoch: Epoch| crypto_streams[epoch].writer();

    let crypto_stream_read_tasks = Epoch::EPOCHS.map(epoch_read_task);
    let mut crypto_stream_writers = Epoch::EPOCHS.map(epoch_crypto_writer);

    let tls_session = components.tls_session.clone();
    let handshake_keys = components.spaces.handshake().keys();
    let one_rtt_keys = components.spaces.data().one_rtt_keys();
    let handshake = components.handshake.clone();
    let parameters = components.parameters.clone();
    let event_broker = components.event_broker.clone();
    let handshake_status = components.handshake_status.clone();

    async move {
        let mut messages = Vec::with_capacity(1500);
        let mut cur_epoch = Epoch::Initial;
        loop {
            let key_upgrade = match tls_session
                .read_and_process(&mut messages, &parameters, &handshake)
                .await
            {
                Ok(results) => results,
                Err(e) => {
                    event_broker.emit(Event::Failed(e));
                    break;
                }
            };

            if !messages.is_empty() {
                let write_result = crypto_stream_writers[cur_epoch].write_all(&messages).await;
                if let Err(e) = write_result {
                    let error = Error::with_default_fty(ErrorKind::Internal, e.to_string());
                    event_broker.emit(Event::Failed(error));
                    break;
                }
            }

            if let Some(key_change) = key_upgrade {
                match key_change {
                    rustls::quic::KeyChange::Handshake { keys } => {
                        handshake_keys.set_keys(keys);
                        handshake.on_key_upgrade();
                        handshake_status.got_handshake_key();
                        cur_epoch = Epoch::Handshake;
                    }
                    rustls::quic::KeyChange::OneRtt { keys, next } => {
                        one_rtt_keys.set_keys(keys, next);
                        handshake_status.handshake_confirmed();
                        cur_epoch = Epoch::Data;
                    }
                }
            }
        }

        for read_task in crypto_stream_read_tasks {
            read_task.abort();
        }
    }
    .instrument_in_current()
    .in_current_span()
}
