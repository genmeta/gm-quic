mod client_auth;
use std::{
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
};

pub use client_auth::{ArcSendLock, AuthClient, ClientAuthers};
use futures::{future::poll_fn, never::Never};
use qbase::{
    Epoch,
    error::{Error, ErrorKind, QuicError},
    packet::keys::{ArcKeys, ArcOneRttKeys, ArcZeroRttKeys, DirectionalKeys},
    param::{ArcParameters, ClientParameters, ParameterId, ServerParameters, WriteParameters},
    util::Future,
};
use qrecovery::crypto::CryptoStream;
use rustls::{
    ClientConfig, ServerConfig,
    quic::{ClientConnection, KeyChange, ServerConnection},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::Handshake;

pub enum TlsSession {
    Client(ClientTlsSession),
    Server(ServerTlsSession),
}

pub const QUIC_VERSION: rustls::quic::Version = rustls::quic::Version::V1;

impl TlsSession {
    fn poll_read_hs(&mut self, cx: &mut Context, buf: &mut Vec<u8>) -> Poll<Option<KeyChange>> {
        match match self {
            TlsSession::Client(session) => session.tls_conn.write_hs(buf),
            TlsSession::Server(session) => session.tls_conn.write_hs(buf),
        } {
            None if buf.is_empty() => {
                match self {
                    TlsSession::Client(session) => session.read_waker = Some(cx.waker().clone()),
                    TlsSession::Server(session) => session.read_waker = Some(cx.waker().clone()),
                }
                Poll::Pending
            }
            key_change => Poll::Ready(key_change),
        }
    }

    fn write_hs(&mut self, buf: &[u8]) -> Result<(), rustls::Error> {
        match self {
            TlsSession::Client(ClientTlsSession { tls_conn, .. }) => tls_conn.read_hs(buf)?,
            TlsSession::Server(ServerTlsSession { tls_conn, .. }) => tls_conn.read_hs(buf)?,
        }
        if let Some(waker) = match self {
            TlsSession::Client(ClientTlsSession { read_waker, .. }) => read_waker.take(),
            TlsSession::Server(ServerTlsSession { read_waker, .. }) => read_waker.take(),
        } {
            waker.wake();
        }
        Ok(())
    }

    fn alert(&self) -> Option<rustls::AlertDescription> {
        match self {
            TlsSession::Client(session) => session.tls_conn.alert(),
            TlsSession::Server(session) => session.tls_conn.alert(),
        }
    }

    fn is_handshaking(&self) -> bool {
        match self {
            TlsSession::Client(session) => session.tls_conn.is_handshaking(),
            TlsSession::Server(session) => session.tls_conn.is_handshaking(),
        }
    }

    fn r#yield(&self) -> TlsHandshakeInfo {
        match self {
            TlsSession::Client(tls_handshake) => TlsHandshakeInfo::Client {
                zero_rtt_accepted: tls_handshake.zero_rtt.unwrap(),
                peer_cert: tls_handshake.server_certs.clone().unwrap(),
            },
            TlsSession::Server(tls_handshake) => TlsHandshakeInfo::Server {
                peer_cert: tls_handshake.client_cert.clone(),
                server_name: tls_handshake.server_name.clone().unwrap(),
                client_name: tls_handshake.client_name.clone(),
            },
        }
    }
}

pub struct ClientTlsSession {
    tls_conn: ClientConnection,
    read_waker: Option<Waker>,

    zero_rtt: Option<bool>,
    server_certs: Option<Vec<u8>>,
}

impl ClientTlsSession {
    pub fn init(
        server_name: String,
        tls_config: Arc<ClientConfig>,
        client_params: &ClientParameters,
    ) -> Result<Self, rustls::Error> {
        let mut params_buf = Vec::with_capacity(1024);
        params_buf.put_parameters(client_params);

        let name = rustls::pki_types::ServerName::try_from(server_name.clone())
            .map_err(|e| rustls::Error::Other(rustls::OtherError(Arc::new(e))))?;
        let tls_conn = ClientConnection::new(tls_config, QUIC_VERSION, name, params_buf)?;

        let tls_session = Self {
            tls_conn,
            read_waker: None,
            zero_rtt: None,
            server_certs: None,
        };
        Ok(tls_session)
    }

    #[must_use]
    pub fn load_zero_rtt(&self) -> Option<(ServerParameters, DirectionalKeys)> {
        match (
            self.tls_conn.quic_transport_parameters(),
            self.tls_conn.zero_rtt_keys(),
        ) {
            (Some(raw_params), Some(keys)) => {
                let params = ServerParameters::parse_from_bytes(raw_params).ok()?;
                Some((params, keys.into()))
            }
            _ => None,
        }
    }

    fn try_process_sh(&mut self) {
        self.server_certs = self.server_certs.take().or_else(|| {
            self.tls_conn
                .peer_certificates()
                .map(|certs_or_public_key| certs_or_public_key[0].to_vec())
        })
    }

    fn try_process_ee(&mut self, parameters: &ArcParameters) -> Result<(), Error> {
        let Some(handshake_kind) = self.tls_conn.handshake_kind() else {
            return Ok(());
        };
        let raw_params = self
            .tls_conn
            .quic_transport_parameters()
            .expect("Parameters must be known at this point");
        let mut parameters = parameters.lock_guard()?;
        let remebered = parameters.remembered().cloned();
        let params = ServerParameters::parse_from_bytes(raw_params)?;
        self.zero_rtt = Some(
            matches!(remebered, Some(remembered) if remembered.is_0rtt_accepted(&params))
                && matches!(handshake_kind, rustls::HandshakeKind::Resumed),
        );
        parameters.recv_remote_params(params)?;
        Ok(())
    }
}

impl Drop for ClientTlsSession {
    fn drop(&mut self) {
        if let Some(read_waker) = self.read_waker.take() {
            read_waker.wake();
        }
    }
}

pub struct ServerTlsSession {
    tls_conn: ServerConnection,
    read_waker: Option<Waker>,

    client_name: Option<String>,
    server_name: Option<String>,
    send_lock: ArcSendLock,
    client_authers: ClientAuthers,
    client_cert: Option<Vec<u8>>,
}

impl ServerTlsSession {
    pub fn init(
        tls_config: Arc<ServerConfig>,
        server_params: &ServerParameters,
        client_authers: ClientAuthers,
        anti_port_scan: bool,
    ) -> Result<Self, rustls::Error> {
        let mut params_buf = Vec::with_capacity(1024);
        params_buf.put_parameters(server_params);

        let tls_conn = ServerConnection::new(tls_config, QUIC_VERSION, params_buf)?;

        let tls_session = Self {
            tls_conn,
            read_waker: None,
            client_name: None,
            server_name: None,
            send_lock: match anti_port_scan {
                true => ArcSendLock::new(),
                false => ArcSendLock::unrestricted(),
            },
            client_authers,
            client_cert: None,
        };
        Ok(tls_session)
    }

    pub fn send_lock(&self) -> &ArcSendLock {
        &self.send_lock
    }

    fn try_process_ch(
        &mut self,
        parameters: &ArcParameters,
        zero_rtt_keys: &ArcZeroRttKeys,
    ) -> Result<(), Error> {
        let client_params = ClientParameters::parse_from_bytes(
            self.tls_conn
                .quic_transport_parameters()
                .expect("Client parameters must be present in ClientHello"),
        )?;

        self.client_name = client_params.get(ParameterId::ClientName);
        self.server_name = self.tls_conn.server_name().map(|s| s.to_string());
        let host = self.server_name.as_ref().ok_or_else(|| {
            QuicError::with_default_fty(ErrorKind::ConnectionRefused, "Missing SNI in client hello")
        })?;

        if !(self.client_authers.iter())
            .all(|auther| auther.verify_client_params(host, self.client_name.as_deref()))
        {
            tracing::warn!(
                host,
                ?self.client_name,
                "Client SNI or client name verification failed, refusing connection."
            );
            return Err(Error::Quic(QuicError::with_default_fty(
                ErrorKind::ConnectionRefused,
                "",
            )));
        }
        self.send_lock.grant_permit();
        parameters.lock_guard()?.recv_remote_params(client_params)?;

        match self.tls_conn.zero_rtt_keys() {
            Some(keys) => zero_rtt_keys.set_keys(keys.into()),
            None => _ = zero_rtt_keys.invalid(),
        }

        Ok(())
    }

    fn try_process_cert(&mut self) -> Result<(), Error> {
        self.client_cert = self.client_cert.take().or_else(|| {
            self.tls_conn
                .peer_certificates()
                .map(|certs_or_public_key| certs_or_public_key[0].to_vec())
        });

        let Some(cert) = self.client_cert.as_ref() else {
            return Ok(());
        };
        let host = self
            .server_name
            .as_deref()
            .expect("Server name must be known at this point");

        if !(self.client_authers.iter())
            .all(|auther| auther.verify_client_certs(host, self.client_name.as_deref(), cert))
        {
            tracing::warn!(
                ?host,
                ?self.client_name,
                "Client certificate verification failed, refusing connection."
            );
            return Err(Error::Quic(QuicError::with_default_fty(
                ErrorKind::ConnectionRefused,
                "",
            )));
        }

        Ok(())
    }
}

impl Drop for ServerTlsSession {
    fn drop(&mut self) {
        if let Some(read_waker) = self.read_waker.take() {
            read_waker.wake();
        }
    }
}

#[derive(Clone)]
pub enum TlsHandshakeInfo {
    Client {
        zero_rtt_accepted: bool,
        peer_cert: Vec<u8>,
    },
    Server {
        peer_cert: Option<Vec<u8>>,
        server_name: String,
        client_name: Option<String>,
    },
}

impl TlsHandshakeInfo {
    pub fn zero_rtt_accepted(&self) -> Option<bool> {
        match self {
            TlsHandshakeInfo::Client {
                zero_rtt_accepted, ..
            } => Some(*zero_rtt_accepted),
            TlsHandshakeInfo::Server { .. } => None,
        }
    }
}

pub struct TlsHandshake {
    session: TlsSession,
    info: Future<Arc<TlsHandshakeInfo>>,
}

#[derive(Clone)]
pub struct ArcTlsHandshake(Arc<Mutex<Result<TlsHandshake, Error>>>);

impl ArcTlsHandshake {
    pub fn new(session: TlsSession) -> ArcTlsHandshake {
        Self(Arc::new(Mutex::new(Ok(TlsHandshake {
            session,
            info: Future::default(),
        }))))
    }

    fn state(&self) -> MutexGuard<'_, Result<TlsHandshake, Error>> {
        self.0.lock().unwrap()
    }

    async fn read_hs(&self, buf: &mut Vec<u8>) -> Result<Option<KeyChange>, Error> {
        poll_fn(|cx| {
            let mut tls_handshake = self.state();
            match tls_handshake.as_mut() {
                Ok(state) => state.session.poll_read_hs(cx, buf).map(Ok),
                Err(e) => Poll::Ready(Err(e.clone())),
            }
        })
        .await
    }

    fn write_hs(&self, buf: &[u8]) -> Result<(), Error> {
        let mut tls_handshake = self.state();
        let tls_handshake = tls_handshake.as_mut().map_err(|e| e.clone())?;
        match tls_handshake.session.write_hs(buf) {
            Ok(_) => Ok(()),
            Err(error) => {
                tracing::error!("TLS write error: {error}");
                let error_kind = match tls_handshake.session.alert() {
                    Some(alert) => ErrorKind::Crypto(alert.into()),
                    None => ErrorKind::ProtocolViolation,
                };
                Err(Error::Quic(QuicError::with_default_fty(
                    error_kind,
                    format!("TLS error: {error}"),
                )))
            }
        }
    }

    pub async fn info(&self) -> Result<Arc<TlsHandshakeInfo>, Error> {
        poll_fn(|cx| {
            let mut tls_handshake = self.state();
            match tls_handshake.as_mut() {
                Ok(state) => state.info.poll_get(cx).map(|info| info.clone()).map(Ok),
                Err(e) => Poll::Ready(Err(e.clone())),
            }
        })
        .await
    }

    pub async fn finished(&self) -> bool {
        self.info().await.is_ok()
    }

    pub fn is_finished(&self) -> Result<bool, Error> {
        let tls_handshake = self.state();
        match tls_handshake.as_ref() {
            Ok(state) => Ok(!state.session.is_handshaking()),
            Err(e) => Err(e.clone()),
        }
    }

    pub fn server_name(&self) -> Result<Option<String>, Error> {
        let tls_handshake = self.state();
        match tls_handshake.as_ref() {
            Ok(state) => match &state.session {
                TlsSession::Client(_) => Ok(None),
                TlsSession::Server(session) => Ok(session.server_name.clone()),
            },
            Err(e) => Err(e.clone()),
        }
    }

    pub fn on_conn_error(&self, error: &Error) {
        *self.state() = Err(error.clone())
    }

    fn try_process_tls_message(
        &self,
        parameters: &ArcParameters,
        zero_rtt_keys: &ArcZeroRttKeys,
    ) -> Result<Option<Arc<TlsHandshakeInfo>>, Error> {
        let mut state = self.state();
        let tls_handshake = state.as_mut().map_err(|e| e.clone())?;

        match &mut tls_handshake.session {
            TlsSession::Client(session) => {
                if session.server_certs.is_none() {
                    session.try_process_sh();
                }
                if !parameters.lock_guard()?.is_remote_params_received() {
                    session.try_process_ee(parameters)?;
                }
            }
            TlsSession::Server(session) => {
                if !parameters.lock_guard()?.is_remote_params_received() {
                    session.try_process_ch(parameters, zero_rtt_keys)?;
                }
                if session.client_cert.is_none() {
                    session.try_process_cert()?;
                }
            }
        }

        if !tls_handshake.session.is_handshaking() && tls_handshake.info.try_get().is_none() {
            let info = Arc::new(tls_handshake.session.r#yield());
            tls_handshake.info.set(info.clone());
            return Ok(Some(info));
        }

        Ok(None)
    }

    pub fn launch(
        self,
        parameters: ArcParameters,
        quic_handshake: Handshake,
        crypto_streams: [CryptoStream; 3],
        (handshake_keys, zero_rtt_keys, one_rtt_keys): (ArcKeys, ArcZeroRttKeys, ArcOneRttKeys),
        on_handshake_conmplete: impl FnOnce(&TlsHandshakeInfo) -> Result<(), Error> + Send + 'static,
    ) -> impl futures::Future<Output = Result<(), Error>> + Send + 'static {
        let mut on_handshake_conmplete = Some(on_handshake_conmplete);

        let crypto_read_task = |epoch: Epoch| {
            let tls_handshake = self.clone();
            let mut stream_reader = crypto_streams[epoch].reader();
            async move {
                let mut buf = [0; 2048];
                while let Ok(read) = stream_reader.read(&mut buf).await {
                    tls_handshake.write_hs(&buf[..read])?;
                }
                Result::<_, Error>::Ok(())
            }
        };

        let [initial_read_task, handshake_read_task, data_read_task] =
            Epoch::EPOCHS.map(|epoch: Epoch| crypto_read_task(epoch));

        let mut crypto_writers =
            Epoch::EPOCHS.map(|epoch: Epoch| crypto_streams[epoch].writer().clone());

        let crypto_write_task = async move {
            let mut buf = Vec::with_capacity(2048);
            let mut cur_epoch = Epoch::Initial;
            loop {
                let key_change = self.read_hs(&mut buf).await?;
                if !buf.is_empty() {
                    // error: crypto buffer offset overflow
                    (crypto_writers[cur_epoch].write_all(&buf).await).map_err(|e| {
                        QuicError::with_default_fty(ErrorKind::Internal, format!("{e:?}"))
                    })?;
                    buf.clear();
                }
                match key_change {
                    Some(KeyChange::Handshake { keys }) => {
                        handshake_keys.set_keys(keys.into());
                        quic_handshake.got_handshake_key();
                        cur_epoch = Epoch::Handshake;
                    }
                    Some(KeyChange::OneRtt { keys, next }) => {
                        one_rtt_keys.set_keys(keys, next);
                        cur_epoch = Epoch::Data;
                    }
                    None => {}
                };
                if let Some(info) = self.try_process_tls_message(&parameters, &zero_rtt_keys)? {
                    (on_handshake_conmplete.take().expect("tls complete twice"))(&info)?;
                }
            }
        };

        // rustc: error[E0282]: type annotations needed
        let crypto_write_task = async move {
            let result: Result<Never, Error> = crypto_write_task.await;
            result
        };

        async move {
            tokio::try_join!(
                initial_read_task,
                handshake_read_task,
                data_read_task,
                crypto_write_task,
            )?;
            Ok(())
        }
    }
}
