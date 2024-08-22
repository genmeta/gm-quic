use std::{
    future::Future,
    ops::DerefMut,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
};

use qbase::{
    cid::ConnectionId,
    config::{
        ext::{be_parameters, WriteParameters},
        Parameters,
    },
    error::{Error, ErrorKind},
    packet::keys::{ArcKeys, ArcOneRttKeys},
};
use qrecovery::{space::Epoch, streams::crypto::CryptoStream};
use rustls::{crypto::CryptoProvider, quic::Keys, Side};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::ConnError;

/// write_tls_msg()，将明文数据写入tls_conn，同步的，可能会唤醒read数据发送
/// poll_read_tls_msg()，从tls_conn读取数据，异步的，返回(Vec<u8>, Option<KeyChange>)
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum RawTlsSession {
    Exist {
        tls_conn: rustls::quic::Connection,
        wants_write: Option<Waker>,
    },
    Invalid,
}

impl RawTlsSession {
    fn new_client(
        server_name: rustls::pki_types::ServerName<'static>,
        tls_config: Arc<rustls::ClientConfig>,
        parameters: &Parameters,
    ) -> Self {
        let mut params_bytes = Vec::new();
        params_bytes.put_parameters(parameters);

        let connection = rustls::quic::Connection::Client(
            rustls::quic::ClientConnection::new(
                tls_config,
                rustls::quic::Version::V1,
                server_name,
                params_bytes,
            )
            .unwrap(),
        );
        Self::Exist {
            tls_conn: connection,
            wants_write: None,
        }
    }

    pub fn new_server(tls_config: Arc<rustls::ServerConfig>, server_params: &Parameters) -> Self {
        let mut params = Vec::new();
        params.put_parameters(server_params);

        let connection = rustls::quic::Connection::Server(
            rustls::quic::ServerConnection::new(tls_config, rustls::quic::Version::V1, params)
                .unwrap(),
        );
        Self::Exist {
            tls_conn: connection,
            wants_write: None,
        }
    }

    // 将plaintext中的数据写入tls_conn供其处理
    fn write_tls_msg(&mut self, plaintext: &[u8]) -> Result<(), rustls::Error> {
        let Self::Exist {
            tls_conn,
            wants_write,
        } = self
        else {
            return Ok(());
        };
        // rusltls::quic::Connection::read_hs()，该函数即消费掉plaintext的数据给到tls_conn内部处理
        tls_conn.read_hs(plaintext)?;
        if tls_conn.wants_write() {
            if let Some(waker) = wants_write.take() {
                waker.wake();
            }
        }
        Ok(())
    }

    // 轮询tls_conn，看是否有数据要从中读取并发送给对方，或者密钥升级。如果什么都没发生，则返回Pending
    fn poll_read_tls_msg(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<(Vec<u8>, Option<rustls::quic::KeyChange>)>> {
        let Self::Exist {
            tls_conn,
            wants_write,
        } = self
        else {
            return Poll::Ready(None);
        };
        let mut buf = Vec::with_capacity(1200);
        // rusltls::quic::Connection::write_hs()，该函数即将tls_conn内部的数据写入到buf中
        let key_change = tls_conn.write_hs(&mut buf);
        if key_change.is_none() && buf.is_empty() {
            *wants_write = Some(cx.waker().clone());
            return Poll::Pending;
        }

        Poll::Ready(Some((buf, key_change)))
    }
}

#[derive(Debug, Clone)]
pub struct ArcTlsSession(Arc<Mutex<RawTlsSession>>);

impl ArcTlsSession {
    pub fn new_client(
        server_name: rustls::pki_types::ServerName<'static>,
        tls_config: Arc<rustls::ClientConfig>,
        parameters: &Parameters,
    ) -> Self {
        Self(Arc::new(Mutex::new(RawTlsSession::new_client(
            server_name,
            tls_config,
            parameters,
        ))))
    }

    pub fn new_server(tls_config: Arc<rustls::ServerConfig>, parameters: &Parameters) -> Self {
        Self(Arc::new(Mutex::new(RawTlsSession::new_server(
            tls_config, parameters,
        ))))
    }

    pub fn initial_keys(
        crypto_provider: &Arc<CryptoProvider>,
        side: Side,
        cid: ConnectionId,
    ) -> Keys {
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

    fn lock_guard(&self) -> MutexGuard<'_, RawTlsSession> {
        self.0.lock().unwrap()
    }

    pub fn write_tls_msg(&self, plaintext: &[u8]) -> Result<(), rustls::Error> {
        self.lock_guard().write_tls_msg(plaintext)
    }

    pub fn read_tls_msg(&self) -> ReadTlsMsg {
        ReadTlsMsg(self.clone())
    }

    fn invalid(&self) {
        let mut guard = self.lock_guard();
        if let RawTlsSession::Exist { wants_write, .. } = guard.deref_mut() {
            if let Some(waker) = wants_write.take() {
                waker.wake();
            }
        }
        *guard = RawTlsSession::Invalid;
    }

    pub fn on_conn_error(&self, error: &Error) {
        _ = error;
        self.invalid();
    }

    /// 自托管密钥升级
    pub fn keys_upgrade(
        &self,
        crypto_streams: [&CryptoStream; 3],
        handshake_keys: ArcKeys,
        one_rtt_keys: ArcOneRttKeys,
        conn_error: ConnError,
    ) -> GetParameters {
        let get_parameters = GetParameters::default();

        let for_each_epoch = |epoch: Epoch| {
            let mut crypto_stream_reader = crypto_streams[epoch].reader();
            let tls_session = self.clone();
            let get_parameters = get_parameters.clone();
            let conn_error = conn_error.clone();
            tokio::spawn(async move {
                // 不停地从crypto_stream_reader读取数据，读到就送给tls_conn
                let mut buf = Vec::with_capacity(1200);
                loop {
                    buf.truncate(0);
                    // 总是Ok
                    _ = crypto_stream_reader.read(&mut buf).await;
                    let tls_write_result = tls_session.write_tls_msg(&buf);
                    if let Err(err) = tls_write_result {
                        conn_error.on_error(err.into());
                        break;
                    }

                    if let Some(params) = tls_session.get_transport_parameters() {
                        get_parameters.set_parameters(params);
                    }
                }
            })
        };

        // 在此创建reader任务
        let crypto_readers = Epoch::EPOCHS.map(for_each_epoch);

        // 在此创建不停地检查tls_conn是否有数据要给到对方，或者产生了密钥升级
        // TODO: 处理错误，处理它们的异常终止
        tokio::spawn({
            let tls_session = self.clone();
            let get_parameters = get_parameters.clone();
            let mut crypto_stream_writers = [
                crypto_streams[0].writer(),
                crypto_streams[1].writer(),
                crypto_streams[2].writer(),
            ];
            async move {
                // rustls严格限制了tls握手过程中的其中各类消息的发送顺序，这就是由read_tls_msg函数的顺序调用的返回
                // 值保证的。因此，其返回了密钥升级，则需要升级到相应密级，然后后续的数据都将在新密级下发送。
                let mut epoch = Epoch::Initial;
                loop {
                    let Some((buf, key_upgrade)) = tls_session.read_tls_msg().await else {
                        break;
                    };
                    if let Some(key_change) = key_upgrade {
                        match key_change {
                            rustls::quic::KeyChange::Handshake { keys } => {
                                handshake_keys.set_keys(keys);
                                epoch = Epoch::Handshake;
                            }
                            rustls::quic::KeyChange::OneRtt { keys, next } => {
                                one_rtt_keys.set_keys(keys, next);
                                // epoch = Epoch::Data;
                                break;
                            }
                        }
                    }

                    if !buf.is_empty() {
                        let write_result = crypto_stream_writers[epoch].write(&buf).await;
                        if let Err(err) = write_result {
                            conn_error.on_error(Error::with_default_fty(
                                ErrorKind::Internal,
                                err.to_string(),
                            ));
                            break;
                        }
                    }
                }

                for reader in crypto_readers {
                    reader.abort();
                }
                get_parameters.on_handshake_done();
            }
        });
        get_parameters
    }

    fn get_transport_parameters(&self) -> Option<Parameters> {
        let mut tls_session = self.lock_guard();
        if let RawTlsSession::Exist { tls_conn, .. } = tls_session.deref_mut() {
            let raw = tls_conn.quic_transport_parameters()?;
            be_parameters(raw).ok().map(|(_, p)| p)
        } else {
            None
        }
    }
}

pub struct ReadTlsMsg(ArcTlsSession);

impl Future for ReadTlsMsg {
    type Output = Option<(Vec<u8>, Option<rustls::quic::KeyChange>)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.lock_guard().poll_read_tls_msg(cx)
    }
}

#[derive(Default, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
enum RawGetParameters {
    #[default]
    None,
    Pending(Waker),
    Ready(Parameters),
    End,
}

impl RawGetParameters {
    fn poll_get_parameters(&mut self, cx: &mut Context) -> Poll<Option<Parameters>> {
        match self {
            RawGetParameters::None | RawGetParameters::Pending(..) => {
                *self = RawGetParameters::Pending(cx.waker().clone());
                Poll::Pending
            }
            RawGetParameters::Ready(..) => {
                let p = std::mem::replace(self, RawGetParameters::End);
                let RawGetParameters::Ready(p) = p else {
                    unreachable!()
                };
                Poll::Ready(Some(p))
            }
            RawGetParameters::End => Poll::Ready(None),
        }
    }
}

#[derive(Default, Clone)]
pub struct GetParameters(Arc<Mutex<RawGetParameters>>);

impl GetParameters {
    fn set_parameters(&self, parameters: Parameters) {
        let mut guard = self.0.lock().unwrap();
        let RawGetParameters::Pending(waker) = guard.deref_mut() else {
            return;
        };
        waker.wake_by_ref();
        *guard = RawGetParameters::Ready(parameters);
    }

    fn on_handshake_done(&self) {
        let mut guard = self.0.lock().unwrap();
        let RawGetParameters::Pending(waker) = guard.deref_mut() else {
            return;
        };
        waker.wake_by_ref();
        *guard = RawGetParameters::End;
    }

    pub fn poll_get_parameters(&self, cx: &mut Context) -> Poll<Option<Parameters>> {
        self.0.lock().unwrap().poll_get_parameters(cx)
    }
}

impl Future for GetParameters {
    type Output = Option<Parameters>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.lock().unwrap().poll_get_parameters(cx)
    }
}
