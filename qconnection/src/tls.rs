use std::{
    future::Future,
    ops::{Deref, DerefMut},
    pin::Pin,
    sync::{Arc, Mutex},
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
    util::AsyncCell,
};
use qrecovery::{space::Epoch, streams::crypto::CryptoStream};
use rustls::{crypto::CryptoProvider, quic::Keys, Side};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::ConnError;

/// write_tls_msg()，将明文数据写入tls_conn，同步的，可能会唤醒read数据发送
/// poll_read_tls_msg()，从tls_conn读取数据，异步的，返回([`Vec<u8>`], [`Option<KeyChange>`])
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub(crate) struct RawTlsSession {
    tls_conn: rustls::quic::Connection,
    waker: Option<Waker>,
}

#[derive(Debug, Error)]
#[error("TLS session is aborted")]
pub struct Aborted;

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
        Self {
            tls_conn: connection,
            waker: None,
        }
    }

    pub fn new_server(tls_config: Arc<rustls::ServerConfig>, server_params: &Parameters) -> Self {
        let mut params = Vec::new();
        params.put_parameters(server_params);

        let connection = rustls::quic::Connection::Server(
            rustls::quic::ServerConnection::new(tls_config, rustls::quic::Version::V1, params)
                .unwrap(),
        );
        Self {
            tls_conn: connection,
            waker: None,
        }
    }

    // 将plaintext中的数据写入tls_conn供其处理
    fn write_tls_msg(&mut self, plaintext: &[u8]) -> Result<(), rustls::Error> {
        // rusltls::quic::Connection::read_hs()，该函数即消费掉plaintext的数据给到tls_conn内部处理
        self.tls_conn.read_hs(plaintext)?;
        // want to read from tls_conn and then write into the crypto stream?
        if self.tls_conn.wants_read() {
            if let Some(w) = self.waker.take() {
                w.wake();
            }
        }
        Ok(())
    }

    // 轮询tls_conn，看是否有数据要从中读取并发送给对方，或者密钥升级。如果什么都没发生，则返回Pending
    fn poll_read_tls_msg(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<(Vec<u8>, Option<rustls::quic::KeyChange>)>> {
        let mut buf = Vec::with_capacity(1200);
        // rusltls::quic::Connection::write_hs()，该函数即将tls_conn内部的数据写入到buf中
        let key_change = self.tls_conn.write_hs(&mut buf);
        if key_change.is_none() && buf.is_empty() {
            self.waker = Some(cx.waker().clone());
            return Poll::Pending;
        }

        Poll::Ready(Some((buf, key_change)))
    }

    fn alert(&self) -> Option<rustls::AlertDescription> {
        self.tls_conn.alert()
    }
}

#[derive(Debug, Clone)]
pub struct ArcTlsSession(Arc<Mutex<Result<RawTlsSession, Aborted>>>);

impl ArcTlsSession {
    pub fn new_client(
        server_name: rustls::pki_types::ServerName<'static>,
        tls_config: Arc<rustls::ClientConfig>,
        parameters: &Parameters,
    ) -> Self {
        Self(Arc::new(Mutex::new(Ok(RawTlsSession::new_client(
            server_name,
            tls_config,
            parameters,
        )))))
    }

    pub fn new_server(tls_config: Arc<rustls::ServerConfig>, parameters: &Parameters) -> Self {
        Self(Arc::new(Mutex::new(Ok(RawTlsSession::new_server(
            tls_config, parameters,
        )))))
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

    pub fn write_tls_msg(&self, plaintext: &[u8]) -> Result<(), rustls::Error> {
        let mut guard = self.0.lock().unwrap();
        match guard.deref_mut() {
            Ok(tls_conn) => tls_conn.write_tls_msg(plaintext),
            Err(_) => Ok(()),
        }
    }

    pub fn read_tls_msg(&self) -> ReadTlsMsg {
        ReadTlsMsg(self.clone())
    }

    pub fn alert(&self) -> Option<rustls::AlertDescription> {
        let guard = self.0.lock().unwrap();
        if let Ok(ref tls_conn) = guard.deref() {
            tls_conn.alert()
        } else {
            None
        }
    }

    pub fn abort(&self) {
        let mut guard = self.0.lock().unwrap();
        if let Ok(ref mut tls_conn) = guard.deref_mut() {
            if let Some(waker) = tls_conn.waker.take() {
                waker.wake();
            }
        }
        *guard = Err(Aborted);
    }

    /// 自托管密钥升级
    pub fn keys_upgrade(
        &self,
        crypto_streams: [&CryptoStream; 3],
        handshake_keys: ArcKeys,
        one_rtt_keys: ArcOneRttKeys,
        conn_error: ConnError,
    ) -> Arc<AsyncCell<Arc<Parameters>>> {
        let remote_params = Arc::new(AsyncCell::new());

        let for_each_epoch = |epoch: Epoch| {
            let mut crypto_stream_reader = crypto_streams[epoch].reader();
            let tls_session = self.clone();
            let remote_params = remote_params.clone();
            let conn_error = conn_error.clone();
            tokio::spawn(async move {
                // 不停地从crypto_stream_reader读取数据，读到就送给tls_conn
                let mut buf = [0u8; 1500];
                loop {
                    // 总是Ok
                    let n = match crypto_stream_reader.read(&mut buf[..]).await {
                        Ok(n) => n,
                        // 读取到EOF，即crypto_stream_reader已经关闭，连接都已经关闭
                        Err(_err) => break,
                    };
                    let tls_write_result = tls_session.write_tls_msg(&buf[..n]);
                    if let Err(e) = tls_write_result {
                        let error_kind = if let Some(alert) = tls_session.alert() {
                            ErrorKind::Crypto(alert.into())
                        } else {
                            ErrorKind::ProtocolViolation
                        };
                        conn_error.on_error(Error::with_default_fty(
                            error_kind,
                            format!("TLS error: {e}"),
                        ));
                        break;
                    }

                    if let Some(params) = tls_session.get_transport_parameters() {
                        match params {
                            Ok(params) => _ = remote_params.write(params.into()),
                            Err(error) => conn_error.on_error(error),
                        }
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
                }

                for reader in crypto_readers {
                    reader.abort();
                }
            }
        });
        remote_params
    }

    pub fn server_name(&self) -> Option<String> {
        let mut guard = self.0.lock().unwrap();
        if let Ok(ref mut tls_session) = guard.deref_mut() {
            if let rustls::quic::Connection::Server(server) = &tls_session.tls_conn {
                return server.server_name().map(|s| s.to_string());
            } else {
                return None;
            }
        }
        None
    }

    fn get_transport_parameters(&self) -> Option<Result<Parameters, Error>> {
        let mut guard = self.0.lock().unwrap();
        if let Ok(ref mut tls_session) = guard.deref_mut() {
            let raw = tls_session.tls_conn.quic_transport_parameters()?;
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
        } else {
            None
        }
    }
}

pub struct ReadTlsMsg(ArcTlsSession);

impl Future for ReadTlsMsg {
    type Output = Option<(Vec<u8>, Option<rustls::quic::KeyChange>)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut guard = self.0 .0.lock().unwrap();
        if let Ok(ref mut tls_session) = guard.deref_mut() {
            tls_session.poll_read_tls_msg(cx)
        } else {
            Poll::Ready(None)
        }
    }
}
