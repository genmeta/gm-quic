use qrecovery::crypto::{CryptoStreamReader, CryptoStreamWriter};
use rustls::quic::{Connection as TlsConnection, KeyChange};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    select,
};

#[derive(Debug)]
pub(crate) struct TlsSession {
    connection: TlsConnection,
    wants_write: Option<Waker>,
}

pub(crate) type ArcTlsSession = Arc<Mutex<TlsSession>>;

#[derive(Debug, Clone)]
pub struct TlsIO(ArcTlsSession);

impl TlsIO {
    pub fn new_client() -> Self {
        /*
        Self(Arc::new(Mutex::new(TlsSession {
            connection: todo!(),
            wants_write: None,
        })))
        */
        todo!()
    }

    pub fn split_io(&self) -> (TlsReader, TlsWriter) {
        (TlsReader(self.0.clone()), TlsWriter(self.0.clone()))
    }
}

#[derive(Debug, Clone)]
pub struct TlsReader(ArcTlsSession);

impl TlsReader {
    pub fn read_hs(&mut self, plaintext: &[u8]) -> Result<(), rustls::Error> {
        let mut tls_session = self.0.lock().unwrap();
        tls_session.connection.read_hs(plaintext)?;
        if tls_session.connection.wants_write() {
            if let Some(waker) = tls_session.wants_write.take() {
                waker.wake();
            }
        }
        Ok(())
    }

    pub fn loop_read_from(mut self, mut stream_reader: CryptoStreamReader) -> HandshakeReader {
        let (close_tx, mut close_rx) = tokio::sync::oneshot::channel::<()>();
        let join_handler = tokio::spawn(async move {
            loop {
                let mut buf = Vec::with_capacity(1500);
                select! {
                    _ = &mut close_rx => return Ok(()),
                    n = stream_reader.read(&mut buf)=> {
                        self.read_hs(&buf[..n?]).expect("tls read hs failed");
                    },
                }
            }
        });
        HandshakeReader {
            close_tx,
            join_handler,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TlsWriter(ArcTlsSession);

impl Future for TlsWriter {
    type Output = (Vec<u8>, Option<KeyChange>);

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut buf = Vec::with_capacity(1200);
        let mut tls_session = self.0.lock().unwrap();
        let key_change = tls_session.connection.write_hs(&mut buf);
        if key_change.is_none() && buf.is_empty() {
            tls_session.wants_write = Some(cx.waker().clone());
            Poll::Pending
        } else {
            Poll::Ready((buf, key_change))
        }
    }
}

impl TlsWriter {
    pub fn write_to(self, stream_writer: CryptoStreamWriter) -> HandshakeWriter {
        HandshakeWriter {
            tls_writer: self,
            stream_writer,
        }
    }
}

/// 因为TLSv1.3中的握手消息是严格按照逻辑来的，所以不会有什么打包ClientHello、ServerHello等消息格式的打包，
/// 这些都是封装在TLS库中设定好的。所以在握手期间，要不停地读取TLS握手的数据，一旦有数据要发送，就送交恰当的密
/// 级中的Crypto流中发送，一旦有新密钥产生，还得升级密级、替换密钥，即便到1-RTT阶段，也是一样的，密钥也有更新
/// 的可能。
pub struct HandshakeReader {
    close_tx: tokio::sync::oneshot::Sender<()>,
    join_handler: tokio::task::JoinHandle<io::Result<()>>,
}

impl HandshakeReader {
    pub async fn end(self) -> io::Result<()> {
        self.close_tx
            .send(())
            .expect("close handshake reader failed");
        self.join_handler.await?
    }
}

pub struct HandshakeWriter {
    tls_writer: TlsWriter,
    stream_writer: CryptoStreamWriter,
}

impl HandshakeWriter {
    pub async fn loop_write(&mut self) -> io::Result<KeyChange> {
        loop {
            let (buf, key_change) = self.tls_writer.clone().await;
            self.stream_writer.write_all(&buf).await?;
            if let Some(key_change) = key_change {
                return Ok(key_change);
            }
        }
    }
}

#[cfg(test)]
mod tests {}
