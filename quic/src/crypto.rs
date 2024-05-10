use qrecovery::crypto_stream::{CryptoStreamReader, CryptoStreamWriter};
use rustls::quic::{Connection as TlsConnection, KeyChange, Keys, Secrets};
use std::{
    future::Future,
    pin::Pin,
    sync::{atomic::AtomicUsize, Arc, Mutex},
    task::{Context, Poll, Waker},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug)]
pub struct TlsSession {
    connection: TlsConnection,
    wants_write: Option<Waker>,
}

pub type ArcTlsSession = Arc<Mutex<TlsSession>>;

#[derive(Debug, Clone)]
pub struct TlsIO(ArcTlsSession);

impl TlsIO {
    pub fn split(&self) -> (TlsReader, TlsWriter) {
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

/// 因为TLSv1.3中的握手消息是严格按照逻辑来的，所以不会有什么打包ClientHello、ServerHello等消息格式的打包，
/// 这些都是封装在TLS库中设定好的。所以在握手期间，要不停地读取TLS握手的数据，一旦有数据要发送，就送交恰当的密
/// 级中的Crypto流中发送，一旦有新密钥产生，还得升级密级、替换密钥，即便到1-RTT阶段，也是一样的，密钥也有更新
/// 的可能。
pub struct HandshakeReader {
    tls_reader: TlsReader,
    level: AtomicUsize,
    readers: [CryptoStreamReader; 3],
}

impl HandshakeReader {
    pub async fn loop_read(&mut self) -> std::io::Result<()> {
        loop {
            let mut buf = [0u8; 1500];
            let n = self.readers[self.level.load(std::sync::atomic::Ordering::Relaxed)]
                .read(&mut buf)
                .await?;
            self.tls_reader
                .read_hs(&buf[..n])
                .expect("tls read hs failed");
        }
    }
}

pub struct HandshakeWriter {
    tls_writer: TlsWriter,
    level: AtomicUsize,
    writers: [CryptoStreamWriter; 3],
    keys: [Option<Keys>; 3],
    next: Option<Secrets>,
}

impl HandshakeWriter {
    pub async fn loop_write(&mut self) -> std::io::Result<()> {
        loop {
            let (buf, key_change) = self.tls_writer.clone().await;
            self.writers[self.level.load(std::sync::atomic::Ordering::Relaxed)]
                .write_all(&buf)
                .await?;
            if let Some(key_change) = key_change {
                match key_change {
                    KeyChange::Handshake { keys } => {
                        self.level.store(1, std::sync::atomic::Ordering::Relaxed);
                        self.keys[1] = Some(keys);
                    }
                    KeyChange::OneRtt { keys, next } => {
                        self.level.store(2, std::sync::atomic::Ordering::Relaxed);
                        self.keys[2] = Some(keys);
                        self.next = Some(next);
                    }
                };
            }
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
