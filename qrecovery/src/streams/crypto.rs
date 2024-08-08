mod send {
    use std::{
        io,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll, Waker},
    };

    use bytes::BufMut;
    use qbase::{
        frame::{io::WriteCryptoFrame, CryptoFrame},
        util::DescribeData,
        varint::{VarInt, VARINT_MAX},
    };
    use tokio::io::AsyncWrite;

    use crate::send::sndbuf::SendBuf;

    #[derive(Debug)]
    pub(super) struct Sender {
        sndbuf: SendBuf,
        writable_waker: Option<Waker>,
        flush_waker: Option<Waker>,
    }

    impl Sender {
        fn try_read_data(&mut self, mut buffer: &mut [u8]) -> Option<(CryptoFrame, usize)> {
            let buf_len = buffer.len();
            let predicate = |offset: u64| CryptoFrame::estimate_max_capacity(buf_len, offset);
            if let Some((offset, _is_fresh, data)) = self.sndbuf.pick_up(predicate, usize::MAX) {
                let frame = CryptoFrame {
                    offset: VarInt::from_u64(offset).unwrap(),
                    length: VarInt::try_from(data.len()).unwrap(),
                };
                buffer.put_crypto_frame(&frame, &data);
                let written = buf_len - buffer.remaining_mut();
                Some((frame, written))
            } else {
                None
            }
        }

        fn on_data_acked(&mut self, crypto_frame: &CryptoFrame) {
            self.sndbuf.on_data_acked(&crypto_frame.range());
            if self.sndbuf.remaining_mut() > 0 {
                if let Some(waker) = self.writable_waker.take() {
                    waker.wake();
                }
            }
        }

        fn may_loss_data(&mut self, crypto_frame: &CryptoFrame) {
            self.sndbuf.may_loss_data(&crypto_frame.range())
        }
    }

    impl Sender {
        fn poll_write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            assert!(self.writable_waker.is_none());
            assert!(self.flush_waker.is_none());
            if self.sndbuf.len() + buf.len() as u64 > VARINT_MAX {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "The largest offset delivered on the crypto stream cannot exceed 2^62-1",
                )));
            }

            let remaining = self.sndbuf.remaining_mut();
            if remaining > 0 {
                let n = std::cmp::min(remaining, buf.len());
                Poll::Ready(Ok(self.sndbuf.write(&buf[..n])))
            } else {
                self.writable_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }

        fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            assert!(self.flush_waker.is_none());
            if self.sndbuf.is_all_rcvd() {
                Poll::Ready(Ok(()))
            } else {
                self.flush_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    pub(super) type ArcSender = Arc<Mutex<Sender>>;

    #[derive(Debug, Clone)]
    pub struct CryptoStreamWriter(pub(super) ArcSender);
    #[derive(Debug, Clone)]
    pub struct CryptoStreamOutgoing(pub(super) ArcSender);

    impl AsyncWrite for CryptoStreamWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.0.lock().unwrap().poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.0.lock().unwrap().poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            // 永远不会关闭，直到Connection级别的关闭
            Poll::Pending
        }
    }

    impl CryptoStreamOutgoing {
        pub fn try_read_data(&self, buffer: &mut [u8]) -> Option<(CryptoFrame, usize)> {
            self.0.lock().unwrap().try_read_data(buffer)
        }

        pub fn on_data_acked(&self, crypto_frame: &CryptoFrame) {
            self.0.lock().unwrap().on_data_acked(crypto_frame)
        }

        pub fn may_loss_data(&self, crypto_frame: &CryptoFrame) {
            self.0.lock().unwrap().may_loss_data(crypto_frame)
        }
    }

    pub(super) fn create(capacity: usize) -> ArcSender {
        Arc::new(Mutex::new(Sender {
            sndbuf: SendBuf::with_capacity(capacity),
            writable_waker: None,
            flush_waker: None,
        }))
    }
}

mod recv {
    use std::{
        io,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll, Waker},
    };

    use bytes::{BufMut, Bytes};
    use qbase::{frame::CryptoFrame, varint::VARINT_MAX};
    use tokio::io::{AsyncRead, ReadBuf};

    use crate::recv::rcvbuf::RecvBuf;

    #[derive(Debug)]
    pub(super) struct Recver {
        rcvbuf: RecvBuf,
        read_waker: Option<Waker>,
    }

    impl Recver {
        fn recv(&mut self, offset: u64, data: Bytes) {
            assert!(offset + data.len() as u64 <= VARINT_MAX);
            self.rcvbuf.recv(offset, data);
            if self.rcvbuf.is_readable() {
                if let Some(waker) = self.read_waker.take() {
                    waker.wake()
                }
            }
        }

        fn poll_read<T: BufMut>(
            &mut self,
            cx: &mut Context<'_>,
            buf: &mut T,
        ) -> Poll<io::Result<()>> {
            assert!(self.read_waker.is_none());
            if self.rcvbuf.is_readable() {
                self.rcvbuf.read(buf);
                Poll::Ready(Ok(()))
            } else {
                self.read_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    pub(super) type ArcRecver = Arc<Mutex<Recver>>;

    #[derive(Debug, Clone)]
    pub struct CryptoStreamReader(pub(super) ArcRecver);
    #[derive(Debug, Clone)]
    pub struct CryptoStreamIncoming(pub(super) ArcRecver);

    impl AsyncRead for CryptoStreamReader {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.0.lock().unwrap().poll_read(cx, buf)
        }
    }

    impl CryptoStreamIncoming {
        pub fn recv_crypto_frame(&self, (frame, data): &(CryptoFrame, Bytes)) {
            self.0
                .lock()
                .unwrap()
                .recv(frame.offset.into(), data.clone())
        }
    }

    pub(super) fn create() -> ArcRecver {
        Arc::new(Mutex::new(Recver {
            rcvbuf: RecvBuf::default(),
            read_waker: None,
        }))
    }
}

pub use recv::{CryptoStreamIncoming, CryptoStreamReader};
pub use send::{CryptoStreamOutgoing, CryptoStreamWriter};

/// Crypto data stream
#[derive(Debug, Clone)]
pub struct CryptoStream {
    sender: send::ArcSender,
    recver: recv::ArcRecver,
}

impl CryptoStream {
    pub fn new(sndbuf_size: usize, _rcvbuf_size: usize) -> Self {
        Self {
            sender: send::create(sndbuf_size),
            recver: recv::create(),
        }
    }

    pub fn writer(&self) -> CryptoStreamWriter {
        CryptoStreamWriter(self.sender.clone())
    }

    pub fn reader(&self) -> CryptoStreamReader {
        CryptoStreamReader(self.recver.clone())
    }

    pub fn outgoing(&self) -> send::CryptoStreamOutgoing {
        send::CryptoStreamOutgoing(self.sender.clone())
    }

    pub fn incoming(&self) -> recv::CryptoStreamIncoming {
        recv::CryptoStreamIncoming(self.recver.clone())
    }
}

#[cfg(test)]
mod tests {
    use qbase::{frame::CryptoFrame, varint::VarInt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::CryptoStream;

    #[tokio::test]
    async fn test_read() {
        let crypto_stream: CryptoStream = CryptoStream::new(1000_0000, 0);
        crypto_stream
            .writer()
            .write_all(b"hello world")
            .await
            .unwrap();

        crypto_stream.incoming().recv_crypto_frame(&(
            CryptoFrame {
                offset: VarInt::from_u32(0),
                length: VarInt::from_u32(11),
            },
            bytes::Bytes::copy_from_slice(b"hello world"),
        ));
        let mut buf = [0u8; 11];
        crypto_stream.reader().read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf[..], b"hello world");
    }
}
