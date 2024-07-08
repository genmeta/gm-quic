/// Crypto data stream
use qbase::{error::Error, frame::CryptoFrame};

mod send {
    use std::{
        io,
        ops::Range,
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

    use crate::{
        send::sndbuf::{Picker, SendBuf},
        space::TransportLimit,
    };

    #[derive(Debug)]
    pub(super) struct Sender {
        sndbuf: SendBuf,
        writable_waker: Option<Waker>,
        flush_waker: Option<Waker>,
    }

    impl Sender {
        fn try_read_data(
            &mut self,
            limit: &mut TransportLimit,
            mut buffer: &mut [u8],
        ) -> Option<(CryptoFrame, usize)> {
            let remain = limit.remaining();
            let estimater = |offset: u64| CryptoFrame::estimate_max_capacity(remain, offset);
            let mut picker = Picker::new(estimater, None);
            if let Some((offset, data)) = self.sndbuf.pick_up(&mut picker) {
                let frame = CryptoFrame {
                    offset: VarInt::from_u64(offset).unwrap(),
                    length: VarInt::try_from(data.len()).unwrap(),
                };
                buffer.put_crypto_frame(&frame, &data);
                let written = remain - buffer.remaining_mut();
                limit.record_write(written);
                Some((frame, written))
            } else {
                None
            }
        }

        fn on_data_acked(&mut self, range: &Range<u64>) {
            self.sndbuf.on_data_acked(range);
            if self.sndbuf.remaining_mut() > 0 {
                if let Some(waker) = self.writable_waker.take() {
                    waker.wake();
                }
            }
        }

        fn may_loss_data(&mut self, range: &Range<u64>) {
            self.sndbuf.may_loss_data(range)
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

    type ArcSender = Arc<Mutex<Sender>>;

    #[derive(Debug, Clone)]
    pub struct CryptoStreamWriter(ArcSender);
    #[derive(Debug, Clone)]
    pub(super) struct CryptoStreamOutgoing(ArcSender);

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
        pub(crate) fn try_read_data(
            &self,
            limit: &mut TransportLimit,
            buffer: &mut [u8],
        ) -> Option<(CryptoFrame, usize)> {
            self.0.lock().unwrap().try_read_data(limit, buffer)
        }

        pub(super) fn on_data_acked(&self, range: &Range<u64>) {
            self.0.lock().unwrap().on_data_acked(range)
        }

        pub(super) fn may_loss_data(&self, range: &Range<u64>) {
            self.0.lock().unwrap().may_loss_data(range)
        }
    }

    pub(super) fn create(capacity: usize) -> (CryptoStreamOutgoing, CryptoStreamWriter) {
        let sender = Arc::new(Mutex::new(Sender {
            sndbuf: SendBuf::with_capacity(capacity),
            writable_waker: None,
            flush_waker: None,
        }));
        (
            CryptoStreamOutgoing(sender.clone()),
            CryptoStreamWriter(sender),
        )
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
    use qbase::varint::VARINT_MAX;
    use tokio::io::{AsyncRead, ReadBuf};

    use crate::recv::rcvbuf::RecvBuf;

    #[derive(Debug)]
    struct Recver {
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

    type ArcRecver = Arc<Mutex<Recver>>;

    #[derive(Debug, Clone)]
    pub struct CryptoStreamReader(ArcRecver);
    #[derive(Debug, Clone)]
    pub(super) struct CryptoStreamIncoming(ArcRecver);

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
        pub(super) fn recv(&self, offset: u64, data: Bytes) {
            self.0.lock().unwrap().recv(offset, data)
        }
    }

    pub(super) fn create() -> (CryptoStreamIncoming, CryptoStreamReader) {
        let recver = Arc::new(Mutex::new(Recver {
            rcvbuf: RecvBuf::default(),
            read_waker: None,
        }));
        (
            CryptoStreamIncoming(recver.clone()),
            CryptoStreamReader(recver),
        )
    }
}

pub use recv::CryptoStreamReader;
pub use send::CryptoStreamWriter;

use crate::space::TransportLimit;

/// Crypto data stream
/// ## Example
/// ```rust
/// use bytes::Bytes;
/// use qbase::{frame::CryptoFrame, varint::VarInt};
/// use qrecovery::crypto::CryptoStream;
/// use tokio::io::{AsyncWriteExt, AsyncReadExt};
///
/// #[tokio::main]
/// async fn main() {
///     let mut crypto_stream = CryptoStream::new(1000_0000, 0);
///     crypto_stream.writer().write(b"hello world").await.unwrap();
///
///     // simulate recv some data from network
///     crypto_stream.recv_data(CryptoFrame {
///         offset: VarInt::from_u32(0),
///         length: VarInt::from_u32(11),
///     }, Bytes::copy_from_slice(b"hello world")).unwrap();
///
///     // async read content from crypto stream
///     let mut buf = [0u8; 11];
///     crypto_stream.reader().read_exact(&mut buf).await.unwrap();
///     assert_eq!(&buf[..], b"hello world");
/// }
/// ```
#[derive(Debug, Clone)]
pub struct CryptoStream {
    incoming: recv::CryptoStreamIncoming,
    outgoing: send::CryptoStreamOutgoing,
    reader: CryptoStreamReader,
    writer: CryptoStreamWriter,
}

impl CryptoStream {
    pub fn new(sndbuf_size: usize, _rcvbuf_size: usize) -> Self {
        let (incoming, reader) = recv::create();
        let (outgoing, writer) = send::create(sndbuf_size);
        Self {
            incoming,
            outgoing,
            reader,
            writer,
        }
    }

    pub fn split(&self) -> (CryptoStreamReader, CryptoStreamWriter) {
        (self.reader.clone(), self.writer.clone())
    }

    pub fn reader(&self) -> recv::CryptoStreamReader {
        self.reader.clone()
    }

    pub fn writer(&self) -> send::CryptoStreamWriter {
        self.writer.clone()
    }
}

impl CryptoStream {
    #[inline]
    pub fn try_read_data(
        &self,
        limit: &mut TransportLimit,
        buf: &mut [u8],
    ) -> Option<(CryptoFrame, usize)> {
        self.outgoing.try_read_data(limit, buf)
    }

    #[inline]
    pub fn on_data_acked(&self, data_frame: CryptoFrame) {
        self.outgoing.on_data_acked(&data_frame.range());
    }

    #[inline]
    pub fn may_loss_data(&self, data_frame: CryptoFrame) {
        self.outgoing.may_loss_data(&data_frame.range())
    }

    #[inline]
    pub fn recv_data(&self, crypto_frame: CryptoFrame, body: bytes::Bytes) -> Result<(), Error> {
        self.incoming.recv(crypto_frame.offset.into_inner(), body);
        Ok(())
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

        crypto_stream
            .recv_data(
                CryptoFrame {
                    offset: VarInt::from_u32(0),
                    length: VarInt::from_u32(11),
                },
                bytes::Bytes::copy_from_slice(b"hello world"),
            )
            .unwrap();
        let mut buf = [0u8; 11];
        crypto_stream.reader().read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf[..], b"hello world");
    }
}
