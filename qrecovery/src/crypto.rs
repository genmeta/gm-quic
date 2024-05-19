/// Crypto data stream
use qbase::{error::Error, frame::CryptoFrame};

mod send {
    use crate::send::sndbuf::SendBuf;
    use bytes::BufMut;
    use qbase::{
        frame::{ext::WriteCryptoFrame, CryptoFrame},
        varint::{VarInt, VARINT_MAX},
    };
    use std::{
        io,
        ops::Range,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll, Waker},
    };
    use tokio::io::AsyncWrite;

    #[derive(Debug)]
    pub(super) struct Sender {
        sndbuf: SendBuf,
        writable_waker: Option<Waker>,
        flush_waker: Option<Waker>,
    }

    impl Sender {
        fn try_send<B>(&mut self, mut buffer: B) -> Option<(CryptoFrame, usize)>
        where
            B: BufMut,
        {
            let remaining = buffer.remaining_mut();
            let estimater = |offset: u64| CryptoFrame::estimate_max_capacity(remaining, offset);
            if let Some((offset, data)) = self.sndbuf.pick_up(estimater) {
                let frame = CryptoFrame {
                    offset: VarInt::from_u64(offset).unwrap(),
                    length: VarInt::from_u32(data.len() as u32),
                };
                buffer.put_crypto_frame(&frame, data);
                Some((frame, remaining - buffer.remaining_mut()))
            } else {
                None
            }
        }

        fn ack_rcvd(&mut self, range: &Range<u64>) {
            self.sndbuf.confirm_rcvd(range);
            if self.sndbuf.remaining_mut() > 0 {
                if let Some(waker) = self.writable_waker.take() {
                    waker.wake();
                }
            }
        }

        fn may_loss(&mut self, range: &Range<u64>) {
            self.sndbuf.may_loss(range)
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
        pub(crate) fn try_send<B>(&mut self, buffer: B) -> Option<(CryptoFrame, usize)>
        where
            B: BufMut,
        {
            self.0.lock().unwrap().try_send(buffer)
        }

        pub(super) fn ack_rcvd(&mut self, range: &Range<u64>) {
            self.0.lock().unwrap().ack_rcvd(range)
        }

        pub(super) fn may_loss(&mut self, range: &Range<u64>) {
            self.0.lock().unwrap().may_loss(range)
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
    use crate::recv::rcvbuf::RecvBuf;
    use bytes::{BufMut, Bytes};
    use qbase::varint::VARINT_MAX;
    use std::{
        io,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll, Waker},
    };
    use tokio::io::{AsyncRead, ReadBuf};

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
        pub(super) fn recv(&mut self, offset: u64, data: Bytes) {
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

/// Crypto data stream
/// ## Example
/// ```rust
/// use bytes::Bytes;
/// use qbase::{frame::CryptoFrame, varint::VarInt};
/// use qrecovery::crypto::{CryptoStream, TransmitCrypto};
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
#[derive(Debug)]
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

pub trait TransmitCrypto {
    type Buffer: bytes::BufMut;

    fn try_send_data(&mut self, buf: &mut Self::Buffer) -> Option<(CryptoFrame, usize)>;

    fn confirm_data(&mut self, data_frame: CryptoFrame);

    fn may_loss_data(&mut self, data_frame: CryptoFrame);

    fn recv_data(&mut self, crypto_frame: CryptoFrame, body: bytes::Bytes) -> Result<(), Error>;
}

impl TransmitCrypto for CryptoStream {
    type Buffer = bytes::BytesMut;

    fn try_send_data(&mut self, buf: &mut Self::Buffer) -> Option<(CryptoFrame, usize)> {
        self.outgoing.try_send(buf)
    }

    fn confirm_data(&mut self, data_frame: CryptoFrame) {
        self.outgoing.ack_rcvd(&data_frame.range());
    }

    fn may_loss_data(&mut self, data_frame: CryptoFrame) {
        self.outgoing.may_loss(&data_frame.range())
    }

    fn recv_data(&mut self, crypto_frame: CryptoFrame, body: bytes::Bytes) -> Result<(), Error> {
        self.incoming.recv(crypto_frame.offset.into_inner(), body);
        Ok(())
    }
}

/// 在0-RTT中，不允许传输CryptoFrame，CryptoFrame只能承担加密握手的Message
/// 实际上，1-RTT中也没任何传输CryptoFrame的需求，只是未来可能会有，且1-RTT是经过验证的安全
#[derive(Debug)]
pub struct NoCrypto;

impl TransmitCrypto for NoCrypto {
    type Buffer = bytes::BytesMut;

    fn try_send_data(&mut self, _buf: &mut Self::Buffer) -> Option<(CryptoFrame, usize)> {
        None
    }

    fn confirm_data(&mut self, _data_frame: CryptoFrame) {
        unreachable!()
    }

    fn may_loss_data(&mut self, _data_frame: CryptoFrame) {
        unreachable!()
    }

    fn recv_data(&mut self, _crypto_frame: CryptoFrame, _body: bytes::Bytes) -> Result<(), Error> {
        unreachable!()
    }
}

#[cfg(test)]
mod tests {
    use super::{CryptoStream, TransmitCrypto};
    use qbase::{frame::CryptoFrame, varint::VarInt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_read() {
        let mut crypto_stream = CryptoStream::new(1000_0000, 0);
        crypto_stream.writer().write(b"hello world").await.unwrap();

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
