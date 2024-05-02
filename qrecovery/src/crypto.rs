/// Crypto data stream

pub(crate) mod send {
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
        fn try_send<B>(&mut self, mut buffer: B) -> Option<CryptoFrame>
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
                self.wake_write();
                Some(frame)
            } else {
                None
            }
        }

        fn wake_write(&mut self) {
            if self.sndbuf.remaining_mut() > 0 {
                if let Some(waker) = self.writable_waker.take() {
                    waker.wake();
                }
            }
        }

        fn ack_rcvd(&mut self, range: &Range<u64>) {
            self.sndbuf.ack_rcvd(range)
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
                    "The largest offset delivered on a stream cannot exceed 2^62-1",
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

    #[derive(Debug)]
    pub(crate) struct CryptoWriter(ArcSender);
    #[derive(Debug)]
    pub(crate) struct CryptoOutgoing(ArcSender);

    impl AsyncWrite for CryptoWriter {
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

    impl CryptoOutgoing {
        pub(crate) fn try_send<B>(&mut self, buffer: B) -> Option<CryptoFrame>
        where
            B: BufMut,
        {
            self.0.lock().unwrap().try_send(buffer)
        }

        pub(crate) fn ack_rcvd(&mut self, range: &Range<u64>) {
            self.0.lock().unwrap().ack_rcvd(range)
        }

        pub(crate) fn may_loss(&mut self, range: &Range<u64>) {
            self.0.lock().unwrap().may_loss(range)
        }
    }

    pub(crate) fn create(capacity: usize) -> (CryptoOutgoing, CryptoWriter) {
        let sender = Arc::new(Mutex::new(Sender {
            sndbuf: SendBuf::with_capacity(capacity),
            writable_waker: None,
            flush_waker: None,
        }));
        (CryptoOutgoing(sender.clone()), CryptoWriter(sender))
    }
}

pub(crate) mod recv {
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

    #[derive(Debug)]
    pub(crate) struct CryptoReader(ArcRecver);
    #[derive(Debug)]
    pub(crate) struct CryptoIncoming(ArcRecver);

    impl AsyncRead for CryptoReader {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.0.lock().unwrap().poll_read(cx, buf)
        }
    }

    impl CryptoIncoming {
        pub(crate) fn recv(&mut self, offset: u64, data: Bytes) {
            self.0.lock().unwrap().recv(offset, data)
        }
    }

    pub(crate) fn create() -> (CryptoIncoming, CryptoReader) {
        let recver = Arc::new(Mutex::new(Recver {
            rcvbuf: RecvBuf::default(),
            read_waker: None,
        }));
        (CryptoIncoming(recver.clone()), CryptoReader(recver))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
