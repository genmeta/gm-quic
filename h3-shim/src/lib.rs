use std::{
    marker::PhantomPinned,
    pin::Pin,
    sync::Arc,
    task::{ready, Context, Poll},
};

use bytes::{Buf, BufMut};
use futures::Stream;
use h3::quic;
use qrecovery::{recv::Reader, send::Writer, streams::StreamReset};
use tokio::io::ReadBuf;

type BoxStream<T> = Pin<Box<dyn Stream<Item = T> + Send + Sync>>;

struct OpenBiStreams(BoxStream<Result<(Reader, Writer), Error>>);

impl OpenBiStreams {
    pub fn new(conn: ::quic::QuicConnection) -> Self {
        let stream = futures::stream::unfold(conn, |conn| async {
            let bidi = conn
                .open_bi_stream()
                .await
                .and_then(|o| o.ok_or_else(sid_exceed_error))
                .map_err(Into::into);
            Some((bidi, conn))
        });
        Self(Box::pin(stream))
    }

    pub fn poll_open<B>(&mut self, cx: &mut Context<'_>) -> Poll<Result<BidiStream<B>, Error>> {
        self.0
            .as_mut()
            .poll_next(cx)
            .map(Option::unwrap)
            .map_ok(BidiStream::new)
    }
}

struct OpenUniStreams(BoxStream<Result<Writer, Error>>);

impl OpenUniStreams {
    pub fn new(conn: ::quic::QuicConnection) -> Self {
        let stream = futures::stream::unfold(conn, |conn| async {
            let send = conn
                .open_uni_stream()
                .await
                .and_then(|o| o.ok_or_else(sid_exceed_error))
                .map_err(Into::into);
            Some((send, conn))
        });
        Self(Box::pin(stream))
    }

    pub fn poll_open<B>(&mut self, cx: &mut Context<'_>) -> Poll<Result<SendStream<B>, Error>> {
        self.0
            .as_mut()
            .poll_next(cx)
            .map(Option::unwrap)
            .map_ok(SendStream::new)
    }
}

struct AcceptBiStreams(BoxStream<Result<(Reader, Writer), Error>>);

impl AcceptBiStreams {
    pub fn new(conn: ::quic::QuicConnection) -> Self {
        let stream = futures::stream::unfold(conn, |conn| async {
            let bidi = conn.accept_bi_stream().await.map_err(Into::into);
            if bidi.is_err() && !conn.is_active() {
                return None;
            }
            Some((bidi, conn))
        });
        Self(Box::pin(stream))
    }

    pub fn poll_accept<B>(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<BidiStream<B>>, Error>> {
        self.0
            .as_mut()
            .poll_next(cx)
            .map(Option::transpose)
            .map_ok(|rw| rw.map(BidiStream::new))
    }
}

struct AcceptUniStreams(BoxStream<Result<Reader, Error>>);

impl AcceptUniStreams {
    pub fn new(conn: ::quic::QuicConnection) -> Self {
        let stream = futures::stream::unfold(conn, |conn| async {
            let recv = conn.accept_uni_stream().await.map_err(Into::into);
            if recv.is_err() && !conn.is_active() {
                return None;
            }
            Some((recv, conn))
        });
        Self(Box::pin(stream))
    }

    pub fn poll_accept(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<RecvStream>, Error>> {
        self.0
            .as_mut()
            .poll_next(cx)
            .map(Option::transpose)
            .map_ok(|r| r.map(RecvStream::new))
    }
}

pub struct QuicConnection {
    connection: ::quic::QuicConnection,
    accpet_bi: AcceptBiStreams,
    accpet_uni: AcceptUniStreams,
    open_bi: OpenBiStreams,
    open_uni: OpenUniStreams,
}

impl QuicConnection {
    pub fn new(conn: ::quic::QuicConnection) -> Self {
        Self {
            accpet_bi: AcceptBiStreams::new(conn.clone()),
            accpet_uni: AcceptUniStreams::new(conn.clone()),
            open_bi: OpenBiStreams::new(conn.clone()),
            open_uni: OpenUniStreams::new(conn.clone()),
            connection: conn,
        }
    }
}

impl<B: bytes::Buf> quic::Connection<B> for QuicConnection {
    type RecvStream = RecvStream;

    type OpenStreams = OpenStreams;

    type AcceptError = Error;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::RecvStream>, Self::AcceptError>> {
        self.accpet_uni.poll_accept(cx)
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::BidiStream>, Self::AcceptError>> {
        self.accpet_bi.poll_accept(cx)
    }

    fn opener(&self) -> Self::OpenStreams {
        OpenStreams::new(self.connection.clone())
    }
}

impl<B: bytes::Buf> quic::OpenStreams<B> for QuicConnection {
    type BidiStream = BidiStream<B>;

    type SendStream = SendStream<B>;

    type OpenError = Error;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, Self::OpenError>> {
        self.open_bi.poll_open(cx)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, Self::OpenError>> {
        self.open_uni.poll_open(cx)
    }

    fn close(&mut self, _code: h3::error::Code, reason: &[u8]) {
        let reason = unsafe { String::from_utf8_unchecked(reason.to_vec()) };
        self.connection.close(reason);
    }
}

pub struct OpenStreams {
    connection: ::quic::QuicConnection,
    open_bi: OpenBiStreams,
    open_uni: OpenUniStreams,
}

fn sid_exceed_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Other,
        "the stream IDs in the `dir` direction exceed 2^60, this is very very hard to happen.",
    )
}

impl OpenStreams {
    fn new(conn: ::quic::QuicConnection) -> Self {
        Self {
            open_bi: OpenBiStreams::new(conn.clone()),
            open_uni: OpenUniStreams::new(conn.clone()),
            connection: conn,
        }
    }
}

impl<B: bytes::Buf> quic::OpenStreams<B> for OpenStreams {
    type BidiStream = BidiStream<B>;

    type SendStream = SendStream<B>;

    type OpenError = Error;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, Self::OpenError>> {
        self.open_bi.poll_open(cx)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, Self::OpenError>> {
        self.open_uni.poll_open(cx)
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        let _ignored = code;
        let reason = unsafe { String::from_utf8_unchecked(reason.to_vec()) };
        self.connection.close(reason);
    }
}

// pub struct DatagramReader(qunreliable::DatagramReader);

// pub struct DatagramWriter(qunreliable::DatagramWriter);

pub struct RecvStream(Result<Reader, Error>);

impl RecvStream {
    fn new(reader: Reader) -> Self {
        Self(Ok(reader))
    }
}

impl quic::RecvStream for RecvStream {
    type Buf = bytes::Bytes;

    type Error = Error;

    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Self::Buf>, Self::Error>> {
        let reader = match &mut self.0 {
            Ok(reader) => reader,
            Err(e) => return Poll::Ready(Err(e.clone())),
        };

        let mut buf = vec![0; 4096];
        let mut read_buf = ReadBuf::new(&mut buf);
        let poll = tokio::io::AsyncRead::poll_read(Pin::new(reader), cx, &mut read_buf);
        let data_written = read_buf.remaining_mut() != buf.len();
        match ready!(poll) {
            Ok(()) => {
                if !data_written {
                    return Poll::Ready(Ok(None));
                }
                Poll::Ready(Ok(Some(bytes::Bytes::from(buf))))
            }
            Err(e) => Poll::Ready(Err(e.into())),
        }
    }

    fn stop_sending(&mut self, error_code: u64) {
        if self.0.is_err() {
            return;
        }
        let err = Err(Error::from(StreamReset(error_code)));
        let reader = core::mem::replace(&mut self.0, err).expect("unreachable");
        reader.stop(error_code);
    }

    fn recv_id(&self) -> quic::StreamId {
        unimplemented!()
    }
}

pub struct SendStream<B> {
    writer: Result<Writer, Error>,
    frame: Option<Frame<B>>,
}

impl<B> SendStream<B> {
    pub fn new(writer: Writer) -> Self {
        Self {
            writer: Ok(writer),
            frame: None,
        }
    }
}

pub struct Frame<B> {
    _buf: quic::WriteBuf<B>,
    buf: &'static [u8],
    _pin: PhantomPinned,
}

impl<B: bytes::Buf> Frame<B> {
    fn new(buf: impl Into<quic::WriteBuf<B>>) -> Self {
        let _buf = buf.into();
        let buf = unsafe { std::mem::transmute::<&[u8], &[u8]>(_buf.chunk()) };
        Self {
            _buf,
            buf,
            _pin: PhantomPinned,
        }
    }
}

impl<B: bytes::Buf> quic::SendStream<B> for SendStream<B> {
    type Error = Error;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let writer = self.writer.as_mut().map_err(|e| e.clone())?;
        let Some(Frame { buf, .. }) = self.frame.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        let poll = tokio::io::AsyncWrite::poll_write(Pin::new(writer), cx, buf);
        match ready!(poll).map_err(Error::from) {
            Ok(written) => {
                *buf = &buf[written..];
                if buf.is_empty() {
                    self.frame = None;
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            }
            Err(e) => {
                self.writer = Err(e.clone());
                self.frame = None;
                Poll::Ready(Err(e))
            }
        }
    }

    fn send_data<T: Into<quic::WriteBuf<B>>>(&mut self, data: T) -> Result<(), Self::Error> {
        if let Err(e) = &self.writer {
            return Err(e.clone());
        }
        assert!(self.frame.is_none());
        self.frame = Some(Frame::new(data));
        Ok(())
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        assert!(self.frame.is_none());

        match &mut self.writer {
            Ok(writer) => tokio::io::AsyncWrite::poll_shutdown(Pin::new(writer), cx).map(|r| {
                r.map_err(Error::from)
                    .inspect_err(|e| self.writer = Err(e.clone()))
                // .inspect_err(|_| self.frame = None)
            }),
            Err(e) => Poll::Ready(Err(e.clone())),
        }
    }

    fn reset(&mut self, reset_code: u64) {
        assert!(self.frame.is_none());
        if self.writer.is_err() {
            return;
        }

        let error = Err(Error::from(StreamReset(reset_code)));
        let writer = core::mem::replace(&mut self.writer, error).expect("unreachable");
        writer.cancel(reset_code);
    }

    fn send_id(&self) -> quic::StreamId {
        unimplemented!()
    }
}

impl<B: bytes::Buf> quic::SendStreamUnframed<B> for SendStream<B> {
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, Self::Error>> {
        assert!(self.frame.is_none());

        match &mut self.writer {
            Ok(writer) => {
                tokio::io::AsyncWrite::poll_write(Pin::new(writer), cx, buf.chunk()).map(|r| {
                    r.map_err(Error::from)
                        .inspect_err(|e| self.writer = Err(e.clone()))
                })
            }
            Err(e) => Poll::Ready(Err(e.clone())),
        }
    }
}
pub struct BidiStream<B> {
    send: SendStream<B>,
    recv: RecvStream,
}

impl<B> BidiStream<B> {
    pub fn new((reader, writer): (Reader, Writer)) -> Self {
        Self {
            send: SendStream::new(writer),
            recv: RecvStream::new(reader),
        }
    }
}
impl<B> quic::RecvStream for BidiStream<B> {
    type Buf = bytes::Bytes;

    type Error = Error;

    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Self::Buf>, Self::Error>> {
        self.recv.poll_data(cx)
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.recv.stop_sending(error_code);
    }

    fn recv_id(&self) -> quic::StreamId {
        self.recv.recv_id()
    }
}

impl<B: bytes::Buf> quic::SendStream<B> for BidiStream<B> {
    type Error = Error;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.send.poll_ready(cx)
    }

    fn send_data<T: Into<quic::WriteBuf<B>>>(&mut self, data: T) -> Result<(), Self::Error> {
        self.send.send_data(data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.send.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.send.reset(reset_code);
    }

    fn send_id(&self) -> quic::StreamId {
        self.send.send_id()
    }
}

#[derive(Clone)]
pub struct Error(Arc<std::io::Error>);

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl core::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

impl quic::Error for Error {
    #[inline]
    fn is_timeout(&self) -> bool {
        false
    }

    #[inline]
    fn err_code(&self) -> Option<u64> {
        core::error::Error::source(self).and_then(|e| e.downcast_ref::<StreamReset>().map(|e| e.0))
    }
}

impl From<std::io::Error> for Error {
    #[inline]
    fn from(value: std::io::Error) -> Self {
        Self(value.into())
    }
}

impl From<StreamReset> for Error {
    #[inline]
    fn from(value: StreamReset) -> Self {
        std::io::Error::new(std::io::ErrorKind::BrokenPipe, value).into()
    }
}
