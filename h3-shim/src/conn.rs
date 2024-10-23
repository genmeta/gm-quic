use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use futures::Stream;
use qrecovery::{recv::Reader, send::Writer};

use crate::{
    ext::{RecvDatagram, SendDatagram},
    streams::{BidiStream, RecvStream, SendStream},
    Error,
};

pub struct QuicConnection {
    connection: quic::QuicConnection,
    accpet_bi: AcceptBiStreams,
    accpet_uni: AcceptUniStreams,
    open_bi: OpenBiStreams,
    open_uni: OpenUniStreams,
    pub(crate) send_datagram: SendDatagram,
    pub(crate) recv_datagram: RecvDatagram,
}

impl QuicConnection {
    pub async fn new(conn: quic::QuicConnection) -> Self {
        Self {
            accpet_bi: AcceptBiStreams::new(conn.clone()),
            accpet_uni: AcceptUniStreams::new(conn.clone()),
            open_bi: OpenBiStreams::new(conn.clone()),
            open_uni: OpenUniStreams::new(conn.clone()),
            send_datagram: SendDatagram(conn.datagram_writer().await.map_err(Into::into)),
            recv_datagram: RecvDatagram(conn.datagram_reader().map_err(Into::into)),
            connection: conn,
        }
    }
}

/// 首先，QuicConnection需能主动创建双向流和发送流，以及关闭连接.
impl<B: bytes::Buf> h3::quic::OpenStreams<B> for QuicConnection {
    type BidiStream = BidiStream<B>;

    type SendStream = SendStream<B>;

    type OpenError = Error;

    #[inline]
    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, Self::OpenError>> {
        self.open_bi.poll_open(cx)
    }

    #[inline]
    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, Self::OpenError>> {
        self.open_uni.poll_open(cx)
    }

    #[inline]
    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        let _ignored = code;
        let reason = unsafe { String::from_utf8_unchecked(reason.to_vec()) };
        self.connection.close(reason);
    }
}

/// 其次，QuicConnection需能接收双向流和发送流.
/// 欲实现`h3::quic::Connection`，必须先实现`h3::quic::OpenStreams`
impl<B: bytes::Buf> h3::quic::Connection<B> for QuicConnection {
    type RecvStream = RecvStream;

    type OpenStreams = OpenStreams;

    type AcceptError = Error;

    #[inline]
    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::RecvStream>, Self::AcceptError>> {
        self.accpet_uni.poll_accept(cx)
    }

    #[inline]
    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::BidiStream>, Self::AcceptError>> {
        self.accpet_bi.poll_accept(cx)
    }

    #[inline]
    fn opener(&self) -> Self::OpenStreams {
        OpenStreams::new(self.connection.clone())
    }
}

/// 多此一举，实在是多此一举
pub struct OpenStreams {
    connection: quic::QuicConnection,
    open_bi: OpenBiStreams,
    open_uni: OpenUniStreams,
}

impl OpenStreams {
    fn new(conn: quic::QuicConnection) -> Self {
        Self {
            open_bi: OpenBiStreams::new(conn.clone()),
            open_uni: OpenUniStreams::new(conn.clone()),
            connection: conn,
        }
    }
}

impl<B: bytes::Buf> h3::quic::OpenStreams<B> for OpenStreams {
    type BidiStream = BidiStream<B>;

    type SendStream = SendStream<B>;

    type OpenError = Error;

    #[inline]
    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, Self::OpenError>> {
        self.open_bi.poll_open(cx)
    }

    #[inline]
    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, Self::OpenError>> {
        self.open_uni.poll_open(cx)
    }

    #[inline]
    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        let _ignored = code;
        let reason = unsafe { String::from_utf8_unchecked(reason.to_vec()) };
        self.connection.close(reason);
    }
}

type BoxStream<T> = Pin<Box<dyn Stream<Item = T> + Send + Sync>>;

fn sid_exceed_limit_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::Other,
        "the stream IDs in the `dir` direction exceed 2^60, this is very very hard to happen.",
    )
}

struct OpenBiStreams(BoxStream<Result<(Reader, Writer), Error>>);

impl OpenBiStreams {
    fn new(conn: quic::QuicConnection) -> Self {
        let stream = futures::stream::unfold(conn, |conn| async {
            let bidi = conn
                .open_bi_stream()
                .await
                .and_then(|o| o.ok_or_else(sid_exceed_limit_error))
                .map_err(Into::into);
            Some((bidi, conn))
        });
        Self(Box::pin(stream))
    }

    fn poll_open<B>(&mut self, cx: &mut Context<'_>) -> Poll<Result<BidiStream<B>, Error>> {
        self.0
            .as_mut()
            .poll_next(cx)
            .map(Option::unwrap)
            .map_ok(BidiStream::new)
    }
}

struct OpenUniStreams(BoxStream<Result<Writer, Error>>);

impl OpenUniStreams {
    fn new(conn: quic::QuicConnection) -> Self {
        let stream = futures::stream::unfold(conn, |conn| async {
            let send = conn
                .open_uni_stream()
                .await
                .and_then(|o| o.ok_or_else(sid_exceed_limit_error))
                .map_err(Into::into);
            Some((send, conn))
        });
        Self(Box::pin(stream))
    }

    fn poll_open<B>(&mut self, cx: &mut Context<'_>) -> Poll<Result<SendStream<B>, Error>> {
        self.0
            .as_mut()
            .poll_next(cx)
            .map(Option::unwrap)
            .map_ok(SendStream::new)
    }
}

struct AcceptBiStreams(BoxStream<Result<(Reader, Writer), Error>>);

impl AcceptBiStreams {
    fn new(conn: quic::QuicConnection) -> Self {
        let stream = futures::stream::unfold(conn, |conn| async {
            let bidi = conn.accept_bi_stream().await.map_err(Into::into);
            if bidi.is_err() && !conn.is_active() {
                return None;
            }
            Some((bidi, conn))
        });
        Self(Box::pin(stream))
    }

    fn poll_accept<B>(
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
    fn new(conn: quic::QuicConnection) -> Self {
        let stream = futures::stream::unfold(conn, |conn| async {
            let recv = conn.accept_uni_stream().await.map_err(Into::into);
            if recv.is_err() && !conn.is_active() {
                return None;
            }
            Some((recv, conn))
        });
        Self(Box::pin(stream))
    }

    fn poll_accept(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<RecvStream>, Error>> {
        self.0
            .as_mut()
            .poll_next(cx)
            .map(Option::transpose)
            .map_ok(|r| r.map(RecvStream::new))
    }
}
