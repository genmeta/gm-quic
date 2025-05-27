use std::{
    io,
    ops::Deref,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures::Stream;
use gm_quic::{StreamId, StreamReader, StreamWriter};
use h3::quic::{ConnectionErrorIncoming, StreamErrorIncoming};

use crate::{
    error::{self, convert_connection_io_error},
    streams::{BidiStream, RecvStream, SendStream},
};
// 由于数据报的特性，接收流的特征，QuicConnection不允许被Clone
pub struct QuicConnection {
    connection: Arc<gm_quic::Connection>,
    accpet_bi: AcceptBiStreams,
    accpet_uni: AcceptUniStreams,
    open_bi: OpenBiStreams,
    open_uni: OpenUniStreams,
}

impl Deref for QuicConnection {
    type Target = Arc<gm_quic::Connection>;

    fn deref(&self) -> &Self::Target {
        &self.connection
    }
}

impl QuicConnection {
    pub fn new(conn: Arc<gm_quic::Connection>) -> Self {
        Self {
            accpet_bi: AcceptBiStreams::new(conn.clone()),
            accpet_uni: AcceptUniStreams::new(conn.clone()),
            open_bi: OpenBiStreams::new(conn.clone()),
            open_uni: OpenUniStreams::new(conn.clone()),
            connection: conn,
        }
    }
}

/// 首先，QuicConnection需能主动创建双向流和发送流，以及关闭连接.
impl<B: bytes::Buf> h3::quic::OpenStreams<B> for QuicConnection {
    type BidiStream = BidiStream<B>;

    type SendStream = SendStream<B>;

    #[inline]
    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        // 以下代码的代价是，每次调用open_bi_stream()都是一个新的实现了Future的闭包
        // 实际上应该是同一个，否则每次poll都会造成open_bi_stream()中的每个await点
        // 都得重新执行一遍，这是有问题的。
        // let mut fut = self.connection.open_bi_stream();
        // let mut task = pin!(fut);
        // let result = ready!(task.as_mut().poll_unpin(cx));
        // let bi_stream = result
        //     .and_then(|o| o.ok_or_else(sid_exceed_limit_error))
        //     .map(|s| BidiStream::new(s))
        //     .map_err(Into::into);
        // Poll::Ready(bi_stream)

        // 以下代码的问题是：不可重入，切忌上个流未成功打开返回前，任何地方不可尝试打开流
        self.open_bi.poll_open(cx)

        // 应该的做法是，与这个poll_open_bidi关联的一个open_bi_stream()返回的固定Future来poll
    }

    #[inline]
    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        self.open_uni.poll_open(cx)
    }

    #[inline]
    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        let reason = unsafe { String::from_utf8_unchecked(reason.to_vec()) };
        self.connection.close(reason, code.into());
    }
}

/// 其次，QuicConnection需能接收双向流和发送流.
/// 欲实现`h3::quic::Connection`，必须先实现`h3::quic::OpenStreams`
impl<B: bytes::Buf> h3::quic::Connection<B> for QuicConnection {
    type RecvStream = RecvStream;

    type OpenStreams = OpenStreams;

    #[inline]
    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        self.accpet_uni.poll_accept(cx)
    }

    #[inline]
    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        self.accpet_bi.poll_accept(cx)
    }

    /// 为何要再来个这玩意？多次一举
    /// 如果这个opener()的返回值只负责打开一条流，不可重用；
    /// 再打开流，要再次调用opener()来open，那还有点意思
    #[inline]
    fn opener(&self) -> Self::OpenStreams {
        OpenStreams::new(self.connection.clone())
    }
}

/// 多此一举，实在是多此一举
pub struct OpenStreams {
    connection: Arc<gm_quic::Connection>,
    open_bi: OpenBiStreams,
    open_uni: OpenUniStreams,
}

impl OpenStreams {
    fn new(conn: Arc<gm_quic::Connection>) -> Self {
        Self {
            open_bi: OpenBiStreams::new(conn.clone()),
            open_uni: OpenUniStreams::new(conn.clone()),
            connection: conn,
        }
    }
}

impl Clone for OpenStreams {
    fn clone(&self) -> Self {
        Self {
            open_bi: OpenBiStreams::new(self.connection.clone()),
            open_uni: OpenUniStreams::new(self.connection.clone()),
            connection: self.connection.clone(),
        }
    }
}

/// 跟QuicConnection::poll_open_bidi()的实现一样，重复
impl<B: bytes::Buf> h3::quic::OpenStreams<B> for OpenStreams {
    type BidiStream = BidiStream<B>;

    type SendStream = SendStream<B>;

    #[inline]
    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        self.open_bi.poll_open(cx)
    }

    #[inline]
    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        self.open_uni.poll_open(cx)
    }

    #[inline]
    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        let reason = unsafe { String::from_utf8_unchecked(reason.to_vec()) };
        self.connection.close(reason, code.into());
    }
}

type BoxStream<T> = Pin<Box<dyn Stream<Item = T> + Send + Sync>>;

fn sid_exceed_limit_error() -> io::Error {
    io::Error::other(
        "the stream IDs in the `dir` direction exceed 2^60, this is very very hard to happen.",
    )
}

#[allow(clippy::type_complexity)]
struct OpenBiStreams(
    BoxStream<Result<(StreamId, (StreamReader, StreamWriter)), ConnectionErrorIncoming>>,
);

impl OpenBiStreams {
    fn new(conn: Arc<gm_quic::Connection>) -> Self {
        let stream = futures::stream::unfold(conn, |conn| async {
            let bidi = conn
                .open_bi_stream()
                .await
                .and_then(|o| o.ok_or_else(sid_exceed_limit_error))
                .map_err(convert_connection_io_error);
            Some((bidi, conn))
        });
        Self(Box::pin(stream))
    }

    /// TODO: 以此法实现的`poll_open`方法，不可重入，即A、B同时要打开一个流，
    /// 实际上只有一个能成功，后一个的waker会取代前一个的waker注册在stream中，导致前一个waker无法被唤醒
    /// 以下同
    fn poll_open<B>(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<BidiStream<B>, StreamErrorIncoming>> {
        self.0
            .as_mut()
            .poll_next(cx)
            .map(Option::unwrap)
            .map_ok(|(sid, stream)| BidiStream::new(sid, stream))
            .map_err(|e| StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: e,
            })
    }
}

struct OpenUniStreams(BoxStream<Result<(StreamId, StreamWriter), ConnectionErrorIncoming>>);

impl OpenUniStreams {
    fn new(conn: Arc<gm_quic::Connection>) -> Self {
        let stream = futures::stream::unfold(conn, |conn| async {
            let send = conn
                .open_uni_stream()
                .await
                .and_then(|o| o.ok_or_else(sid_exceed_limit_error))
                .map_err(convert_connection_io_error);
            Some((send, conn))
        });
        Self(Box::pin(stream))
    }

    fn poll_open<B>(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<SendStream<B>, StreamErrorIncoming>> {
        self.0
            .as_mut()
            .poll_next(cx)
            .map(Option::unwrap)
            .map_ok(|(sid, writer)| SendStream::new(sid, writer))
            .map_err(|e| StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: e,
            })
    }
}

#[allow(clippy::type_complexity)]
struct AcceptBiStreams(
    BoxStream<Result<(StreamId, (StreamReader, StreamWriter)), ConnectionErrorIncoming>>,
);

impl AcceptBiStreams {
    fn new(conn: Arc<gm_quic::Connection>) -> Self {
        let stream = futures::stream::unfold(conn, |conn| async {
            Some((
                conn.accept_bi_stream()
                    .await
                    .map(Option::unwrap)
                    .map_err(error::convert_connection_io_error),
                conn,
            ))
        });
        Self(Box::pin(stream))
    }

    fn poll_accept<B>(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<BidiStream<B>, ConnectionErrorIncoming>> {
        self.0
            .as_mut()
            .poll_next(cx)
            .map(Option::unwrap)
            .map_ok(|(sid, stream)| BidiStream::new(sid, stream))
    }
}

struct AcceptUniStreams(BoxStream<Result<(StreamId, StreamReader), ConnectionErrorIncoming>>);

impl AcceptUniStreams {
    fn new(conn: Arc<gm_quic::Connection>) -> Self {
        let stream = futures::stream::unfold(conn, |conn| async {
            let uni = conn
                .accept_uni_stream()
                .await
                .map(Option::unwrap)
                .map_err(error::convert_connection_io_error);
            Some((uni, conn))
        });
        Self(Box::pin(stream))
    }

    fn poll_accept(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<RecvStream, ConnectionErrorIncoming>> {
        self.0
            .as_mut()
            .poll_next(cx)
            .map(Option::unwrap)
            .map_ok(|(sid, reader)| RecvStream::new(sid, reader))
    }
}
