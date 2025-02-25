use std::{
    mem::MaybeUninit,
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::Buf;
use gm_quic::{StreamReader, StreamWriter};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::Error;

pub struct SendStream<B> {
    writer: StreamWriter,
    data: Option<h3::quic::WriteBuf<B>>,
    send_id: h3::quic::StreamId,
}

impl<B> SendStream<B> {
    pub fn new(sid: qbase::sid::StreamId, writer: StreamWriter) -> Self {
        let sid = u64::from(sid);
        Self {
            writer,
            data: None,
            send_id: h3::quic::StreamId::try_from(sid).expect("unreachable"),
        }
    }
}

impl<B: bytes::Buf> h3::quic::SendStream<B> for SendStream<B> {
    type Error = Error;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let Some(buf) = self.data.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        loop {
            match ready!(Pin::new(&mut self.writer).poll_write(cx, buf.chunk())) {
                Ok(written) => {
                    buf.advance(written);
                    if buf.remaining() == 0 {
                        self.data = None;
                        return Poll::Ready(Ok(()));
                    }
                }
                Err(e) => {
                    self.data = None;
                    return Poll::Ready(Err(e.into()));
                }
            }
        }
    }

    #[inline]
    fn send_data<T: Into<h3::quic::WriteBuf<B>>>(&mut self, data: T) -> Result<(), Self::Error> {
        assert!(self.data.is_none());
        self.data = Some(data.into());
        Ok(())
    }

    #[inline]
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        assert!(self.data.is_none());

        Pin::new(&mut self.writer)
            .poll_shutdown(cx)
            .map(|r| r.map_err(Error::from))
    }

    #[inline]
    fn reset(&mut self, reset_code: u64) {
        assert!(self.data.is_none());
        self.writer.cancel(reset_code);
    }

    #[inline]
    fn send_id(&self) -> h3::quic::StreamId {
        self.send_id
    }
}

impl<B: bytes::Buf> h3::quic::SendStreamUnframed<B> for SendStream<B> {
    #[inline]
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, Self::Error>> {
        assert!(self.data.is_none());

        Pin::new(&mut self.writer)
            .poll_write(cx, buf.chunk())
            .map(|r| r.map_err(Error::from))
    }
}

pub struct RecvStream {
    reader: StreamReader,
    recv_id: h3::quic::StreamId,
}

impl RecvStream {
    pub(crate) fn new(sid: qbase::sid::StreamId, reader: StreamReader) -> Self {
        let sid = u64::from(sid);
        Self {
            reader,
            recv_id: h3::quic::StreamId::try_from(sid).expect("unreachable"),
        }
    }
}

impl h3::quic::RecvStream for RecvStream {
    type Buf = bytes::Bytes;

    type Error = Error;

    #[inline]
    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Self::Buf>, Self::Error>> {
        let mut uninit_buf = [MaybeUninit::uninit(); 4096];
        let mut read_buf = ReadBuf::uninit(&mut uninit_buf);
        match ready!(Pin::new(&mut self.reader).poll_read(cx, &mut read_buf)) {
            Ok(()) => {
                if read_buf.filled().is_empty() {
                    return Poll::Ready(Ok(None));
                }
                let bytes = bytes::Bytes::copy_from_slice(read_buf.filled());
                Poll::Ready(Ok(Some(bytes)))
            }
            Err(e) => Poll::Ready(Err(e.into())),
        }
    }

    #[inline]
    fn stop_sending(&mut self, error_code: u64) {
        self.reader.stop(error_code);
    }

    #[inline]
    fn recv_id(&self) -> h3::quic::StreamId {
        self.recv_id
    }
}

pub struct BidiStream<B> {
    send: SendStream<B>,
    recv: RecvStream,
}

impl<B> BidiStream<B> {
    pub(crate) fn new(
        sid: qbase::sid::StreamId,
        (reader, writer): (StreamReader, StreamWriter),
    ) -> Self {
        Self {
            send: SendStream::new(sid, writer),
            recv: RecvStream::new(sid, reader),
        }
    }
}

impl<B> h3::quic::RecvStream for BidiStream<B> {
    type Buf = bytes::Bytes;

    type Error = Error;

    #[inline]
    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Self::Buf>, Self::Error>> {
        self.recv.poll_data(cx)
    }

    #[inline]
    fn stop_sending(&mut self, error_code: u64) {
        self.recv.stop_sending(error_code);
    }

    #[inline]
    fn recv_id(&self) -> h3::quic::StreamId {
        self.recv.recv_id()
    }
}

impl<B: bytes::Buf> h3::quic::SendStream<B> for BidiStream<B> {
    type Error = Error;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.send.poll_ready(cx)
    }

    #[inline]
    fn send_data<T: Into<h3::quic::WriteBuf<B>>>(&mut self, data: T) -> Result<(), Self::Error> {
        self.send.send_data(data)
    }

    #[inline]
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.send.poll_finish(cx)
    }

    #[inline]
    fn reset(&mut self, reset_code: u64) {
        self.send.reset(reset_code);
    }

    #[inline]
    fn send_id(&self) -> h3::quic::StreamId {
        self.send.send_id()
    }
}

impl<B: bytes::Buf> h3::quic::SendStreamUnframed<B> for BidiStream<B> {
    #[inline]
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, Self::Error>> {
        self.send.poll_send(cx, buf)
    }
}

impl<B: bytes::Buf> h3::quic::BidiStream<B> for BidiStream<B> {
    type SendStream = SendStream<B>;

    type RecvStream = RecvStream;

    #[inline]
    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        (self.send, self.recv)
    }
}
