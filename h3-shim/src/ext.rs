use std::task::{Context, Poll};

use gm_quic::{DatagramReader, DatagramWriter};
use h3_datagram::{
    datagram::Datagram,
    quic_traits::{RecvDatagramExt, SendDatagramExt},
};

use crate::{Error, conn::QuicConnection};

impl<B: bytes::Buf> SendDatagramExt<B> for QuicConnection {
    type Error = Error;

    #[inline]
    fn send_datagram(&mut self, data: Datagram<B>) -> Result<(), Self::Error> {
        self.send_datagram.send_datagram(data)
    }
}

impl RecvDatagramExt for QuicConnection {
    type Buf = bytes::Bytes;

    type Error = Error;

    // [`Poll::Ready(Err(e))`] means the connection is broken.
    // [`Poll::Ready(Ok(None))`] is meaningless.

    #[inline]
    fn poll_accept_datagram(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, Self::Error>> {
        self.recv_datagram.poll_accept_datagram(cx)
    }
}

pub struct SendDatagram(pub(crate) Result<DatagramWriter, Error>);

impl<B: bytes::Buf> SendDatagramExt<B> for SendDatagram {
    type Error = Error;

    fn send_datagram(&mut self, data: Datagram<B>) -> Result<(), Self::Error> {
        let writer = match &mut self.0 {
            Ok(writer) => writer,
            Err(e) => return Err(e.clone()),
        };
        let mut buf = bytes::BytesMut::new();
        data.encode(&mut buf);
        writer
            .send_bytes(buf.freeze())
            .map_err(Error::from)
            .inspect_err(|e| self.0 = Err(e.clone()))
    }
}

pub struct RecvDatagram(pub(crate) Result<DatagramReader, Error>);

impl RecvDatagramExt for RecvDatagram {
    type Buf = bytes::Bytes;

    type Error = Error;

    fn poll_accept_datagram(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, Self::Error>> {
        let reader = match &mut self.0 {
            Ok(reader) => reader,
            Err(e) => return Poll::Ready(Err(e.clone())),
        };

        reader.poll_recv(cx).map(|r| {
            r.map(Some)
                .map_err(Error::from)
                .inspect_err(|e| self.0 = Err(e.clone()))
        })
    }
}
