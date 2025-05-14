// See https://github.com/hyperium/h3/issues/307"

// use std::{
//     io,
//     ops::Deref,
//     task::{Context, Poll},
// };

// use bytes::{Buf, Bytes};
// use futures::future::BoxFuture;
// use gm_quic::{DatagramReader, DatagramWriter};
// use h3_datagram::{
//     ConnectionErrorIncoming,
//     datagram::EncodedDatagram,
//     quic_traits::{DatagramConnectionExt, RecvDatagram, SendDatagram, SendDatagramErrorIncoming},
// };

// use crate::{conn::QuicConnection, error::convert_connection_io_error};

// impl<B: bytes::Buf> DatagramConnectionExt<B> for QuicConnection {
//     type SendDatagramHandler = DatagramSender;

//     type RecvDatagramHandler = DatagramReceiver;

//     fn send_datagram_handler(&self) -> Self::SendDatagramHandler {
//         let conn = self.deref().clone();
//         DatagramSender::Pending(Box::pin(async move { conn.unreliable_writer().await }))
//     }

//     fn recv_datagram_handler(&self) -> Self::RecvDatagramHandler {
//         let conn = self.deref().clone();
//         DatagramReceiver::Pending(Box::pin(async move { conn.unreliable_reader() }))
//     }
// }

// pub enum DatagramSender {
//     Pending(BoxFuture<'static, io::Result<DatagramWriter>>),
//     Ready(Result<DatagramWriter, SendDatagramErrorIncoming>),
// }

// impl<B: bytes::Buf> SendDatagram<B> for DatagramSender {
//     fn send_datagram<T: Into<EncodedDatagram<B>>>(
//         &mut self,
//         data: T,
//     ) -> Result<(), SendDatagramErrorIncoming> {
//         // let mut buf = bytes::BytesMut::new();
//         // buf
//         // data.encode(&mut buf);
//         let mut datagram = <T as Into<EncodedDatagram<B>>>::into(data);
//         self.0
//             .send_bytes(datagram.copy_to_bytes(datagram.remaining()))
//             .map_err(|e| match e {
//                 e if e.kind() == io::ErrorKind::InvalidInput => SendDatagramErrorIncoming::TooLarge,
//                 e => SendDatagramErrorIncoming::ConnectionError(convert_connection_io_error(e)),
//             })
//     }
// }

// pub enum DatagramReceiver {
//     Pending(BoxFuture<'static, io::Result<DatagramReader>>),
//     Ready(Result<DatagramReader, ConnectionErrorIncoming>),
// }

// impl RecvDatagram for DatagramReceiver {
//     /// The buffer type
//     type Buffer = Bytes;

//     /// Poll the connection for incoming datagrams.
//     fn poll_incoming_datagram(
//         &mut self,
//         cx: &mut Context<'_>,
//     ) -> Poll<Result<Self::Buffer, ConnectionErrorIncoming>> {
//         self.0.poll_recv(cx).map_err(convert_connection_io_error)
//     }
// }
