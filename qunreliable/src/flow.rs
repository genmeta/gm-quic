use std::{
    io,
    sync::{Arc, Mutex},
};

use qbase::{
    error::Error,
    frame::{DatagramFrame, ReceiveFrame},
};

use super::{
    reader::{DatagramReader, RawDatagramReader},
    writer::{DatagramWriter, RawDatagramWriter},
};
use crate::{DatagramIncoming, DatagramOutgoing};

/// Combination of [`DatagramIncoming`] and [`DatagramOutgoing`]
#[derive(Debug, Clone)]
pub struct DatagramFlow {
    /// The incoming datagram frame, see type's doc for more details.
    incoming: DatagramIncoming,
    /// The outgoing datagram frame, see type's doc for more details.
    outgoing: DatagramOutgoing,
}

impl DatagramFlow {
    /// Creates a new instance of [`DatagramFlow`].
    ///
    /// This method takes two parameters, local and remote's transport parameter [`max_datagram_frame_size`],
    /// the local's transport parameter [`max_datagram_frame_size`] is used to create the reader, and the remote's transport parameter
    /// [`max_datagram_frame_size`] is used to create the writer.
    ///
    /// Most of the time, the remote's transport parameter [`max_datagram_frame_size`] is unknow when creating the flow, so it's optional.
    /// But if the connection enabled 0-rtt, the remote's transport parameter [`max_datagram_frame_size`] will be set to the previous value.
    ///
    /// In handshake, if the new parameter is smaller than the previous value,a connection error occurs.
    ///
    /// [`max_datagram_frame_size`]: https://www.rfc-editor.org/rfc/rfc9221.html#name-transport-parameter
    #[inline]
    pub fn new(
        local_max_datagram_frame_size: u64,
        remote_max_datagram_frame_size: Option<u64>,
    ) -> Self {
        let reader = RawDatagramReader::new(local_max_datagram_frame_size as _);
        let writer = RawDatagramWriter::new(remote_max_datagram_frame_size.map(|n| n as _));

        Self {
            incoming: DatagramIncoming(Arc::new(Mutex::new(Ok(reader)))),
            outgoing: DatagramOutgoing(Arc::new(Mutex::new(Ok(writer)))),
        }
    }

    /// See [`DatagramOutgoing::update_remote_max_datagram_frame_size`] for more details.
    #[inline]
    pub fn update_remote_max_datagram_frame_size(&self, size: u64) -> Result<(), Error> {
        self.outgoing
            .update_remote_max_datagram_frame_size(size as _)
    }

    /// See [`DatagramOutgoing::try_read_datagram`] for more details.
    #[inline]
    pub fn try_read_datagram(&self, buf: &mut [u8]) -> Option<(DatagramFrame, usize)> {
        self.outgoing.try_read_datagram(buf)
    }

    /// Create a new **unuiqe** instance of [`DatagramReader`].
    ///
    /// Return an error if the connection is closing or already closed, or there is already a reader exist.
    ///
    /// See [`DatagramIncoming::new_reader`] for more details.
    #[inline]
    pub fn reader(&self) -> io::Result<DatagramReader> {
        self.incoming.new_reader()
    }

    /// Create a new instance of [`DatagramWriter`].
    ///
    /// Return an error if the connection is closing or already closed,
    ///
    /// See [`DatagramOutgoing::new_writer`] for more details.
    #[inline]
    pub async fn writer(&self) -> io::Result<DatagramWriter> {
        self.outgoing.new_writer().await
    }

    /// See [`DatagramOutgoing::on_conn_error`] and [`DatagramIncoming::on_conn_error`] for more details.
    #[inline]
    pub fn on_conn_error(&self, error: &Error) {
        self.incoming.on_conn_error(error);
        self.outgoing.on_conn_error(error);
    }
}

/// See [`DatagramIncoming::recv_datagram`] for more details.
impl ReceiveFrame<(DatagramFrame, bytes::Bytes)> for DatagramFlow {
    type Output = ();

    #[inline]
    fn recv_frame(
        &self,
        (frame, body): &(DatagramFrame, bytes::Bytes),
    ) -> Result<Self::Output, Error> {
        self.incoming.recv_datagram(frame, body.clone())
    }
}
