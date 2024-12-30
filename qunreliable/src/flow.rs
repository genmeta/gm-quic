use std::{
    io,
    sync::{Arc, Mutex},
};

use qbase::{
    error::Error,
    frame::{DatagramFrame, ReceiveFrame},
};

use super::{
    reader::{ReceivedDatagramFrames, UnreliableReader},
    writer::{DatagramFrameSink, UnreliableWriter},
};
use crate::{UnreliableIncoming, UnreliableOutgoing};

/// Combination of [`UnreliableIncoming`] and [`UnreliableOutgoing`]
#[derive(Debug, Clone)]
pub struct DatagramFlow {
    /// The incoming datagram frame, see type's doc for more details.
    incoming: UnreliableIncoming,
    /// The outgoing datagram frame, see type's doc for more details.
    outgoing: UnreliableOutgoing,
}

impl DatagramFlow {
    /// Creates a new instance of [`DatagramFlow`].
    ///
    /// This method takes local protocol parameter [`max_datagram_frame_size`],
    /// the local's transport parameter [`max_datagram_frame_size`] limits the size of the datagram frames that peer
    /// can send.
    ///
    /// [`max_datagram_frame_size`]: https://www.rfc-editor.org/rfc/rfc9221.html#name-transport-parameter
    #[inline]
    pub fn new(local_max_datagram_frame_size: u64) -> Self {
        let reader = ReceivedDatagramFrames::new(local_max_datagram_frame_size as _);
        let writer = DatagramFrameSink::new();

        Self {
            incoming: UnreliableIncoming(Arc::new(Mutex::new(Ok(reader)))),
            outgoing: UnreliableOutgoing(Arc::new(Mutex::new(Ok(writer)))),
        }
    }

    /// See [`UnreliableOutgoing::try_read_datagram`] for more details.
    #[inline]
    pub fn try_read_datagram(&self, buf: &mut [u8]) -> Option<(DatagramFrame, usize)> {
        self.outgoing.try_read_datagram(buf)
    }

    pub fn try_load_data_into<P, B>(&self, packet: &mut P)
    where
        B: bytes::BufMut,
        P: core::ops::DerefMut<Target = B>
            + qbase::packet::MarshalDataFrame<DatagramFrame, bytes::Bytes>,
    {
        self.outgoing.try_load_data_into(packet)
    }

    /// Create a new **unique** instance of [`UnreliableReader`].
    ///
    /// Return an error if the connection is closing or already closed, or there is already a reader exist.
    ///
    /// See [`UnreliableIncoming::new_reader`] for more details.
    #[inline]
    pub fn reader(&self) -> io::Result<UnreliableReader> {
        self.incoming.new_reader()
    }

    /// Create a new instance of [`UnreliableWriter`].
    ///
    /// Return an error if the connection is closing or already closed,
    ///
    /// See [`UnreliableOutgoing::new_writer`] for more details.
    #[inline]
    pub fn writer(&self, max_datagram_frame_size: u64) -> io::Result<UnreliableWriter> {
        self.outgoing.new_writer(max_datagram_frame_size)
    }

    /// See [`UnreliableOutgoing::on_conn_error`] and [`UnreliableIncoming::on_conn_error`] for more details.
    #[inline]
    pub fn on_conn_error(&self, error: &Error) {
        self.incoming.on_conn_error(error);
        self.outgoing.on_conn_error(error);
    }
}

/// See [`UnreliableIncoming::recv_datagram`] for more details.
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
