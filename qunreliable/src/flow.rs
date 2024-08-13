use std::sync::{Arc, Mutex};

use qbase::{
    config::Parameters,
    error::Error,
    frame::{DatagramFrame, ReceiveFrame},
};

use super::{
    reader::{DatagramReader, RawDatagramReader},
    writer::{DatagramWriter, RawDatagramWriter},
};

/// The unique [`RawDatagramFlow`] struct represents a flow for sending and receiving datagrams frame from a connection.
#[derive(Debug, Clone)]
pub struct RawDatagramFlow {
    reader: DatagramReader,
    writer: DatagramWriter,
}

#[derive(Debug, Clone)]
pub struct DatagramFlow(Arc<RawDatagramFlow>);

impl RawDatagramFlow {
    /// Creates a new instance of [`DatagramFlow`].
    ///
    /// # Arguments
    ///
    /// * `local_max_datagram_frame_size` - The maximum size of the datagram frame that can be received.
    ///
    /// * `remote_max_datagram_frame_size` - The maximum size of the datagram frame that can be sent.
    ///
    /// # Notes
    ///
    /// The arguments chould be the default value, or the value negotiation by last connection.
    ///
    /// If the new `remote_max_datagram_frame_size` is smaller than the previous value, a connection error will occur,
    /// see [`DatagramWriter::update_remote_max_datagram_frame_size`] for more details.
    fn new(local_max_datagram_frame_size: u64, remote_max_datagram_frame_size: u64) -> Self {
        let reader = RawDatagramReader::new(remote_max_datagram_frame_size as _);
        let writer = RawDatagramWriter::new(local_max_datagram_frame_size as _);

        Self {
            reader: DatagramReader(Arc::new(Mutex::new(Ok(reader)))),
            writer: DatagramWriter(Arc::new(Mutex::new(Ok(writer)))),
        }
    }
}

/// The shared [`RawDatagramFlow`] struct represents a flow for sending and receiving datagrams frame from a connection.

impl DatagramFlow {
    /// see [`RawDatagramFlow::new`] for more details.
    #[inline]
    pub fn new(local_max_datagram_frame_size: u64, remote_max_datagram_frame_size: u64) -> Self {
        let flow = RawDatagramFlow::new(
            local_max_datagram_frame_size,
            remote_max_datagram_frame_size,
        );
        Self(Arc::new(flow))
    }
    /// See [`DatagramWriter::update_remote_max_datagram_frame_size`] for more details.
    #[inline]
    pub fn apply_transport_parameters(&self, params: &Parameters) -> Result<(), Error> {
        self.0.writer.update_remote_max_datagram_frame_size(
            params.max_datagram_frame_size().into_inner() as usize,
        )
    }

    /// See [`DatagramWriter::try_read_datagram`] for more details.
    #[inline]
    pub fn try_read_datagram(&self, buf: &mut [u8]) -> Option<(DatagramFrame, usize)> {
        self.0.writer.try_read_datagram(buf)
    }

    /// Create a pair of [`DatagramReader`] and [`DatagramWriter`] for the application to read and write datagrams.
    #[inline]
    pub fn rw(&self) -> (DatagramReader, DatagramWriter) {
        let flow = &self.0;
        (
            DatagramReader(flow.reader.0.clone()),
            DatagramWriter(flow.writer.0.clone()),
        )
    }

    /// Handles a connection error.
    ///
    /// # Arguments
    ///
    /// * `error` - The error that occurred.
    ///
    /// # Note
    ///
    /// This method will wake up all the wakers that are waiting for the data to be read.
    ///
    /// if the connection is already closed, the new error will be ignored.
    ///
    /// See [`DatagramReader::on_conn_error`] and [`DatagramWriter::on_conn_error`] for more details.
    #[inline]
    pub fn on_conn_error(&self, error: &Error) {
        let raw_flow = &self.0;
        raw_flow.reader.on_conn_error(error);
        raw_flow.writer.on_conn_error(error);
    }
}

/// See [`DatagramReader::recv_datagram`] for more details.
impl ReceiveFrame<(DatagramFrame, bytes::Bytes)> for DatagramFlow {
    type Output = ();

    #[inline]
    fn recv_frame(
        &mut self,
        (frame, body): &(DatagramFrame, bytes::Bytes),
    ) -> Result<Self::Output, Error> {
        self.0.reader.recv_datagram(frame, body.clone())
    }
}
