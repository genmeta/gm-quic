//! Types for receiving data on a Stream.
mod incoming;
mod rcvbuf;
mod reader;
mod recver;

pub use incoming::{Incoming, IsStopped, UpdateWindow};
use qbase::streamid::StreamId;
pub use rcvbuf::RecvBuf;
pub use reader::Reader;
pub use recver::ArcRecver;

/// Create the internal representations of [`Incoming`] and [`Reader`] with the given receiving buffer size.
///
/// The size of the receiving buffer is the default flow control limit of a QUIC Stream.
pub fn new(buf_size: u64, sid: StreamId) -> ArcRecver {
    ArcRecver::new(buf_size, sid)
}
