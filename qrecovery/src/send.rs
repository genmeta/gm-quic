//! Types for sending data on a Stream.
mod outgoing;
mod sender;
mod sndbuf;
mod writer;

pub use outgoing::{IsCancelled, Outgoing};
pub use sender::ArcSender;
pub use sndbuf::SendBuf;
pub use writer::Writer;

/// Create the internal representations of [`Outgoing`] and [`Writer`] with the given sending window size.
///
/// The size of the sending window is the default flow control limit of a QUIC Stream.
pub fn new(wnd_size: u64) -> ArcSender {
    ArcSender::with_wnd_size(wnd_size)
}
