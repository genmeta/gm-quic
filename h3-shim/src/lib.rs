pub mod conn;
pub use conn::{OpenStreams, QuicConnection};
pub mod error;
pub use error::Error;
#[cfg(feature = "unreliable")]
pub mod ext;
#[cfg(feature = "unreliable")]
pub use ext::{RecvDatagram, SendDatagram};
pub mod streams;
pub use gm_quic;
pub use streams::{BidiStream, RecvStream, SendStream};

#[cfg(test)]
mod tests;
