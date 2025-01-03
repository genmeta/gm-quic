pub mod conn;
pub use conn::{OpenStreams, QuicConnection};
pub mod error;
pub use error::Error;
pub mod ext;
pub use ext::{RecvDatagram, SendDatagram};
pub mod streams;
pub use gm_quic::*;
pub use streams::{BidiStream, RecvStream, SendStream};

#[cfg(test)]
mod tests;
