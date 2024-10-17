//! # The QUIC base library
//!
//! The `qbase` library defines the necessary basic structures in the QUIC protocol,
//! including connection IDs, stream IDs, frames, packets, keys, parameters, error codes, etc.
//!
//! Additionally, based on these basic structures,
//! it defines components for various mechanisms in QUIC,
//! including flow control, handshake, tokens, stream ID management, connection ID management, etc.
//!
//! Finally, the `qbase` module also defines some utility functions
//! for handling common data structures in the QUIC protocol.
//!

/// Operations about QUIC connection IDs.
pub mod cid;
/// [QUIC transport parameters and their codec](https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-encodin).
pub mod config;
/// [QUIC errors](https://www.rfc-editor.org/rfc/rfc9000.html#name-error-codes).
pub mod error;
/// QUIC connection-level flow control.
pub mod flow;
/// QUIC frames and their codec.
pub mod frame;
/// Handshake signal for QUIC connections.
pub mod handshake;
/// QUIC packets and their codec.
pub mod packet;
/// Stream id types and controllers for different roles and different directions.
pub mod streamid;
/// Issuing, storing and verifing tokens operations.
pub mod token;
/// Utilities for common data structures.
pub mod util;
/// [Variable-length integers](https://www.rfc-editor.org/rfc/rfc9000.html#name-variable-length-integer-enc).
pub mod varint;

#[cfg(test)]
mod tests {}
