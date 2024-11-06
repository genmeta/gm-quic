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

use std::ops::{Index, IndexMut};

/// Operations about QUIC connection IDs.
pub mod cid;
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
/// [QUIC transport parameters and their codec](https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-encodin).
pub mod param;
/// Stream id types and controllers for different roles and different directions.
pub mod sid;
/// Issuing, storing and verifing tokens operations.
pub mod token;
/// Utilities for common data structures.
pub mod util;
/// [Variable-length integers](https://www.rfc-editor.org/rfc/rfc9000.html#name-variable-length-integer-enc).
pub mod varint;

/// The epoch of sending, usually been seen as the index of spaces.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Epoch {
    Initial = 0,
    Handshake = 1,
    Data = 2,
}

impl Epoch {
    pub const EPOCHS: [Epoch; 3] = [Epoch::Initial, Epoch::Handshake, Epoch::Data];
    /// An iterator for the epoch of each spaces.
    ///
    /// Equals to `Epoch::EPOCHES.iter()`
    pub fn iter() -> std::slice::Iter<'static, Epoch> {
        Self::EPOCHS.iter()
    }

    /// The number of epoches.
    pub const fn count() -> usize {
        Self::EPOCHS.len()
    }
}

impl<T> Index<Epoch> for [T]
where
    T: Sized,
{
    type Output = T;

    fn index(&self, index: Epoch) -> &Self::Output {
        self.index(index as usize)
    }
}

impl<T> IndexMut<Epoch> for [T]
where
    T: Sized,
{
    fn index_mut(&mut self, index: Epoch) -> &mut Self::Output {
        self.index_mut(index as usize)
    }
}

#[cfg(test)]
mod tests {}
