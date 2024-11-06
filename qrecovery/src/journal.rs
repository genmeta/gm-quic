//! The space that reliably transmites frames.
use std::ops::{Index, IndexMut};

use qbase::frame::CryptoFrame;

use crate::reliable::GuaranteedFrame;

mod rcvd;
pub use rcvd::*;
mod sent;
pub use sent::*;

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

/// The bundle of sent packet records and received packet records.
///
/// The generic `T` is the generic on [`ArcSentJournal`].
///
/// See [`ArcSentJournal`] and [`ArcRcvdJournal`] for more.
#[derive(Debug, Default, Clone)]
pub struct Journal<T> {
    sent: ArcSentJournal<T>,
    rcvd: ArcRcvdJournal,
}

impl<T> Journal<T> {
    /// Create a [`Journal`] containing records with the given `capacity`.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            sent: ArcSentJournal::with_capacity(capacity),
            rcvd: ArcRcvdJournal::with_capacity(capacity),
        }
    }

    /// Get the [`ArcSentJournal`] of space.
    pub fn sent(&self) -> ArcSentJournal<T> {
        self.sent.clone()
    }

    /// Get the [`ArcRcvdJournal`] of space.
    pub fn rcvd(&self) -> ArcRcvdJournal {
        self.rcvd.clone()
    }
}

impl<T> AsRef<ArcSentJournal<T>> for Journal<T> {
    fn as_ref(&self) -> &ArcSentJournal<T> {
        &self.sent
    }
}

impl<T> AsRef<ArcRcvdJournal> for Journal<T> {
    fn as_ref(&self) -> &ArcRcvdJournal {
        &self.rcvd
    }
}

/// For initial space, only reliable transmission of crypto frames is required.
pub type InitialJournal = Journal<CryptoFrame>;
/// For handshake space, only reliable transmission of crypto frames is required.
pub type HandshakeJournal = Journal<CryptoFrame>;
/// For handshake space, reliable transmission of [`GuaranteedFrame`] (crypto frames, stream frames and reliable frames) is required.
pub type DataJournal = Journal<GuaranteedFrame>;

#[cfg(test)]
mod tests {
    use qbase::packet::PacketNumber;

    #[test]
    fn test_initial_space() {
        use super::*;
        let space = InitialJournal::with_capacity(10);
        // assert_eq!(AsRef::<ArcSentJournal<_>>::as_ref(&space).lock_guard().len(), 0);
        assert_eq!(
            AsRef::<ArcRcvdJournal>::as_ref(&space).decode_pn(PacketNumber::encode(0, 0)),
            Ok(0)
        );
    }
}
