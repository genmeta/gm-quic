//! The space that reliably transmites frames.
use std::ops::{Index, IndexMut};

use qbase::frame::CryptoFrame;

use crate::reliable::{ArcRcvdPktRecords, ArcSentPktRecords, GuaranteedFrame};

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
/// The generic `T` is the generic on [`ArcSentPktRecords`].
///
/// See [`ArcSentPktRecords`] and [`ArcRcvdPktRecords`] for more.
#[derive(Debug, Default, Clone)]
pub struct Space<T> {
    sent_pkt_records: ArcSentPktRecords<T>,
    rcvd_pkt_records: ArcRcvdPktRecords,
}

impl<T> Space<T> {
    /// Create a [`Space`] containing records with the given `capacity`.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            sent_pkt_records: ArcSentPktRecords::with_capacity(capacity),
            rcvd_pkt_records: ArcRcvdPktRecords::with_capacity(capacity),
        }
    }

    /// Get the [`ArcSentPktRecords`] of space.
    pub fn sent_packets(&self) -> ArcSentPktRecords<T> {
        self.sent_pkt_records.clone()
    }

    /// Get the [`ArcRcvdPktRecords`] of space.
    pub fn rcvd_packets(&self) -> ArcRcvdPktRecords {
        self.rcvd_pkt_records.clone()
    }
}

impl<T> AsRef<ArcSentPktRecords<T>> for Space<T> {
    fn as_ref(&self) -> &ArcSentPktRecords<T> {
        &self.sent_pkt_records
    }
}

impl<T> AsRef<ArcRcvdPktRecords> for Space<T> {
    fn as_ref(&self) -> &ArcRcvdPktRecords {
        &self.rcvd_pkt_records
    }
}

/// For initial space, only reliable transmission of crypto frames is required.
pub type InitialSpace = Space<CryptoFrame>;
/// For handshake space, only reliable transmission of crypto frames is required.
pub type HandshakeSpace = Space<CryptoFrame>;
/// For handshake space, reliable transmission of [`GuaranteedFrame`] (crypto frames, stream frames and reliable frames) is required.
pub type DataSpace = Space<GuaranteedFrame>;

#[cfg(test)]
mod tests {
    use qbase::packet::PacketNumber;

    #[test]
    fn test_initial_space() {
        use super::*;
        let space = InitialSpace::with_capacity(10);
        // assert_eq!(AsRef::<ArcSentPktRecords<_>>::as_ref(&space).lock_guard().len(), 0);
        assert_eq!(
            AsRef::<ArcRcvdPktRecords>::as_ref(&space).decode_pn(PacketNumber::encode(0, 0)),
            Ok(0)
        );
    }
}
