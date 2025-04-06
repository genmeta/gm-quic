//! The space that reliably transmites frames.
use std::time::Duration;

mod rcvd;
pub use rcvd::*;
mod sent;
pub use sent::*;

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
    pub fn with_capacity(capacity: usize, max_ack_delay: Option<Duration>) -> Self {
        Self {
            sent: ArcSentJournal::with_capacity(capacity),
            rcvd: ArcRcvdJournal::with_capacity(capacity, max_ack_delay),
        }
    }

    /// Get the [`ArcSentJournal`] of space.
    pub fn of_sent_packets(&self) -> ArcSentJournal<T> {
        self.sent.clone()
    }

    /// Get the [`ArcRcvdJournal`] of space.
    pub fn of_rcvd_packets(&self) -> ArcRcvdJournal {
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
