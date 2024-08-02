use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, MutexGuard},
};

use enum_dispatch::enum_dispatch;
use qbase::frame::*;

pub mod rcvdpkt;
pub mod sentpkt;

#[derive(Debug, Clone, Eq, PartialEq)]
#[enum_dispatch(BeFrame)]
pub enum ReliableFrame {
    NewToken(NewTokenFrame),
    MaxData(MaxDataFrame),
    DataBlocked(DataBlockedFrame),
    NewConnectionId(NewConnectionIdFrame),
    RetireConnectionId(RetireConnectionIdFrame),
    HandshakeDone(HandshakeDoneFrame),
    Stream(StreamCtlFrame),
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[enum_dispatch(BeFrame)]
pub enum GuaranteedFrame {
    Data(DataFrame),
    Reliable(ReliableFrame),
}

pub type RawReliableFrameDeque = VecDeque<ReliableFrame>;

/// 对于Initial和Handshake空间，仅需负责CryptoFrame的可靠传输
/// 对与Data空间，则需负责上述ReliableFrame的可靠传输
#[derive(Debug, Default, Clone)]
pub struct ArcReliableFrameDeque(Arc<Mutex<RawReliableFrameDeque>>);

impl ArcReliableFrameDeque {
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Arc::new(Mutex::new(RawReliableFrameDeque::with_capacity(
            capacity,
        ))))
    }

    pub fn lock_guard(&self) -> MutexGuard<'_, RawReliableFrameDeque> {
        self.0.lock().unwrap()
    }
}

impl<'a> Extend<&'a NewTokenFrame> for ArcReliableFrameDeque {
    fn extend<T: IntoIterator<Item = &'a NewTokenFrame>>(&mut self, iter: T) {
        self.lock_guard()
            .extend(iter.into_iter().cloned().map(ReliableFrame::NewToken));
    }
}

impl<'a> Extend<&'a MaxDataFrame> for ArcReliableFrameDeque {
    fn extend<T: IntoIterator<Item = &'a MaxDataFrame>>(&mut self, iter: T) {
        self.lock_guard()
            .extend(iter.into_iter().cloned().map(ReliableFrame::MaxData));
    }
}

impl<'a> Extend<&'a DataBlockedFrame> for ArcReliableFrameDeque {
    fn extend<T: IntoIterator<Item = &'a DataBlockedFrame>>(&mut self, iter: T) {
        self.lock_guard()
            .extend(iter.into_iter().cloned().map(ReliableFrame::DataBlocked));
    }
}

impl<'a> Extend<&'a NewConnectionIdFrame> for ArcReliableFrameDeque {
    fn extend<T: IntoIterator<Item = &'a NewConnectionIdFrame>>(&mut self, iter: T) {
        self.lock_guard().extend(
            iter.into_iter()
                .cloned()
                .map(ReliableFrame::NewConnectionId),
        );
    }
}

impl<'a> Extend<&'a RetireConnectionIdFrame> for ArcReliableFrameDeque {
    fn extend<T: IntoIterator<Item = &'a RetireConnectionIdFrame>>(&mut self, iter: T) {
        self.lock_guard().extend(
            iter.into_iter()
                .cloned()
                .map(ReliableFrame::RetireConnectionId),
        );
    }
}

impl<'a> Extend<&'a HandshakeDoneFrame> for ArcReliableFrameDeque {
    fn extend<T: IntoIterator<Item = &'a HandshakeDoneFrame>>(&mut self, iter: T) {
        self.lock_guard()
            .extend(iter.into_iter().cloned().map(ReliableFrame::HandshakeDone));
    }
}

impl<'a> Extend<&'a StreamCtlFrame> for ArcReliableFrameDeque {
    fn extend<T: IntoIterator<Item = &'a StreamCtlFrame>>(&mut self, iter: T) {
        self.lock_guard()
            .extend(iter.into_iter().cloned().map(ReliableFrame::Stream));
    }
}

impl<'a> Extend<&'a ReliableFrame> for ArcReliableFrameDeque {
    fn extend<T: IntoIterator<Item = &'a ReliableFrame>>(&mut self, iter: T) {
        self.lock_guard().extend(iter.into_iter().cloned());
    }
}

#[cfg(test)]
mod tests {}
