use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, MutexGuard},
};

use deref_derive::{Deref, DerefMut};
use qbase::frame::*;

pub mod rcvdpkt;
pub mod sentpkt;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ReliableFrame {
    NewToken(NewTokenFrame),
    MaxData(MaxDataFrame),
    DataBlocked(DataBlockedFrame),
    NewConnectionId(NewConnectionIdFrame),
    RetireConnectionId(RetireConnectionIdFrame),
    HandshakeDone(HandshakeDoneFrame),
    Stream(StreamCtlFrame),
    Data(DataFrame),
}

/// 对于Initial和Handshake空间，仅需负责CryptoFrame的可靠传输
/// 对与Data空间，则需负责上述ReliableFrame的可靠传输
#[derive(Debug, Default, Deref, DerefMut)]
pub struct RawReliableFrameDeque<T> {
    #[deref]
    queue: VecDeque<T>,
}

#[derive(Debug, Default, Clone)]
pub struct ArcReliableFrameDeque<T>(Arc<Mutex<RawReliableFrameDeque<T>>>);

impl<T> ArcReliableFrameDeque<T> {
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Arc::new(Mutex::new(RawReliableFrameDeque {
            queue: VecDeque::with_capacity(capacity),
        })))
    }

    pub fn lock_guard(&self) -> MutexGuard<'_, RawReliableFrameDeque<T>> {
        self.0.lock().unwrap()
    }
}

#[cfg(test)]
mod tests {}
