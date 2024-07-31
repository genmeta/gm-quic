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

/// 对于Initial和Handshake空间，仅需负责CryptoFrame的可靠传输
/// 对与Data空间，则需负责上述ReliableFrame的可靠传输
type RawReliableFrameDeque = VecDeque<ReliableFrame>;

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

#[cfg(test)]
mod tests {}
