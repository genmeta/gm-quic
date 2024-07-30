use std::{
    ops::{Index, IndexMut},
    sync::Arc,
};

use deref_derive::Deref;
use qbase::frame::CryptoFrame;

use crate::reliable::{
    rcvdpkt::ArcRcvdPktRecords, sentpkt::ArcSentPktRecords, ArcReliableFrameDeque, ReliableFrame,
};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Epoch {
    Initial = 0,
    Handshake = 1,
    Data = 2,
}

impl Epoch {
    pub fn iter() -> std::slice::Iter<'static, Epoch> {
        const EPOCHS: [Epoch; 3] = [Epoch::Initial, Epoch::Handshake, Epoch::Data];
        EPOCHS.iter()
    }

    pub const fn count() -> usize {
        3
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

#[derive(Debug, Default, Clone)]
pub struct RawSpace<T> {
    reliable_frame_queue: ArcReliableFrameDeque<T>,
    sent_pkt_records: ArcSentPktRecords<T>,
    rcvd_pkt_records: ArcRcvdPktRecords,
}

impl<T> RawSpace<T> {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            reliable_frame_queue: ArcReliableFrameDeque::with_capacity(capacity),
            sent_pkt_records: ArcSentPktRecords::with_capacity(capacity),
            rcvd_pkt_records: ArcRcvdPktRecords::with_capacity(capacity),
        }
    }
}

impl<T> AsRef<ArcReliableFrameDeque<T>> for RawSpace<T> {
    fn as_ref(&self) -> &ArcReliableFrameDeque<T> {
        &self.reliable_frame_queue
    }
}

impl<T> AsRef<ArcSentPktRecords<T>> for RawSpace<T> {
    fn as_ref(&self) -> &ArcSentPktRecords<T> {
        &self.sent_pkt_records
    }
}

impl<T> AsRef<ArcRcvdPktRecords> for RawSpace<T> {
    fn as_ref(&self) -> &ArcRcvdPktRecords {
        &self.rcvd_pkt_records
    }
}

#[derive(Debug, Deref, Clone)]
pub struct ArcSpace<T>(#[deref] Arc<RawSpace<T>>);

pub type InitialSpace = ArcSpace<CryptoFrame>;
pub type HandshakeSpace = ArcSpace<CryptoFrame>;
pub type DataSpace = ArcSpace<ReliableFrame>;

#[derive(Debug, Clone)]
pub enum Space {
    Initial(InitialSpace),
    Handshake(HandshakeSpace),
    Data(DataSpace),
}
