use std::ops::{Index, IndexMut};

use qbase::frame::CryptoFrame;

use crate::reliable::{rcvdpkt::ArcRcvdPktRecords, sentpkt::ArcSentPktRecords, ReliableFrame};

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
    sent_pkt_records: ArcSentPktRecords<T>,
    rcvd_pkt_records: ArcRcvdPktRecords,
}

impl<T> RawSpace<T> {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            sent_pkt_records: ArcSentPktRecords::with_capacity(capacity),
            rcvd_pkt_records: ArcRcvdPktRecords::with_capacity(capacity),
        }
    }

    pub fn sent_packets(&self) -> ArcSentPktRecords<T> {
        self.sent_pkt_records.clone()
    }

    pub fn rcvd_packets(&self) -> ArcRcvdPktRecords {
        self.rcvd_pkt_records.clone()
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

pub type InitialSpace = RawSpace<CryptoFrame>;
pub type HandshakeSpace = RawSpace<CryptoFrame>;
pub type DataSpace = RawSpace<ReliableFrame>;

#[derive(Debug, Clone)]
pub enum Space {
    Initial(InitialSpace),
    Handshake(HandshakeSpace),
    Data(DataSpace),
}

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
