pub mod data;
pub mod nodata;

use std::{
    ops::{Index, IndexMut},
    sync::Arc,
    time::Instant,
};

use bytes::{BufMut, Bytes};
use deref_derive::Deref;

pub type InitialSpace = ArcSpace<nodata::NoDataSpace<nodata::Initial>>;
pub type HandshakeSpace = ArcSpace<nodata::NoDataSpace<nodata::Handshake>>;
pub type DataSpace = ArcSpace<data::DataSpace>;

use enum_dispatch::enum_dispatch;
use qbase::{
    frame::{io::WriteAckFrame, *},
    util::TransportLimit,
};

use crate::{
    crypto::CryptoStream,
    reliable::{rcvdpkt::ArcRcvdPktRecords, sentpkt::ArcSentPktRecords, ArcReliableFrameQueue},
    streams::DataStreams,
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

#[derive(Debug, Clone)]
pub enum SpaceFrame {
    Stream(StreamCtlFrame),
    Data(DataFrame, Bytes),
}

#[derive(Debug, Clone, Deref)]
pub struct RawSpace<T> {
    pub reliable_frame_queue: ArcReliableFrameQueue,
    pub sent_pkt_records: ArcSentPktRecords,
    pub rcvd_pkt_records: ArcRcvdPktRecords,
    #[deref]
    space: T,
}

// tool methods

impl<T> RawSpace<T> {
    fn read_ack_frame_until(
        &self,
        mut buf: &mut [u8],
        ack_pkt: Option<(u64, Instant)>,
    ) -> Option<(AckFrame, usize)> {
        let remain = buf.remaining_mut();

        let ack_frame = self.rcvd_pkt_records.gen_ack_frame_util(ack_pkt?, remain);
        buf.put_ack_frame(&ack_frame);

        let written = remain - buf.remaining_mut();
        Some((ack_frame, written))
    }
}

#[enum_dispatch]
pub trait ReadSpace: Send + Sync + 'static {
    fn read_frame(
        &self,
        limit: &mut TransportLimit,
        buf: &mut [u8],
        ack_pkt: Option<(u64, Instant)>,
    ) -> (usize, bool);

    fn read_pn(&self, buf: &mut [u8], limit: &mut TransportLimit) -> (u64, usize);

    fn finish(&self);
}

#[enum_dispatch]
pub trait ReliableTransmit: ReadSpace {
    fn on_ack(&self, ack_frmae: AckFrame);
    fn may_loss_pkt(&self, pn: u64);
    fn probe_timeout(&self);
    fn indicate_ack(&self, pn: u64);
}

#[derive(Debug, Deref)]
pub struct ArcSpace<T>(Arc<RawSpace<T>>);

impl<T> Clone for ArcSpace<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> AsRef<CryptoStream> for ArcSpace<T>
where
    T: AsRef<CryptoStream>,
{
    fn as_ref(&self) -> &CryptoStream {
        self.0.space.as_ref()
    }
}

impl<T> AsRef<DataStreams> for ArcSpace<T>
where
    T: AsRef<DataStreams>,
{
    fn as_ref(&self) -> &DataStreams {
        self.0.space.as_ref()
    }
}

#[derive(Debug, Clone)]
#[enum_dispatch(ReliableTransmit, ReadSpace)]
pub enum Space {
    Initial(InitialSpace),
    Handshake(HandshakeSpace),
    Data(DataSpace),
}

#[derive(Clone)]
pub struct Spaces(pub [Option<Space>; 3]);

impl Index<Epoch> for Spaces {
    type Output = Option<Space>;

    fn index(&self, index: Epoch) -> &Self::Output {
        &self.0[index as usize]
    }
}
