pub mod data;
pub mod nodata;

use std::{
    ops::{Index, IndexMut},
    sync::{Arc, Mutex},
    time::Instant,
};

use bytes::{BufMut, Bytes};
use deref_derive::Deref;
use enum_dispatch::enum_dispatch;

pub type InitialSpace = ArcSpace<nodata::NoDataSpace<nodata::Initial>>;
pub type HandshakeSpace = ArcSpace<nodata::NoDataSpace<nodata::Handshake>>;
pub type DataSpace = ArcSpace<data::DataSpace>;

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
pub trait ReliableTransmit: Send + Sync + 'static {
    fn read(
        &self,
        limit: &mut TransportLimit,
        buf: &mut [u8],
        ack_pkt: Option<(u64, Instant)>,
    ) -> (u64, usize, usize);
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
#[enum_dispatch(ReliableTransmit)]
pub enum Space {
    Initial(InitialSpace),
    Handshake(HandshakeSpace),
    Data(DataSpace),
}

#[derive(Debug, Clone)]
pub struct RawSpaces {
    initial: Option<Space>,
    handshake: Option<Space>,
    data: Space,
}

impl RawSpaces {
    pub fn new(initial: InitialSpace, handshake: HandshakeSpace, data: DataSpace) -> Self {
        Self {
            initial: Some(Space::Initial(initial)),
            handshake: Some(Space::Handshake(handshake)),
            data: Space::Data(data),
        }
    }
}

#[derive(Clone)]
pub struct ArcSpaces(Arc<Mutex<RawSpaces>>);

impl ArcSpaces {
    pub fn new(initial: InitialSpace, handshake: HandshakeSpace, data: DataSpace) -> Self {
        Self(Arc::new(Mutex::new(RawSpaces::new(
            initial, handshake, data,
        ))))
    }

    pub fn initial_space(&self) -> Option<InitialSpace> {
        self.0
            .lock()
            .unwrap()
            .initial
            .clone()
            .map(|space| match space {
                Space::Initial(space) => space,
                _ => unreachable!(),
            })
    }

    pub fn handshake_space(&self) -> Option<HandshakeSpace> {
        self.0
            .lock()
            .unwrap()
            .handshake
            .clone()
            .map(|space| match space {
                Space::Handshake(space) => space,
                _ => unreachable!(),
            })
    }

    pub fn data_space(&self) -> DataSpace {
        match self.0.lock().unwrap().data.clone() {
            Space::Data(space) => space,
            _ => unreachable!(),
        }
    }

    pub fn invalid_initial_space(&mut self) {
        self.0.lock().unwrap().initial = None;
    }

    pub fn invalid_handshake_space(&mut self) {
        self.0.lock().unwrap().handshake = None;
    }

    pub fn reliable_space(&self, epoch: Epoch) -> Option<impl ReliableTransmit> {
        match epoch {
            Epoch::Initial => self.0.lock().unwrap().initial.clone(),
            Epoch::Handshake => self.0.lock().unwrap().handshake.clone(),
            Epoch::Data => Some(self.0.lock().unwrap().data.clone()),
        }
    }
}
