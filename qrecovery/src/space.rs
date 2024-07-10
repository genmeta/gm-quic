pub mod data;
pub mod nodata;

use std::{
    sync::{Arc, Mutex},
    time::Instant,
};

use bytes::{BufMut, Bytes};
use deref_derive::Deref;

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
        limit: &mut TransportLimit,
        mut buf: &mut [u8],
        ack_pkt: Option<(u64, Instant)>,
    ) -> Option<(AckFrame, usize)> {
        let remain = limit.available();

        let ack_frame = self.rcvd_pkt_records.gen_ack_frame_util(ack_pkt?, remain);
        buf.put_ack_frame(&ack_frame);

        let written = remain - buf.remaining_mut();
        limit.record_write(written);
        Some((ack_frame, written))
    }
}

pub trait ReliableTransmit: Send + Sync + 'static {
    fn read(
        &self,
        limit: &mut TransportLimit,
        buf: &mut [u8],
        ack_pkt: Option<(u64, Instant)>,
    ) -> (u64, usize, usize);
    fn on_ack(&self, ack_frmae: AckFrame);
    fn may_loss_pkt(&self, pn: u64);
    // 交给Space里的各个组件自己receive
    // fn receive(&self, frame: SpaceFrame) -> Result<(), Error>;
    fn probe_timeout(&self);
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
pub struct RawSpaces {
    initial: Option<InitialSpace>,
    handshake: Option<HandshakeSpace>,
    data: DataSpace,
}

impl RawSpaces {
    pub fn new(initial: InitialSpace, handshake: HandshakeSpace, data: DataSpace) -> Self {
        Self {
            initial: Some(initial),
            handshake: Some(handshake),
            data,
        }
    }
}

pub struct ArcSpaces(Arc<Mutex<RawSpaces>>);

impl ArcSpaces {
    pub fn new(initial: InitialSpace, handshake: HandshakeSpace, data: DataSpace) -> Self {
        Self(Arc::new(Mutex::new(RawSpaces::new(
            initial, handshake, data,
        ))))
    }

    pub fn initial_space(&self) -> Option<InitialSpace> {
        self.0.lock().unwrap().initial.clone()
    }

    pub fn handshake_space(&self) -> Option<HandshakeSpace> {
        self.0.lock().unwrap().handshake.clone()
    }

    pub fn data_space(&self) -> DataSpace {
        self.0.lock().unwrap().data.clone()
    }

    pub fn invalid_initial_space(&mut self) {
        self.0.lock().unwrap().initial = None;
    }

    pub fn initial_handshake_space(&mut self) {
        self.0.lock().unwrap().handshake = None;
    }
}
