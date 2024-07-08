pub mod data;
pub mod nodata;

use std::{
    sync::{Arc, Mutex},
    time::Instant,
};

use bytes::{BufMut, Bytes};
use deref_derive::Deref;
use futures::StreamExt;

pub type InitialSpace = ArcSpace<nodata::NoDataSpace<nodata::Initial>>;
pub type HandshakeSpace = ArcSpace<nodata::NoDataSpace<nodata::Handshake>>;
pub type DataSpace = ArcSpace<data::DataSpace>;

use qbase::{
    error::Error,
    frame::{io::WriteAckFrame, *},
    util::{ArcAsyncDeque, TransportLimit},
};
use tokio::sync::mpsc;

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
        let remain = limit.remaining();

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
    fn receive(&self, frame: SpaceFrame) -> Result<(), Error>;
    fn probe_timeout(&self);
}

#[derive(Debug, Deref)]
pub struct ArcSpace<T>(Arc<RawSpace<T>>);

impl<T> Clone for ArcSpace<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> ArcSpace<T>
where
    Self: ReliableTransmit,
{
    pub fn spawn_recv_ack(&self) -> mpsc::UnboundedSender<AckFrame> {
        let (ack_tx, mut ack_rx) = mpsc::unbounded_channel();
        let space = self.clone();
        tokio::spawn(async move {
            while let Some(ack_frame) = ack_rx.recv().await {
                space.on_ack(ack_frame);
            }
        });
        ack_tx
    }

    pub fn spawn_handle_may_loss(&self) -> mpsc::UnboundedSender<u64> {
        let (loss_tx, mut loss_rx) = mpsc::unbounded_channel();
        let space = self.clone();
        tokio::spawn(async move {
            while let Some(pn) = loss_rx.recv().await {
                space.may_loss_pkt(pn);
            }
        });
        loss_tx
    }

    pub fn spawn_recv_space_frames(
        &self,
        error_tx: mpsc::UnboundedSender<Error>,
    ) -> ArcAsyncDeque<SpaceFrame> {
        let space = self.clone();
        let deque = ArcAsyncDeque::new();
        let mut inner_deque = deque.clone();
        tokio::spawn(async move {
            while let Some(frame) = inner_deque.next().await {
                if let Err(error) = space.receive(frame) {
                    _ = error_tx.send(error);
                }
            }
        });
        deque
    }

    pub fn spawn_probe_timeout(&self) -> mpsc::UnboundedSender<()> {
        let (pto_tx, mut pto_rx) = mpsc::unbounded_channel();
        let space = self.clone();
        tokio::spawn(async move {
            while (pto_rx.recv().await).is_some() {
                space.probe_timeout();
            }
        });
        pto_tx
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
