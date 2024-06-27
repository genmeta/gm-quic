pub mod data;
pub mod nodata;

use std::{sync::Arc, time::Instant};

use bytes::{BufMut, Bytes};
pub use data::DataSpace;
use deref_derive::Deref;
pub use nodata::{HandshakeSpace, InitalSpace};
use qbase::frame::{
    io::{WriteAckFrame, WriteFrame},
    AckFrame, BeFrame, DataFrame, StreamCtlFrame,
};
use qrecovery::{
    crypto::CryptoStream,
    reliable::{
        rcvdpkt::ArcRcvdPktRecords,
        sentpkt::{ArcSentPktRecords, SendGuard},
        ArcReliableFrameQueue,
    },
    streams::DataStreams,
};

#[derive(Debug, Clone)]
pub enum SpaceFrame {
    Stream(StreamCtlFrame),
    Data(DataFrame, Bytes),
}

#[derive(Debug, Clone, Deref)]
pub struct RawSpace<T> {
    reliable_frame_queue: ArcReliableFrameQueue,
    pub sent_pkt_records: ArcSentPktRecords,
    pub rcvd_pkt_records: ArcRcvdPktRecords,
    #[deref]
    space: T,
}

// tool methods
impl<T> RawSpace<T> {
    fn read_ack_frame_until(
        &self,
        send_guard: &mut SendGuard,
        mut buf: &mut [u8],
        ack_pkt: Option<(u64, Instant)>,
    ) -> usize {
        let remain = buf.remaining_mut();
        if let Some(largest) = ack_pkt {
            let ack_frame = self
                .rcvd_pkt_records
                .gen_ack_frame_util(largest, buf.remaining_mut());
            buf.put_ack_frame(&ack_frame);
            send_guard.record_ack_frame(ack_frame);
        }
        remain - buf.remaining_mut()
    }

    fn read_reliable_frames(&self, send_guard: &mut SendGuard, mut buf: &mut [u8]) -> usize {
        let remain = buf.remaining_mut();
        let mut reliable_frame_reader = self.reliable_frame_queue.read();
        while let Some(frame) = reliable_frame_reader.front() {
            let remain = buf.remaining_mut();
            if remain < frame.max_encoding_size() && remain < frame.encoding_size() {
                break;
            }

            buf.put_frame(frame);
            let frame = reliable_frame_reader.pop_front().unwrap();
            send_guard.record_reliable_frame(frame);
        }
        remain - buf.remaining_mut()
    }
}

pub trait Space {
    fn read(&self, buf: &mut [u8], ack_pkt: Option<(u64, Instant)>) -> (u64, usize, usize);
    fn on_ack(&self, ack_frmae: AckFrame);
    fn may_loss_pkt(&self, pn: u64);
    // fn receive(&self, queue: ...);
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
