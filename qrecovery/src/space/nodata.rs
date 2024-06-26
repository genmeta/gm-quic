use std::{marker::PhantomData, sync::Arc, time::Instant};

use bytes::BufMut;
use qbase::{
    error::Error,
    frame::{AckFrame, DataFrame},
    packet::WritePacketNumber,
};

use super::{ArcSpace, BeSpace, RawSpace, SpaceFrame};
use crate::{
    crypto::CryptoStream,
    reliable::{
        rcvdpkt::ArcRcvdPktRecords,
        sentpkt::{ArcSentPktRecords, SentRecord},
        ArcReliableFrameQueue,
    },
};

#[derive(Debug, Clone)]
pub struct NoDataSpace<K: NoDataSpaceKind> {
    pub crypto_stream: CryptoStream,
    _kind: PhantomData<K>,
}

unsafe impl<K: NoDataSpaceKind> Send for NoDataSpace<K> {}
unsafe impl<K: NoDataSpaceKind> Sync for NoDataSpace<K> {}

pub trait NoDataSpaceKind: 'static {}

pub struct Inital;
impl NoDataSpaceKind for Inital {}
pub type InitalSpace = NoDataSpace<Inital>;

pub struct Handshake;
impl NoDataSpaceKind for Handshake {}
pub type HandshakeSpace = NoDataSpace<Handshake>;

impl<K: NoDataSpaceKind> AsRef<CryptoStream> for NoDataSpace<K> {
    fn as_ref(&self) -> &CryptoStream {
        &self.crypto_stream
    }
}

impl<K: NoDataSpaceKind> NoDataSpace<K> {
    pub fn new() -> Self {
        Self {
            crypto_stream: CryptoStream::new(1_000_000, 1_000_000),
            _kind: PhantomData,
        }
    }
}

impl<K: NoDataSpaceKind> Default for NoDataSpace<K> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: NoDataSpaceKind> ArcSpace<NoDataSpace<K>> {
    fn new_nodata_space() -> Self {
        Self(Arc::new({
            let space = NoDataSpace::new();
            RawSpace {
                reliable_frame_queue: ArcReliableFrameQueue::default(),
                sent_pkt_records: ArcSentPktRecords::default(),
                rcvd_pkt_records: ArcRcvdPktRecords::default(),
                space,
            }
        }))
    }
}
impl<K: NoDataSpaceKind> BeSpace for ArcSpace<NoDataSpace<K>> {
    fn read(&self, mut buf: &mut [u8], ack_pkt: Option<(u64, Instant)>) -> (u64, usize, usize) {
        let orign = buf.remaining_mut();

        let mut send_guard = self.0.sent_pkt_records.send();

        let (pn, encoded_pn) = send_guard.next_pn();
        if buf.remaining_mut() > encoded_pn.size() {
            buf.put_packet_number(encoded_pn);
        } else {
            return (pn, encoded_pn.size(), 0);
        }

        let n = self.read_ack_frame_until(&mut send_guard, buf, ack_pkt);
        buf = &mut buf[n..];
        let n = self.read_reliable_frames(&mut send_guard, buf);
        buf = &mut buf[n..];

        if let Some((crypto_frame, n)) = self.crypto_stream.try_read_data(buf) {
            send_guard.record_data_frame(DataFrame::Crypto(crypto_frame));
            buf = &mut buf[n..];
        }

        (pn, encoded_pn.size(), orign - buf.remaining_mut())
    }

    fn on_ack(&self, ack_frame: AckFrame) {
        let mut recv_guard = self.0.sent_pkt_records.receive();
        recv_guard.update_largest(ack_frame.largest.into_inner());

        for pn in ack_frame.iter().flat_map(|r| r.rev()) {
            for record in recv_guard.on_pkt_acked(pn) {
                match record {
                    SentRecord::Data(DataFrame::Crypto(frame)) => {
                        self.crypto_stream.on_data_acked(frame);
                    }
                    SentRecord::Reliable(..) | SentRecord::Ack(..) => {}
                    _ => unreachable!(),
                }
            }
        }
    }

    fn may_loss_pkt(&self, pn: u64) {
        let mut sent_pkt_guard = self.0.sent_pkt_records.receive();
        let mut write_frame_guard = self.0.reliable_frame_queue.write();
        for recorf in sent_pkt_guard.may_loss_pkt(pn) {
            match recorf {
                SentRecord::Data(DataFrame::Crypto(frame)) => {
                    self.crypto_stream.may_loss_data(frame);
                }
                SentRecord::Reliable(frame) => {
                    write_frame_guard.push_reliable_frame(frame);
                }
                SentRecord::Ack(..) => {}
                _ => unreachable!(),
            }
        }
    }

    fn receive(&self, frame: SpaceFrame) -> Result<(), Error> {
        match frame {
            SpaceFrame::Data(DataFrame::Crypto(frame), data) => {
                self.crypto_stream.recv_data(frame, data)
            }
            _ => unreachable!(),
        }
    }
}

impl ArcSpace<InitalSpace> {
    pub fn new_initial_space() -> Self {
        ArcSpace::new_nodata_space()
    }
}

impl ArcSpace<HandshakeSpace> {
    pub fn new_handshake_space() -> Self {
        ArcSpace::new_nodata_space()
    }
}
