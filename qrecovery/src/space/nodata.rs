use std::{marker::PhantomData, sync::Arc, time::Instant};

use bytes::BufMut;
use qbase::{
    frame::{io::WriteFrame, AckFrame, BeFrame, DataFrame},
    packet::WritePacketNumber,
};

use super::{ArcSpace, RawSpace, ReliableTransmit, SpaceRead, TransportLimit};
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

#[derive(Debug, Clone, Copy)]
pub struct Initial;
impl NoDataSpaceKind for Initial {}
pub type InitialSpace = NoDataSpace<Initial>;

#[derive(Debug, Clone, Copy)]
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

impl<K: NoDataSpaceKind> SpaceRead for ArcSpace<NoDataSpace<K>> {
    fn read_frame(
        &self,
        limit: &mut TransportLimit,
        mut buf: &mut [u8],
        ack_pkt: Option<(u64, Instant)>,
    ) -> (usize, bool) {
        let origin = limit.available();

        let mut send_guard = self.0.sent_pkt_records.send();

        if let Some((frame, n)) = self.read_ack_frame_until(buf, ack_pkt) {
            send_guard.record_ack_frame(frame);
            buf = &mut buf[n..];
        }

        let mut is_ack_eliciting = false;
        {
            let mut reliable_frame_reader = self.reliable_frame_queue.read();
            while let Some(frame) = reliable_frame_reader.front() {
                let available = limit.available();
                if available < frame.max_encoding_size() && available < frame.encoding_size() {
                    break;
                }
                if frame.is_ack_eliciting() {
                    is_ack_eliciting = true;
                }
                buf.put_frame(frame);
                let frame = reliable_frame_reader.pop_front().unwrap();
                limit.record_write(frame.encoding_size());
                send_guard.record_reliable_frame(frame);
            }
        };

        if let Some((crypto_frame, n)) = self.crypto_stream.try_read_data(limit, buf) {
            send_guard.record_data_frame(DataFrame::Crypto(crypto_frame));
            buf = &mut buf[n..];
            is_ack_eliciting = true;
        }

        (origin - buf.remaining_mut(), is_ack_eliciting)
    }

    // todo: data 和 no data 实现是一样的
    fn read_pn(&self, mut buf: &mut [u8], limit: &mut TransportLimit) -> (u64, usize) {
        let send_guard = self.0.sent_pkt_records.send();
        let (pn, encoded_pn) = send_guard.next_pn();
        if buf.remaining_mut() > encoded_pn.size() {
            buf.put_packet_number(encoded_pn);
            limit.record_write(encoded_pn.size());
            (pn, encoded_pn.size())
        } else {
            (0, 0)
        }
    }

    fn read_finish(&self) {
        let mut gaurd = self.0.sent_pkt_records.send();
        gaurd.finish();
    }
}

impl<K: NoDataSpaceKind> ReliableTransmit for ArcSpace<NoDataSpace<K>> {
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

    fn probe_timeout(&self) {
        // 握手期间 PTO 超时，重发 INITIAL 包或 HANDSHAKE 包
        todo!()
    }

    fn indicate_ack(&self, pn: u64) {
        self.0.rcvd_pkt_records.write().inactivate(pn);
    }
}

impl ArcSpace<InitialSpace> {
    pub fn new_initial_space() -> Self {
        ArcSpace::new_nodata_space()
    }
}

impl ArcSpace<HandshakeSpace> {
    pub fn new_handshake_space() -> Self {
        ArcSpace::new_nodata_space()
    }
}
