use std::{sync::Arc, time::Instant};

use bytes::BufMut;
use qbase::{
    config::TransportParameters,
    frame::{io::WriteFrame, AckFrame, BeFrame, DataFrame},
    packet::WritePacketNumber,
    streamid::Role,
};

use super::{ArcSpace, RawSpace, ReliableTransmit, TransportLimit};
use crate::{
    crypto::CryptoStream,
    reliable::{
        rcvdpkt::ArcRcvdPktRecords,
        sentpkt::{ArcSentPktRecords, SentRecord},
        ArcReliableFrameQueue,
    },
    streams::DataStreams,
};

#[derive(Debug, Clone)]
pub struct DataSpace {
    pub crypto_stream: CryptoStream,
    pub data_stream: DataStreams,
}

impl AsRef<CryptoStream> for DataSpace {
    fn as_ref(&self) -> &CryptoStream {
        &self.crypto_stream
    }
}

impl AsRef<DataStreams> for DataSpace {
    fn as_ref(&self) -> &DataStreams {
        &self.data_stream
    }
}

impl ArcSpace<DataSpace> {
    pub fn new_data_space(role: Role, max_bi_streams: u64, max_uni_streams: u64) -> Self {
        let crypto_stream = CryptoStream::new(1_000_000, 1_000_000);
        let reliable_frame_queue = ArcReliableFrameQueue::default();
        let data_stream = DataStreams::with_role_and_limit(
            role,
            max_bi_streams,
            max_uni_streams,
            reliable_frame_queue.clone(),
        );

        Self(Arc::new(RawSpace {
            reliable_frame_queue,
            sent_pkt_records: ArcSentPktRecords::default(),
            rcvd_pkt_records: ArcRcvdPktRecords::default(),
            space: DataSpace {
                crypto_stream,
                data_stream,
            },
        }))
    }

    pub fn accept_transmute_parameters(&self, param: &TransportParameters) {
        self.0.space.data_stream.update_limit(
            param.initial_max_streams_bidi().into(),
            param.initial_max_streams_uni().into(),
        );
    }
}

impl ReliableTransmit for ArcSpace<DataSpace> {
    fn read(
        &self,
        limit: &mut TransportLimit,
        mut buf: &mut [u8],
        ack_pkt: Option<(u64, Instant)>,
    ) -> (u64, usize, usize) {
        let remain = limit.available();

        let mut send_guard = self.0.sent_pkt_records.send();

        let (pn, encoded_pn) = send_guard.next_pn();
        if buf.remaining_mut() > encoded_pn.size() {
            buf.put_packet_number(encoded_pn);
            limit.record_write(encoded_pn.size());
        } else {
            return (pn, encoded_pn.size(), 0);
        }

        if let Some((frame, n)) = self.read_ack_frame_until(limit, buf, ack_pkt) {
            send_guard.record_ack_frame(frame);
            buf = &mut buf[n..];
        }

        // 可靠帧数量大，一个个读可能太慢了
        {
            // 不用算长度，否则会消耗双倍空间
            let mut reliable_frame_reader = self.reliable_frame_queue.read();
            while let Some(frame) = reliable_frame_reader.front() {
                let available = limit.available();
                if available < frame.max_encoding_size() && available < frame.encoding_size() {
                    break;
                }
                buf.put_frame(frame);
                let frame = reliable_frame_reader.pop_front().unwrap();
                limit.record_write(frame.encoding_size());
                send_guard.record_reliable_frame(frame);
            }
        };

        if let Some((crypto_frame, written)) = self.crypto_stream.try_read_data(limit, buf) {
            send_guard.record_data_frame(DataFrame::Crypto(crypto_frame));
            buf = &mut buf[written..];
        }

        if let Some((stream_frame, written)) = self.data_stream.try_read_data(limit, buf) {
            send_guard.record_data_frame(DataFrame::Stream(stream_frame));
            buf = &mut buf[written..];
        }

        (pn, encoded_pn.size(), remain - buf.remaining_mut())
    }

    fn on_ack(&self, ack_frmae: AckFrame) {
        let mut recv_guard = self.0.sent_pkt_records.receive();
        recv_guard.update_largest(ack_frmae.largest.into_inner());

        for pn in ack_frmae.iter().flat_map(|r| r.rev()) {
            for record in recv_guard.on_pkt_acked(pn) {
                match record {
                    SentRecord::Data(DataFrame::Crypto(frame)) => {
                        self.crypto_stream.on_data_acked(frame);
                    }
                    SentRecord::Data(DataFrame::Stream(frame)) => {
                        self.data_stream.on_data_acked(frame);
                    }
                    SentRecord::Reliable(..) | SentRecord::Ack(..) => {}
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
                SentRecord::Data(DataFrame::Stream(frame)) => {
                    self.data_stream.may_loss_data(frame);
                }
                SentRecord::Reliable(frame) => {
                    write_frame_guard.push_reliable_frame(frame);
                }
                SentRecord::Ack(..) => {}
            }
        }
    }

    fn probe_timeout(&self) {
        // TODO: pto 超时，
        // 1. 有数据发送，发送新数据
        // 2. 没有数据发送，发送 ping 帧
    }
}
