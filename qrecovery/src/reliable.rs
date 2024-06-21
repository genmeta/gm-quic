use std::time::Instant;

use bytes::BufMut;
use qbase::{
    frame::{
        io::{WriteAckFrame, WriteFrame},
        AckFrame, BeFrame, DataFrame,
    },
    packet::WritePacketNumber,
};

mod queue;
mod rcvdpkt;
mod sendpkt;

pub use queue::*;
pub use rcvdpkt::*;
pub use sendpkt::*;

#[derive(Default, Debug, Clone)]
pub struct ReliableTransmit {
    pub reliable_frame_queue: ArcReliableFrameQueue,
    pub sent_pkt_records: ArcSentPktRecords,
    pub rcvd_pkt_records: ArcRcvdPktRecords,
}

impl ReliableTransmit {
    pub fn try_read(&self, buf: &mut impl BufMut, ack_pkt: Option<(u64, Instant)>) -> (u64, usize) {
        let mut send_guard = self.sent_pkt_records.send();

        let (pn, encoded_pb) = send_guard.next_pn();
        if buf.remaining_mut() > encoded_pb.size() {
            buf.put_packet_number(encoded_pb);
        } else {
            return (pn, encoded_pb.size());
        }

        if let Some(largest) = ack_pkt {
            let ack_frame = self
                .rcvd_pkt_records
                .gen_ack_frame_util(largest, buf.remaining_mut());
            buf.put_ack_frame(&ack_frame);
            send_guard.record_ack_frame(ack_frame);
        }

        let mut read_frame_guard = self.reliable_frame_queue.read();
        while let Some(frame) = read_frame_guard.front() {
            let remaining = buf.remaining_mut();
            if remaining > frame.max_encoding_size() || remaining > frame.encoding_size() {
                buf.put_frame(frame);
                let frame = read_frame_guard.pop_front().unwrap();
                send_guard.record_reliable_frame(frame);
            } else {
                break;
            }
        }

        (pn, encoded_pb.size())
    }

    pub fn on_rcvd_ack(&self, ack: &AckFrame, mut data_frame_resolver: impl FnMut(DataFrame)) {
        let mut recv_guard = self.sent_pkt_records.receive();
        recv_guard.update_largest(ack.largest.into_inner());

        for pn in ack.iter().flat_map(|r| r.rev()) {
            for record in recv_guard.on_pkt_acked(pn) {
                if let SentRecord::Data(data_frame) = record {
                    data_frame_resolver(data_frame)
                }
            }
        }
    }

    pub fn may_loss_pkt(&self, pn: u64, mut data_frame_resolver: impl FnMut(DataFrame)) {
        let mut sent_pkt_guard = self.sent_pkt_records.receive();
        let mut write_frame_guard = self.reliable_frame_queue.write();
        for record in sent_pkt_guard.may_loss_pkt(pn) {
            match record {
                SentRecord::Reliable(frame) => {
                    write_frame_guard.push_reliable_frame(frame);
                }
                SentRecord::Data(data_frame) => data_frame_resolver(data_frame),
                SentRecord::Ack(_) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {}
