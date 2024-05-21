/// Application data space, 0-RTT data space
use super::OneRttDataSpace;
use crate::{
    crypto::{CryptoStream, NoCrypto},
    streams::Streams,
};
use qbase::{streamid::StreamIds, SpaceId};

pub type ZeroRttDataSpace = super::Space<NoCrypto, Streams>;

impl ZeroRttDataSpace {
    pub fn new(stream_ids: StreamIds) -> Self {
        let streams = Streams::new(stream_ids);
        ZeroRttDataSpace::build(SpaceId::ZeroRtt, NoCrypto, streams)
    }

    pub fn upgrade(self, crypto_stream: CryptoStream) -> OneRttDataSpace {
        OneRttDataSpace {
            space_id: SpaceId::OneRtt,
            frames: self.frames,
            inflight_packets: self.inflight_packets,
            disorder_tolerance: self.disorder_tolerance,
            time_of_last_sent_ack_eliciting_packet: self.time_of_last_sent_ack_eliciting_packet,
            largest_acked_pktid: self.largest_acked_pktid,
            loss_time: self.loss_time,
            rcvd_packets: self.rcvd_packets,
            largest_rcvd_ack_eliciting_pktid: self.largest_rcvd_ack_eliciting_pktid,
            last_synced_ack_largest: self.last_synced_ack_largest,
            new_lost_event: self.new_lost_event,
            rcvd_unreached_packet: self.rcvd_unreached_packet,
            time_to_sync: self.time_to_sync,
            max_ack_delay: self.max_ack_delay,
            stm_trans: self.stm_trans,
            tls_trans: crypto_stream,
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
