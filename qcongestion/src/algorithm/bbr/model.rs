use std::time::Instant;

// 4.1.  Maintaining the Network Path Model
// This model includes two estimated parameters: self.BtlBw, and self.RTprop.
use super::{Bbr, RTPROP_FILTER_LEN};
use crate::packets::AckedPackets;

impl Bbr {
    // 4.1.1.3.  Tracking Time for the self.BtlBw Max Filter
    // Upon connection initialization:
    pub(super) fn init_round_counting(&mut self) {
        self.next_round_delivered = 0;
        self.round_count = 0;
        self.is_round_start = false;
    }

    // Upon receiving an ACK for a given data packet:
    fn update_round(&mut self, packet: &AckedPackets) {
        if packet.delivered >= self.next_round_delivered {
            self.next_round_delivered = self.delivery_rate.delivered();
            self.round_count += 1;
            self.is_round_start = true;
            self.packet_conservation = false;
        } else {
            self.is_round_start = false;
        }
    }

    // 4.1.1.5.  Updating the BBR.BtlBw Max Filter
    pub(super) fn update_btlbw(&mut self, packet: &AckedPackets) {
        self.update_round(packet);

        if self.delivery_rate.sample_delivery_rate() >= self.btlbw
            || !self.delivery_rate.sample_is_app_limited()
        {
            self.btlbw = self
                .btlbwfilter
                .update_max(self.round_count, self.delivery_rate.sample_delivery_rate());
        }
    }

    // 4.1.2.2.  BBR.RTprop Min Filter
    pub(super) fn update_rtprop(&mut self) {
        let sample_rtt = self.delivery_rate.sample_rtt();
        let now = tokio::time::Instant::now();
        self.is_rtprop_expired =
            now.saturating_duration_since(self.rtprop_stamp) > RTPROP_FILTER_LEN;

        if !sample_rtt.is_zero() && (sample_rtt <= self.rtprop || self.is_rtprop_expired) {
            self.rtprop = sample_rtt;
            self.rtprop_stamp = now;
        }
    }
}
