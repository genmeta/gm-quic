use crate::{Acked, Sent};

use super::*;

impl BBRState {
    // BBR2 Functions on every packet loss event.
    //
    // 4.2.4.  Per-Loss Steps
    pub fn update_on_loss(&mut self, packet: &Sent, now: Instant) {
        self.handle_lost_packet(packet, now);
    }

    // 4.5.6.  Updating the Model Upon Packet Loss
    // 4.5.6.2.  Probing for Bandwidth In ProbeBW
    pub fn check_inflight_too_high(&mut self, now: Instant) -> bool {
        if self.is_inflight_too_high() {
            if self.bw_probe_samples {
                self.handle_inflight_too_high(now);
            }

            // inflight too high.
            return true;
        }

        // inflight not too high.
        false
    }

    pub fn is_inflight_too_high(&mut self) -> bool {
        self.lost > (self.tx_in_flight as f64 * LOSS_THRESH) as usize
    }

    fn handle_inflight_too_high(&mut self, now: Instant) {
        // Only react once per bw probe.
        self.bw_probe_samples = false;

        if !self.delivery_rate.sample_is_app_limited() {
            self.inflight_hi = self
                .tx_in_flight
                .max((self.target_inflight() as f64 * BETA) as usize);
        }

        if self.state == BBRStateMachine::ProbeBWUP {
            self.start_probe_bw_down(now);
        }
    }

    fn handle_lost_packet(&mut self, packet: &Sent, now: Instant) {
        if !self.bw_probe_samples {
            return;
        }

        self.tx_in_flight = packet.tx_in_flight;
        self.lost = (self.bytes_lost - packet.lost) as usize;

        self.delivery_rate.update_app_limited(packet.is_app_limited);

        if self.is_inflight_too_high() {
            self.tx_in_flight = self.inflight_hi_from_lost_packet(packet);

            self.handle_inflight_too_high(now);
        }
    }

    fn inflight_hi_from_lost_packet(&mut self, packet: &Sent) -> usize {
        let size = packet.size;
        let inflight_prev = self.tx_in_flight - size;
        let lost_prev = self.lost - size;
        let lost_prefix =
            (LOSS_THRESH * inflight_prev as f64 - lost_prev as f64) / (1.0 - LOSS_THRESH);

        inflight_prev + lost_prefix as usize
    }

    // 4.5.6.3.  When not Probing for Bandwidth
    pub fn update_latest_delivery_signals(&mut self) {
        // Near start of ACK processing.
        self.loss_round_start = false;
        self.bw_latest = self
            .bw_latest
            .max(self.delivery_rate.sample_delivery_rate());
        self.inflight_latest = self
            .inflight_latest
            .max(self.delivery_rate.sample_delivered());

        if self.delivery_rate.sample_prior_delivered() >= self.loss_round_delivered {
            self.loss_round_delivered = self.delivery_rate.delivered();
            self.loss_round_start = true;
        }
    }

    pub fn advance_latest_delivery_signals(&mut self) {
        // Near end of ACK processing.
        if self.loss_round_start {
            self.bw_latest = self.delivery_rate.sample_delivery_rate();
            self.inflight_latest = self.delivery_rate.sample_delivered();
        }
    }

    pub fn reset_congestion_signals(&mut self) {
        self.loss_in_round = false;
        self.loss_events_in_round = 0;
        self.bw_latest = 0;
        self.inflight_latest = 0;
    }

    pub fn update_congestion_signals(&mut self, packet: &Acked) {
        // Update congestion state on every ACK.
        self.update_max_bw(packet);

        if self.lost > 0 {
            self.loss_in_round = true;
            self.loss_events_in_round += 1;
        }

        if !self.loss_round_start {
            // Wait until end of round trip.
            return;
        }

        self.adapt_lower_bounds_from_congestion();

        self.loss_in_round = false;
        self.loss_events_in_round = 0;
    }

    fn adapt_lower_bounds_from_congestion(&mut self) {
        // Once per round-trip respond to congestion.
        if self.is_probing_bw() {
            return;
        }

        if self.loss_in_round {
            self.init_lower_bounds();
            self.loss_lower_bounds();
        }
    }

    fn init_lower_bounds(&mut self) {
        // Handle the first congestion episode in this cycle.
        if self.bw_lo == u64::MAX {
            self.bw_lo = self.max_bw;
        }

        if self.inflight_lo == usize::MAX {
            self.inflight_lo = self.congestion_window;
        }
    }

    fn loss_lower_bounds(&mut self) {
        // Adjust model once per round based on loss.
        self.bw_lo = self.bw_latest.max((self.bw_lo as f64 * BETA) as u64);
        self.inflight_lo = self
            .inflight_latest
            .max((self.inflight_lo as f64 * BETA) as usize);
    }

    pub fn reset_lower_bounds(&mut self) {
        self.bw_lo = u64::MAX;
        self.inflight_lo = usize::MAX;
    }

    pub fn bound_bw_for_model(&mut self) {
        self.bw = self.max_bw.min(self.bw_lo.min(self.bw_hi));
    }

    // This function is not defined in the draft but used.
    fn is_probing_bw(&mut self) -> bool {
        let state = self.state;

        state == BBRStateMachine::Startup
            || state == BBRStateMachine::ProbeBWREFILL
            || state == BBRStateMachine::ProbeBWUP
    }
}
