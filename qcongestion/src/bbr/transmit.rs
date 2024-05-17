use super::*;

use std::time::Instant;

impl BBRState {
    // 4.2.2.  Per-Transmit Steps
    pub fn on_transmit(&mut self, now: Instant) {
        self.handle_restart_from_idle(now);
    }

    // 4.4.3.  Logic
    fn handle_restart_from_idle(&mut self, now: Instant) {
        if self.bytes_in_flight == 0 && self.delivery_rate.app_limited() {
            self.idle_restart = true;
            self.extra_acked_interval_start = now;

            if self.is_in_a_probe_bw_state() {
                self.set_pacing_rate_with_gain(1.0);
            } else if self.state == BBRStateMachine::ProbeRTT {
                self.check_probe_rtt_done(now);
            }
        }
    }
}
