use std::time::Instant;

use rand::Rng;

use super::{Bbr, BbrStateMachine};

// BBRGainCycleLen: the number of phases in the BBR ProbeBW gain cycle:
// 8.
const GAIN_CYCLE_LEN: usize = 8;

// Pacing Gain Cycles. Each phase normally lasts for roughly BBR.RTprop.
const PACING_GAIN_CYCLE: [f64; GAIN_CYCLE_LEN] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];

impl Bbr {
    // 4.3.4.3.  Gain Cycling Algorithm
    pub fn enter_probe_bw(&mut self) {
        self.state = BbrStateMachine::ProbeBW;
        self.pacing_gain = 1.0;
        self.cwnd_gain = 2.0;

        // 随机从一个阶段开始
        self.cycle_index = GAIN_CYCLE_LEN - 1 - rand::thread_rng().gen_range(0..GAIN_CYCLE_LEN - 1);
        self.advance_cycle_phase()
    }

    // On each ACK BBR runs BBRCheckCyclePhase(), to see if it's time to
    // advance to the next gain cycle phase:
    fn check_cycle_phase(&mut self) {
        if self.state == BbrStateMachine::ProbeBW && self.is_next_cycle_phase() {
            self.advance_cycle_phase();
        }
    }

    fn advance_cycle_phase(&mut self) {
        self.cycle_stamp = Instant::now();
        self.cycle_index = (self.cycle_index + 1) % GAIN_CYCLE_LEN;
        self.pacing_gain = PACING_GAIN_CYCLE[self.cycle_index];
    }

    // 是否要进入下一阶段
    fn is_next_cycle_phase(&mut self) -> bool {
        let now = Instant::now();
        let is_full_length = now.saturating_duration_since(self.cycle_stamp) > self.rtprop;

        // pacing_gain == 1.0 持续 rtprop
        if (self.pacing_gain - 1.0).abs() < f64::EPSILON {
            return is_full_length;
        }

        // pacing_gain > 1 至少持续 rtprop 且 出现丢包或 inflight 达到 5/4 * estimated_BDP
        if self.pacing_gain > 1.0 {
            return is_full_length
                && (self.newly_lost_bytes > 0
                    || self.prior_bytes_in_flight >= self.inflight(self.pacing_gain));
        }

        // pacing_gain < 1 至少持续 rtprop 且  inflight 达到 estimated_BDP
        is_full_length || self.prior_bytes_in_flight <= self.inflight(1.0)
    }

    // 4.3.4.4.  Restarting From Idle
    fn handle_restart_from_idle(&mut self, bytes_in_flight: u64) {
        if bytes_in_flight == 0 && self.delivery_rate.app_limited() {
            self.is_idle_restart = true;

            if self.state == BbrStateMachine::ProbeBW {
                self.set_pacing_rate_with_gain(1.0);
            }
        }
    }
}
