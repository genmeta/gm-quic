use super::{Bbr, BbrStateMachine, DEFAULT_MTU, INITIAL_CWND, MIN_PIPE_CWND_PKTS};
use std::time::Duration;

impl Bbr {
    // 4.2.3.2.  Target cwnd
    pub fn inflight(&self, gain: f64) -> u64 {
        if self.rtprop == Duration::MAX {
            return INITIAL_CWND;
        }

        let quanta = 3 * self.send_quantum;
        let estimated_bdp = self.btlbw as f64 * self.rtprop.as_secs_f64();
        (gain * estimated_bdp) as u64 + quanta
    }

    fn update_target_cwnd(&mut self) {
        self.target_cwnd = self.inflight(self.cwnd_gain);
    }

    // 4.2.1.  Pacing Rate
    pub fn set_pacing_rate_with_gain(&mut self, pacing_gain: f64) {
        let rate = (pacing_gain * self.btlbw as f64) as u64;
        if self.is_filled_pipe || rate > self.pacing_rate {
            self.pacing_rate = rate;
        }
    }

    pub fn restore_cwnd(&mut self) {
        self.cwnd = self.cwnd.max(self.prior_cwnd)
    }

    pub(super) fn save_cwnd(&mut self) {
        self.prior_cwnd = if !self.in_recovery && self.state != BbrStateMachine::ProbeRTT {
            self.cwnd
        } else {
            self.cwnd.max(self.prior_cwnd)
        }
    }

    /// The minimal cwnd value BBR tries to target, in bytes
    pub(super) fn min_pipe_cwnd(&self) -> usize {
        MIN_PIPE_CWND_PKTS * DEFAULT_MTU as usize
    }
}
