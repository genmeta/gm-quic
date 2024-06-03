// 4.2.  BBR Control Parameters
// BBR uses three distinct but interrelated control parameters: pacing rate,
// send quantum, and congestion window (cwnd).

use std::time::Duration;

use super::{
    Bbr, BbrStateMachine, INITIAL_CWND, MINIMUM_WINDOW_PACKETS, MIN_PIPE_CWND_PKTS, MSS,
    SEND_QUANTUM_THRESHOLD_PACING_RATE,
};
use crate::rtt::INITIAL_RTT;

impl Bbr {
    // 4.2.1.  Pacing Rate
    pub(super) fn init_pacing_rate(&mut self) {
        let srtt = INITIAL_RTT;
        let nominal_bandwidth = INITIAL_CWND as f64 / srtt.as_secs_f64();
        self.pacing_rate = (self.pacing_gain * nominal_bandwidth) as u64;
    }

    pub(super) fn set_pacing_rate(&mut self) {
        self.set_pacing_rate_with_gain(self.pacing_gain);
    }

    pub(super) fn set_pacing_rate_with_gain(&mut self, pacing_gain: f64) {
        let rate = (pacing_gain * self.btlbw as f64) as u64;
        if self.is_filled_pipe || rate > self.pacing_rate {
            self.pacing_rate = rate;
        }
    }

    // 4.2.2.  Send Quantum
    pub(super) fn set_send_quantum(&mut self) {
        let floor = if self.pacing_rate < SEND_QUANTUM_THRESHOLD_PACING_RATE {
            MSS
        } else {
            2 * MSS
        };

        // BBR.send_quantum  = min(BBR.pacing_rate * 1ms, 64KBytes)
        self.send_quantum = (self.pacing_rate / 1000).clamp(floor as u64, 64 * 1024);
    }

    // 4.2.3.  Congestion Window
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

    // 4.2.3.4 Modulating cwnd in Loss Recovery
    pub(super) fn save_cwnd(&mut self) {
        self.prior_cwnd = if !self.in_recovery && self.state != BbrStateMachine::ProbeRTT {
            self.cwnd
        } else {
            self.cwnd.max(self.prior_cwnd)
        }
    }

    pub fn restore_cwnd(&mut self) {
        self.cwnd = self.cwnd.max(self.prior_cwnd)
    }

    fn modulate_cwnd_for_recovery(&mut self, bytes_in_flight: u64) {
        if self.newly_lost_bytes > 0 {
            self.cwnd = self
                .cwnd
                .saturating_sub(self.newly_lost_bytes)
                .max((MSS * MINIMUM_WINDOW_PACKETS) as u64);
        }

        if self.packet_conservation {
            self.cwnd = self.cwnd.max(bytes_in_flight + self.newly_acked_bytes);
        }
    }

    // 4.2.3.5 Modulating cwnd in ProbeRTT
    fn modulate_cwnd_for_probe_rtt(&mut self) {
        if self.state == BbrStateMachine::ProbeRTT {
            self.cwnd = self.cwnd.min(self.min_pipe_cwnd());
        }
    }

    // 4.2.3.6.  Core cwnd Adjustment Mechanism
    pub(super) fn set_cwnd(&mut self) {
        let bytes_in_flight = self.bytes_in_flight;

        self.update_target_cwnd();
        self.modulate_cwnd_for_recovery(bytes_in_flight);

        if !self.packet_conservation {
            if self.is_filled_pipe {
                self.cwnd = self.target_cwnd.min(self.cwnd + self.newly_acked_bytes);
            } else if self.cwnd < self.target_cwnd
                || self.delivery_rate.delivered() < INITIAL_CWND as usize
            {
                self.cwnd += self.newly_acked_bytes;
            }
            self.cwnd = self.cwnd.max(self.min_pipe_cwnd());
        }

        self.modulate_cwnd_for_probe_rtt();
    }

    /// The minimal cwnd value BBR tries to target, in bytes
    pub(super) fn min_pipe_cwnd(&self) -> u64 {
        (MIN_PIPE_CWND_PKTS * MSS) as u64
    }
}
