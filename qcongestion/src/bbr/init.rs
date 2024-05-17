use super::*;

use std::time::Instant;

impl BBRState {
    // 4.2.1.  Initialization
    pub fn init(&mut self) {
        let now = Instant::now();

        // self.min_rtt = rtt;
        self.min_rtt_stamp = now;
        self.probe_rtt_done_stamp = None;
        self.probe_rtt_round_done = false;
        self.prior_cwnd = 0;
        self.idle_restart = false;
        self.extra_acked_interval_start = now;
        self.extra_acked_delivered = 0;
        self.bw_lo = u64::MAX;
        self.bw_hi = u64::MAX;
        self.inflight_lo = usize::MAX;
        self.inflight_hi = usize::MAX;
        self.probe_up_cnt = usize::MAX;

        self.reset_congestion_signals();
        self.reset_lower_bounds();
        self.init_round_counting();
        self.init_full_pipe();
        self.init_pacing_rate();
        self.enter_startup();
    }

    // 4.5.1.  BBR.round_count: Tracking Packet-Timed Round Trips
    fn init_round_counting(&mut self) {
        self.next_round_delivered = 0;
        self.round_start = false;
        self.round_count = 0;
    }

    // 4.3.1.1.  Startup Dynamics
    pub fn enter_startup(&mut self) {
        self.state = BBRStateMachine::Startup;
        self.pacing_gain = STARTUP_PACING_GAIN;
        self.cwnd_gain = STARTUP_CWND_GAIN;
    }

    // 4.3.1.2.  Exiting Startup Based on Bandwidth Plateau
    fn init_full_pipe(&mut self) {
        self.filled_pipe = false;
        self.full_bw = 0;
        self.full_bw_count = 0;
    }
}
