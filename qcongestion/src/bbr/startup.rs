use std::time::Instant;

use crate::rtt::INITIAL_RTT;

use super::{Bbr, BbrStateMachine, HIGH_GAIN, INITIAL_CWND};

impl Bbr {
    fn init(&mut self) {
        self.rtprop = INITIAL_RTT;
        self.rtprop_stamp = Instant::now();
        self.probe_rtt_done_stamp = None;
        self.probe_rtt_round_done = false;
        self.packet_conservation = false;
        self.prior_cwnd = 0;
        self.is_idle_restart = false;

        self.init_round_counting();
        self.init_full_pipe();
        self.init_pacing_rate();
        self.enter_startup();
    }

    // 4.1.1.3
    fn init_round_counting(&mut self) {
        self.next_round_delivered = 0;
        self.round_count = 0;
        self.is_round_start = false;
    }

    // 4.2.1.  Pacing Rate
    fn init_pacing_rate(&mut self) {
        let srtt = INITIAL_RTT;
        let nominal_bandwidth = INITIAL_CWND as f64 / srtt.as_secs_f64();
        self.pacing_rate = (self.pacing_gain * nominal_bandwidth) as u64;
    }

    // 4.3.2.2 Estimating When Startup has Filled the Pipe
    fn init_full_pipe(&mut self) {
        self.is_filled_pipe = false;
        self.full_bw = 0;
        self.full_bw_count = 0;
    }

    // 退出 startup 进入 drain 的条件是连续三回合没有带宽增长
    fn check_full_pipe(&mut self) {
        if self.is_filled_pipe || !self.is_round_start || self.delivery_rate.app_limited() {
            // no need to check for a full pipe now
            return;
        }

        // BBR.BtlBw still growing?
        if self.btlbw as f64 >= self.full_bw as f64 * 1.25 {
            // record new baseline level
            self.full_bw = self.btlbw;
            self.full_bw_count = 0;
        }

        self.full_bw_count += 1;
        if self.full_bw_count >= 3 {
            self.is_filled_pipe = true;
        }
    }

    // 4.3.2.1. Startup Dynamics
    pub(crate) fn enter_startup(&mut self) {
        self.state = BbrStateMachine::Startup;
        self.pacing_gain = HIGH_GAIN;
        self.cwnd_gain = HIGH_GAIN;
    }
}
