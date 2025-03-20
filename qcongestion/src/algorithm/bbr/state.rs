use std::time::Instant;

use rand::Rng;

use super::{Bbr, BbrStateMachine, HIGH_GAIN, PROBE_RTT_DURATION};
use crate::rtt::INITIAL_RTT;

// BBRGainCycleLen: the number of phases in the BBR ProbeBW gain cycle: 8.
const GAIN_CYCLE_LEN: usize = 8;

// Pacing Gain Cycles. Each phase normally lasts for roughly BBR.RTprop.
const PACING_GAIN_CYCLE: [f64; GAIN_CYCLE_LEN] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];

impl Bbr {
    pub(super) fn init(&mut self) {
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

    // 4.3.2.1. Startup Dynamics
    pub(crate) fn enter_startup(&mut self) {
        self.state = BbrStateMachine::Startup;
        self.pacing_gain = HIGH_GAIN;
        self.cwnd_gain = HIGH_GAIN;
    }

    // 4.3.2.2.  Estimating When Startup has Filled the Pipe
    fn init_full_pipe(&mut self) {
        self.is_filled_pipe = false;
        self.full_bw = 0;
        self.full_bw_count = 0;
    }

    // 退出 startup 进入 drain 的条件是连续三回合没有带宽增长
    pub(super) fn check_full_pipe(&mut self) {
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

    // 4.3.3.  Drain
    fn enter_drain(&mut self) {
        self.state = BbrStateMachine::Drain;
        self.pacing_gain = 1.0 / HIGH_GAIN; // pace slowly
        self.cwnd_gain = HIGH_GAIN; // maintain cwnd
    }

    pub(super) fn check_drain(&mut self) {
        if self.state == BbrStateMachine::Startup && self.is_filled_pipe {
            self.enter_drain()
        }
        if self.state == BbrStateMachine::Drain && self.bytes_in_flight <= self.inflight(1.0) {
            self.enter_probe_bw();
        }
    }

    // 4.3.4.  ProbeBW
    pub fn enter_probe_bw(&mut self) {
        self.state = BbrStateMachine::ProbeBW;
        self.pacing_gain = 1.0;
        self.cwnd_gain = 2.0;

        // 随机从一个阶段开始
        self.cycle_index = GAIN_CYCLE_LEN - 1 - rand::rng().random_range(0..GAIN_CYCLE_LEN - 1);
        self.advance_cycle_phase()
    }

    // On each ACK BBR runs BBRCheckCyclePhase(), to see if it's time to
    // advance to the next gain cycle phase:
    pub(super) fn check_cycle_phase(&mut self) {
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
    pub(super) fn handle_restart_from_idle(&mut self) {
        if self.bytes_in_flight == 0 && self.delivery_rate.app_limited() {
            self.is_idle_restart = true;

            if self.state == BbrStateMachine::ProbeBW {
                self.set_pacing_rate_with_gain(1.0);
            }
        }
    }

    // 4.3.5.  ProbeRTT
    pub(super) fn check_probe_rtt(&mut self) {
        if self.state != BbrStateMachine::ProbeRTT
            && self.is_rtprop_expired
            && !self.is_idle_restart
        {
            self.enter_probe_rtt();
            self.save_cwnd();
            self.probe_rtt_done_stamp = None;
        }

        if self.state == BbrStateMachine::ProbeRTT {
            self.handle_probe_rtt();
        }

        self.is_idle_restart = false;
    }

    fn enter_probe_rtt(&mut self) {
        self.state = BbrStateMachine::ProbeRTT;

        self.pacing_gain = 1.0;
        self.cwnd_gain = 1.0;
    }

    fn handle_probe_rtt(&mut self) {
        // C.app_limited = (BW.delivered + packets_in_flight) ? : 1
        self.delivery_rate.update_app_limited(true);

        let now = Instant::now();
        if let Some(probe_rtt_done_stamp) = self.probe_rtt_done_stamp {
            if self.is_round_start {
                self.probe_rtt_round_done = true;
            }

            if self.probe_rtt_round_done && now >= probe_rtt_done_stamp {
                self.rtprop_stamp = now;

                self.restore_cwnd();
                self.exit_probe_rtt(now);
            }
        } else if self.bytes_in_flight <= self.min_pipe_cwnd() {
            self.probe_rtt_done_stamp = Some(now + PROBE_RTT_DURATION);
            self.probe_rtt_round_done = false;
            self.next_round_delivered = self.delivery_rate.delivered();
        }
    }

    fn exit_probe_rtt(&mut self, _: Instant) {
        if self.is_filled_pipe {
            self.enter_probe_bw();
        } else {
            self.enter_startup();
        }
    }
}

#[cfg(test)]
mod tests {

    use std::time::{Duration, Instant};

    use crate::algorithm::bbr::{
        BbrStateMachine, HIGH_GAIN, INITIAL_CWND, MSS, tests::simulate_round_trip,
    };

    #[test]
    fn test_bbr_init() {
        let mut bbr = super::Bbr::new();
        bbr.init();
        assert_eq!(bbr.state, BbrStateMachine::Startup);
        assert_eq!(bbr.pacing_gain, HIGH_GAIN);
        assert_eq!(bbr.cwnd_gain, HIGH_GAIN);
        assert_eq!(bbr.cwnd, INITIAL_CWND);
    }

    #[test]
    fn test_bbr_enter_startup() {
        let mut bbr = super::Bbr::new();
        bbr.enter_startup();
        assert_eq!(bbr.state, BbrStateMachine::Startup);
        assert_eq!(bbr.pacing_gain, HIGH_GAIN);
        assert_eq!(bbr.cwnd_gain, HIGH_GAIN);
    }

    #[test]
    fn test_bbr_check_full_pipe() {
        let mut bbr = super::Bbr::new();

        let mut now = Instant::now();
        let rtt = Duration::from_millis(100);
        simulate_round_trip(&mut bbr, now, rtt, 0, 10, MSS);
        now += Duration::from_secs(1);
        simulate_round_trip(&mut bbr, now, rtt, 0, 10, MSS);

        assert_eq!(bbr.btlbw, (10 * 10 * MSS) as u64);
        bbr.check_full_pipe();
        assert!(!bbr.is_filled_pipe);

        now += Duration::from_secs(1);
        simulate_round_trip(&mut bbr, now, rtt, 0, 10, MSS);
        assert_eq!(bbr.btlbw, (10 * 10 * MSS) as u64);

        bbr.check_full_pipe();
        assert!(!bbr.is_filled_pipe);

        now += Duration::from_secs(1);
        simulate_round_trip(&mut bbr, now, rtt, 0, 10, MSS);

        bbr.check_full_pipe();
        assert!(bbr.is_filled_pipe);
    }

    #[test]
    fn test_bbr_check_drain() {
        let mut bbr = super::Bbr::new();
        bbr.init();
        bbr.is_filled_pipe = true;
        bbr.bytes_in_flight = 100;
        bbr.check_drain();
        assert_eq!(bbr.state, BbrStateMachine::Drain);

        let mut bbr = super::Bbr::new();
        bbr.init();
        bbr.is_filled_pipe = true;
        bbr.check_drain();
        assert_eq!(bbr.state, BbrStateMachine::ProbeBW);
    }

    #[test]
    fn test_bbr_enter_probe_bw() {
        let mut bbr = super::Bbr::new();
        bbr.init();
        bbr.enter_probe_bw();
        assert_eq!(bbr.state, BbrStateMachine::ProbeBW);
        assert_eq!(bbr.cwnd_gain, 2.0);
    }

    #[test]
    fn test_bbr_advance_cycle_phase() {
        let mut bbr = super::Bbr::new();
        bbr.init();
        bbr.cycle_index = 0;
        bbr.advance_cycle_phase();
        assert_eq!(bbr.pacing_gain, 0.75);

        bbr.cycle_index = 7;
        bbr.advance_cycle_phase();
        assert_eq!(bbr.pacing_gain, 1.25)
    }

    #[test]
    fn test_bbr_is_next_cycle_phase() {
        let mut bbr = super::Bbr::new();
        bbr.init();
        bbr.enter_probe_bw();
        let now = Instant::now();

        bbr.pacing_gain = 1.0;
        bbr.cycle_stamp = now - Duration::from_secs(1);
        assert!(bbr.is_next_cycle_phase());

        bbr.pacing_gain = 0.75;
        bbr.cycle_stamp = now - Duration::from_secs(1);
        bbr.prior_bytes_in_flight = 100;
        assert!(bbr.is_next_cycle_phase());

        bbr.pacing_gain = 1.25;
        bbr.cycle_stamp = now - Duration::from_secs(1);
        assert!(bbr.is_next_cycle_phase());
    }

    #[test]
    fn test_restart_from_idle() {
        let mut bbr = super::Bbr::new();
        bbr.init();

        bbr.bytes_in_flight = 0;
        bbr.handle_restart_from_idle();

        assert!(!bbr.is_idle_restart);
    }
}
