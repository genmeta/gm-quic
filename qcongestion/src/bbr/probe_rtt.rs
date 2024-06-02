use std::time::Instant;

use super::{Bbr, BbrStateMachine, PROBE_RTT_DURATION};

impl Bbr {
    // 4.3.5.  ProbeRTT
    fn check_probe_rtt(&mut self, bytes_in_flight: u64) {
        if self.state != BbrStateMachine::ProbeRTT
            && self.is_rtprop_expired
            && !self.is_idle_restart
        {
            self.enter_probe_rtt();
            self.save_cwnd();
            self.probe_rtt_done_stamp = None;
        }

        if self.state == BbrStateMachine::ProbeRTT {
            self.handle_probe_rtt(bytes_in_flight);
        }

        self.is_idle_restart = false;
    }

    fn enter_probe_rtt(&mut self) {
        self.state = BbrStateMachine::ProbeRTT;

        self.pacing_gain = 1.0;
        self.cwnd_gain = 1.0;
    }

    fn handle_probe_rtt(&mut self, bytes_in_flight: u64) {
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
        } else if bytes_in_flight <= self.min_pipe_cwnd() as u64 {
            self.probe_rtt_done_stamp = Some(now + PROBE_RTT_DURATION);
            self.probe_rtt_round_done = false;
            self.next_round_delivered = self.delivery_rate.delivered();
        }
    }

    fn exit_probe_rtt(&mut self, now: Instant) {
        if self.is_filled_pipe {
            self.enter_probe_bw();
        } else {
            self.enter_startup();
        }
    }
}
