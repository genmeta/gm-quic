use super::{Bbr, BbrStateMachine, HIGH_GAIN};

impl Bbr {
    fn enter_drain(&mut self) {
        self.state = BbrStateMachine::Drain;
        self.pacing_gain = 1.0 / HIGH_GAIN; // pace slowly
        self.cwnd_gain = HIGH_GAIN; // maintain cwnd
    }

    fn check_drain(&mut self) {
        if self.state == BbrStateMachine::Startup && self.is_filled_pipe {
            self.enter_drain()
        }
        if self.state == BbrStateMachine::Drain && self.bytes_in_flight <= self.inflight(1.0) {
            self.enter_probe_bw();
        }
    }
}
