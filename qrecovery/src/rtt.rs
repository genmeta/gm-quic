use std::{
    ops::Mul,
    time::{Duration, Instant},
};

const INITIAL_RTT: Duration = Duration::from_millis(333);
const GRANULARITY: Duration = Duration::from_millis(1);

#[derive(Debug, Clone)]
pub struct Rtt {
    first_rtt_sample: Option<Instant>,
    smoothed_rtt: Duration,
    rttvar: Duration,
    min_rtt: Duration,
}

impl Default for Rtt {
    fn default() -> Self {
        Self {
            first_rtt_sample: None,
            smoothed_rtt: INITIAL_RTT,
            rttvar: INITIAL_RTT / 2,
            min_rtt: Duration::from_millis(0),
        }
    }
}

impl Rtt {
    pub fn update(&mut self, latest_rtt: Duration, ack_delay: Duration) {
        if self.first_rtt_sample.is_none() {
            self.min_rtt = latest_rtt;
            self.smoothed_rtt = latest_rtt;
            self.rttvar = latest_rtt / 2;
            self.first_rtt_sample = Some(Instant::now());
            return;
        }

        // min_rtt ignores acknowledgment delay.
        self.min_rtt = std::cmp::min(self.min_rtt, latest_rtt);

        // Adjust for acknowledgment delay if plausible.
        let mut adjusted_rtt = latest_rtt;
        if latest_rtt >= self.min_rtt + ack_delay {
            adjusted_rtt = latest_rtt - ack_delay;
        }

        let abs_diff = if self.smoothed_rtt > adjusted_rtt {
            self.smoothed_rtt - adjusted_rtt
        } else {
            adjusted_rtt - self.smoothed_rtt
        };
        self.rttvar = self.rttvar.mul_f32(0.75) + abs_diff.mul_f32(0.25);
        self.smoothed_rtt = self.smoothed_rtt.mul_f32(0.875) + adjusted_rtt.mul_f32(0.125);
    }

    pub fn loss_delay(&self, latest_rtt: Duration) -> Duration {
        let delay = std::cmp::max(latest_rtt, self.smoothed_rtt).mul_f32(1.125);
        std::cmp::max(delay, GRANULARITY)
    }

    pub fn pto_base_duration(&self, pto_count: u32) -> Duration {
        (self.smoothed_rtt + std::cmp::max(self.rttvar * 4, GRANULARITY)) * (1 << pto_count)
    }
}
