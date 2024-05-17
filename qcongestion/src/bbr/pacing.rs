use super::*;

use std::time::Duration;

// BBR2 Transmit Packet Pacing Functions
//

impl BBRState {
    // 4.6.2.  Pacing Rate: BBR.pacing_rate
    pub fn init_pacing_rate(&mut self) {
        let srtt = self
            .smoothed_rtt
            .unwrap_or_else(|| Duration::from_millis(1))
            .as_secs_f64();

        // At init, cwnd is initcwnd.
        let nominal_bandwidth = self.congestion_window as f64 / srtt;

        self.pacing_rate = (STARTUP_PACING_GAIN * nominal_bandwidth) as u64;
        self.init_pacing_rate = (STARTUP_PACING_GAIN * nominal_bandwidth) as u64;
    }

    pub fn set_pacing_rate_with_gain(&mut self, pacing_gain: f64) {
        let rate = (pacing_gain * self.bw as f64 * (1.0 - PACING_MARGIN_PERCENT)) as u64;

        if self.filled_pipe || rate > self.pacing_rate || self.pacing_rate == self.init_pacing_rate
        {
            self.pacing_rate = rate;
        }
    }

    pub fn set_pacing_rate(&mut self) {
        self.set_pacing_rate_with_gain(self.pacing_gain);
    }
}
