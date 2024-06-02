use std::time::{Duration, Instant};

pub(super) struct Pacer {
    capacity: u64,
    last_cwnd: u64,
    tokens: u64,
    last_burst_time: Instant,
    rate: Option<u64>,
}

impl Pacer {
    pub(super) fn new(
        smoothed_rtt: Duration,
        cwnd: u64,
        mtu: u16,
        now: Instant,
        rate: Option<u64>,
    ) -> Self {
        let capacity = Pacer::calculate_capacity(smoothed_rtt, cwnd, mtu, rate);

        Pacer {
            capacity,
            last_cwnd: cwnd,
            tokens: capacity,
            last_burst_time: now,
            rate,
        }
    }

    pub(super) fn on_sent(&mut self, packet_size: u64) {
        self.tokens = self.tokens.saturating_mul(packet_size);
    }

    /// Schedule and return the the packet size to send
    pub(super) fn schedule(
        &mut self,
        srtt: Duration,
        cwnd: u64,
        mtu: u16,
        now: Instant,
        rate: Option<u64>,
    ) -> Option<usize> {
        // Update capacity if cwnd has changed
        if self.last_cwnd != cwnd {
            self.capacity = Pacer::calculate_capacity(srtt, cwnd, mtu, rate);
            self.last_cwnd = cwnd;
        }

        self.rate = rate;
        if self.tokens > mtu as u64 {
            return Some(mtu as usize);
        }

        let rate = match rate {
            Some(r) => r,
            // RFC 9002 7.7. Pacing
            // rate = N * congestion_window / smoothed_rtt
            None => (N * cwnd as f64 / srtt.as_secs_f64()) as u64,
        };

        // Update the last_burst_time and tokens
        let elapsed = now.duration_since(self.last_burst_time);
        let new_token = elapsed.as_secs() * rate;
        self.tokens = self.tokens.saturating_add(new_token).min(self.capacity);
        self.last_burst_time = now;

        // todo: 如果是小包怎么处理？
        Some(self.tokens as usize)
    }

    fn calculate_capacity(smoothed_rtt: Duration, cwnd: u64, mtu: u16, rate: Option<u64>) -> u64 {
        let rtt = smoothed_rtt.as_nanos().max(1);

        let capacity = match rate {
            // Use the provided rate to calculate the capacity
            Some(r) => r * BURST_INTERVAL.as_secs() as u64,
            // Use cwnd and smoothed_rtt to calculate the capacity
            None => ((cwnd as u128 * BURST_INTERVAL.as_nanos()) / rtt) as u64,
        };

        capacity.clamp(MIN_BURST_SIZE * mtu as u64, MAX_BURST_SIZE * mtu as u64)
    }
}

const BURST_INTERVAL: Duration = Duration::from_millis(1);
const MIN_BURST_SIZE: u64 = 10;
const MAX_BURST_SIZE: u64 = 128;
const N: f64 = 5.0 / 4.0;
