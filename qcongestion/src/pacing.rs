use std::time::{Duration, Instant};

//  The burst  interval in milliseconds
const BURST_INTERVAL: Duration = Duration::from_millis(1);
const MIN_BURST_SIZE: u64 = 10;
const MAX_BURST_SIZE: u64 = 128;
// Using a value for N that is small, but at least 1 (for example, 1.25)
// ensures that variations in RTT do not result in underutilization of the congestion window.
const N: f64 = 1.25;

pub(super) struct Pacer {
    capacity: u64,
    cwnd: u64,
    tokens: u64,
    last_burst_time: Instant,
    rate: Option<u64>,
}

impl Pacer {
    pub(super) fn new(
        smoothed_rtt: Duration,
        cwnd: u64,
        mtu: usize,
        now: Instant,
        rate: Option<u64>,
    ) -> Self {
        let capacity = Pacer::calculate_capacity(smoothed_rtt, cwnd, mtu, rate);

        Pacer {
            capacity,
            cwnd,
            tokens: capacity,
            last_burst_time: now,
            rate,
        }
    }

    pub(super) fn on_sent(&mut self, packet_size: u64) {
        self.tokens = self.tokens.saturating_sub(packet_size);
    }

    // Schedule and return the packet size to send, max size is mtu
    pub(super) fn schedule(
        &mut self,
        srtt: Duration,
        cwnd: u64,
        mtu: usize,
        now: Instant,
        rate: Option<u64>,
    ) -> usize {
        // Update capacity if cwnd or rate has changed
        if self.cwnd != cwnd || rate != self.rate {
            self.capacity = Pacer::calculate_capacity(srtt, cwnd, mtu, rate);
            self.tokens = self.tokens.min(self.capacity);
        }

        self.cwnd = cwnd;
        self.rate = rate;
        if self.tokens > mtu as u64 {
            return self.tokens as usize;
        }

        let rate = match rate {
            Some(r) => r,
            // RFC 9002 7.7. Pacing
            // rate = N * congestion_window / smoothed_rtt
            None => (N * cwnd as f64 / srtt.as_secs_f64()) as u64,
        };

        // Update the last_burst_time and tokens
        let elapsed = now.duration_since(self.last_burst_time);
        let new_token = elapsed.as_secs_f64() * rate as f64;
        self.tokens = self
            .tokens
            .saturating_add(new_token as u64)
            .min(self.capacity);
        self.last_burst_time = now;

        self.tokens as usize
    }

    fn calculate_capacity(smoothed_rtt: Duration, cwnd: u64, mtu: usize, rate: Option<u64>) -> u64 {
        let rtt = smoothed_rtt.as_nanos().max(1);

        let capacity = match rate {
            // Use the provided rate to calculate the capacity
            Some(r) => (r as f64 * BURST_INTERVAL.as_secs_f64()) as u64,
            // Use cwnd and smoothed_rtt to calculate the capacity
            None => ((cwnd as u128 * BURST_INTERVAL.as_nanos()) / rtt) as u64,
        };

        // capacity between [15KB,192KB]
        capacity.clamp(MIN_BURST_SIZE * mtu as u64, MAX_BURST_SIZE * mtu as u64)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;

    #[test]
    fn test_pacer_initialization() {
        let now = Instant::now();
        let pacer = Pacer::new(
            Duration::from_millis(100),
            10,
            1500, // MTU
            now,
            Some(1_000_000),
        );
        // min capacity is 15KB
        assert_eq!(pacer.capacity, 15_000);
        assert_eq!(pacer.tokens, pacer.capacity);
        assert_eq!(pacer.last_burst_time, now);

        // if rate is None capacity = cwnd * brust_interval / rtt
        let pacer = Pacer::new(Duration::from_millis(100), 2_000_000, 1500, now, None);
        assert_eq!(pacer.capacity, 20_000);

        let pacer = Pacer::new(
            Duration::from_millis(100),
            2_000_000,
            1500,
            now,
            Some(18_000_000), // 18_000 kB/s
        );
        // 18KB
        assert_eq!(pacer.capacity, 18000);
    }

    #[test]
    fn test_on_sent() {
        let mut pacer = Pacer::new(
            Duration::from_millis(100),
            10,
            1500,
            Instant::now(),
            Some(1_000_000),
        );
        // token 15_000
        assert_eq!(pacer.tokens, 15_000);
        pacer.on_sent(1500); // 发送一个 MTU 大小的数据包
        assert_eq!(pacer.tokens, 15_000 - 1500);

        pacer.on_sent(20_000);
        assert_eq!(pacer.tokens, 0);
    }

    #[test]
    fn test_schedule_no_rate() {
        let srtt = Duration::from_millis(100);
        let mut cwnd = 2_000_000; // 2MB
        let mtu: usize = 1500;
        let mut update_time = Instant::now();
        let mut pacer = Pacer::new(srtt, cwnd, mtu, update_time, None);
        // token  = 20_000
        pacer.on_sent(20_000);
        assert_eq!(pacer.tokens, 0);

        // rate  = 1.25 * cwnd / srtt
        // after 2 ms
        update_time += BURST_INTERVAL * 2;
        let packet_size = pacer.schedule(srtt, cwnd, mtu, update_time, None);

        assert_eq!(pacer.tokens, 20_000);
        assert_eq!(packet_size, 20_000);
        pacer.on_sent(1500 * 13);

        assert_eq!(pacer.tokens, 500);

        // add token
        update_time += BURST_INTERVAL;
        let packet_size = pacer.schedule(srtt, cwnd, mtu, update_time, None);

        // burst interval add token 25000
        assert_eq!(pacer.capacity, 20_000);
        assert_eq!(pacer.tokens, 20_000);
        assert_eq!(packet_size, 20_000);

        // change cwnd, change capacity
        cwnd = 1_500_000; // 1.5 MB
        let packet_size = pacer.schedule(srtt, cwnd, mtu, update_time, None);
        assert_eq!(pacer.capacity, 15_000);
        assert_eq!(pacer.tokens, 15_000);
        assert_eq!(packet_size, 15_000);
    }

    #[test]
    fn test_schedule_with_rate() {
        let srtt = Duration::from_millis(100);
        let cwnd = 2_000_000; // 2MB
        let mtu: usize = 1500;
        let mut update_time = Instant::now();
        // 16MB/s
        let mut rate = Some(16_000_000);

        let mut pacer = Pacer::new(srtt, cwnd, mtu, update_time, rate);
        assert_eq!(pacer.capacity, 16_000);

        let size = pacer.schedule(srtt, cwnd, mtu, update_time, rate);
        assert_eq!(size, 16_000);
        pacer.on_sent(15_000);
        let size = pacer.schedule(srtt, cwnd, mtu, update_time, rate);
        assert_eq!(size, 1_000);

        // update rate to update capacity
        // 1 MB
        rate = Some(1_000_000);
        let size = pacer.schedule(srtt, cwnd, mtu, update_time, rate);
        assert_eq!(size, 1_000);
        assert_eq!(pacer.capacity, 15_000);
        update_time += BURST_INTERVAL;
        let size = pacer.schedule(srtt, cwnd, mtu, update_time, rate);
        assert_eq!(pacer.tokens, 2000);
        assert_eq!(size, 2000);
    }
}
