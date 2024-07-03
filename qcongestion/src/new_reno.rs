use std::{collections::VecDeque, time::Instant};

use crate::congestion::{AckedPkt, Algorithm, MSS};

// The upper bound for the initial window will be
// min (10*MSS, max (2*MSS, 14600))
// See https://datatracker.ietf.org/doc/html/rfc6928#autoid-3
const INIT_CWND: u64 = 10 * MSS as u64;
const INFINITRE_SSTHRESH: u64 = u64::MAX;
const LOSS_REDUCTION_FACTOR: f64 = 0.5;

pub(super) struct NewReno {
    // Congestion window.
    cwnd: u64,
    // Slow start threshold.
    ssthresh: u64,
    // The number of bytes that have been ACKed.
    // https://datatracker.ietf.org/doc/html/rfc3465#autoid-3
    bytes_acked: u64,
    // The time at which the most recent loss recovery period started.
    recovery_start_time: Option<Instant>,
}

impl NewReno {
    pub(super) fn new() -> Self {
        NewReno {
            cwnd: INIT_CWND,
            ssthresh: INFINITRE_SSTHRESH,
            bytes_acked: 0,
            recovery_start_time: None,
        }
    }

    fn in_congestion_recovery(&mut self, sent_time: &Instant) -> bool {
        self.recovery_start_time
            .as_ref()
            .map(|recovery_start_time| sent_time <= recovery_start_time)
            .unwrap_or(false)
    }

    fn on_per_ack(&mut self, ack: &AckedPkt) {
        if self.in_congestion_recovery(&ack.time_sent) {
            return;
        }
        // In slow start
        if self.cwnd < self.ssthresh {
            self.cwnd += ack.size as u64;

            if self.cwnd >= self.ssthresh {
                // Exiting slow start
                self.bytes_acked = self.cwnd - self.ssthresh;
            }
        } else {
            // Congestion avodiance
            // When bytes_acked becomes greater than or equal to the value of the
            // congestion window, bytes_acked is reduced by the value of cwnd.
            // Next, cwnd is incremented by a full-sized segment (SMSS).
            self.bytes_acked += ack.size as u64;
            if self.bytes_acked >= self.cwnd {
                self.bytes_acked -= self.cwnd;
                self.cwnd += MSS as u64;
            }
        }
    }
}

impl Algorithm for NewReno {
    fn on_sent(&mut self, _: &mut crate::congestion::SentPkt, _: usize, _: std::time::Instant) {}

    fn on_ack(&mut self, packet: VecDeque<AckedPkt>, _: std::time::Instant) {
        for acked in packet {
            self.on_per_ack(&acked);
        }
    }

    fn on_congestion_event(&mut self, lost: &crate::congestion::SentPkt, now: std::time::Instant) {
        if self.in_congestion_recovery(&lost.time_sent) {
            return;
        }
        self.recovery_start_time = Some(now);
        self.cwnd = (self.cwnd as f64 * LOSS_REDUCTION_FACTOR) as u64;
        self.cwnd = self.cwnd.max(2 * MSS as u64);

        self.bytes_acked = (self.bytes_acked as f64 * LOSS_REDUCTION_FACTOR) as u64;
        self.ssthresh = self.cwnd;
    }

    fn cwnd(&self) -> u64 {
        self.cwnd
    }

    fn pacing_rate(&self) -> Option<u64> {
        None
    }
}

#[cfg(test)]
mod tests {

    use crate::congestion::SentPkt;

    use super::*;

    #[test]
    fn test_reno_init() {
        let reno = NewReno::new();
        assert_eq!(reno.cwnd, INIT_CWND);
        assert_eq!(reno.ssthresh, super::INFINITRE_SSTHRESH);
        assert_eq!(reno.recovery_start_time, None);
    }

    #[test]
    fn test_reno_slow_start() {
        let mut reno = NewReno::new();
        let now = Instant::now();
        let acks = generate_acks(0, 10);

        // first roud trip
        reno.on_ack(acks, now);
        assert_eq!(reno.cwnd, 20 * MSS as u64);

        // second roud trip
        let acks = generate_acks(10, 30);
        reno.on_ack(acks, now);
        assert_eq!(reno.cwnd, 40 * MSS as u64);
    }

    #[test]
    fn test_reno_congestion_avoidance() {
        let mut reno = NewReno::new();
        let now = Instant::now();

        reno.ssthresh = 30 * MSS as u64;
        let acks = generate_acks(0, 20);
        let pre_cwnd = reno.cwnd();
        // slow start
        reno.on_ack(acks, now);
        assert_eq!(reno.cwnd, pre_cwnd + 20 * MSS as u64);

        let pre_cwnd = reno.cwnd();
        let acks = generate_acks(20, 60);
        // congestion avoidance
        // increase a MSS when bytes_acked is greater than cwnd
        reno.on_ack(acks, now);
        assert_eq!(reno.cwnd, pre_cwnd + MSS as u64);
    }

    #[test]
    fn test_reno_congestion_event() {
        let mut reno = NewReno::new();
        let now = Instant::now();
        reno.ssthresh = 20 * MSS as u64;
        let acks = generate_acks(0, 10);

        reno.on_ack(acks, now);

        assert_eq!(reno.cwnd, 20 * MSS as u64);
        assert_eq!(reno.recovery_start_time, None);

        let time_lost = now + std::time::Duration::from_millis(100);
        let lost = SentPkt {
            pn: 11,
            size: MSS,
            time_sent: now,
            ..Default::default()
        };

        reno.on_congestion_event(&lost, time_lost);

        assert_eq!(reno.cwnd, 10 * MSS as u64);
        assert_eq!(reno.ssthresh, 10 * MSS as u64);
        assert_eq!(reno.recovery_start_time, Some(time_lost));
    }

    fn generate_acks(start: usize, end: usize) -> VecDeque<AckedPkt> {
        let mut acks = VecDeque::with_capacity(end - start);
        for i in start..end {
            let sent = SentPkt {
                pn: i as u64,
                size: MSS,
                time_sent: Instant::now(),
                ..Default::default()
            };
            let ack: AckedPkt = sent.into();
            acks.push_back(ack);
        }
        acks
    }
}
