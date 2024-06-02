// https://tools.ietf.org/html/draft-cheng-iccrg-delivery-rate-estimation-01

use std::time::Duration;
use std::time::Instant;

use crate::congestion::Acked;
use crate::congestion::Sent;

#[derive(Debug)]
pub struct Rate {
    delivered: usize,
    delivered_time: Instant,
    first_sent_time: Instant,
    // Packet number of the last sent packet with app limited.
    end_of_app_limited: u64,
    // Packet number of the last sent packet.
    last_sent_packet: u64,
    // Packet number of the largest acked packet.
    largest_acked: u64,
    // Sample of rate estimation.
    rate_sample: RateSample,
}

impl Default for Rate {
    fn default() -> Self {
        let now = Instant::now();

        Rate {
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            end_of_app_limited: 0,
            last_sent_packet: 0,
            largest_acked: 0,
            rate_sample: RateSample::default(),
        }
    }
}

impl Rate {
    // 3.2. Transmitting or retransmitting a data packet
    pub fn on_packet_sent(&mut self, pkt: &mut Sent, bytes_in_flight: usize, bytes_lost: u64) {
        // No packets in flight.
        if bytes_in_flight == 0 {
            self.first_sent_time = pkt.time_sent;
            self.delivered_time = pkt.time_sent;
        }

        pkt.first_sent_time = self.first_sent_time;
        pkt.delivered_time = self.delivered_time;
        pkt.delivered = self.delivered;
        pkt.is_app_limited = self.app_limited();
        pkt.tx_in_flight = bytes_in_flight;
        pkt.lost = bytes_lost;

        self.last_sent_packet = pkt.pn;
    }

    // Update the delivery rate sample when a packet is acked.
    pub fn update_rate_sample(&mut self, pkt: &Acked, now: Instant) {
        self.delivered += pkt.size;
        self.delivered_time = now;

        if self.rate_sample.prior_time.is_none() || pkt.delivered > self.rate_sample.prior_delivered
        {
            self.rate_sample.prior_delivered = pkt.delivered;
            self.rate_sample.prior_time = Some(pkt.delivered_time);
            self.rate_sample.is_app_limited = pkt.is_app_limited;
            self.rate_sample.send_elapsed =
                pkt.time_sent.saturating_duration_since(pkt.first_sent_time);
            self.rate_sample.rtt = pkt.rtt;
            self.rate_sample.ack_elapsed = self
                .delivered_time
                .saturating_duration_since(pkt.delivered_time);

            self.first_sent_time = pkt.time_sent;
        }

        self.largest_acked = self.largest_acked.max(pkt.pn);
    }

    pub fn generate_rate_sample(&mut self) {
        // End app-limited phase if bubble is ACKed and gone.
        if self.app_limited() && self.largest_acked > self.end_of_app_limited {
            self.update_app_limited(false);
        }

        if self.rate_sample.prior_time.is_some() {
            let interval = self
                .rate_sample
                .send_elapsed
                .max(self.rate_sample.ack_elapsed);

            self.rate_sample.delivered = self
                .delivered
                .saturating_sub(self.rate_sample.prior_delivered);
            self.rate_sample.interval = interval;

            if !interval.is_zero() {
                // Fill in rate_sample with a rate sample.
                self.rate_sample.delivery_rate =
                    (self.rate_sample.delivered as f64 / interval.as_secs_f64()) as u64;
            }
        }
    }

    pub fn update_app_limited(&mut self, v: bool) {
        self.end_of_app_limited = if v { self.last_sent_packet.max(1) } else { 0 }
    }

    pub fn app_limited(&mut self) -> bool {
        self.end_of_app_limited != 0
    }

    pub fn delivered(&self) -> usize {
        self.delivered
    }

    pub fn sample_delivery_rate(&self) -> u64 {
        self.rate_sample.delivery_rate
    }

    pub fn sample_rtt(&self) -> Duration {
        self.rate_sample.rtt
    }

    pub fn sample_is_app_limited(&self) -> bool {
        self.rate_sample.is_app_limited
    }

    pub fn sample_delivered(&self) -> usize {
        self.rate_sample.delivered
    }

    pub fn sample_prior_delivered(&self) -> usize {
        self.rate_sample.prior_delivered
    }
}

#[derive(Default, Debug)]
struct RateSample {
    delivery_rate: u64,
    is_app_limited: bool,
    interval: Duration,
    delivered: usize,
    prior_delivered: usize,
    prior_time: Option<Instant>,
    send_elapsed: Duration,
    ack_elapsed: Duration,
    rtt: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate() {
        let mut rate = Rate::default();

        let now = Instant::now();

        let mut sents: Vec<Sent> = (0..5)
            .map(|i| {
                let mut sent = Sent::default();
                sent.pn = i;
                sent.size = 100;
                sent.time_sent = now;
                sent
            })
            .collect();

        for sent in &mut sents {
            let pkt_num = sent.pn;
            rate.on_packet_sent(sent, (pkt_num * 100) as usize, 0);
        }

        let delay = Duration::from_millis(100);
        let recv_ack_time = now + delay;

        for _ in 0..3 {
            let sent = sents.pop().unwrap();
            let acked = Acked {
                pn: sent.pn,
                time_sent: sent.time_sent,
                size: sent.size,
                rtt: recv_ack_time.saturating_duration_since(sent.time_sent),
                delivered: sent.delivered,
                delivered_time: sent.delivered_time,
                first_sent_time: sent.first_sent_time,
                is_app_limited: sent.is_app_limited,
                tx_in_flight: sent.tx_in_flight,
                lost: sent.lost,
            };

            rate.update_rate_sample(&acked, recv_ack_time);
            rate.generate_rate_sample();
        }
        // 300 / 0.1
        assert_eq!(rate.sample_delivery_rate(), 3000);
        assert_eq!(rate.sample_rtt(), delay);
        assert_eq!(rate.sample_is_app_limited(), false);
        assert_eq!(rate.sample_delivered(), 300);
        assert_eq!(rate.sample_prior_delivered(), 0);
    }
}
