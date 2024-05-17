//! Delivery rate estimation.
//!
//! This implements the algorithm for estimating delivery rate as described in
//! <https://tools.ietf.org/html/draft-cheng-iccrg-delivery-rate-estimation-01>

use std::time::Duration;
use std::time::Instant;

use crate::Acked;
use crate::Sent;

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

        self.last_sent_packet = pkt.pkt_num;
    }

    // Update the delivery rate sample when a packet is acked.
    pub fn update_rate_sample(&mut self, pkt: &Acked, now: Instant) {
        self.delivered += pkt.size;
        self.delivered_time = now;

        // Update info using the newest packet. If rate_sample is not yet
        // initialized, initialize with the first packet.
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

        self.largest_acked = self.largest_acked.max(pkt.pkt_num);
    }

    pub fn generate_rate_sample(&mut self, min_rtt: Duration) {
        // End app-limited phase if bubble is ACKed and gone.
        if self.app_limited() && self.largest_acked > self.end_of_app_limited {
            self.update_app_limited(false);
        }

        if self.rate_sample.prior_time.is_some() {
            let interval = self
                .rate_sample
                .send_elapsed
                .max(self.rate_sample.ack_elapsed);

            self.rate_sample.delivered = self.delivered - self.rate_sample.prior_delivered;
            self.rate_sample.interval = interval;

            if interval < min_rtt {
                self.rate_sample.interval = Duration::ZERO;

                // No reliable sample.
                return;
            }

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
