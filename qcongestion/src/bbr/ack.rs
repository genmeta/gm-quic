use rand::Rng;

use crate::Acked;

use super::*;

use std::cmp;
use std::time::Instant;

/// 1.2Mbps in bytes/sec
const PACING_RATE_1_2MBPS: u64 = 1200 * 1000 / 8;

impl BBRState {
    /// The minimal cwnd value BBR2 tries to target, in bytes
    #[inline]
    fn min_pipe_cwnd(&mut self) -> usize {
        MIN_PIPE_CWND_PKTS * self.max_datagram_size
    }

    // BBR2 Functions when ACK is received.
    //
    pub fn update_model_and_state(&mut self, packet: &Acked, now: Instant) {
        self.update_latest_delivery_signals();
        self.update_congestion_signals(packet);
        self.update_ack_aggregation(packet, now);
        self.check_startup_done();
        self.check_drain(now);
        self.update_probe_bw_cycle_phase(now);
        self.update_min_rtt(now);
        self.check_probe_rtt(now);
        self.advance_latest_delivery_signals();
        self.bound_bw_for_model();
    }

    pub fn update_control_parameters(&mut self, _now: Instant) {
        self.set_pacing_rate();
        self.set_send_quantum();

        // Set outgoing packet pacing rate
        // It is called here because send_quantum may be updated too.
        // self.set_pacing_rate(self.pacing_rate, now);

        self.set_cwnd();
    }

    // BBR2 Functions while processing ACKs.
    //

    // 4.3.1.1.  Startup Dynamics
    fn check_startup_done(&mut self) {
        self.check_startup_full_bandwidth();
        self.check_startup_high_loss();

        if self.state == BBRStateMachine::Startup && self.filled_pipe {
            self.enter_drain();
        }
    }

    // 4.3.1.2.  Exiting Startup Based on Bandwidth Plateau
    fn check_startup_full_bandwidth(&mut self) {
        if self.filled_pipe || !self.round_start || self.delivery_rate.sample_is_app_limited() {
            // No need to check for a full pipe now.
            return;
        }

        // Still growing?
        if self.max_bw >= (self.full_bw as f64 * MAX_BW_GROWTH_THRESHOLD) as u64 {
            // Record new baseline level
            self.full_bw = self.max_bw;
            self.full_bw_count = 0;
            return;
        }

        // Another round w/o much growth
        self.full_bw_count += 1;

        if self.full_bw_count >= MAX_BW_COUNT {
            self.filled_pipe = true;
        }
    }

    // 4.3.1.3.  Exiting Startup Based on Packet Loss
    fn check_startup_high_loss(&mut self) {
        // TODO: this is not implemented (not in the draft)
        if self.loss_round_start
            && self.in_recovery
            && self.loss_events_in_round >= FULL_LOSS_COUNT as usize
            && self.is_inflight_too_high()
        {
            self.handle_queue_too_high_in_startup();
        }
        if self.loss_round_start {
            self.loss_events_in_round = 0
        }
    }

    fn handle_queue_too_high_in_startup(&mut self) {
        self.filled_pipe = true;
        self.inflight_hi = self.inflight(self.max_bw, 1.0);
    }

    // 4.3.2.  Drain
    fn enter_drain(&mut self) {
        self.state = BBRStateMachine::Drain;

        // pace slowly
        self.pacing_gain = PACING_GAIN / STARTUP_CWND_GAIN;

        // maintain cwnd
        self.cwnd_gain = STARTUP_CWND_GAIN;
    }

    fn check_drain(&mut self, now: Instant) {
        if self.state == BBRStateMachine::Drain
            && self.bytes_in_flight <= self.inflight(self.max_bw, 1.0)
        {
            // BBR estimates the queue was drained
            self.enter_probe_bw(now);
        }
    }

    // 4.3.3.  ProbeBW
    // 4.3.3.5.3.  Design Considerations for Choosing Constant Parameters
    fn check_time_to_probe_bw(&mut self, now: Instant) -> bool {
        // Is it time to transition from DOWN or CRUISE to REFILL?
        if self.has_elapsed_in_phase(self.bw_probe_wait, now)
            || self.is_reno_coexistence_probe_time()
        {
            self.start_probe_bw_refill();

            return true;
        }

        false
    }

    // Randomized decision about how long to wait until
    // probing for bandwidth, using round count and wall clock.
    fn pick_probe_wait(&mut self) {
        // Decide random round-trip bound for wait

        let rounds: u8 = rand::thread_rng().gen();
        self.rounds_since_probe = rounds as usize % 2;

        // Decide the random wall clock bound for wait
        let wait = 2.0 + rand::thread_rng().gen_range(0..1000000) as f64 / 1000000.0;
        self.bw_probe_wait = Duration::from_secs_f64(wait);
    }

    fn is_reno_coexistence_probe_time(&mut self) -> bool {
        let reno_rounds = self.target_inflight();
        let rounds = reno_rounds.min(63);

        self.rounds_since_probe >= rounds
    }

    // How much data do we want in flight?
    // Our estimated BDP, unless congestion cut cwnd.
    pub fn target_inflight(&mut self) -> usize {
        self.bdp.min(self.congestion_window)
    }

    // 4.3.3.6.  ProbeBW Algorithm Details
    fn enter_probe_bw(&mut self, now: Instant) {
        self.start_probe_bw_down(now);
    }

    pub fn start_probe_bw_down(&mut self, now: Instant) {
        self.reset_congestion_signals();

        // not growing inflight_hi
        self.probe_up_cnt = usize::MAX;

        self.pick_probe_wait();

        // start wall clock
        self.cycle_stamp = now;
        self.ack_phase = BBRAckPhase::ProbeStopping;

        self.start_round();

        self.state = BBRStateMachine::ProbeBWDOWN;
        self.pacing_gain = PROBE_DOWN_PACING_GAIN;
        self.cwnd_gain = CWND_GAIN
    }

    fn start_probe_bw_cruise(&mut self) {
        self.state = BBRStateMachine::ProbeBWCRUISE;
        self.pacing_gain = PACING_GAIN;
        self.cwnd_gain = CWND_GAIN;
    }

    fn start_probe_bw_refill(&mut self) {
        self.reset_lower_bounds();

        self.bw_probe_up_rounds = 0;
        self.bw_probe_up_acks = 0;
        self.ack_phase = BBRAckPhase::Refilling;

        self.start_round();

        self.state = BBRStateMachine::ProbeBWREFILL;
        self.pacing_gain = PACING_GAIN;
        self.cwnd_gain = CWND_GAIN;
    }

    fn start_probe_bw_up(&mut self, now: Instant) {
        self.ack_phase = BBRAckPhase::ProbeStarting;

        self.start_round();

        // Start wall clock.
        self.cycle_stamp = now;
        self.state = BBRStateMachine::ProbeBWUP;
        self.pacing_gain = PROBE_UP_PACING_GAIN;
        self.cwnd_gain = CWND_GAIN;

        self.raise_inflight_hi_slope();
    }

    // The core state machine logic for ProbeBW
    fn update_probe_bw_cycle_phase(&mut self, now: Instant) {
        if !self.filled_pipe {
            // only handling steady-state behavior here
            return;
        }

        self.adapt_upper_bounds(now);

        if !self.is_in_a_probe_bw_state() {
            // only handling ProbeBW states here
            return;
        }

        match self.state {
            BBRStateMachine::ProbeBWDOWN => {
                if self.check_time_to_probe_bw(now) {
                    // Already decided state transition.
                    return;
                }

                if self.check_time_to_cruise() {
                    self.start_probe_bw_cruise();
                }
            }

            BBRStateMachine::ProbeBWCRUISE => {
                self.check_time_to_probe_bw(now);
            }

            BBRStateMachine::ProbeBWREFILL => {
                // After one round of REFILL, start UP.
                if self.round_start {
                    self.bw_probe_samples = true;

                    self.start_probe_bw_up(now);
                }
            }

            BBRStateMachine::ProbeBWUP => {
                if self.has_elapsed_in_phase(self.min_rtt, now)
                    && self.bytes_in_flight > self.inflight(self.max_bw, 1.25)
                {
                    self.start_probe_bw_down(now);
                }
            }

            _ => (),
        }
    }

    pub fn is_in_a_probe_bw_state(&mut self) -> bool {
        let state = self.state;

        state == BBRStateMachine::ProbeBWDOWN
            || state == BBRStateMachine::ProbeBWCRUISE
            || state == BBRStateMachine::ProbeBWREFILL
            || state == BBRStateMachine::ProbeBWUP
    }

    fn check_time_to_cruise(&mut self) -> bool {
        if self.bytes_in_flight > self.inflight_with_headroom() {
            // Not enough headroom.
            return false;
        }

        if self.bytes_in_flight <= self.inflight(self.max_bw, 1.0) {
            // inflight <= estimated BDP
            return true;
        }

        false
    }

    fn has_elapsed_in_phase(&mut self, interval: Duration, now: Instant) -> bool {
        now > self.cycle_stamp + interval
    }

    // Return a volume of data that tries to leave free
    // headroom in the bottleneck buffer or link for
    // other flows, for fairness convergence and lower
    // RTTs and loss
    fn inflight_with_headroom(&mut self) -> usize {
        if self.inflight_hi == usize::MAX {
            return usize::MAX;
        }

        let headroom = ((HEADROOM * self.inflight_hi as f64) as usize).max(1);

        self.inflight_hi
            .saturating_sub(headroom)
            .max(self.min_pipe_cwnd())
    }

    // Raise inflight_hi slope if appropriate.
    fn raise_inflight_hi_slope(&mut self) {
        let growth_this_round = (1 << self.bw_probe_up_rounds) * self.max_datagram_size;

        self.bw_probe_up_rounds = (self.bw_probe_up_rounds + 1).min(30);
        self.probe_up_cnt = (self.congestion_window / growth_this_round).max(1);
    }

    // Increase inflight_hi if appropriate.
    fn probe_inflight_hi_upward(&mut self) {
        if self.app_limited() || self.congestion_window < self.inflight_hi {
            // Not fully using inflight_hi, so don't grow it.
            return;
        }

        // bw_probe_up_acks is a packet count.
        self.bw_probe_up_acks += 1;

        if self.bw_probe_up_acks >= self.probe_up_cnt {
            let delta = self.bw_probe_up_acks / self.probe_up_cnt;

            self.bw_probe_up_acks -= delta * self.probe_up_cnt;

            self.inflight_hi += delta * self.max_datagram_size;
        }

        if self.round_start {
            self.raise_inflight_hi_slope();
        }
    }

    // Track ACK state and update self.max_bw window and
    // self.inflight_hi and self.bw_hi.
    fn adapt_upper_bounds(&mut self, now: Instant) {
        if self.ack_phase == BBRAckPhase::ProbeStarting && self.round_start {
            // Starting to get bw probing samples.
            self.ack_phase = BBRAckPhase::ProbeFeedback;
        }

        if self.ack_phase == BBRAckPhase::ProbeStopping && self.round_start {
            self.bw_probe_samples = false;
            self.ack_phase = BBRAckPhase::Init;

            // End of samples from bw probing phase.
            if self.is_in_a_probe_bw_state() && !self.delivery_rate.sample_is_app_limited() {
                self.advance_max_bw_filter();
            }
        }

        if !self.check_inflight_too_high(now) {
            // Loss rate is safe. Adjust upper bounds upward.
            if self.inflight_hi == usize::MAX || self.bw_hi == u64::MAX {
                // No upper bounds to raise.
                return;
            }

            if self.tx_in_flight > self.inflight_hi {
                self.inflight_hi = self.tx_in_flight;
            }

            if self.delivery_rate() > self.bw_hi {
                self.bw_hi = self.delivery_rate();
            }

            if self.state == BBRStateMachine::ProbeBWUP {
                self.probe_inflight_hi_upward();
            }
        }
    }

    // 4.3.4. ProbeRTT
    // 4.3.4.4.  ProbeRTT Logic
    fn update_min_rtt(&mut self, now: Instant) {
        self.probe_rtt_expired = now > self.probe_rtt_min_stamp + PROBE_RTT_INTERVAL;

        let rs_rtt = self.delivery_rate.sample_rtt();

        if !rs_rtt.is_zero() && (rs_rtt < self.probe_rtt_min_delay || self.probe_rtt_expired) {
            self.probe_rtt_min_delay = rs_rtt;
            self.probe_rtt_min_stamp = now;
        }

        let min_rtt_expired = now > self.min_rtt_stamp + rs_rtt.saturating_mul(MIN_RTT_FILTER_LEN);

        // To do: Figure out Probe RTT logic
        // if self.probe_rtt_min_delay < self.min_rtt ||  self.min_rtt == INITIAL_RTT ||
        // min_rtt_expired {
        if self.min_rtt == INITIAL_RTT || min_rtt_expired {
            // self.min_rtt = self.probe_rtt_min_delay;
            // self.min_rtt_stamp = self.probe_rtt_min_stamp;
            self.min_rtt = rs_rtt;
            self.min_rtt_stamp = now;
        }
    }

    fn check_probe_rtt(&mut self, now: Instant) {
        if self.state != BBRStateMachine::ProbeRTT && self.probe_rtt_expired && !self.idle_restart {
            self.enter_probe_rtt();

            self.prior_cwnd = self.save_cwnd();
            self.probe_rtt_done_stamp = None;
            self.ack_phase = BBRAckPhase::ProbeStopping;

            self.start_round();
        }

        if self.state == BBRStateMachine::ProbeRTT {
            self.handle_probe_rtt(now);
        }

        if self.delivery_rate.sample_delivered() > 0 {
            self.idle_restart = false;
        }
    }

    fn enter_probe_rtt(&mut self) {
        self.state = BBRStateMachine::ProbeRTT;
        self.pacing_gain = PACING_GAIN;
        self.cwnd_gain = PROBE_RTT_CWND_GAIN;
    }

    fn handle_probe_rtt(&mut self, now: Instant) {
        // Ignore low rate samples during ProbeRTT.
        self.delivery_rate.update_app_limited(true);

        if self.probe_rtt_done_stamp.is_some() {
            if self.round_start {
                self.probe_rtt_round_done = true;
            }

            if self.probe_rtt_round_done {
                self.check_probe_rtt_done(now);
            }
        } else if self.bytes_in_flight <= self.probe_rtt_cwnd() {
            // Wait for at least ProbeRTTDuration to elapse.
            self.probe_rtt_done_stamp = Some(now + PROBE_RTT_DURATION);

            // Wait for at lease one round to elapse.
            self.probe_rtt_round_done = false;

            self.start_round();
        }
    }

    pub fn check_probe_rtt_done(&mut self, now: Instant) {
        if let Some(probe_rtt_done_stamp) = self.probe_rtt_done_stamp {
            if now > probe_rtt_done_stamp {
                // Schedule next ProbeRTT.
                self.probe_rtt_min_stamp = now;

                self.restore_cwnd();
                self.exit_probe_rtt(now);
            }
        }
    }

    // 4.3.4.5.  Exiting ProbeRTT
    fn exit_probe_rtt(&mut self, now: Instant) {
        self.reset_lower_bounds();

        if self.filled_pipe {
            self.start_probe_bw_down(now);
            self.start_probe_bw_cruise();
        } else {
            self.enter_startup();
        }
    }

    // 4.5.1.  BBR.round_count: Tracking Packet-Timed Round Trips
    fn update_round(&mut self, packet: &Acked) {
        if packet.delivered >= self.next_round_delivered {
            self.start_round();

            self.round_count += 1;
            self.rounds_since_probe += 1;
            self.round_start = true;
        } else {
            self.round_start = false;
        }
    }

    fn start_round(&mut self) {
        self.next_round_delivered = self.delivery_rate.delivered();
    }

    // 4.5.2.4.  Updating the BBR.max_bw Max Filter
    pub fn update_max_bw(&mut self, packet: &Acked) {
        self.update_round(packet);

        if self.delivery_rate() >= self.max_bw || !self.delivery_rate.sample_is_app_limited() {
            let max_bw_filter_len = self
                .delivery_rate
                .sample_rtt()
                .saturating_mul(MIN_RTT_FILTER_LEN);

            self.max_bw = self.max_bw_filter.running_max(
                max_bw_filter_len,
                self.start_time + Duration::from_secs(self.cycle_count),
                self.delivery_rate(),
            );
        }
    }

    // 4.5.2.5.  Tracking Time for the BBR.max_bw Max Filter
    fn advance_max_bw_filter(&mut self) {
        self.cycle_count += 1;
    }

    // 4.5.4.  BBR.offload_budget
    fn update_offload_budget(&mut self) {
        self.offload_budget = 3 * self.send_quantum;
    }

    // 4.5.5.  BBR.extra_acked
    fn update_ack_aggregation(&mut self, packet: &Acked, now: Instant) {
        // Find excess ACKed beyond expected amount over this interval.
        let interval = now - self.extra_acked_interval_start;
        let mut expected_delivered = (self.bw as f64 * interval.as_secs_f64()) as usize;

        // Reset interval if ACK rate is below expected rate.
        if self.extra_acked_delivered <= expected_delivered {
            self.extra_acked_delivered = 0;
            self.extra_acked_interval_start = now;
            expected_delivered = 0;
        }

        self.extra_acked_delivered += packet.size;

        let extra = self
            .extra_acked_delivered
            .saturating_sub(expected_delivered);
        let extra = extra.min(self.congestion_window);

        let extra_acked_filter_len = self
            .delivery_rate
            .sample_rtt()
            .saturating_mul(MIN_RTT_FILTER_LEN);

        self.extra_acked = self.extra_acked_filter.running_max(
            extra_acked_filter_len,
            self.start_time + Duration::from_secs(self.round_count),
            extra,
        );
    }

    // 4.6.3.  Send Quantum: BBR.send_quantum
    fn set_send_quantum(&mut self) {
        let rate = self.pacing_rate;
        let floor = if rate < PACING_RATE_1_2MBPS {
            self.max_datagram_size
        } else {
            2 * self.max_datagram_size
        };

        self.send_quantum = cmp::min((rate / 1000_u64) as usize, 64 * 1024); // Assumes send buffer is limited to 64KB
        self.send_quantum = self.send_quantum.max(floor);
    }

    // 4.6.4.1.  Initial cwnd
    // 4.6.4.2.  Computing BBR.max_inflight
    fn bdp_multiple(&mut self, bw: u64, gain: f64) -> usize {
        if self.min_rtt == Duration::MAX {
            // No valid RTT samples yet.
            return self.max_datagram_size * self.initial_congestion_window_packets;
        }

        self.bdp = (bw as f64 * self.min_rtt.as_secs_f64()) as usize;

        (gain * self.bdp as f64) as usize
    }

    fn quantization_budget(&mut self, inflight: usize) -> usize {
        self.update_offload_budget();

        let inflight = inflight.max(self.offload_budget);
        let inflight = inflight.max(self.min_pipe_cwnd());

        // TODO: cycle_idx is unused
        if self.state == BBRStateMachine::ProbeBWUP {
            return inflight + 2 * self.max_datagram_size;
        }

        inflight
    }

    fn inflight(&mut self, bw: u64, gain: f64) -> usize {
        let inflight = self.bdp_multiple(bw, gain);

        self.quantization_budget(inflight)
    }

    fn update_max_inflight(&mut self) {
        // TODO: not implemented (not in the draft)
        // update_aggregation_budget();

        let inflight = self.bdp_multiple(self.max_bw, self.cwnd_gain);
        let inflight = inflight + self.extra_acked;

        self.max_inflight = self.quantization_budget(inflight);
    }

    // 4.6.4.4.  Modulating cwnd in Loss Recovery
    pub fn save_cwnd(&mut self) -> usize {
        if !self.in_recovery && self.state != BBRStateMachine::ProbeRTT {
            self.congestion_window
        } else {
            self.congestion_window.max(self.prior_cwnd)
        }
    }

    pub fn restore_cwnd(&mut self) {
        self.congestion_window = self.congestion_window.max(self.prior_cwnd);
    }

    fn modulate_cwnd_for_recovery(&mut self) {
        let acked_bytes = self.newly_acked_bytes;
        let lost_bytes = self.newly_lost_bytes;

        if lost_bytes > 0 {
            // QUIC mininum cwnd is 2 x MSS.
            self.congestion_window = self
                .congestion_window
                .saturating_sub(lost_bytes)
                .max(self.max_datagram_size * MINIMUM_WINDOW_PACKETS);
        }

        if self.packet_conservation {
            self.congestion_window = self
                .congestion_window
                .max(self.bytes_in_flight + acked_bytes);
        }
    }

    // 4.6.4.5.  Modulating cwnd in ProbeRTT
    fn probe_rtt_cwnd(&mut self) -> usize {
        let probe_rtt_cwnd = self.bdp_multiple(self.bw, PROBE_RTT_CWND_GAIN);

        probe_rtt_cwnd.max(self.min_pipe_cwnd())
    }

    fn bound_cwnd_for_probe_rtt(&mut self) {
        if self.state == BBRStateMachine::ProbeRTT {
            self.congestion_window = self.congestion_window.min(self.probe_rtt_cwnd());
        }
    }

    // 4.6.4.6.  Core cwnd Adjustment Mechanism
    fn set_cwnd(&mut self) {
        let acked_bytes = self.newly_acked_bytes;

        self.update_max_inflight();
        self.modulate_cwnd_for_recovery();

        if !self.packet_conservation {
            if self.filled_pipe {
                self.congestion_window =
                    cmp::min(self.congestion_window + acked_bytes, self.max_inflight)
            } else if self.congestion_window < self.max_inflight
                || self.delivery_rate.delivered()
                    < self.max_datagram_size * self.initial_congestion_window_packets
            {
                self.congestion_window += acked_bytes;
            }

            self.congestion_window = self.congestion_window.max(self.min_pipe_cwnd())
        }

        self.bound_cwnd_for_probe_rtt();
        self.bound_cwnd_for_model();
    }

    // 4.6.4.7.  Bounding cwnd Based on Recent Congestion
    fn bound_cwnd_for_model(&mut self) {
        let mut cap = usize::MAX;

        if self.is_in_a_probe_bw_state() && self.state != BBRStateMachine::ProbeBWCRUISE {
            cap = self.inflight_hi;
        } else if self.state == BBRStateMachine::ProbeRTT
            || self.state == BBRStateMachine::ProbeBWCRUISE
        {
            cap = self.inflight_with_headroom();
        }

        // Apply inflight_lo (possibly infinite).
        cap = cap.min(self.inflight_lo);
        cap = cap.max(self.min_pipe_cwnd());

        self.congestion_window = self.congestion_window.min(cap);
    }
}
