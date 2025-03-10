use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use qlog::quic::recovery::RecoveryMetricsUpdated;

use crate::{
    congestion::{AckedPkt, Algorithm, MSS, SentPkt},
    delivery_rate::Rate,
    min_max::MinMax,
};

mod model;
mod parameters;
mod state;

// RTpropFilterLen: A constant specifying the length of the RTProp min
// filter window, RTpropFilterLen is `10` secs.
const RTPROP_FILTER_LEN: Duration = Duration::from_secs(10);

// BBRHighGain: A constant specifying the minimum gain value that will
// allow the sending rate to double each round (`2/ln(2)` ~= `2.89`), used
// in Startup mode for both BBR.pacing_gain and BBR.cwnd_gain.
const HIGH_GAIN: f64 = 2.89;

// ProbeRTTDuration: A constant specifying the minimum duration for
// which ProbeRTT state holds inflight to BBRMinPipeCwnd or fewer
// packets: 200 ms.
const PROBE_RTT_DURATION: Duration = Duration::from_millis(200);

// Pacing rate threshold for select different send quantum. Default `1.2Mbps`.
const SEND_QUANTUM_THRESHOLD_PACING_RATE: u64 = 1_200_000 / 8;

// Initial congestion window in bytes.
pub(crate) const INITIAL_CWND: u64 = 80 * MSS as u64;

// The minimal cwnd value BBR tries to target using: 4 packets, or 4 * SMSS
const MIN_PIPE_CWND_PKTS: usize = 4;

const MINIMUM_WINDOW_PACKETS: usize = 2;

// BBR State
//
// https://datatracker.ietf.org/doc/html/draft-cardwell-iccrg-bbr-congestion-control-00#section-3.4
#[derive(Debug, PartialEq, Eq)]
enum BbrStateMachine {
    Startup,
    Drain,
    ProbeBW,
    ProbeRTT,
}

pub(crate) struct Bbr {
    // StateMachine
    state: BbrStateMachine,
    // BBR.pacing_rate: The current pacing rate for a BBR flow, which
    // controls inter-packet spacing.
    pacing_rate: u64,
    // BBR.send_quantum: The maximum size of a data aggregate scheduled and
    // transmitted together.
    send_quantum: u64,
    // Cwnd: The transport sender's congestion window, which limits the
    // amount of data in flight.
    cwnd: u64,
    // BBR.BtlBw: BBR's estimated bottleneck bandwidth available to the transport
    // flow, estimated from the maximum delivery rate sample in a sliding window.
    btlbw: u64,
    // BBR.BtlBwFilter: The max filter used to estimate BBR.BtlBw.
    btlbwfilter: MinMax,
    // Delivery rate.
    delivery_rate: Rate,
    // BBR.RTprop: BBR's estimated two-way round-trip propagation delay of path,
    // estimated from the windowed minimum recent round-trip delay sample.
    rtprop: Duration,
    // BBR.rtprop_stamp: The wall clock time at which the current BBR.RTProp
    // sample was obtained.
    rtprop_stamp: Instant,
    // BBR.rtprop_expired: A boolean recording whether the BBR.RTprop has
    // expired and is due for a refresh with an application idle period or a
    // transition into ProbeRTT state.
    is_rtprop_expired: bool,
    // BBR.pacing_gain: The dynamic gain factor used to scale BBR.BtlBw to
    // produce BBR.pacing_rate.
    pacing_gain: f64,
    // BBR.cwnd_gain: The dynamic gain factor used to scale the estimated
    // BDP to produce a congestion window (cwnd).
    cwnd_gain: f64,
    // BBR.round_count: Count of packet-timed round trips.
    round_count: u64,
    // BBR.round_start: A boolean that BBR sets to true once per packet-
    // timed round trip, on ACKs that advance BBR.round_count.
    is_round_start: bool,
    // BBR.next_round_delivered: packet.delivered value denoting the end of
    // a packet-timed round trip.
    next_round_delivered: usize,
    // Estimator of full pipe.
    // BBR.filled_pipe: A boolean that records whether BBR estimates that it
    // has ever fully utilized its available bandwidth ("filled the pipe").
    is_filled_pipe: bool,
    // Baseline level delivery rate for full pipe estimator.
    full_bw: u64,
    // The number of round for full pipe estimator without much growth.
    full_bw_count: u64,
    // Timestamp when ProbeRTT state ends.
    probe_rtt_done_stamp: Option<Instant>,
    // Whether a roundtrip in ProbeRTT state ends.
    probe_rtt_round_done: bool,
    // Whether in packet sonservation mode.
    packet_conservation: bool,
    // Cwnd before loss recovery.
    prior_cwnd: u64,
    // Whether restarting from idle.
    is_idle_restart: bool,
    // Last time when cycle_index is updated.
    cycle_stamp: Instant,
    // Current index of pacing_gain_cycle[].
    cycle_index: usize,
    // The upper bound on the volume of data BBR allows in flight.
    target_cwnd: u64,
    // Whether in the recovery mode.
    in_recovery: bool,
    // Time of the last recovery event starts.
    recovery_epoch_start: Option<Instant>,
    // Ack time.
    ack_time: Instant,
    // Newly marked lost data size in bytes.
    newly_lost_bytes: u64,
    // lost data size in total bytes.
    bytes_lost_in_total: u64,
    // Newly acked data size in bytes.
    newly_acked_bytes: u64,
    // The last P.delivered in bytes.
    packet_delivered: u64,
    // The last P.sent_time to determine whether exit recovery.
    last_ack_packet_sent_time: Instant,
    // The amount of data that was in flight before processing this ACK.
    prior_bytes_in_flight: u64,
    // The sum of the size in bytes of all sent packets that contain at least
    // one ack-eliciting or PADDING frame and have not been acknowledged or
    // declared lost. The size does not include IP or UDP overhead.
    pub bytes_in_flight: u64,
}

impl From<&Bbr> for RecoveryMetricsUpdated {
    fn from(value: &Bbr) -> Self {
        qlog::build!(RecoveryMetricsUpdated {
            congestion_window: value.cwnd,
            bytes_in_flight: value.bytes_in_flight,
            pacing_rate: value.pacing_rate,
            custom_fields: Map {
                // AI补全
                delivery_rate: value.delivery_rate.sample_delivery_rate(),
                packet_delivered: value.packet_delivered,
                newly_acked_bytes: value.newly_acked_bytes,
                newly_lost_bytes: value.newly_lost_bytes,
                bytes_lost_in_total: value.bytes_lost_in_total,
            }
        })
    }
}

impl Bbr {
    pub fn new() -> Self {
        let now = Instant::now();
        let mut bbr = Bbr {
            state: BbrStateMachine::Startup,
            pacing_rate: 0,
            send_quantum: 0,
            cwnd: INITIAL_CWND,
            btlbw: 0,
            btlbwfilter: MinMax::default(),
            delivery_rate: Rate::default(),
            rtprop: Duration::MAX,
            rtprop_stamp: now,
            is_rtprop_expired: false,
            pacing_gain: HIGH_GAIN,
            cwnd_gain: HIGH_GAIN,
            round_count: 0,
            is_round_start: false,
            next_round_delivered: 0,
            is_filled_pipe: false,
            full_bw: 0,
            full_bw_count: 0,
            probe_rtt_done_stamp: None,
            probe_rtt_round_done: false,
            packet_conservation: false,
            prior_cwnd: 0,
            is_idle_restart: false,
            cycle_stamp: now,
            cycle_index: 0,
            target_cwnd: 0,
            in_recovery: false,
            recovery_epoch_start: None,
            ack_time: now,
            newly_lost_bytes: 0,
            newly_acked_bytes: 0,
            last_ack_packet_sent_time: now,
            prior_bytes_in_flight: 0,
            packet_delivered: 0,
            bytes_in_flight: 0,
            bytes_lost_in_total: 0,
        };
        bbr.on_connection_init();
        bbr
    }
}

impl Algorithm for Bbr {
    fn on_sent(&mut self, sent: &mut SentPkt, _: usize, _: Instant) {
        self.delivery_rate.on_packet_sent(
            sent,
            self.bytes_in_flight as usize,
            self.bytes_lost_in_total,
        );

        self.bytes_in_flight += sent.size as u64;
        self.on_transmit();

        let event = RecoveryMetricsUpdated::from(&*self);
        qlog::event!(event);
    }

    //  todo: VecDeque 是否有必要
    fn on_ack(&mut self, packets: VecDeque<AckedPkt>, now: Instant) {
        self.newly_acked_bytes = 0;
        self.newly_lost_bytes = 0;
        self.packet_delivered = 0;
        self.last_ack_packet_sent_time = now;
        self.prior_bytes_in_flight = self.bytes_in_flight;
        self.ack_time = now;

        for mut ack in packets {
            self.delivery_rate.update_rate_sample(&ack, now);
            self.bytes_in_flight = self.bytes_in_flight.saturating_sub(ack.size as u64);
            self.packet_delivered = self
                .packet_delivered
                .max(self.delivery_rate.delivered() as u64);
            self.update_model_and_state(&mut ack);
        }

        self.delivery_rate.generate_rate_sample();
        if self.in_recovery
            && self
                .recovery_epoch_start
                .is_none_or(|t| self.last_ack_packet_sent_time > t)
        {
            // exit_recovery
            self.recovery_epoch_start = None;
            self.packet_conservation = false;
            self.in_recovery = false;
            self.restore_cwnd();
        }

        self.update_control_parameters();

        let event = RecoveryMetricsUpdated::from(&*self);
        qlog::event!(event);
    }

    fn on_congestion_event(&mut self, _: &SentPkt, _: Instant) {
        // todo: enter_recovery
        // update newly lost bytes, set BBR.packet_conservation = true, and emit qlog
    }

    fn cwnd(&self) -> u64 {
        self.cwnd
    }

    fn pacing_rate(&self) -> Option<u64> {
        Some(self.pacing_rate)
    }
}

impl Bbr {
    // 3.5.1.  Initialization
    fn on_connection_init(&mut self) {
        self.init();
    }

    // 3.5.2.  Per-ACK Steps
    fn update_model_and_state(&mut self, ack: &mut AckedPkt) {
        self.update_btlbw(ack);
        self.check_cycle_phase();
        self.check_full_pipe();
        self.check_drain();
        self.update_rtprop();
        self.check_probe_rtt();
    }

    fn update_control_parameters(&mut self) {
        self.set_pacing_rate();
        self.set_send_quantum();
        self.set_cwnd();
    }

    // 3.5.3.  Per-Transmit Steps
    fn on_transmit(&mut self) {
        self.handle_restart_from_idle();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        time::{Duration, Instant},
    };

    use crate::{
        bbr::{BbrStateMachine, HIGH_GAIN, INITIAL_CWND, MSS},
        congestion::{AckedPkt, Algorithm, SentPkt},
        rtt::INITIAL_RTT,
    };

    #[test]
    fn test_bbr_init() {
        let mut bbr = super::Bbr::new();
        bbr.init();
        assert_eq!(bbr.state, BbrStateMachine::Startup);
        assert_eq!(bbr.pacing_gain, HIGH_GAIN);
        assert_eq!(bbr.cwnd_gain, HIGH_GAIN);
        assert_eq!(bbr.cycle_index, 0);
        assert_eq!(bbr.cwnd, INITIAL_CWND);
        assert_eq!(bbr.bytes_in_flight, 0);
        assert_eq!(
            bbr.pacing_rate,
            (bbr.pacing_gain * INITIAL_CWND as f64 / INITIAL_RTT.as_secs_f64()) as u64
        );
    }

    #[test]
    fn test_bbr_sent() {
        let mut bbr = super::Bbr::new();
        let now = Instant::now();
        for _ in 0..10 {
            let mut sent = SentPkt {
                size: MSS,
                ..Default::default()
            };
            bbr.on_sent(&mut sent, MSS, now);
        }
        assert_eq!(bbr.bytes_in_flight, 10 * MSS as u64);
    }

    #[test]
    fn test_bbr_ack() {
        let mut bbr = super::Bbr::new();
        let mut now = Instant::now();
        let rtt = Duration::from_millis(100);

        simulate_round_trip(&mut bbr, now, rtt, 0, 10, MSS);
        assert_eq!(bbr.bytes_in_flight, 0);
        assert_eq!(bbr.delivery_rate.delivered(), 10 * MSS);
        assert_eq!(
            bbr.delivery_rate.sample_delivery_rate(),
            (10 * 10 * MSS) as u64
        );

        now += Duration::from_secs(1);
        // next roud
        // generate btlbw
        simulate_round_trip(&mut bbr, now, rtt, 10, 40, MSS);
        assert_eq!(bbr.delivery_rate.delivered(), 40 * MSS);
        assert_eq!(
            bbr.delivery_rate.sample_delivery_rate(),
            (30 * 10 * MSS) as u64
        );
        assert_eq!(bbr.btlbw, (10 * 10 * MSS) as u64);
        assert_eq!(
            bbr.pacing_rate,
            (bbr.pacing_gain * INITIAL_CWND as f64 / INITIAL_RTT.as_secs_f64()) as u64
        );

        now += Duration::from_secs(1);
        // update btlbw
        simulate_round_trip(&mut bbr, now, rtt, 40, 60, MSS);
        assert_eq!(
            bbr.delivery_rate.sample_delivery_rate(),
            (20 * 10 * MSS) as u64
        );
        assert_eq!(bbr.btlbw, (3 * 10 * 10 * MSS) as u64);
        assert_eq!(bbr.pacing_rate, (bbr.btlbw as f64 * bbr.pacing_gain) as u64);
    }

    pub(super) fn simulate_round_trip(
        bbr: &mut super::Bbr,
        start_time: Instant,
        rtt: Duration,
        start: usize,
        end: usize,
        packet_size: usize,
    ) {
        let mut acks = VecDeque::with_capacity(end - start);
        for i in start..end {
            let mut sent: SentPkt = SentPkt {
                pn: i as u64,
                size: packet_size,
                time_sent: start_time,
                ..Default::default()
            };
            bbr.on_sent(&mut sent, 0, start_time);

            let mut ack: AckedPkt = sent.into();
            ack.rtt = rtt;
            acks.push_back(ack);
        }

        let ack_time = start_time + rtt;
        bbr.on_ack(acks, ack_time);
    }
}
