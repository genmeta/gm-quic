use std::time::{Duration, Instant};

use crate::{congestion::Algorithm, delivery_rate::Rate, min_max::Minmax};

mod drain;
mod parameters;
mod probe_bw;
mod probe_rtt;
mod startup;

// BtlBwFilterLen: A constant specifying the length of the BBR.BtlBw max
// filter window for BBR.BtlBwFilter, BtlBwFilterLen is `10` packet-timed
// round trips.
const BTLBW_FILTER_LEN: u64 = 10;

// RTpropFilterLen: A constant specifying the length of the RTProp min
// filter window, RTpropFilterLen is `10` secs.
const RTPROP_FILTER_LEN: Duration = Duration::from_secs(10);

// BBRHighGain: A constant specifying the minimum gain value that will
// allow the sending rate to double each round (`2/ln(2)` ~= `2.89`), used
// in Startup mode for both BBR.pacing_gain and BBR.cwnd_gain.
const HIGH_GAIN: f64 = 2.89;

// Bandwidth growth rate before pipe got filled.
const BTLBW_GROWTH_RATE: f64 = 0.25;

// Max count of full bandwidth reached, before pipe is supposed to be filled.
// This three-round threshold was validated by YouTube experimental data.
const FULL_BW_COUNT_THRESHOLD: u64 = 3;

// ProbeRTTInterval: A constant specifying the minimum time interval
// between ProbeRTT states: 10 secs.
const PROBE_RTT_INTERVAL: Duration = Duration::from_secs(10);

// ProbeRTTDuration: A constant specifying the minimum duration for
// which ProbeRTT state holds inflight to BBRMinPipeCwnd or fewer
// packets: 200 ms.
const PROBE_RTT_DURATION: Duration = Duration::from_millis(200);

// Pacing rate threshold for select different send quantum. Default `1.2Mbps`.
const SEND_QUANTUM_THRESHOLD_PACING_RATE: u64 = 1_200_000 / 8;

//  default datagram size in bytes.
const DEFAULT_MTU: u16 = 1200;

// Initial congestion window in bytes.
const INITIAL_CWND: u64 = 80 * DEFAULT_MTU as u64;

/// The minimal cwnd value BBR tries to target using: 4 packets, or 4 * SMSS
const MIN_PIPE_CWND_PKTS: usize = 4;

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
    btlbwfilter: Minmax<u64>,

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

    /// Ack time.
    ack_time: Instant,

    /// Newly marked lost data size in bytes.
    newly_lost_bytes: u64,

    /// Newly acked data size in bytes.
    newly_acked_bytes: u64,

    /// The last P.delivered in bytes.
    packet_delivered: u64,

    /// The last P.sent_time to determine whether exit recovery.
    last_ack_packet_sent_time: Instant,

    /// The amount of data that was in flight before processing this ACK.
    prior_bytes_in_flight: u64,

    /// The sum of the size in bytes of all sent packets that contain at least
    /// one ack-eliciting or PADDING frame and have not been acknowledged or
    /// declared lost. The size does not include IP or UDP overhead.
    pub bytes_in_flight: u64,
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
            btlbwfilter: Minmax::new(0),
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
        };
        bbr.init();
        bbr
    }
}

impl Algorithm for Bbr {
    fn init(&mut self) {
        todo!()
    }

    fn on_packet_sent(
        &mut self,
        sent: &mut crate::congestion::Sent,
        sent_bytes: usize,
        now: Instant,
    ) {
        todo!()
    }

    fn on_packet_acked(&mut self, packet: &crate::congestion::Acked, now: Instant) {
        todo!()
    }

    fn on_congestion_event(&mut self, lost: &crate::congestion::Sent, now: Instant) {
        todo!()
    }

    fn cwnd(&self) -> u64 {
        todo!()
    }
}
