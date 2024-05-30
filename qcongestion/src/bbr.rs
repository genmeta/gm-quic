//! BBR Congestion Control
//!
//! This implementation is based on the following draft:
//! <https://datatracker.ietf.org/doc/html/draft-cardwell-iccrg-bbr-congestion-control-02>

use std::time::{Duration, Instant};

use crate::{
    congestion::{Acked, Algorithm, Sent},
    delivery_rate,
};

use self::min_max::Minmax;

mod ack;
mod init;
mod loss;
mod min_max;
mod pacing;
mod transmit;

const INITIAL_RTT: Duration = Duration::from_millis(333);

const MINIMUM_WINDOW_PACKETS: usize = 2;
/// The static discount factor of 1% used to scale BBR.bw to produce
/// BBR.pacing_rate.
const PACING_MARGIN_PERCENT: f64 = 0.01;

/// A constant specifying the minimum gain value
/// for calculating the pacing rate that will allow the sending rate to
/// double each round (4*ln(2) ~=2.77 ) BBRStartupPacingGain; used in
/// Startup mode for BBR.pacing_gain.
const STARTUP_PACING_GAIN: f64 = 2.77;

/// A constant specifying the pacing gain value for Probe Down mode.
const PROBE_DOWN_PACING_GAIN: f64 = 3_f64 / 4_f64;

/// A constant specifying the pacing gain value for Probe Up mode.
const PROBE_UP_PACING_GAIN: f64 = 5_f64 / 4_f64;

/// A constant specifying the pacing gain value for Probe Refill, Probe RTT,
/// Cruise mode.
const PACING_GAIN: f64 = 1.0;

/// A constant specifying the minimum gain value for the cwnd in the Startup
/// phase
const STARTUP_CWND_GAIN: f64 = 2.77;

/// A constant specifying the minimum gain value for
/// calculating the cwnd that will allow the sending rate to double each
/// round (2.0); used in Probe and Drain mode for BBR.cwnd_gain.
const CWND_GAIN: f64 = 2.0;

/// The maximum tolerated per-round-trip packet loss rate
/// when probing for bandwidth (the default is 2%).
const LOSS_THRESH: f64 = 0.02;

/// Exit startup if the number of loss marking events is >=FULL_LOSS_COUNT
const FULL_LOSS_COUNT: u32 = 8;

/// The default multiplicative decrease to make upon each round
/// trip during which the connection detects packet loss (the value is
/// 0.7).
const BETA: f64 = 0.7;

/// The multiplicative factor to apply to BBR.inflight_hi
/// when attempting to leave free headroom in the path (e.g. free space
/// in the bottleneck buffer or free time slots in the bottleneck link)
/// that can be used by cross traffic (the value is 0.85).
const HEADROOM: f64 = 0.85;

/// The minimal cwnd value BBR targets, to allow
/// pipelining with TCP endpoints that follow an "ACK every other packet"
/// delayed-ACK policy: 4 * SMSS.
const MIN_PIPE_CWND_PKTS: usize = 4;

// To do: Tune window for expiry of Max BW measurement
// The filter window length for BBR.MaxBwFilter = 2 (representing up to 2
// ProbeBW cycles, the current cycle and the previous full cycle).
// const MAX_BW_FILTER_LEN: Duration = Duration::from_secs(2);

// To do: Tune window for expiry of ACK aggregation measurement
// The window length of the BBR.ExtraACKedFilter max filter window: 10 (in
// units of packet-timed round trips).
// const EXTRA_ACKED_FILTER_LEN: Duration = Duration::from_secs(10);

/// A constant specifying the length of the BBR.min_rtt min filter window,
/// MinRTTFilterLen is 10 secs.
const MIN_RTT_FILTER_LEN: u32 = 1;

/// A constant specifying the gain value for calculating the cwnd during
/// ProbeRTT: 0.5 (meaning that ProbeRTT attempts to reduce in-flight data to
/// 50% of the estimated BDP).
const PROBE_RTT_CWND_GAIN: f64 = 0.5;

/// A constant specifying the minimum duration for which ProbeRTT state holds
/// inflight to BBRMinPipeCwnd or fewer packets: 200 ms.
const PROBE_RTT_DURATION: Duration = Duration::from_millis(200);

/// ProbeRTTInterval: A constant specifying the minimum time interval between
/// ProbeRTT states. To do: investigate probe duration. Set arbitrarily high for
/// now.
const PROBE_RTT_INTERVAL: Duration = Duration::from_secs(86400);

/// Threshold for checking a full bandwidth growth during Startup.
const MAX_BW_GROWTH_THRESHOLD: f64 = 1.25;

/// Threshold for determining maximum bandwidth of network during Startup.
const MAX_BW_COUNT: usize = 3;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
enum BBRStateMachine {
    Startup,
    Drain,
    ProbeBWDOWN,
    ProbeBWCRUISE,
    ProbeBWREFILL,
    ProbeBWUP,
    ProbeRTT,
}

#[derive(Debug, PartialEq, Eq)]
enum BBRAckPhase {
    Init,
    ProbeFeedback,
    ProbeStarting,
    ProbeStopping,
    Refilling,
}

pub struct BBRState {
    // 2.3.  Per-ACK Rate Sample State
    // It's stored in rate sample but we keep in BBR state here.

    // The volume of data that was estimated to be in
    // flight at the time of the transmission of the packet that has just
    // been ACKed.
    tx_in_flight: usize,

    // The volume of data that was declared lost between the
    // transmission and acknowledgement of the packet that has just been
    // ACKed.
    lost: usize,

    // The volume of data cumulatively or selectively acknowledged upon the ACK
    // that was just received.  (This quantity is referred to as "DeliveredData"
    // in [RFC6937].)
    newly_acked_bytes: usize,

    // The volume of data newly marked lost upon the ACK that was just received.
    newly_lost_bytes: usize,

    // 2.4.  Output Control Parameters
    // The current pacing rate for a BBR2 flow, which controls inter-packet
    // spacing.
    pacing_rate: u64,

    // Save initial pacing rate so we can update when more reliable bytes
    // delivered and RTT samples are available
    init_pacing_rate: u64,

    // 2.5.  Pacing State and Parameters
    // The dynamic gain factor used to scale BBR.bw to
    // produce BBR.pacing_rate.
    pacing_gain: f64,

    // 2.6.  cwnd State and Parameters
    // The dynamic gain factor used to scale the estimated BDP to produce a
    // congestion window (cwnd).
    cwnd_gain: f64,

    // A boolean indicating whether BBR is currently using packet conservation
    // dynamics to bound cwnd.
    packet_conservation: bool,

    // 2.7.  General Algorithm State
    // The current state of a BBR2 flow in the BBR2 state machine.
    state: BBRStateMachine,

    // Count of packet-timed round trips elapsed so far.
    round_count: u64,

    // A boolean that BBR2 sets to true once per packet-timed round trip,
    // on ACKs that advance BBR2.round_count.
    round_start: bool,

    // packet.delivered value denoting the end of a packet-timed round trip.
    next_round_delivered: usize,

    // A boolean that is true if and only if a connection is restarting after
    // being idle.
    idle_restart: bool,

    // 2.9.1.  Data Rate Network Path Model Parameters
    // The windowed maximum recent bandwidth sample - obtained using the BBR
    // delivery rate sampling algorithm
    // [draft-cheng-iccrg-delivery-rate-estimation] - measured during the current
    // or previous bandwidth probing cycle (or during Startup, if the flow is
    // still in that state).  (Part of the long-term model.)
    max_bw: u64,

    // The long-term maximum sending bandwidth that the algorithm estimates will
    // produce acceptable queue pressure, based on signals in the current or
    // previous bandwidth probing cycle, as measured by loss.  (Part of the
    // long-term model.)
    bw_hi: u64,

    // The short-term maximum sending bandwidth that the algorithm estimates is
    // safe for matching the current network path delivery rate, based on any
    // loss signals in the current bandwidth probing cycle.  This is generally
    // lower than max_bw or bw_hi (thus the name).  (Part of the short-term
    // model.)
    bw_lo: u64,

    // The maximum sending bandwidth that the algorithm estimates is appropriate
    // for matching the current network path delivery rate, given all available
    // signals in the model, at any time scale.  It is the min() of max_bw,
    // bw_hi, and bw_lo.
    bw: u64,

    // 2.9.2.  Data Volume Network Path Model Parameters
    // The windowed minimum round-trip time sample measured over the last
    // MinRTTFilterLen = 10 seconds.  This attempts to estimate the two-way
    // propagation delay of the network path when all connections sharing a
    // bottleneck are using BBR, but also allows BBR to estimate the value
    // required for a bdp estimate that allows full throughput if there are
    // legacy loss-based Reno or CUBIC flows sharing the bottleneck.
    min_rtt: Duration,

    // The estimate of the network path's BDP (Bandwidth-Delay Product), computed
    // as: BBR.bdp = BBR.bw * BBR.min_rtt.
    bdp: usize,

    // A volume of data that is the estimate of the recent degree of aggregation
    // in the network path.
    extra_acked: usize,

    // The estimate of the minimum volume of data necessary to achieve full
    // throughput when using sender (TSO/GSO) and receiver (LRO, GRO) host
    // offload mechanisms.
    offload_budget: usize,

    // The estimate of the volume of in-flight data required to fully utilize the
    // bottleneck bandwidth available to the flow, based on the BDP estimate
    // (BBR.bdp), the aggregation estimate (BBR.extra_acked), the offload budget
    // (BBR.offload_budget), and BBRMinPipeCwnd.
    max_inflight: usize,

    // Analogous to BBR.bw_hi, the long-term maximum volume of in-flight data
    // that the algorithm estimates will produce acceptable queue pressure, based
    // on signals in the current or previous bandwidth probing cycle, as measured
    // by loss.  That is, if a flow is probing for bandwidth, and observes that
    // sending a particular volume of in-flight data causes a loss rate higher
    // than the loss rate objective, it sets inflight_hi to that volume of data.
    // (Part of the long-term model.)
    inflight_hi: usize,

    // Analogous to BBR.bw_lo, the short-term maximum volume of in-flight data
    // that the algorithm estimates is safe for matching the current network path
    // delivery process, based on any loss signals in the current bandwidth
    // probing cycle.  This is generally lower than max_inflight or inflight_hi
    // (thus the name).  (Part of the short-term model.)
    inflight_lo: usize,

    // 2.10.  State for Responding to Congestion
    // a 1-round-trip max of delivered bandwidth (rs.delivery_rate).
    bw_latest: u64,

    // a 1-round-trip max of delivered volume of data (rs.delivered).
    inflight_latest: usize,

    // 2.11.  Estimating BBR.max_bw
    // The filter for tracking the maximum recent rs.delivery_rate sample, for
    // estimating BBR.max_bw.
    max_bw_filter: Minmax<u64>,

    // The virtual time used by the BBR.max_bw filter window.  Note that
    // BBR.cycle_count only needs to be tracked with a single bit, since the
    // BBR.MaxBwFilter only needs to track samples from two time slots: the
    // previous ProbeBW cycle and the current ProbeBW cycle.
    cycle_count: u64,

    // 2.12.  Estimating BBR.extra_acked
    // the start of the time interval for estimating the excess amount of data
    // acknowledged due to aggregation effects.
    extra_acked_interval_start: Instant,

    // the volume of data marked as delivered since
    // BBR.extra_acked_interval_start.
    extra_acked_delivered: usize,

    // BBR.ExtraACKedFilter: the max filter tracking the recent maximum degree of
    // aggregation in the path.
    extra_acked_filter: Minmax<usize>,

    // 2.13.  Startup Parameters and State
    // A boolean that records whether BBR estimates that it has ever fully
    // utilized its available bandwidth ("filled the pipe").
    filled_pipe: bool,

    // A recent baseline BBR.max_bw to estimate if BBR has "filled the pipe" in
    // Startup.
    full_bw: u64,

    // The number of non-app-limited round trips without large increases in
    // BBR.full_bw.
    full_bw_count: usize,

    // 2.14.1.  Parameters for Estimating BBR.min_rtt
    // The wall clock time at which the current BBR.min_rtt sample was obtained.
    min_rtt_stamp: Instant,

    // 2.14.2.  Parameters for Scheduling ProbeRTT
    // The minimum RTT sample recorded in the last ProbeRTTInterval.
    probe_rtt_min_delay: Duration,

    // The wall clock time at which the current BBR.probe_rtt_min_delay sample
    // was obtained.
    probe_rtt_min_stamp: Instant,

    // A boolean recording whether the BBR.probe_rtt_min_delay has expired and is
    // due for a refresh with an application idle period or a transition into
    // ProbeRTT state.
    probe_rtt_expired: bool,

    // Others
    // A state indicating we are in the recovery.
    in_recovery: bool,

    // Start time of the connection.
    start_time: Instant,

    // Saved cwnd before loss recovery.
    prior_cwnd: usize,

    // Whether we have a bandwidth probe samples.
    bw_probe_samples: bool,

    // Others
    probe_up_cnt: usize,

    prior_bytes_in_flight: usize,

    probe_rtt_done_stamp: Option<Instant>,

    probe_rtt_round_done: bool,

    bw_probe_wait: Duration,

    rounds_since_probe: usize,

    cycle_stamp: Instant,

    ack_phase: BBRAckPhase,

    bw_probe_up_rounds: usize,

    bw_probe_up_acks: usize,

    loss_round_start: bool,

    loss_round_delivered: usize,

    loss_in_round: bool,

    loss_events_in_round: usize,

    congestion_window: usize,

    bytes_in_flight: usize,

    congestion_recovery_start_time: Option<Instant>,

    max_datagram_size: usize,

    smoothed_rtt: Option<Duration>,

    // The maximum size of a data aggregate scheduled and
    // transmitted together.
    send_quantum: usize,

    /// Initial congestion window size in terms of packet count.
    initial_congestion_window_packets: usize,

    pub bytes_lost: u64,

    delivery_rate: delivery_rate::Rate,
}

impl Default for BBRState {
    fn default() -> Self {
        Self::new()
    }
}

impl BBRState {
    pub fn new() -> BBRState {
        BBRState {
            tx_in_flight: 0,
            lost: 0,
            newly_acked_bytes: 0,
            newly_lost_bytes: 0,
            pacing_rate: 0,
            init_pacing_rate: 0,
            pacing_gain: 0.0,
            cwnd_gain: 0.0,
            packet_conservation: false,
            state: BBRStateMachine::Startup,
            round_count: 0,
            round_start: false,
            next_round_delivered: 0,
            idle_restart: false,
            max_bw: 0,
            bw_hi: 0,
            bw_lo: 0,
            bw: 0,
            min_rtt: Duration::from_secs(0),
            bdp: 0,
            extra_acked: 0,
            offload_budget: 0,
            max_inflight: 0,
            inflight_hi: 0,
            inflight_lo: 0,
            bw_latest: 0,
            inflight_latest: 0,
            max_bw_filter: Minmax::new(0),
            cycle_count: 0,
            extra_acked_interval_start: Instant::now(),
            extra_acked_delivered: 0,
            extra_acked_filter: Minmax::new(0),
            filled_pipe: false,
            full_bw: 0,
            full_bw_count: 0,
            min_rtt_stamp: Instant::now(),
            probe_rtt_min_delay: Duration::from_secs(0),
            probe_rtt_min_stamp: Instant::now(),
            probe_rtt_expired: false,
            in_recovery: false,
            start_time: Instant::now(),
            prior_cwnd: 0,
            bw_probe_samples: false,
            probe_up_cnt: 0,
            prior_bytes_in_flight: 0,
            probe_rtt_done_stamp: None,
            probe_rtt_round_done: false,
            bw_probe_wait: Duration::from_secs(0),
            rounds_since_probe: 0,
            cycle_stamp: Instant::now(),
            ack_phase: BBRAckPhase::Init,
            bw_probe_up_rounds: 0,
            bw_probe_up_acks: 0,
            loss_round_start: false,
            loss_round_delivered: 0,
            loss_in_round: false,
            loss_events_in_round: 0,
            congestion_window: 0,
            bytes_in_flight: 0,
            congestion_recovery_start_time: None,
            max_datagram_size: 0,
            smoothed_rtt: None,
            send_quantum: 0,
            initial_congestion_window_packets: 0,
            bytes_lost: 0,
            delivery_rate: delivery_rate::Rate::default(),
        }
    }

    fn in_congestion_recovery(&self, sent_time: Instant) -> bool {
        match self.congestion_recovery_start_time {
            Some(congestion_recovery_start_time) => sent_time <= congestion_recovery_start_time,
            None => false,
        }
    }

    fn exit_recovery(&mut self) {
        self.congestion_recovery_start_time = None;

        self.packet_conservation = false;
        self.in_recovery = false;
        self.restore_cwnd();
    }

    fn enter_recovery(&mut self, now: Instant) {
        self.prior_cwnd = self.save_cwnd();

        self.congestion_window =
            self.bytes_in_flight + self.newly_acked_bytes.max(self.max_datagram_size);
        self.congestion_recovery_start_time = Some(now);
        self.in_recovery = true;
        self.packet_conservation = true;

        // start round
        self.next_round_delivered = self.delivery_rate.delivered();
    }
}

impl Algorithm for BBRState {
    fn init(&mut self) {
        self.init();
    }

    fn on_packet_sent(&mut self, sent: &mut Sent, sent_bytes: usize, now: Instant) {
        self.delivery_rate
            .on_packet_sent(sent, self.bytes_in_flight, self.bytes_lost);
        self.bytes_in_flight += sent_bytes;
        self.on_transmit(now)
    }

    fn on_congestion_event(&mut self, largest_lost_pkt: &Sent, now: Instant) {
        self.newly_lost_bytes = largest_lost_pkt.size;
        self.update_on_loss(largest_lost_pkt, now);

        if self.in_congestion_recovery(largest_lost_pkt.time_sent) {
            self.enter_recovery(now);
        }
    }

    fn cwnd(&self) -> u64 {
        self.congestion_window as u64
    }

    fn on_packet_acked(&mut self, packet: &Acked, now: Instant) {
        // update delivery rate
        self.delivery_rate.update_rate_sample(packet, now);
        self.delivery_rate.generate_rate_sample(self.min_rtt);

        self.newly_acked_bytes = 0;

        let time_sent = packet.time_sent;

        self.prior_bytes_in_flight = self.bytes_in_flight;

        self.update_model_and_state(packet, now);

        if self.bytes_in_flight < packet.size {
            self.bytes_in_flight = 0;
        } else {
            self.bytes_in_flight -= packet.size
        }
        self.newly_acked_bytes += packet.size;

        if !self.in_congestion_recovery(time_sent) {
            self.exit_recovery();
        }

        // update_control_parameters(self, now);
        self.newly_lost_bytes = 0;
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        time::{Duration, Instant},
    };

    use crate::congestion::{Acked, Algorithm, Sent};

    #[test]
    fn test_bbr_sent() {
        let mut bbr = super::BBRState::default();
        let now = Instant::now();
        // 发送 5 个包
        for pn in 0..5 {
            let mut sent = Sent::default();
            sent.size = 100;
            sent.time_sent = now;
            sent.pkt_num = pn;
            bbr.on_packet_sent(&mut sent, 100, now);
            assert_eq!(bbr.bytes_in_flight as u64, 100 * (pn + 1));
            assert_eq!(bbr.delivery_rate.delivered(), 0);
            assert_eq!(sent.first_sent_time, now);
            assert_eq!(sent.delivered_time, now);
        }
        let next = Instant::now() + Duration::from_secs(1);
        // 再发送 5 个包
        for pn in 5..10 {
            let mut sent = Sent::default();
            sent.size = 100;
            sent.time_sent = next;
            sent.pkt_num = pn;
            bbr.on_packet_sent(&mut sent, 100, next);
            assert_eq!(bbr.bytes_in_flight as u64, 100 * (pn + 1));
            assert_eq!(bbr.delivery_rate.delivered(), 0);
            // 记录的是第一次发包时间
            assert_eq!(sent.first_sent_time, now);
            assert_eq!(sent.delivered_time, now);
        }
    }

    #[test]
    fn test_bbr_acked() {
        let mut bbr = super::BBRState::default();
        bbr.init();
        let mut packets: VecDeque<Sent> = VecDeque::new();
        let now = Instant::now();
        for pn in 0..5 {
            let mut sent = Sent::default();
            sent.size = 100;
            sent.time_sent = now;
            sent.pkt_num = pn;
            bbr.on_packet_sent(&mut sent, 100 as usize, now);
            packets.push_back(sent);
        }

        let recv_time = now + Duration::from_millis(100);
        // receive ack for 3 packets
        for _ in 0..3 {
            let packet = packets.pop_front().unwrap();
            let acked = Acked {
                pkt_num: packet.pkt_num,
                time_sent: packet.time_sent,
                size: packet.size,
                rtt: recv_time.saturating_duration_since(packet.time_sent),
                delivered: packet.delivered,
                delivered_time: packet.delivered_time,
                first_sent_time: packet.first_sent_time,
                is_app_limited: packet.is_app_limited,
                tx_in_flight: packet.tx_in_flight,
                lost: packet.lost,
            };
            bbr.on_packet_acked(&acked, now);
            println!("bbr.bytes_in_flight: {}", bbr.bytes_in_flight);
            assert!(bbr.bytes_in_flight as u64 == 500 - (packet.pkt_num + 1) * 100);
            assert!(bbr.delivery_rate.delivered() as u64 == 100 * (packet.pkt_num + 1));
        }
        assert_eq!(bbr.delivery_rate.sample_delivery_rate(), 0);
    }
}
