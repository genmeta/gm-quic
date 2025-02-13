use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::{PacketHeader, PacketNumberSpace, QuicFrame};

/// The recovery_parameters_set event groups initial parameters from both
/// loss detection and congestion control into a single event.  It has
/// Base importance level; see Section 9.2 of [QLOG-MAIN].
///
/// All these settings are typically set once and never change.
/// Implementation that do, for some reason, change these parameters
/// during execution, MAY emit the recovery_parameters_set event more
/// than once
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde_with::skip_serializing_none]
pub struct RecoveryParametersSet {
    /// Loss detection, see RFC 9002 Appendix A.2
    /// in amount of packets
    pub reordering_threshold: Option<u16>,

    /// as RTT multiplier
    pub time_threshold: Option<f32>,

    /// in ms
    pub timer_granularity: u16,

    /// in ms
    pub initial_rtt: Option<f32>,

    /// congestion control, see RFC 9002 Appendix B.2
    /// in bytes. Note that this could be updated after pmtud
    pub max_datagram_size: Option<u32>,

    /// in bytes
    pub initial_congestion_window: Option<u64>,

    /// Note that this could change when max_datagram_size changes
    /// in bytes
    pub minimum_congestion_window: Option<u64>,
    pub loss_reduction_factor: Option<f32>,

    /// as PTO multiplier
    pub persistent_congestion_threshold: Option<u16>,

    /// Additionally, this event can contain any number of unspecified fields
    /// to support different recovery approaches.
    #[serde(flatten)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub custom_fileds: HashMap<String, String>,
}

/// The recovery_metrics_updated event is emitted when one or more of the
/// observable recovery metrics changes value.  It has Core importance
/// level; see Section 9.2 of [QLOG-MAIN].
///
/// This event SHOULD group all possible metric updates that happen at or
/// around the same time in a single event (e.g., if min_rtt and
/// smoothed_rtt change at the same time, they should be bundled in a
/// single recovery_metrics_updated entry, rather than split out into
/// two).  Consequently, a recovery_metrics_updated event is only
/// guaranteed to contain at least one of the listed metrics.
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde_with::skip_serializing_none]
pub struct RecoveryMetricsUpdated {
    /// Loss detection, see RFC 9002 Appendix A.3
    /// all following rtt fields are expressed in ms
    pub smoothed_rtt: Option<f32>,
    pub min_rtt: Option<f32>,
    pub latest_rtt: Option<f32>,
    pub rtt_variance: Option<f32>,
    pub pto_count: Option<u16>,

    /// Congestion control, see RFC 9002 Appendix B.2.
    /// in bytes
    pub congestion_window: Option<u64>,
    pub bytes_in_flight: Option<u64>,

    /// in bytes
    pub ssthresh: Option<u64>,

    /// qlog defined
    /// sum of all packet number spaces
    pub packets_in_flight: Option<u64>,
    /// in bits per second
    pub pacing_rate: Option<u64>,

    /// Additionally, the recovery_metrics_updated event can contain any
    /// number of unspecified fields to support different recovery
    /// approaches.
    #[serde(flatten)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub custom_fileds: HashMap<String, String>,
}

/// The congestion_state_updated event indicates when the congestion
/// controller enters a significant new state and changes its behaviour.
/// It has Base importance level; see Section 9.2 of [QLOG-MAIN].
///
/// The values of the event's fields are intentionally unspecified here
/// in order to support different Congestion Control algorithms, as these
/// typically have different states and even different implementations of
/// these states across stacks.  For example, for the algorithm defined
/// in the QUIC Recovery RFC ("enhanced" New Reno), the following states
/// are used: Slow Start, Congestion Avoidance, Application Limited and
/// Recovery.  Similarly, states can be triggered by a variety of events,
/// including detection of Persistent Congestion or receipt of ECN
/// markings.
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde_with::skip_serializing_none]
pub struct CongestionStateUpdated {
    pub old: Option<String>,
    pub new: String,
    pub trigger: Option<String>,
}

/// The loss_timer_updated event is emitted when a recovery loss timer
/// changes state.  It has Extra importance level; see Section 9.2 of
/// [QLOG-MAIN].
///
/// The three main event types are:
///
/// *  set: the timer is set with a delta timeout for when it will
/// trigger next
///
/// *  expired: when the timer effectively expires after the delta
/// timeout
///
/// *  cancelled: when a timer is cancelled (e.g., all outstanding
/// packets are acknowledged, start idle period)
///  
/// In order to indicate an active timer's timeout update, a new set
/// event is used.
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LossTimerUpdated {
    /// called "mode" in RFC 9002 A.9.
    pub timer_type: Option<TimerType>,
    pub packet_number_space: Option<PacketNumberSpace>,
    pub event_type: EventType,

    /// if event_type === "set": delta time is in ms from
    /// this event's timestamp until when the timer will trigger
    pub delta: Option<f32>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TimerType {
    Ack,
    Pto,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    Set,
    Expired,
    Cancelled,
}

/// The packet_lost event is emitted when a packet is deemed lost by loss
/// detection.  It has Core importance level; see Section 9.2 of
/// [QLOG-MAIN].
///
/// It is RECOMMENDED to populate the optional trigger field in order to
/// help disambiguate among the various possible causes of a loss
/// declaration.
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PacketLost {
    /// should include at least the packet_type and packet_number
    pub header: Option<PacketHeader>,

    /// not all implementations will keep track of full
    /// packets, so these are optional
    pub frames: Option<Vec<QuicFrame>>,
    pub is_mtu_probe_packet: Option<bool>,
    pub trigger: Option<PacketLostTrigger>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PacketLostTrigger {
    ReorderingThreshold,
    TimeThreshold,
    /// RFC 9002 Section 6.2.4 paragraph 6, MAY
    PtoExpired,
}

/// The marked_for_retransmit event indicates which data was marked for
/// retransmission upon detection of packet loss (see packet_lost).  It
/// has Extra importance level; see Section 9.2 of [QLOG-MAIN].
///
/// Similar to the reasoning for the frames_processed event, in order to
/// keep the amount of different events low, this signal is grouped into
/// in a single event based on existing QUIC frame definitions for all
/// types of retransmittable data.
///
/// Implementations retransmitting full packets or frames directly can
/// just log the constituent frames of the lost packet here (or do away
/// with this event and use the contents of the packet_lost event
/// instead).  Conversely, implementations that have more complex logic
/// (e.g., marking ranges in a stream's data buffer as in-flight), or
/// that do not track sent frames in full (e.g., only stream offset +
/// length), can translate their internal behaviour into the appropriate
/// frame instance here even if that frame was never or will never be put
/// on the wire.
///
/// Much of this data can be inferred if implementations log packet_sent
/// events (e.g., looking at overlapping stream data offsets and length,
/// one can determine when data was retransmitted).
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MarkedForRetransmit {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub frames: Vec<QuicFrame>,
}

/// The ecn_state_updated event indicates a progression in the ECN state
/// machine as described in section A.4 of [QUIC-TRANSPORT].  It has
/// Extra importance level; see Section 9.2 of [QLOG-MAIN].
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ECNStateUpdated {
    pub old: Option<ECNState>,
    pub new: ECNState,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ECNState {
    /// ECN testing in progress
    Testing,
    /// ECN state unknown, waiting for acknowledgements
    /// for testing packets
    Unknown,
    /// ECN testing failed
    Failed,
    /// testing was successful, the endpoint now
    /// sends packets with ECT(0) marking
    Capable,
}
