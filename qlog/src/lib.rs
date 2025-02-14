pub mod loglevel;
pub mod quic;

use std::{collections::HashMap, net::SocketAddr};

use bytes::Bytes;
use derive_more::{From, Into};
use quic::ConnectionID;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde_with::skip_serializing_none]
pub struct LogFile {
    pub file_schema: String,
    pub serialization_format: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub event_schemas: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QlogFile {
    #[serde(flatten)]
    pub qlog: LogFile,
    pub traces: Vec<Traces>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Traces {
    Trace(Trace),
    TraceError(TraceError),
}

///  The exact conceptual definition of a Trace can be fluid.  For
/// example, a trace could contain all events for a single connection,
/// for a single endpoint, for a single measurement interval, for a
/// single protocol, etc.  In the normal use case however, a trace is a
/// log of a single data flow collected at a single location or vantage
/// point.  For example, for QUIC, a single trace only contains events
/// for a single logical QUIC connection for either the client or the
/// server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde_with::skip_serializing_none]
pub struct Trace {
    /// The optional "title" fields provide additional free-text information about the trace.
    pub title: Option<String>,
    /// The optional "description" fields provide additional free-text information about the trace.
    pub description: Option<String>,
    pub common_fields: Option<CommonFields>,
    pub vantage_point: Option<VantagePoint>,
    pub events: Vec<Event>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommonFields {
    pub path: PathID,
    pub time_format: TimeFormat,
    pub reference_time: ReferenceTime,
    pub protocol_types: ProtocolTypeList,
    pub group_id: GroupID,
    #[serde(flatten)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub custom_fileds: HashMap<String, String>,
}

/// A VantagePoint describes the vantage point from which a trace originates
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde_with::skip_serializing_none]
pub struct VantagePoint {
    pub name: Option<String>,
    pub r#type: VantagePointType,
    pub flow: Option<VantagePointType>,
}

#[derive(Default, Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VantagePointType {
    /// endpoint which initiates the connection
    Client,
    /// endpoint which accepts the connection
    Server,
    /// observer in between client and server
    Network,
    #[default]
    Unknow,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde_with::skip_serializing_none]
pub struct TraceError {
    pub error_description: String,
    pub uri: Option<String>,
    pub vantage_point: Option<VantagePoint>,
}

/// Events are logged at a time instant and convey specific details of the logging use case.
///
/// Events can contain any amount of custom fields.
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Event {
    pub time: f64,
    #[serde(flatten)]
    pub data: EvnetData,
    /// A qlog event can be associated with a single "network path" (usually, but not always, identified by a 4-tuple
    /// of IP addresses and ports). In many cases, the path will be the same for all events in a given trace, and does
    /// not need to be logged explicitly with each event. In this case, the "path" field can be omitted (in which case
    /// the default value of "" is assumed) or reflected in "common_fields" instead
    pub path: Option<PathID>,
    pub time_format: Option<TimeFormat>,
    pub protocol_types: Option<ProtocolTypeList>,
    pub group_id: Option<GroupID>,
    pub system_info: Option<SystemInformation>,
    #[serde(flatten)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub custom_fileds: HashMap<String, String>,
}

#[derive(Debug, Clone, From, Into, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct PathID(String);

#[serde_with::skip_serializing_none]
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "UncheckedReferenceTime")]
pub struct ReferenceTime {
    /// The required "clock_type" field represents the type of clock used for time measurements. The value "system"
    /// represents a clock that uses system time, commonly measured against a chosen or well-known epoch. However,
    /// depending on the system, System time can potentially jump forward or back. In contrast, a clock using monotonic
    /// time is generally guaranteed to never go backwards. The value "monotonic" represents such a clock.
    pub clock_type: TimeClockType,
    /// The required "epoch" field is the start of the ReferenceTime. When using the "system" clock type, the epoch field
    /// **SHOULD** have a date/time value using the format defined in [RFC3339]. However, the value "unknown" **MAY** be
    /// used
    #[serde(default)]
    pub epoch: TimeEpoch,
    /// The optional "wall_clock_time" field can be used to provide an approximate date/time value that logging commenced
    /// at if the epoch value is "unknown". It uses the format defined in [RFC3339]. Note that conversion of timestamps
    /// to calendar time based on wall clock times cannot be safely relied on.
    pub wall_clock_time: Option<RFC3339DateTime>,
}

/// Intermediate data types during deserialization
#[derive(Deserialize)]
struct UncheckedReferenceTime {
    clock_type: TimeClockType,
    #[serde(default)]
    epoch: TimeEpoch,
    wall_clock_time: Option<RFC3339DateTime>,
}

impl TryFrom<UncheckedReferenceTime> for ReferenceTime {
    type Error = &'static str;
    fn try_from(value: UncheckedReferenceTime) -> Result<Self, Self::Error> {
        if value.clock_type == TimeClockType::Monotaonic && value.epoch != TimeEpoch::Unknow {
            return Err(
                r#"When using the "monotonic" clock type, the epoch field MUST have the value "unknown"."#,
            );
        }

        Ok(ReferenceTime {
            clock_type: value.clock_type,
            epoch: value.epoch,
            wall_clock_time: value.wall_clock_time,
        })
    }
}

impl ReferenceTime {}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TimeClockType {
    /// The value "system" represents a clock that uses system time, commonly measured against a chosen or well-known
    /// epoch
    #[default]
    System,
    /// A clock using monotonic time is generally guaranteed to never go backwards. The value "monotonic" represents
    /// such a clock.
    ///
    /// When using the "monotonic" clock type, the epoch field MUST have the value "unknown".
    Monotaonic,
    #[serde(untagged)]
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TimeEpoch {
    Unknow,
    #[serde(untagged)]
    RFC3339DateTime(RFC3339DateTime),
}

impl Default for TimeEpoch {
    fn default() -> Self {
        Self::RFC3339DateTime(Default::default())
    }
}

#[derive(Debug, Clone, From, Into, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct RFC3339DateTime(String);

impl Default for RFC3339DateTime {
    fn default() -> Self {
        Self("1970-01-01T00:00:00.000Z".to_owned())
    }
}

#[derive(Default, Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TimeFormat {
    /// A duration relative to the ReferenceTime "epoch" field. This approach uses the largest amount of characters.
    /// It is good for stateless loggers. This is the default value of the "time_format" field.
    #[default]
    RelativeToEpoch,
    /// A delta-encoded value, based on the previously logged value. The first event in a trace is always relative to
    /// the ReferenceTime. This approach uses the least amount of characters. It is suitable for stateful loggers.
    RelativeToPreviousEvent,
}

#[derive(Debug, Clone, From, Into, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct ProtocolTypeList(Vec<ProtocolType>);

#[derive(Debug, Clone, From, Into, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct ProtocolType(String);

impl ProtocolType {
    pub fn quic() -> ProtocolType {
        ProtocolType("QUIC".to_owned())
    }

    pub fn http3() -> ProtocolType {
        ProtocolType("HTTP/3".to_owned())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct GroupID(String);

impl From<ConnectionID> for GroupID {
    fn from(value: ConnectionID) -> Self {
        Self(format!("{value:x}"))
    }
}

impl From<(SocketAddr, SocketAddr)> for GroupID {
    fn from(_value: (SocketAddr, SocketAddr)) -> Self {
        todo!()
    }
}

/// The "system_info" field can be used to record system-specific details related to an event. This is useful, for instance,
/// where an application splits work across CPUs, processes, or threads and events for a single trace occur on potentially
/// different combinations thereof. Each field is optional to support deployment diversity.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde_with::skip_serializing_none]
pub struct SystemInformation {
    pub processor_id: Option<u32>,
    pub process_id: Option<u32>,
    pub thread_id: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventImportance {
    Core = 1,
    Base = 2,
    Extra = 3,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "name", content = "data")]
#[enum_dispatch::enum_dispatch(BeEventData)]
pub enum EvnetData {
    #[serde(rename = "quic:server_listening")]
    ServerListening(quic::connectivity::ServerListening),
    #[serde(rename = "quic:connection_started")]
    ConnectionStarted(quic::connectivity::ConnectionStarted),
    #[serde(rename = "quic:connection_closed")]
    ConnectionClosed(quic::connectivity::ConnectionClosed),
    #[serde(rename = "quic:connection_id_updated")]
    ConnectionIDUpdated(quic::connectivity::ConnectionIDUpdated),
    #[serde(rename = "quic:spin_bit_updated")]
    SpinBitUpdated(quic::connectivity::SpinBitUpdated),
    #[serde(rename = "quic:connection_state_updated")]
    ConnectionStateUpdated(quic::connectivity::ConnectionStateUpdated),
    #[serde(rename = "quic:path_assigned")]
    PathAssigned(quic::connectivity::PathAssigned),
    #[serde(rename = "quic:mtu_updated")]
    MtuUpdated(quic::connectivity::MtuUpdated),
    #[serde(rename = "quic:version_information")]
    VersionInformation(quic::transport::VersionInformation),
    #[serde(rename = "quic:alpn_information")]
    ALPNInformation(quic::transport::ALPNInformation),
    #[serde(rename = "quic:parameters_set")]
    ParametersSet(quic::transport::ParametersSet),
    #[serde(rename = "quic:parameters_restored")]
    ParametersRestored(quic::transport::ParametersRestored),
    #[serde(rename = "quic:packet_sent")]
    PacketSent(quic::transport::PacketSent),
    #[serde(rename = "quic:packet_received")]
    PacketReceived(quic::transport::PacketReceived),
    #[serde(rename = "quic:packet_dropped")]
    PacketDropped(quic::transport::PacketDropped),
    #[serde(rename = "quic:packet_buffered")]
    PacketBuffered(quic::transport::PacketBuffered),
    #[serde(rename = "quic:packets_acked")]
    PacketsAcked(quic::transport::PacketsAcked),
    #[serde(rename = "quic:udp_datagrams_sent")]
    UdpDatagramSent(quic::transport::UdpDatagramSent),
    #[serde(rename = "quic:udp_datagrams_received")]
    UdpDatagramReceived(quic::transport::UdpDatagramReceived),
    #[serde(rename = "quic:udp_datagram_dropped")]
    UdpDatagramDropped(quic::transport::UdpDatagramDropped),
    #[serde(rename = "quic:stream_state_updated")]
    StreamStateUpdated(quic::transport::StreamStateUpdated),
    #[serde(rename = "quic:frames_processed")]
    FramesProcessed(quic::transport::FramesProcessed),
    #[serde(rename = "quic:stream_data_moved")]
    StreamDataMoved(quic::transport::StreamDataMoved),
    #[serde(rename = "quic:datagram_data_moved")]
    DatagramDataMoved(quic::transport::DatagramDataMoved),
    #[serde(rename = "quic:migration_state_updated")]
    MigrationStateUpdated(quic::transport::MigrationStateUpdated),
    #[serde(rename = "quic:key_updated")]
    KeyUpdated(quic::security::KeyUpdated),
    #[serde(rename = "quic:key_discarded")]
    KeyDiscarded(quic::security::KeyDiscarded),
    #[serde(rename = "quic:recovery_parameters_set")]
    RecoveryParametersSet(quic::recovery::RecoveryParametersSet),
    #[serde(rename = "quic:recovery_metrics_updated")]
    RecoveryMetricsUpdated(quic::recovery::RecoveryMetricsUpdated),
    #[serde(rename = "quic:congestion_state_updated")]
    CongestionStateUpdated(quic::recovery::CongestionStateUpdated),
    #[serde(rename = "quic:loss_timer_updated")]
    LossTimerUpdated(quic::recovery::LossTimerUpdated),
    #[serde(rename = "quic:packet_lost")]
    PacketLost(quic::recovery::PacketLost),
    #[serde(rename = "quic:marked_for_retransmit")]
    MarkedForRetransmit(quic::recovery::MarkedForRetransmit),
    #[serde(rename = "quic:ecn_state_updated")]
    ECNStateUpdated(quic::recovery::ECNStateUpdated),
    #[serde(rename = "loglevel:error")]
    Error(loglevel::Error),
    #[serde(rename = "loglevel:warning")]
    Warning(loglevel::Warning),
    #[serde(rename = "loglevel:info")]
    Info(loglevel::Info),
    #[serde(rename = "loglevel:debug")]
    Debug(loglevel::Debug),
    #[serde(rename = "loglevel:verbose")]
    Verbose(loglevel::Verbose),
}

#[enum_dispatch::enum_dispatch]
pub trait BeEventData {
    fn scheme(&self) -> &'static str;

    fn importance(&self) -> EventImportance;
}

macro_rules! be_events {
    ( $($importance:ident $event:ty => $prefix:ident $schme:literal ;)* ) => {
        $( be_events!{@impl_one $importance $event => $prefix $schme ; } )*
    };
    (@impl_one $importance:ident $event:ty => urn $schme:literal ; ) => {
        impl BeEventData for $event {
            fn scheme(&self) -> &'static str {
                const { concat!["urn:ietf:params:qlog:events:",$schme] }
            }

            fn importance(&self) -> EventImportance {
                const { EventImportance::$importance }
            }
        }
    };
}

be_events! {
    Extra quic::connectivity::ServerListening        => urn "quic:server_listening";
    Base  quic::connectivity::ConnectionStarted      => urn "quic:connection_started";
    Base  quic::connectivity::ConnectionClosed       => urn "quic:connection_closed";
    Base  quic::connectivity::ConnectionIDUpdated    => urn "quic:connection_id_updated";
    Base  quic::connectivity::SpinBitUpdated         => urn "quic:spin_bit_updated";
    Base  quic::connectivity::ConnectionStateUpdated => urn "quic:connection_state_updated";
    Base  quic::connectivity::PathAssigned           => urn "quic:path_assigned";
    Extra quic::connectivity::MtuUpdated             => urn "quic:mtu_updated";
    Core  quic::transport::VersionInformation        => urn "quic:version_information";
    Core  quic::transport::ALPNInformation           => urn "quic:alpn_information";
    Core  quic::transport::ParametersSet             => urn "quic:parameters_set";
    Base  quic::transport::ParametersRestored        => urn "quic:parameters_restored";
    Core  quic::transport::PacketSent                => urn "quic:packet_sent";
    Core  quic::transport::PacketReceived            => urn "quic:packet_received";
    Base  quic::transport::PacketDropped             => urn "quic:packet_dropped";
    Base  quic::transport::PacketBuffered            => urn "quic:packet_buffered";
    Extra quic::transport::PacketsAcked              => urn "quic:packets_acked";
    Extra quic::transport::UdpDatagramSent           => urn "quic:udp_datagrams_sent";
    Extra quic::transport::UdpDatagramReceived       => urn "quic:udp_datagrams_received";
    Extra quic::transport::UdpDatagramDropped        => urn "quic:udp_datagram_dropped";
    Base  quic::transport::StreamStateUpdated        => urn "quic:stream_state_updated";
    Extra quic::transport::FramesProcessed           => urn "quic:frames_processed";
    Base  quic::transport::StreamDataMoved           => urn "quic:stream_data_moved";
    Base  quic::transport::DatagramDataMoved         => urn "quic:datagram_data_moved";
    Extra quic::transport::MigrationStateUpdated     => urn "quic:migration_state_updated";
    Base  quic::security::KeyUpdated                 => urn "quic:key_updated";
    Base  quic::security::KeyDiscarded               => urn "quic:key_discarded";
    Base  quic::recovery::RecoveryParametersSet      => urn "quic:recovery_parameters_set";
    Core  quic::recovery::RecoveryMetricsUpdated     => urn "quic:recovery_metrics_updated";
    Base  quic::recovery::CongestionStateUpdated     => urn "quic:congestion_state_updated";
    Extra quic::recovery::LossTimerUpdated           => urn "quic:loss_timer_updated";
    Core  quic::recovery::PacketLost                 => urn "quic:packet_lost";
    Extra quic::recovery::MarkedForRetransmit        => urn "quic:marked_for_retransmit";
    Extra quic::recovery::ECNStateUpdated            => urn "quic:ecn_state_updated";
    Core  loglevel::Error                            => urn "loglevel:error";
    Base  loglevel::Warning                          => urn "loglevel:warning";
    Extra loglevel::Info                             => urn "loglevel:info";
    Extra loglevel::Debug                            => urn "loglevel:debug";
    Extra loglevel::Verbose                          => urn "loglevel:verbose";
}

/// serialize/deserialize as hex string, but store as bytes in memory
#[serde_with::serde_as]
#[derive(Debug, Clone, From, Into, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct HexString(#[serde_as(as = "serde_with::hex::Hex")] Bytes);

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RawInfo {
    /// the full byte length of the entity (e.g., packet or frame),
    /// including possible headers and trailers
    pub length: Option<u64>,
    /// the byte length of the entity's payload,
    /// excluding possible headers or trailers
    pub payload_length: Option<u64>,
    /// the (potentially truncated) contents of the full entity,
    /// including headers and possibly trailers
    pub data: Option<HexString>,
}

#[cfg(test)]
mod tests {
    use qbase::cid::ConnectionId;

    use super::*;

    #[test]
    fn custom_fields() {
        let odcid = ConnectionID::from(ConnectionId::from_slice(&[
            0x61, 0xb6, 0x91, 0x78, 0x80, 0xf7, 0x95, 0xee,
        ]));
        let common_fields = CommonFields {
            path: String::from("").into(),
            time_format: TimeFormat::default(),
            reference_time: ReferenceTime::default(),
            protocol_types: ProtocolTypeList::from(vec![ProtocolType::quic()]),
            group_id: GroupID::from(odcid),
            custom_fileds: Default::default(),
        };
        let expect = r#"{
  "path": "",
  "time_format": "relative_to_epoch",
  "reference_time": {
    "clock_type": "system",
    "epoch": "1970-01-01T00:00:00.000Z"
  },
  "protocol_types": [
    "QUIC"
  ],
  "group_id": "61b6917880f795ee"
}"#;
        assert_eq!(
            serde_json::to_string_pretty(&common_fields).unwrap(),
            expect
        );
        let with_custom_fields = r#"{
  "path": "",
  "time_format": "relative_to_epoch",
  "reference_time": {
    "clock_type": "system",
    "epoch": "1970-01-01T00:00:00.000Z"
  },
  "protocol_types": [
    "QUIC"
  ],
  "group_id": "61b6917880f795ee",
  "pathway": "from A to relay",
  "customB": "some other extensions"
}"#;
        let des = serde_json::from_str::<CommonFields>(with_custom_fields).unwrap();
        dbg!(&des);
        let filed_string = serde_json::to_string_pretty(&des).unwrap();
        dbg!(&filed_string);
        let des2 = serde_json::from_str::<CommonFields>(&filed_string).unwrap();
        assert_eq!(des, des2,);
    }

    #[test]
    fn evnet_data() {
        let event_data: EvnetData = loglevel::Warning {
            code: Some(255),
            message: Some(String::from(
                "deepseek（已深度思考（用时0秒））：服务器繁忙，请稍后再试。",
            )),
        }
        .into();
        let event = Event {
            time: 1.0,
            data: event_data.clone(),
            path: None,
            time_format: None,
            protocol_types: None,
            group_id: None,
            system_info: None,
            custom_fileds: HashMap::new(),
        };
        let expect = r#"{
  "time": 1.0,
  "name": "loglevel:warning",
  "data": {
    "code": 255,
    "message": "deepseek（已深度思考（用时0秒））：服务器繁忙，请稍后再试。"
  }
}"#;
        assert_eq!(serde_json::to_string_pretty(&event).unwrap(), expect);
        assert_eq!(event_data.importance(), EventImportance::Base);
    }
}
