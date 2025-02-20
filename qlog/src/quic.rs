use std::{collections::HashMap, fmt::Display, net::SocketAddr, time::Duration};

use bytes::Bytes;
use derive_builder::Builder;
use derive_more::{From, Into, LowerHex};
use qbase::frame::{
    AckFrame, AppCloseFrame, BeFrame, ConnectionCloseFrame, CryptoFrame, DatagramFrame, Frame,
    MaxStreamsFrame, NewTokenFrame, PathChallengeFrame, PathResponseFrame, ReliableFrame,
    StreamCtlFrame, StreamFrame, StreamsBlockedFrame,
};
use serde::{Deserialize, Serialize};

pub mod connectivity;
pub mod recovery;
pub mod security;
pub mod transport;

use crate::{HexString, RawInfo};

// 8.1
#[derive(Debug, Clone, From, Into, PartialEq, Eq)]
pub struct QuicVersion(u32);

impl Serialize for QuicVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[serde_with::serde_as]
        #[derive(Serialize)]
        struct Helper(#[serde_as(as = "serde_with::hex::Hex")] [u8; 4]);
        Helper(self.0.to_be_bytes()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for QuicVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[serde_with::serde_as]
        #[derive(Deserialize)]
        struct Helper(#[serde_as(as = "serde_with::hex::Hex")] [u8; 4]);
        Helper::deserialize(deserializer).map(|b| Self(u32::from_be_bytes(b.0)))
    }
}

// 8.2
// TOOD: 这些结构的序列化/反序列化之后都可以写到qbase中，也不重复写两份结构
#[derive(Default, Debug, LowerHex, From, Into, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionID(qbase::cid::ConnectionId);

impl Serialize for ConnectionID {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[serde_with::serde_as]
        #[derive(Serialize)]
        struct Helper<'b>(#[serde_as(as = "serde_with::hex::Hex")] &'b [u8]);

        Helper(self.0.as_ref()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ConnectionID {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[serde_with::serde_as]
        #[derive(Deserialize)]
        struct Helper(#[serde_as(as = "serde_with::hex::Hex")] Vec<u8>);

        let bytes = Helper::deserialize(deserializer)?.0;
        if bytes.len() > qbase::cid::MAX_CID_SIZE {
            return Err(serde::de::Error::custom("ConnectionID too long"));
        }
        Ok(Self(qbase::cid::ConnectionId::from_slice(&bytes)))
    }
}

// 8.3
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Owner {
    Local,
    Remote,
}

// 8.4
/// an IPAddress can either be a "human readable" form
/// (e.g., "127.0.0.1" for v4 or
/// "2001:0db8:85a3:0000:0000:8a2e:0370:7334" for v6) or
/// use a raw byte-form (as the string forms can be ambiguous).
/// Additionally, a hash-based or redacted representation
/// can be used if needed for privacy or security reasons.
#[derive(Debug, Clone, From, Into, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct IPAddress(String);

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde_with::skip_serializing_none]
#[serde(rename_all = "snake_case")]
pub enum IpVersion {
    V4,
    V6,
}

// 8.5
/// PathEndpointInfo indicates a single half/direction of a path.  A full
/// path is comprised of two halves.  Firstly: the server sends to the
/// remote client IP + port using a specific destination Connection ID.
/// Secondly: the client sends to the remote server IP + port using a
/// different destination Connection ID.
///
/// As such, structures logging path information SHOULD include two
/// different PathEndpointInfo instances, one for each half of the path.
#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(
    default,
    setter(into, strip_option),
    build_fn(private, name = "fallible_build")
)]
pub struct PathEndpointInfo {
    ip_v4: Option<IPAddress>,
    ip_v6: Option<IPAddress>,
    port_v4: Option<u16>,
    port_v6: Option<u16>,

    /// Even though usually only a single ConnectionID
    /// is associated with a given path at a time,
    /// there are situations where there can be an overlap
    /// or a need to keep track of previous ConnectionIDs
    conenction_ids: Vec<ConnectionID>,
}

impl From<SocketAddr> for PathEndpointInfo {
    fn from(value: SocketAddr) -> Self {
        match value {
            SocketAddr::V4(addr) => crate::build!(PathEndpointInfo {
                ip_v4: addr.ip().to_string(),
                port_v4: addr.port(),
            }),
            SocketAddr::V6(addr) => crate::build!(PathEndpointInfo {
                ip_v6: addr.ip().to_string(),
                port_v6: addr.port(),
            }),
        }
    }
}

// 8.6
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PacketType {
    Initial,
    Handshake,
    #[serde(rename = "0RTT")]
    ZeroRTT,
    #[serde(rename = "1RTT")]
    OneRTT,
    Retry,
    VersionNegotiation,
    StatelessReset,
    Unknown,
}

impl From<qbase::packet::Type> for PacketType {
    fn from(r#type: qbase::packet::Type) -> Self {
        match r#type {
            qbase::packet::r#type::Type::Long(long) => match long {
                qbase::packet::r#type::long::Type::VersionNegotiation => {
                    PacketType::VersionNegotiation
                }
                qbase::packet::r#type::long::Type::V1(
                    qbase::packet::r#type::long::Version::INITIAL,
                ) => PacketType::Initial,
                qbase::packet::r#type::long::Type::V1(
                    qbase::packet::r#type::long::Version::HANDSHAKE,
                ) => PacketType::Handshake,
                qbase::packet::r#type::long::Type::V1(
                    qbase::packet::r#type::long::Version::ZERO_RTT,
                ) => PacketType::ZeroRTT,
                qbase::packet::r#type::long::Type::V1(
                    qbase::packet::r#type::long::Version::RETRY,
                ) => PacketType::Retry,
            },
            qbase::packet::r#type::Type::Short(_one_rtt) => PacketType::OneRTT,
        }
    }
}

// 8.7
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PacketNumberSpace {
    Initial,
    Handshake,
    ApplicationData,
}

// 8.8
#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct PacketHeader {
    #[builder(default)]
    #[serde(default)]
    quic_bit: bool,
    packet_type: PacketType,

    /// only if packet_type === "initial" || "handshake" || "0RTT" || "1RTT"
    #[builder(default)]
    packet_number: Option<u64>,

    ///  the bit flags of the packet headers (spin bit, key update bit,
    /// etc. up to and including the packet number length bits
    /// if present
    #[builder(default)]
    flags: Option<u8>,

    /// only if packet_type === "initial" || "retry"
    #[builder(default)]
    token: Option<Token>,

    /// only if packet_type === "initial" || "handshake" || "0RTT"
    /// Signifies length of the packet_number plus the payload
    #[builder(default)]
    length: Option<u16>,

    /// only if present in the header
    /// if correctly using transport:connection_id_updated events,
    /// dcid can be skipped for 1RTT packets
    #[builder(default)]
    version: Option<QuicVersion>,
    #[builder(default)]
    scil: Option<u8>,
    #[builder(default)]
    dcil: Option<u8>,
    #[builder(default)]
    scid: Option<ConnectionID>,
    #[builder(default)]
    dcid: Option<ConnectionID>,
}

// 8.9
#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(
    default,
    setter(into, strip_option),
    build_fn(private, name = "fallible_build")
)]
#[serde(default)]
pub struct Token {
    pub r#type: Option<TokenType>,

    /// decoded fields included in the token
    /// (typically: peer's IP address, creation time)
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    details: HashMap<String, serde_json::Value>,

    raw: Option<RawInfo>,
}

impl<H: 'static> TryFrom<&qbase::packet::header::LongHeader<H>> for Token {
    type Error = ();
    fn try_from(header: &qbase::packet::header::LongHeader<H>) -> Result<Self, Self::Error> {
        use qbase::packet::header::{InitialHeader, RetryHeader};
        let header: &dyn core::any::Any = header;
        if let Some(initial) = header.downcast_ref::<InitialHeader>() {
            return Ok(crate::build!(Token {
                r#type: TokenType::Retry,
                raw: RawInfo {
                    length: initial.token().len() as u64,
                    data: { Bytes::from_owner(initial.token().to_vec()) },
                },
            }));
        }
        if let Some(retry) = header.downcast_ref::<RetryHeader>() {
            return Ok(crate::build!(Token {
                r#type: TokenType::Retry,
                raw: RawInfo {
                    length: retry.token().len() as u64,
                    data: { Bytes::from_owner(retry.token().to_vec()) },
                },
            }));
        }
        Err(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    Retry,
    Resumption,
}

// 8.10
#[serde_with::serde_as]
#[derive(Debug, Clone, Copy, From, Into, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatelessResetToken(#[serde_as(as = "serde_with::hex::Hex")] [u8; 16]);

impl From<qbase::token::ResetToken> for StatelessResetToken {
    fn from(value: qbase::token::ResetToken) -> Self {
        Self(*value)
    }
}

// 8.11
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    ServerInitialSecret,
    ClientInitialSecret,
    ServerHandshakeSecret,
    ClientHandshakeSecret,
    #[serde(rename = "server_0rtt_secret")]
    Server0RttSecret,
    #[serde(rename = "client_0rtt_secret")]
    Client0RttSecret,
    #[serde(rename = "server_1rtt_secret")]
    Server1RttSecret,
    #[serde(rename = "client_1rtt_secret")]
    Client1RttSecret,
}

// 8.12
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ECN {
    #[serde(rename = "Not-ECT")]
    NotEct,
    #[serde(rename = "ECT(1)")]
    Ect1,
    #[serde(rename = "ECT(0)")]
    Ect0,
    CE,
}

// 8.13
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "frame_type")]
#[serde(rename_all = "snake_case")]
pub enum QuicFrame {
    Padding {
        /// total frame length, including frame header
        length: Option<u32>,
        payload_length: u32,
    },
    Ping {
        /// total frame length, including frame header
        length: Option<u32>,
        payload_length: Option<u32>,
    },
    Ack {
        /// in ms
        ack_delay: Option<f32>,

        /// e.g., looks like \[\[1,2],\[4,5], \[7], \[10,22]] serialized
        ///
        /// ### AckRange:
        /// either a single number (e.g., \[1]) or two numbers (e.g., \[1,2]).
        ///
        /// For two numbers:
        ///
        /// the first number is "from": lowest packet number in interval
        ///
        /// the second number is "to": up to and including the highest
        /// packet number in the interval
        acked_ranges: Vec<[u64; 2]>,

        /// ECN (explicit congestion notification) related fields
        /// (not always present)
        ect1: Option<u64>,
        ect0: Option<u64>,
        ce: Option<u64>,

        /// total frame length, including frame header
        length: Option<u32>,
        payload_length: Option<u32>,
    },
    ResetStream {
        stream_id: u64,
        error_code: ApplicationCode,

        /// in bytes
        final_size: Option<u64>,

        /// total frame length, including frame header
        length: Option<u32>,
        payload_length: Option<u32>,
    },
    StopSending {
        stream_id: u64,
        error_code: ApplicationCode,

        /// total frame length, including frame header
        length: Option<u32>,
        payload_length: Option<u32>,
    },
    Crypto {
        offset: u64,
        length: u64,
        payload_length: Option<u32>,
        raw: Option<RawInfo>,
    },
    NewToken {
        token: Token,
    },
    Stream {
        stream_id: u64,

        /// These two MUST always be set
        /// If not present in the Frame type, log their default values
        offset: u64,
        length: u64,

        /// this MAY be set any time,
        /// but MUST only be set if the value is true
        /// if absent, the value MUST be assumed to be false
        #[serde(default)]
        fin: bool,
        raw: Option<RawInfo>,
    },
    MaxData {
        maximum: u64,
    },
    MaxStreamData {
        stream_id: u64,
        maximum: u64,
    },
    MaxStream {
        stream_type: StreamType,
        maximum: u64,
    },
    DataBlocked {
        maximum: u64,
    },
    StreamDataBlocked {
        stream_id: u64,
        maximum: u64,
    },
    StreamBlocked {
        stream_type: StreamType,
        limit: u64,
    },
    NewConnectionId {
        sequence_number: u32,
        retire_prior_to: u32,

        /// mainly used if e.g., for privacy reasons the full
        /// connection_id cannot be logged
        connection_id_length: u8,
        connection_id: ConnectionID,
        stateless_reset_token: StatelessResetToken,
    },
    RetireConnectionId {
        sequence_number: u32,
    },
    PathChanllenge {
        /// always 64-bit
        data: HexString,
    },
    PathResponse {
        /// always 64-bit
        data: Option<HexString>,
    },
    /// An endpoint that receives unknown error codes can record it in the
    /// error_code field using the numerical value without variable-length
    /// integer encoding.
    ///
    /// When the connection is closed due a connection-level error, the
    /// trigger_frame_type field can be used to log the frame that triggered
    /// the error.  For known frame types, the appropriate string value is
    /// used.  For unknown frame types, the numerical value without variable-
    /// length integer encoding is used.
    ///
    /// The CONNECTION_CLOSE reason phrase is a byte sequences.  It is likely
    /// that this sequence is presentable as UTF-8, in which case it can be
    /// logged in the reason field.  The reason_bytes field supports logging
    /// the raw bytes, which can be useful when the value is not UTF-8 or
    /// when an endpoint does not want to decode it.  Implementations SHOULD
    /// log at least one format, but MAY log both or none.
    ConnectionClose {
        error_space: ConenctionCloseErrorSpace,
        error_code: ConnectionCloseErrorCode,

        reason: Option<String>,
        reason_bytes: Option<HexString>,

        /// when error_space === "transport"
        trigger_frame_type: Option<ConnectionCloseTriggerFrameType>,
    },
    HandshakeDone {},
    /// The frame_type_bytes field is the numerical value without variable-
    /// length integer encoding.
    Unknow {
        frame_type_bytes: u64,
        raw: Option<RawInfo>,
    },
    DatagramFrame {
        length: Option<u64>,
        raw: Option<RawInfo>,
    },
}

impl From<(&CryptoFrame, &Bytes)> for QuicFrame {
    fn from((frame, bytes): (&CryptoFrame, &Bytes)) -> Self {
        let length = frame.encoding_size() + bytes.len();
        let payload_length = bytes.len();
        QuicFrame::Crypto {
            offset: frame.offset(),
            length: length as _,
            payload_length: Some(payload_length as _),
            raw: Some(RawInfo {
                length: Some(length as _),
                payload_length: Some(payload_length as _),
                data: Some(bytes.clone().into()),
            }),
        }
    }
}

impl From<(&StreamFrame, &Bytes)> for QuicFrame {
    fn from((frame, bytes): (&StreamFrame, &Bytes)) -> Self {
        let length = frame.encoding_size() + bytes.len();
        let payload_length = bytes.len();
        QuicFrame::Stream {
            stream_id: frame.stream_id().id(),
            offset: frame.offset(),
            length: length as _,
            fin: frame.is_fin(),
            raw: Some(RawInfo {
                length: Some(length as _),
                payload_length: Some(payload_length as _),
                data: Some(bytes.clone().into()),
            }),
        }
    }
}

impl From<(&DatagramFrame, &Bytes)> for QuicFrame {
    fn from((frame, bytes): (&DatagramFrame, &Bytes)) -> Self {
        let length = frame.encoding_size() + bytes.len();
        let payload_length = bytes.len();
        QuicFrame::DatagramFrame {
            length: Some(length as _),
            raw: Some(RawInfo {
                length: Some(length as _),
                payload_length: Some(payload_length as _),
                data: Some(bytes.clone().into()),
            }),
        }
    }
}

impl From<&PathChallengeFrame> for QuicFrame {
    fn from(frame: &PathChallengeFrame) -> Self {
        QuicFrame::PathChanllenge {
            data: Bytes::from_owner(frame.to_vec()).into(),
        }
    }
}

impl From<&PathResponseFrame> for QuicFrame {
    fn from(frame: &PathResponseFrame) -> Self {
        QuicFrame::PathResponse {
            data: Some(Bytes::from_owner(frame.to_vec()).into()),
        }
    }
}

impl From<&AckFrame> for QuicFrame {
    fn from(frame: &AckFrame) -> Self {
        Self::Ack {
            ack_delay: Some(Duration::from_micros(frame.delay()).as_secs_f32() * 1000.0),
            acked_ranges: frame
                .ranges()
                .iter()
                .fold(
                    (
                        frame.largest() - frame.first_range(),
                        vec![[frame.largest() - frame.first_range(), frame.largest()]],
                    ),
                    |(previous_smallest, mut acked_ranges), (gap, ack)| {
                        // see https://www.rfc-editor.org/rfc/rfc9000.html#name-ack-ranges
                        let largest = previous_smallest - gap.into_inner() - 2;
                        let smallest = largest - ack.into_inner();
                        acked_ranges.push([smallest, largest]);
                        (smallest, acked_ranges)
                    },
                )
                .1,
            ect1: frame.ecn().map(|ecn| ecn.ect1()),
            ect0: frame.ecn().map(|ecn| ecn.ect0()),
            ce: frame.ecn().map(|ecn| ecn.ce()),
            length: Some(frame.encoding_size() as u32),
            payload_length: None,
        }
    }
}

impl From<&ReliableFrame> for QuicFrame {
    fn from(frame: &ReliableFrame) -> Self {
        match frame {
            ReliableFrame::NewToken(new_token_frame) => new_token_frame.into(),
            ReliableFrame::MaxData(max_data_frame) => QuicFrame::MaxData {
                maximum: max_data_frame.max_data(),
            },
            ReliableFrame::DataBlocked(data_blocked_frame) => QuicFrame::DataBlocked {
                maximum: data_blocked_frame.limit(),
            },
            ReliableFrame::NewConnectionId(new_connection_id_frame) => QuicFrame::NewConnectionId {
                sequence_number: new_connection_id_frame.sequence() as u32,
                retire_prior_to: new_connection_id_frame.retire_prior_to() as u32,
                connection_id_length: new_connection_id_frame.connection_id().len() as _,
                connection_id: (*new_connection_id_frame.connection_id()).into(),
                stateless_reset_token: (**new_connection_id_frame.reset_token()).into(),
            },
            ReliableFrame::RetireConnectionId(retire_connection_id_frame) => {
                QuicFrame::RetireConnectionId {
                    sequence_number: retire_connection_id_frame.sequence() as u32,
                }
            }
            ReliableFrame::HandshakeDone(_handshake_done_frame) => QuicFrame::HandshakeDone {},
            ReliableFrame::Stream(stream_ctl_frame) => QuicFrame::from(stream_ctl_frame),
        }
    }
}

impl From<&NewTokenFrame> for QuicFrame {
    fn from(value: &NewTokenFrame) -> Self {
        QuicFrame::NewToken {
            token: crate::build!(Token {
                r#type: TokenType::Retry,
                raw: RawInfo {
                    length: value.encoding_size() as u64,
                    payload_length: value.token().len() as u64,
                    data: { Bytes::from_owner(value.token().to_vec()) },
                },
            }),
        }
    }
}

impl From<&StreamCtlFrame> for QuicFrame {
    fn from(frame: &StreamCtlFrame) -> Self {
        match frame {
            StreamCtlFrame::ResetStream(reset_stream_frame) => QuicFrame::ResetStream {
                stream_id: reset_stream_frame.stream_id().id(),
                error_code: (reset_stream_frame.app_error_code() as u32).into(),
                final_size: reset_stream_frame.final_size().into(),
                length: None,
                payload_length: None,
            },
            StreamCtlFrame::StopSending(stop_sending_frame) => QuicFrame::StopSending {
                stream_id: stop_sending_frame.stream_id().id(),
                error_code: (stop_sending_frame.app_err_code() as u32).into(),
                length: None,
                payload_length: None,
            },
            StreamCtlFrame::MaxStreamData(max_stream_data_frame) => QuicFrame::MaxStreamData {
                stream_id: max_stream_data_frame.stream_id().id(),
                maximum: max_stream_data_frame.max_stream_data(),
            },
            StreamCtlFrame::MaxStreams(max_streams_frame) => match max_streams_frame {
                MaxStreamsFrame::Bi(maximum) => QuicFrame::MaxStream {
                    stream_type: StreamType::Bidirectional,
                    maximum: maximum.into_inner(),
                },
                MaxStreamsFrame::Uni(maximum) => QuicFrame::MaxStream {
                    stream_type: StreamType::Unidirectional,
                    maximum: maximum.into_inner(),
                },
            },
            StreamCtlFrame::StreamDataBlocked(stream_data_blocked_frame) => {
                QuicFrame::StreamDataBlocked {
                    stream_id: stream_data_blocked_frame.stream_id().id(),
                    maximum: stream_data_blocked_frame.maximum_stream_data(),
                }
            }
            StreamCtlFrame::StreamsBlocked(streams_blocked_frame) => match streams_blocked_frame {
                StreamsBlockedFrame::Bi(limit) => QuicFrame::StreamBlocked {
                    stream_type: StreamType::Bidirectional,
                    limit: limit.into_inner(),
                },
                StreamsBlockedFrame::Uni(limit) => QuicFrame::StreamBlocked {
                    stream_type: StreamType::Unidirectional,
                    limit: limit.into_inner(),
                },
            },
        }
    }
}

impl From<&ConnectionCloseFrame> for QuicFrame {
    fn from(frame: &ConnectionCloseFrame) -> Self {
        Self::ConnectionClose {
            error_space: match &frame {
                ConnectionCloseFrame::App(..) => ConenctionCloseErrorSpace::Application,
                ConnectionCloseFrame::Quic(..) => ConenctionCloseErrorSpace::Transport,
            },
            error_code: match &frame {
                ConnectionCloseFrame::App(frame) => ApplicationCode::from(frame).into(),
                ConnectionCloseFrame::Quic(frame) => {
                    connectivity::ConnectionCode::from(frame).into()
                }
            },
            reason: match &frame {
                ConnectionCloseFrame::App(frame) => Some(frame.reason().to_owned()),
                ConnectionCloseFrame::Quic(frame) => Some(frame.reason().to_owned()),
            },
            // TODO: 不应该强制要求reason是utf8的
            reason_bytes: None,
            trigger_frame_type: match &frame {
                ConnectionCloseFrame::Quic(frame) => {
                    Some((u8::from(frame.frame_type()) as u64).into())
                }
                ConnectionCloseFrame::App(..) => None,
            },
        }
    }
}

impl From<&Frame> for QuicFrame {
    fn from(frame: &Frame) -> Self {
        match frame {
            Frame::Padding(..) => QuicFrame::Padding {
                length: Some(1),
                payload_length: 1,
            },
            Frame::Ping(..) => QuicFrame::Ping {
                length: Some(1),
                payload_length: Some(1),
            },
            Frame::Ack(frame) => frame.into(),
            Frame::Close(frame) => frame.into(),
            Frame::NewToken(frame) => frame.into(),
            Frame::MaxData(frame) => (&ReliableFrame::from(*frame)).into(),
            Frame::DataBlocked(frame) => (&ReliableFrame::from(*frame)).into(),
            Frame::NewConnectionId(frame) => (&ReliableFrame::from(*frame)).into(),
            Frame::RetireConnectionId(frame) => (&ReliableFrame::from(*frame)).into(),
            Frame::HandshakeDone(frame) => (&ReliableFrame::from(*frame)).into(),
            Frame::Challenge(frame) => frame.into(),
            Frame::Response(frame) => frame.into(),
            Frame::StreamCtl(frame) => frame.into(),
            Frame::Stream(frame, bytes) => (frame, bytes).into(),
            Frame::Crypto(frame, bytes) => (frame, bytes).into(),
            Frame::Datagram(frame, bytes) => (frame, bytes).into(),
        }
    }
}

#[derive(Debug, Clone, Copy, From, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ApplicationCode {
    ApplicationError(ApplicationError),
    Value(u32),
}

impl From<ApplicationCode> for ConnectionCloseErrorCode {
    fn from(value: ApplicationCode) -> Self {
        match value {
            ApplicationCode::ApplicationError(error) => {
                ConnectionCloseErrorCode::ApplicationError(error)
            }
            ApplicationCode::Value(value) => ConnectionCloseErrorCode::Value(value as _),
        }
    }
}

impl From<&AppCloseFrame> for ApplicationCode {
    fn from(frame: &AppCloseFrame) -> Self {
        ApplicationCode::Value(frame.error_code() as _)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StreamType {
    Unidirectional,
    Bidirectional,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConenctionCloseErrorSpace {
    Transport,
    Application,
}

#[derive(Debug, Clone, Copy, From, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ConnectionCloseErrorCode {
    TransportError(TransportError),
    CryptoError(CryptoError),
    ApplicationError(ApplicationError),
    Value(u64),
}

#[derive(Debug, Clone, Serialize, From, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ConnectionCloseTriggerFrameType {
    Id(u64),
    Text(String),
}

// 8.13.23
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransportError {
    NoError,
    InternalError,
    ConnectionRefused,
    FlowControlError,
    StreamLimitError,
    StreamStateError,
    FinalSizeError,
    FrameEncodingError,
    TransportParameterError,
    ConnectionIDLimitError,
    ProtocolViolation,
    InvalidToken,
    ApplicationError,
    CryptoBufferExceeded,
    KeyUpdateError,
    AeadLimitReached,
    NoViablePath,
}

// 8.13.24
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationError {
    Unknow,
}

// 8.13.25
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoError(u8);

impl Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "crypto_error_0x1{:02x}", self.0)
    }
}

impl Serialize for CryptoError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for CryptoError {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        string.strip_prefix("crypto_error_0x1").map_or_else(
            || Err(serde::de::Error::custom("invalid crypto error")),
            |s| {
                u8::from_str_radix(s, 16)
                    .map(CryptoError)
                    .map_err(serde::de::Error::custom)
            },
        )
    }
}

crate::gen_builder_method! {
    PathEndpointInfoBuilder => PathEndpointInfo;
    PacketHeaderBuilder     => PacketHeader;
    TokenBuilder            => Token;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ack() {
        // 123 56 9
        let frame = AckFrame::new(
            9u32.into(),
            1000u32.into(),
            0u32.into(),
            vec![(1u32.into(), 1u32.into()), (0u32.into(), 2u32.into())],
            None,
        );

        let encoding_size = frame.encoding_size();

        let quic_frame: QuicFrame = (&frame).into();
        assert_eq!(
            quic_frame,
            QuicFrame::Ack {
                ack_delay: Some(1.0),
                acked_ranges: vec![[9, 9], [5, 6], [1, 3]],
                ect1: None,
                ect0: None,
                ce: None,
                length: Some(encoding_size as u32),
                payload_length: None,
            }
        );
    }
}
