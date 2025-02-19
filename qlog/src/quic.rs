use std::{collections::HashMap, fmt::Display, net::SocketAddr};

use bytes::Bytes;
use derive_builder::Builder;
use derive_more::{From, Into, LowerHex};
use qbase::frame::{
    AppCloseFrame, BeFrame, CryptoFrame, DatagramFrame, MaxStreamsFrame, PathChallengeFrame,
    PathResponseFrame, ReliableFrame, StreamCtlFrame, StreamFrame, StreamsBlockedFrame,
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
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "frame_type")]
#[serde(rename_all = "snake_case")]
#[serde_with::skip_serializing_none]
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
        acked_ranges: Vec<[usize; 2]>,

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
    ConnectionClose {
        error_space: ConenctionCloseErrorSpace,
        error_code: ConnectionCloseErrorCode,

        reason: Option<String>,
        reason_type: Option<HexString>,

        /// when error_space === "transport"
        trigger_frame_type: Option<ConnectionCloseTriggerFrameType>,
    },
    HandshakeDone {},
    Unknow {
        frame_type_bytes: u64,
        raw: Option<RawInfo>,
    },
    DatagramFrame {
        length: Option<u64>,
        raw: Option<RawInfo>,
    },
}

impl From<(CryptoFrame, Bytes)> for QuicFrame {
    fn from((frame, bytes): (CryptoFrame, Bytes)) -> Self {
        let length = frame.encoding_size() + bytes.len();
        let payload_length = bytes.len();
        QuicFrame::Crypto {
            offset: frame.offset(),
            length: length as _,
            payload_length: Some(payload_length as _),
            raw: Some(RawInfo {
                length: Some(length as _),
                payload_length: Some(payload_length as _),
                data: Some(bytes.into()),
            }),
        }
    }
}

impl From<(StreamFrame, Bytes)> for QuicFrame {
    fn from((frame, bytes): (StreamFrame, Bytes)) -> Self {
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
                data: Some(bytes.into()),
            }),
        }
    }
}

impl From<(DatagramFrame, Bytes)> for QuicFrame {
    fn from((frame, bytes): (DatagramFrame, Bytes)) -> Self {
        let length = frame.encoding_size() + bytes.len();
        let payload_length = bytes.len();
        QuicFrame::DatagramFrame {
            length: Some(length as _),
            raw: Some(RawInfo {
                length: Some(length as _),
                payload_length: Some(payload_length as _),
                data: Some(bytes.into()),
            }),
        }
    }
}

impl From<PathChallengeFrame> for QuicFrame {
    fn from(frame: PathChallengeFrame) -> Self {
        QuicFrame::PathChanllenge {
            data: Bytes::from_owner(frame.to_vec()).into(),
        }
    }
}

impl From<PathResponseFrame> for QuicFrame {
    fn from(frame: PathResponseFrame) -> Self {
        QuicFrame::PathResponse {
            data: Some(Bytes::from_owner(frame.to_vec()).into()),
        }
    }
}

impl From<ReliableFrame> for QuicFrame {
    fn from(frame: ReliableFrame) -> Self {
        match frame {
            ReliableFrame::NewToken(new_token_frame) => QuicFrame::NewToken {
                token: crate::build!(Token {
                    r#type: TokenType::Retry,
                    raw: RawInfo {
                        length: new_token_frame.encoding_size() as u64,
                        payload_length: new_token_frame.len() as u64,
                        data: { Bytes::from_owner(new_token_frame.to_vec()) },
                    },
                }),
            },
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

impl From<StreamCtlFrame> for QuicFrame {
    fn from(frame: StreamCtlFrame) -> Self {
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

#[derive(Debug, Clone, Copy, From, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ApplicationCode {
    ApplicationError(ApplicationError),
    Value(u32),
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ConnectionCloseErrorCode {
    TransportError(TransportError),
    CryptoError(CryptoError),
    ApplicationError(ApplicationError),
    Value(u64),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
