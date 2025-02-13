use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::{
    ConnectionID, IPAddress, Owner, PacketHeader, PacketNumberSpace, PathEndpointInfo, QuicFrame,
    QuicVersion, StatelessResetToken, StreamType, ECN,
};
use crate::{HexString, PathID, RawInfo};

/// The version_information event supports QUIC version negotiation; see
/// Section 6 of [QUIC-TRANSPORT].  It has Core importance level; see
/// Section 9.2 of [QLOG-MAIN].
///
/// QUIC endpoints each have their own list of QUIC versions they
/// support.  The client uses the most likely version in their first
/// initial.  If the server does not support that version, it replies
/// with a Version Negotiation packet, which contains its supported
/// versions.  From this, the client selects a version.  The
/// version_information event aggregates all this information in a single
/// event type.  It also allows logging of supported versions at an
/// endpoint without actual version negotiation needing to happen.
///
/// [QUIC-TRANSPORT]: https://www.rfc-editor.org/rfc/rfc9000
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde_with::skip_serializing_none]
pub struct VersionInformation {
    // Vec for `? filed: [ +ty]``, Option<Vec> for `* filed: [* ty]`
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub server_versions: Vec<QuicVersion>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub client_versions: Vec<QuicVersion>,
    pub chosed_version: Option<QuicVersion>,
}

/// The alpn_information event supports Application-Layer Protocol
/// Negotiation (ALPN) over the QUIC transport; see [RFC7301] and
/// Section 7.4 of [QUIC-TRANSPORT].  It has Core importance level; see
/// Section 9.2 of [QLOG-MAIN].
///
/// QUIC endpoints are configured with a list of supported ALPN
/// identifiers.  Clients send the list in a TLS ClientHello, and servers
/// match against their list.  On success, a single ALPN identifier is
/// chosen and sent back in a TLS ServerHello.  If no match is found, the
/// connection is closed.
///
/// ALPN identifiers are byte sequences, that may be possible to present
/// as UTF-8.  The ALPNIdentifier` type supports either format.
/// Implementations SHOULD log at least one format, but MAY log both or
/// none.
///
/// [QUIC-TRANSPORT]: https://www.rfc-editor.org/rfc/rfc9000
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde_with::skip_serializing_none]
pub struct ALPNInformation {
    pub server_alpns: Option<Vec<ALPNIdentifier>>,
    pub client_alpns: Option<Vec<ALPNIdentifier>>,
    pub chosed_alpn: Option<ALPNIdentifier>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde_with::skip_serializing_none]
pub struct ALPNIdentifier {
    pub byte_value: Option<HexString>,
    pub string_value: Option<String>,
}

/// The parameters_set event groups settings from several different
/// sources (transport parameters, TLS ciphers, etc.) into a single
/// event.  This is done to minimize the amount of events and to decouple
/// conceptual setting impacts from their underlying mechanism for easier
/// high-level reasoning.  The event has Core importance level; see
/// Section 9.2 of [QLOG-MAIN].
///
/// Most of these settings are typically set once and never change.
/// However, they are usually set at different times during the
/// connection, so there will regularly be several instances of this
/// event with different fields set.
///
/// Note that some settings have two variations (one set locally, one
/// requested by the remote peer).  This is reflected in the owner field.
/// As such, this field MUST be correct for all settings included a
/// single event instance.  If you need to log settings from two sides,
/// you MUST emit two separate event instances.
///
/// Implementations are not required to recognize, process or support
/// every setting/parameter received in all situations.  For example,
/// QUIC implementations MUST discard transport parameters that they do
/// not understand Section 7.4.2 of [QUIC-TRANSPORT].  The
/// unknown_parameters field can be used to log the raw values of any
/// unknown parameters (e.g., GREASE, private extensions, peer-side
/// experimentation).
///
/// In the case of connection resumption and 0-RTT, some of the server's
/// parameters are stored up-front at the client and used for the initial
/// connection startup.  They are later updated with the server's reply.
/// In these cases, utilize the separate parameters_restored event to
/// indicate the initial values, and this event to indicate the updated
/// values, as normal.
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
/// [QUIC-TRANSPORT]: https://www.rfc-editor.org/rfc/rfc9000

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde_with::skip_serializing_none]
pub struct ParametersSet {
    pub owner: Option<Owner>,

    /// true if valid session ticket was received
    pub resumption_allowed: Option<bool>,

    /// true if early data extension was enabled on the TLS layer
    pub early_data_received: Option<bool>,

    /// e.g., "AES_128_GCM_SHA256"
    pub tls_cipher: Option<String>,

    // RFC9000
    pub original_destination_connection_id: Option<ConnectionID>,
    pub initial_source_connection_id: Option<ConnectionID>,
    pub retry_source_connection_id: Option<ConnectionID>,
    pub stateless_reset_token: Option<StatelessResetToken>,
    pub disable_active_migration: Option<bool>,
    pub max_idle_timeout: Option<u64>,
    pub max_udp_payload_size: Option<u32>,
    pub ack_delay_exponent: Option<u16>,
    pub max_ack_delay: Option<u16>,
    pub active_connection_id_limit: Option<u32>,
    pub initial_max_data: Option<u64>,
    pub initial_max_stream_data_bidi_local: Option<u64>,
    pub initial_max_stream_data_bidi_remote: Option<u64>,
    pub initial_max_stream_data_uni: Option<u64>,
    pub initial_max_streams_bidi: Option<u64>,
    pub initial_max_streams_uni: Option<u64>,
    pub preferred_address: Option<PreferredAddress>,
    pub unknown_parameters: Option<Vec<UnknownParameter>>,

    // RFC9221
    pub max_datagram_frame_size: Option<u64>,

    // RFC9287
    /// can only be restored at the client.
    /// servers MUST NOT restore this parameter!
    pub grease_quic_bit: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PreferredAddress {
    pub ipv4: IPAddress,
    pub ipv6: IPAddress,
    pub port: u16,
    pub connection_id: ConnectionID,
    pub stateless_reset_token: StatelessResetToken,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde_with::skip_serializing_none]
pub struct UnknownParameter {
    pub id: u64,
    pub value: Option<HexString>,
}

/// When using QUIC 0-RTT, clients are expected to remember and restore
/// the server's transport parameters from the previous connection.  The
/// parameters_restored event is used to indicate which parameters were
/// restored and to which values when utilizing 0-RTT.  It has Base
/// importance level; see Section 9.2 of [QLOG-MAIN].
///
/// Note that not all transport parameters should be restored (many are
/// even prohibited from being re-utilized).  The ones listed here are
/// the ones expected to be useful for correct 0-RTT usage.
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde_with::skip_serializing_none]
pub struct ParametersRestored {
    // RFC 9000
    pub disable_active_migration: Option<bool>,
    pub max_idle_timeout: Option<u64>,
    pub max_udp_payload_size: Option<u32>,
    pub active_connection_id_limit: Option<u32>,
    pub initial_max_data: Option<u64>,
    pub initial_max_stream_data_bidi_local: Option<u64>,
    pub initial_max_stream_data_bidi_remote: Option<u64>,
    pub initial_max_stream_data_uni: Option<u64>,
    pub initial_max_streams_bidi: Option<u64>,
    pub initial_max_streams_uni: Option<u64>,

    // RFC9221
    pub max_datagram_frame_size: Option<u64>,

    // RFC9287
    /// can only be restored at the client.
    /// servers MUST NOT restore this parameter!
    pub grease_quic_bit: Option<bool>,
}

/// The packet_sent event indicates a QUIC-level packet was sent.  It has
/// Core importance level; see Section 9.2 of [QLOG-MAIN].
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PacketSent {
    pub header: PacketHeader,
    pub frames: Option<Vec<QuicFrame>>,

    /// only if header.packet_type === "stateless_reset"
    /// is always 128 bits in length.
    pub stateless_reset_token: Option<StatelessResetToken>,

    /// only if header.packet_type === "version_negotiation"
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub supported_versions: Vec<QuicVersion>,
    pub raw: Option<RawInfo>,
    pub datagram_id: Option<u32>,
    #[serde(default)]
    pub is_mtu_probe_packet: bool,

    pub trigger: Option<PacketSentTrigger>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PacketSentTrigger {
    RetransmitReordered,
    RetransmitTimeout,
    PtoProbe,
    RetransmitCrypto,
    CcBandwidthProbe,
}

/// The packet_received event indicates a QUIC-level packet was received.
/// It has Core importance level; see Section 9.2 of [QLOG-MAIN].
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PacketReceived {
    pub header: PacketHeader,
    pub frames: Option<Vec<QuicFrame>>,

    /// only if header.packet_type === "stateless_reset"
    /// is always 128 bits in length.
    pub stateless_reset_token: Option<StatelessResetToken>,

    /// only if header.packet_type === "version_negotiation"
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub supported_versions: Vec<QuicVersion>,
    pub raw: Option<RawInfo>,
    pub datagram_id: Option<u32>,

    pub trigger: Option<PacketReceivedTrigger>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PacketReceivedTrigger {
    /// if packet was buffered because it couldn't be
    /// decrypted before
    KeysAvailable,
}
/// The packet_dropped event indicates a QUIC-level packet was dropped.
/// It has Base importance level; see Section 9.2 of [QLOG-MAIN].
///
/// The trigger field indicates a general reason category for dropping
/// the packet, while the details field can contain additional
/// implementation-specific information.
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde_with::skip_serializing_none]
pub struct PacketDropped {
    /// Primarily packet_type should be filled here,
    /// as other fields might not be decrypteable or parseable
    pub header: Option<PacketHeader>,
    pub raw: Option<RawInfo>,
    pub datagram_id: Option<u32>,
    pub details: HashMap<String, String>,
    pub trigger: Option<PacketDroppedTrigger>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PacketDroppedTrigger {
    /// not initialized, out of memory
    InternalError,
    /// limits reached, DDoS protection, unwilling to track more paths, duplicate packet
    Rejected,
    /// unknown or unsupported version.
    Unsupported,
    /// packet parsing or validation error
    Invalid,
    /// duplicate packet
    Duplicate,
    /// packet does not relate to a known connection or Connection ID
    ConnectionUnknown,
    /// decryption failed
    DecryptionFailure,
    /// decryption key was unavailable
    KeyUnavailable,
    /// situations not clearly covered in the other categories
    Genera,
}

/// The packet_buffered event is emitted when a packet is buffered
/// because it cannot be processed yet.  Typically, this is because the
/// packet cannot be parsed yet, and thus only the full packet contents
/// can be logged when it was parsed in a packet_received event.  The
/// event has Base importance level; see Section 9.2 of [QLOG-MAIN].
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde_with::skip_serializing_none]
pub struct PacketBuffered {
    /// Primarily packet_type should be filled here,
    /// as other fields might not be decrypteable or parseable
    pub header: Option<PacketHeader>,
    pub raw: Option<RawInfo>,
    pub datagram_id: Option<u32>,
    pub trigger: Option<PacketBufferedTrigger>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PacketBufferedTrigger {
    /// indicates the parser cannot keep up, temporarily buffers
    /// packet for later processing
    Backpressure,
    /// if packet cannot be decrypted because the proper keys were
    /// not yet available
    KeysUnavailable,
}

/// The packets_acked event is emitted when a (group of) sent packet(s)
/// is acknowledged by the remote peer _for the first time_. It has Extra
/// importance level; see Section 9.2 of [QLOG-MAIN].
///
/// This information could also be deduced from the contents of received
/// ACK frames.  However, ACK frames require additional processing logic
/// to determine when a given packet is acknowledged for the first time,
/// as QUIC uses ACK ranges which can include repeated ACKs.
/// Additionally, this event can be used by implementations that do not
/// log frame contents.
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde_with::skip_serializing_none]
pub struct PacketsAcked {
    pub packet_number_space: Option<PacketNumberSpace>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub packet_nubers: Vec<u64>,
}
/// The datagrams_sent event indicates when one or more UDP-level
/// datagrams are passed to the underlying network socket.  This is
/// useful for determining how QUIC packet buffers are drained to the OS.
/// The event has Extra importance level; see Section 9.2 of [QLOG-MAIN].
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde_with::skip_serializing_none]
pub struct UdpDatagramSent {
    /// to support passing multiple at once
    pub count: Option<u16>,

    /// The RawInfo fields do not include the UDP headers,
    /// only the UDP payload
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub raw: Vec<RawInfo>,

    /// ECN bits in the IP header
    /// if not set, defaults to the value used on the last
    /// QUICDatagramsSent event
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ecn: Vec<ECN>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub datagram_ids: Vec<u32>,
}

/// When one or more UDP-level datagrams are received from the socket.
/// This is useful for determining how datagrams are passed to the user
/// space stack from the OS.  The event has Extra importance level; see
/// Section 9.2 of [QLOG-MAIN].
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde_with::skip_serializing_none]
pub struct UdpDatagramReceived {
    /// to support passing multiple at once
    pub count: Option<u16>,

    /// The RawInfo fields do not include the UDP headers,
    /// only the UDP payload
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub raw: Vec<RawInfo>,

    /// ECN bits in the IP header
    /// if not set, defaults to the value used on the last
    /// QUICDatagramsSent event
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ecn: Vec<ECN>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub datagram_ids: Vec<u32>,
}

/// When a UDP-level datagram is dropped.  This is typically done if it
/// does not contain a valid QUIC packet.  If it does, but the QUIC
/// packet is dropped for other reasons, the packet_dropped event
/// (Section 5.7) should be used instead.  The event has Extra importance
/// level; see Section 9.2 of [QLOG-MAIN].
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde_with::skip_serializing_none]
pub struct UdpDatagramDropped {
    /// The RawInfo fields do not include the UDP headers,
    /// only the UDP payload
    pub raw: Option<RawInfo>,
}
// The stream_state_updated event is emitted whenever the internal state
// of a QUIC stream is updated; see Section 3 of [QUIC-TRANSPORT].  Most
// of this can be inferred from several types of frames going over the
// wire, but it's much easier to have explicit signals for these state
// changes.  The event has Base importance level; see Section 9.2 of
// [QLOG-MAIN].
///
/// [QUIC-TRANSPORT]: https://www.rfc-editor.org/rfc/rfc9000
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde_with::skip_serializing_none]
pub struct StreamStateUpdated {
    pub stream_id: u64,

    /// mainly useful when opening the stream
    pub stream_type: Option<StreamType>,
    pub old: Option<StreamState>,
    pub new: StreamState,

    pub stream_side: Option<StreamSide>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum StreamState {
    Base(BaseStreamStates),
    Granular(GranularStreamStates),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BaseStreamStates {
    Idle,
    Open,
    Closed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GranularStreamStates {
    // bidirectional stream states, RFC 9000 Section 3.4.
    HalfClosedLocal,
    HalfClosedRemote,
    // sending-side stream states, RFC 9000 Section 3.1.
    Ready,
    Send,
    DataSent,
    ResetSent,
    ResetReceived,
    // receive-side stream states, RFC 9000 Section 3.2.
    Receive,
    SizeKnown,
    DataRead,
    ResetRead,
    // both-side states
    DataReceived,
    // qlog-defined: memory actually freed
    Destroyed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StreamSide {
    Sending,
    Receiving,
}

/// The frame_processed event is intended to prevent a large
/// proliferation of specific purpose events (e.g., packets_acknowledged,
/// flow_control_updated, stream_data_received).  It has Extra importance
/// level; see Section 9.2 of [QLOG-MAIN].
///
/// Implementations have the opportunity to (selectively) log this type
/// of signal without having to log packet-level details (e.g., in
/// packet_received).  Since for almost all cases, the effects of
/// applying a frame to the internal state of an implementation can be
/// inferred from that frame's contents, these events are aggregated into
/// this single frames_processed event.
///
/// The frame_processed event can be used to signal internal state change
/// not resulting directly from the actual "parsing" of a frame (e.g.,
/// the frame could have been parsed, data put into a buffer, then later
/// processed, then logged with this event).
///
/// The packet_received event can convey all constituent frames.  It is
/// not expected that the frames_processed event will also be used for a
/// redundant purpose.  Rather, implementations can use this event to
/// avoid having to log full packets or to convey extra information about
/// when frames are processed (for example, if frame processing is
/// deferred for any reason).
///
/// Note that for some events, this approach will lose some information
/// (e.g., for which encryption level are packets being acknowledged?).
/// If this information is important, the packet_received event can be
/// used instead.
///
/// In some implementations, it can be difficult to log frames directly,
/// even when using packet_sent and packet_received events.  For these
/// cases, the frames_processed event also contains the packet_numbers
/// field, which can be used to more explicitly link this event to the
/// packet_sent/received events.  The field is an array, which supports
/// using a single frames_processed event for multiple frames received
/// over multiple packets.  To map between frames and packets, the
/// position and order of entries in the frames and packet_numbers is
/// used.  If the optional packet_numbers field is used, each frame MUST
/// have a corresponding packet number at the same index.
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FramesProcessed {
    pub frames: Vec<QuicFrame>,
    pub packet_numbers: Option<Vec<u64>>,
}

/// The stream_data_moved event is used to indicate when QUIC stream data
/// moves between the different layers.  This helps make clear the flow
/// of data, how long data remains in various buffers, and the overheads
/// introduced by individual layers.  The event has Base importance
/// level; see Section 9.2 of [QLOG-MAIN].
///
/// This event relates to stream data only.  There are no packet or frame
/// headers and length values in the length or raw fields MUST reflect
/// that.
///
/// For example, it can be useful to understand when data moves from an
/// application protocol (e.g., HTTP) to QUIC stream buffers and vice
/// versa.
///
/// The stream_data_moved event can provide insight into whether received
/// data on a QUIC stream is moved to the application protocol
/// immediately (for example per received packet) or in larger batches
/// (for example, all QUIC packets are processed first and afterwards the
/// application layer reads from the streams with newly available data).
/// This can help identify bottlenecks, flow control issues, or
/// scheduling problems.
///
/// The additional_info field supports optional logging of information
/// related to the stream state.  For example, an application layer that
/// moves data into transport and simultaneously ends the stream, can log
/// fin_set.  As another example, a transport layer that has received an
/// instruction to reset a stream can indicate this to the application
/// layer using reset_stream.  In both cases, the length-carrying fields
/// (length or raw) can be omitted or contain zero values.
///
/// This event is only for data in QUIC streams.  For data in QUIC
/// Datagram Frames, see the datagram_data_moved event defined in
/// Section 5.16.
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde_with::skip_serializing_none]
pub struct StreamDataMoved {
    pub stream_id: Option<u64>,
    pub offset: Option<u64>,

    /// byte length of the moved data
    pub length: Option<u64>,

    pub from: Option<DataLocation>,
    pub to: Option<DataLocation>,

    pub additional_info: Option<DataMovedAdditionalInfo>,

    pub raw: Option<RawInfo>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DataLocation {
    Application,
    Transport,
    Network,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DataMovedAdditionalInfo {
    FinSet,
    StreamReset,
}

/// The datagram_data_moved event is used to indicate when QUIC Datagram
/// Frame data (see [RFC9221]) moves between the different layers.  This
/// helps make clear the flow of data, how long data remains in various
/// buffers, and the overheads introduced by individual layers.  The
/// event has Base importance level; see Section 9.2 of [QLOG-MAIN].
///
/// This event relates to datagram data only.  There are no packet or
/// frame headers and length values in the length or raw fields MUST
/// reflect that.
///
/// For example, passing from the application protocol (e.g.,
/// WebTransport) to QUIC Datagram Frame buffers and vice versa.
///
/// The datagram_data_moved event can provide insight into whether
/// received data in a QUIC Datagram Frame is moved to the application
/// protocol immediately (for example per received packet) or in larger
/// batches (for example, all QUIC packets are processed first and
/// afterwards the application layer reads all Datagrams at once).  This
/// can help identify bottlenecks, flow control issues, or scheduling
/// problems.
///
/// This event is only for data in QUIC Datagram Frames.  For data in
/// QUIC streams, see the stream_data_moved event defined in
/// Section 5.15.
///
/// [RFC9221]: https://www.rfc-editor.org/rfc/rfc9221.html
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde_with::skip_serializing_none]
pub struct DatagramDataMoved {
    /// byte length of the moved data
    pub length: Option<u64>,
    pub from: Option<DataLocation>,
    pub to: Option<DataLocation>,
    pub raw: Option<RawInfo>,
}

/// Use to provide additional information when attempting (client-side)
/// connection migration.  While most details of the QUIC connection
/// migration process can be inferred by observing the PATH_CHALLENGE and
/// PATH_RESPONSE frames, in combination with the QUICPathAssigned event,
/// it can be useful to explicitly log the progression of the migration
/// and potentially made decisions in a single location/event.  The event
/// has Extra importance level; see Section 9.2 of [QLOG-MAIN].
///
/// Generally speaking, connection migration goes through two phases: a
/// probing phase (which is not always needed/present), and a migration
/// phase (which can be abandoned upon error).
///
/// Implementations that log per-path information in a
/// QUICMigrationStateUpdated, SHOULD also emit QUICPathAssigned events,
/// to serve as a ground-truth source of information.
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde_with::skip_serializing_none]
pub struct MigrationStateUpdated {
    pub old: Option<MigrationState>,
    pub new: MigrationState,

    pub path_id: Option<PathID>,

    /// the information for traffic going towards the remote receiver
    pub path_remote: Option<PathEndpointInfo>,

    /// the information for traffic coming in at the local endpoint
    pub path_local: Option<PathEndpointInfo>,
}

/// Note that MigrationState does not describe a full state machine
/// These entries are not necessarily chronological,
/// nor will they always all appear during
/// a connection migration attempt.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MigrationState {
    /// probing packets are sent, migration not initiated yet
    ProbingStarted,
    /// did not get reply to probing packets,
    /// discarding path as an option
    ProbingAbandoned,
    /// received reply to probing packets, path is migration candidate
    ProbingSuccessful,
    /// non-probing packets are sent, attempting migration
    MigrationStarted,
    /// something went wrong during the migration, abandoning attempt
    MigrationAbandoned,
    /// new path is now fully used, old path is discarded
    MigrationComplete,
}
