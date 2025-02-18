use derive_builder::Builder;

use super::{
    ApplicationCode, ConnectionID, CryptoError, IPAddress, IpVersion, Owner, PathEndpointInfo,
    TransportError,
};
use crate::{Deserialize, PathID, Serialize};

/// Emitted when the server starts accepting connections. It has Extra
/// importance level; see Section 9.2 of [QLOG-MAIN].
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct ServerListening {
    #[builder(default)]
    ip_v4: Option<IPAddress>,
    #[builder(default)]
    ip_v6: Option<IPAddress>,
    #[builder(default)]
    port_v4: Option<u16>,
    #[builder(default)]
    port_v6: Option<u16>,

    /// the server will always answer client initials with a retry
    /// (no 1-RTT connection setups by choice)
    #[builder(default)]
    retry_required: Option<bool>,
}

/// The connection_started event is used for both attempting (client-
/// perspective) and accepting (server-perspective) new connections. Note
/// that while there is overlap with the connection_state_updated event,
/// this event is separate event in order to capture additional data that
/// can be useful to log. It has Base importance level; see Section 9.2
/// of [QLOG-MAIN].
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct ConnectionStarted {
    ip_version: IpVersion,
    src_ip: IPAddress,
    dst_ip: IPAddress,

    // transport layer protocol
    #[builder(default = "ConnectionStarted::default_protocol()")]
    #[serde(default = "ConnectionStarted::default_protocol")]
    protocol: String,
    #[builder(default)]
    src_port: Option<u16>,
    #[builder(default)]
    dst_port: Option<u16>,
    #[builder(default)]
    src_cid: Option<ConnectionID>,
    #[builder(default)]
    dst_cid: Option<ConnectionID>,
}

impl ConnectionStarted {
    pub fn default_protocol() -> String {
        String::from("QUIC")
    }
}

/// The connection_closed event is used for logging when a connection was
/// closed, typically when an error or timeout occurred.  It has Base
/// importance level; see Section 9.2 of [QLOG-MAIN].
///
/// Note that this event has overlap with the connection_state_updated
/// event, as well as the CONNECTION_CLOSE frame.  However, in practice,
/// when analyzing large deployments, it can be useful to have a single
/// event representing a connection_closed event, which also includes an
/// additional reason field to provide more information.  Furthermore, it
/// is useful to log closures due to timeouts, which are difficult to
/// reflect using the other options.
///
/// The connection_closed event is intended to be logged either when the
/// local endpoint silently discards the connection due to an idle
/// timeout, when a CONNECTION_CLOSE frame is sent (the connection enters
/// the 'closing' state on the sender side), when a CONNECTION_CLOSE
/// frame is received (the connection enters the 'draining' state on the
/// receiver side) or when a Stateless Reset packet is received (the
/// connection is discarded at the receiver side).  Connectivity-related
/// updates after this point (e.g., exiting a 'closing' or 'draining'
/// state), should be logged using the connection_state_updated event
/// instead.
///
/// In QUIC there are two main connection-closing error categories:
/// connection and application errors.  They have well-defined error
/// codes and semantics.  Next to these however, there can be internal
/// errors that occur that may or may not get mapped to the official
/// error codes in implementation-specific ways.  As such, multiple error
/// codes can be set on the same event to reflect this.
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(
    default,
    setter(into, strip_option),
    build_fn(private, name = "fallible_build")
)]
pub struct ConnectionClosed {
    /// which side closed the connection
    owner: Option<Owner>,
    connection_code: Option<ConnectionCode>,
    application_code: Option<ApplicationCode>,
    internal_code: Option<u32>,
    reason: Option<String>,
    trigger: Option<ConnectionCloseTrigger>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ConnectionCode {
    TransportError(TransportError),
    CryptoError(CryptoError),
    Value(u32),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionCloseTrigger {
    IdleTimeout,
    Application,
    Error,
    VersionMismatch,
    /// when received from peer
    StatelessReset,
    /// when it is unclear what triggered the CONNECTION_CLOSE
    Unspecified,
}

/// The connection_id_updated event is emitted when either party updates
/// their current Connection ID.  As this typically happens only
/// sparingly over the course of a connection, using this event is more
/// efficient than logging the observed CID with each and every
/// packet_sent or packet_received events.  It has Base importance level;
/// see Section 9.2 of [QLOG-MAIN].
///
/// The connection_id_updated event is viewed from the perspective of the
/// endpoint applying the new ID.  As such, when the endpoint receives a
/// new connection ID from the peer, the owner field will be "remote".
/// When the endpoint updates its own connection ID, the owner field will
/// be "local".
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct ConnectionIDUpdated {
    owner: Owner,
    #[builder(default)]
    old: Option<ConnectionID>,
    #[builder(default)]
    new: Option<ConnectionID>,
}

/// The spin_bit_updated event conveys information about the QUIC latency
/// spin bit; see Section 17.4 of [QUIC-TRANSPORT].  The event is emitted
/// when the spin bit changes value, it SHOULD NOT be emitted if the spin
/// bit is set without changing its value.  It has Base importance level;
/// see Section 9.2 of [QLOG-MAIN].
///
/// [QUIC-TRANSPORT]: https://www.rfc-editor.org/rfc/rfc9000
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(setter(into), build_fn(private, name = "fallible_build"))]
pub struct SpinBitUpdated {
    state: bool,
}

/// The connection_state_updated event is used to track progress through
/// QUIC's complex handshake and connection close procedures.  It has
/// Base importance level; see Section 9.2 of [QLOG-MAIN].
///
/// [QUIC-TRANSPORT] does not contain an exhaustive flow diagram with
/// possible connection states nor their transitions (though some are
/// explicitly mentioned, like the 'closing' and 'draining' states).  As
/// such, this document *non-exhaustively* defines those states that are
/// most likely to be useful for debugging QUIC connections.
///
/// QUIC implementations SHOULD mainly log the simplified
/// BaseConnectionStates, adding the more fine-grained
/// GranularConnectionStates when more in-depth debugging is required.
/// Tools SHOULD be able to deal with both types equally.
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
/// [QUIC-TRANSPORT]: https://www.rfc-editor.org/rfc/rfc9000
#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct ConnectionStateUpdated {
    #[builder(default)]
    old: Option<ConnectionState>,
    new: ConnectionState,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ConnectionState {
    Base(BaseConnectionStates),
    Granular(GranularConnectionStates),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BaseConnectionStates {
    /// Initial packet sent/received
    Attempted,
    /// Handshake packet sent/received
    HandshakeStarted,
    /// Both sent a TLS Finished message
    /// and verified the peer's TLS Finished message
    /// 1-RTT packets can be sent
    /// RFC 9001 Section 4.1.1
    HandshakeComplete,
    /// CONNECTION_CLOSE sent/received,
    /// stateless reset received or idle timeout
    Closed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GranularConnectionStates {
    /// RFC 9000 Section 8.1
    /// client sent Handshake packet OR
    /// client used connection ID chosen by the server OR
    /// client used valid address validation token
    PeerValidated,
    /// 1-RTT data can be sent by the server,
    /// but handshake is not done yet
    /// (server has sent TLS Finished; sometimes called 0.5 RTT data)
    EarlyWrite,

    /// HANDSHAKE_DONE sent/received.
    /// RFC 9001 Section 4.1.2
    HandshakeConfirmed,
    /// CONNECTION_CLOSE sent
    Closing,
    /// CONNECTION_CLOSE received
    Draining,
    /// draining or closing period done, connection state discarded
    Closed,
}

/// This event is used to associate a single PathID's value with other
/// parameters that describe a unique network path.
///
/// As described in [QLOG-MAIN], each qlog event can be linked to a
/// single network path by means of the top-level "path" field, whose
/// value is a PathID.  However, since it can be cumbersome to encode
/// additional path metadata (such as IP addresses or Connection IDs)
/// directly into the PathID, this event allows such an association to
/// happen separately.  As such, PathIDs can be short and unique, and can
/// even be updated to be associated with new metadata as the
/// connection's state evolves.
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct PathAssigned {
    path_id: PathID,
    /// the information for traffic going towards the remote receiver
    #[builder(default)]
    path_remote: Option<PathEndpointInfo>,
    /// the information for traffic coming in at the local endpoint
    #[builder(default)]
    path_local: Option<PathEndpointInfo>,
}

/// The mtu_updated event indicates that the estimated Path MTU was
/// updated.  This happens as part of the Path MTU discovery process.  It
/// has Extra importance level; see Section 9.2 of [QLOG-MAIN].
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct MtuUpdated {
    #[builder(default)]
    old: Option<u32>,
    new: u32,

    /// at some point, MTU discovery stops, as a "good enough"
    /// packet size has been found
    #[builder(default)]
    #[serde(default)]
    done: bool,
}

crate::gen_builder_method! {
    ServerListeningBuilder        => ServerListening;
    ConnectionStartedBuilder      => ConnectionStarted;
    ConnectionClosedBuilder       => ConnectionClosed;
    ConnectionIDUpdatedBuilder    => ConnectionIDUpdated;
    SpinBitUpdatedBuilder         => SpinBitUpdated;
    ConnectionStateUpdatedBuilder => ConnectionStateUpdated;
    PathAssignedBuilder           => PathAssigned;
    MtuUpdatedBuilder             => MtuUpdated;
}
