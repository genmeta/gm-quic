use crate::{frame::FrameType, varint::VarInt};
use std::{borrow::Cow, fmt::Display};
use thiserror::Error;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ErrorKind {
    None,
    Internal,
    ConnectionRefused,
    FlowControl,
    StreamLimit,
    StreamState,
    FinalSize,
    FrameEncoding,
    TransportParameter,
    ConnectionIdLimit,
    ProtocolViolation,
    InvalidToken,
    Application,
    CryptoBufferExceeded,
    KeyUpdate,
    AeadLimitReached,
    NoViablePath,
    Crypto(u8),
}

impl Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            ErrorKind::None => "the connection is being closed abruptly in the absence of any error",
            ErrorKind::Internal => "the endpoint encountered an internal error and cannot continue with the connection",
            ErrorKind::ConnectionRefused => "the server refused to accept a new connection",
            ErrorKind::FlowControl => "received more data than permitted in advertised data limits",
            ErrorKind::StreamLimit => "received a frame for a stream identifier that exceeded advertised the stream limit for the corresponding stream type",
            ErrorKind::StreamState => "received a frame for a stream that was not in a state that permitted that frame",
            ErrorKind::FinalSize => "received a STREAM frame or a RESET_STREAM frame containing a different final size to the one already established",
            ErrorKind::FrameEncoding => "received a frame that was badly formatted",
            ErrorKind::TransportParameter => "received transport parameters that were badly formatted, included an invalid value, was absent even though it is mandatory, was present though it is forbidden, or is otherwise in error",
            ErrorKind::ConnectionIdLimit => "the number of connection IDs provided by the peer exceeds the advertised active_connection_id_limit",
            ErrorKind::ProtocolViolation => "detected an error with protocol compliance that was not covered by more specific error codes",
            ErrorKind::InvalidToken => "received an invalid Retry Token in a client Initial",
            ErrorKind::Application => "the application or application protocol caused the connection to be closed during the handshake",
            ErrorKind::CryptoBufferExceeded => "received more data in CRYPTO frames than can be buffered",
            ErrorKind::KeyUpdate => "key update error",
            ErrorKind::AeadLimitReached => "the endpoint has reached the confidentiality or integrity limit for the AEAD algorithm",
            ErrorKind::NoViablePath => "no viable network path exists",
            ErrorKind::Crypto(x) => return write!(f, "crypto error: {}", x),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Error)]
#[error("invalid error code {0}")]
pub struct InvalidErrorKind(u64);

impl TryFrom<VarInt> for ErrorKind {
    type Error = InvalidErrorKind;

    fn try_from(value: VarInt) -> Result<Self, Self::Error> {
        Ok(match value.into_inner() {
            0x00 => ErrorKind::None,
            0x01 => ErrorKind::Internal,
            0x02 => ErrorKind::ConnectionRefused,
            0x03 => ErrorKind::FlowControl,
            0x04 => ErrorKind::StreamLimit,
            0x05 => ErrorKind::StreamState,
            0x06 => ErrorKind::FinalSize,
            0x07 => ErrorKind::FrameEncoding,
            0x08 => ErrorKind::TransportParameter,
            0x09 => ErrorKind::ConnectionIdLimit,
            0x0a => ErrorKind::ProtocolViolation,
            0x0b => ErrorKind::InvalidToken,
            0x0c => ErrorKind::Application,
            0x0d => ErrorKind::CryptoBufferExceeded,
            0x0e => ErrorKind::KeyUpdate,
            0x0f => ErrorKind::AeadLimitReached,
            0x10 => ErrorKind::NoViablePath,
            0x0100..=0x01ff => ErrorKind::Crypto((value.into_inner() & 0xff) as u8),
            other => return Err(InvalidErrorKind(other)),
        })
    }
}

impl From<ErrorKind> for VarInt {
    fn from(value: ErrorKind) -> Self {
        match value {
            ErrorKind::None => VarInt(0x00),
            ErrorKind::Internal => VarInt(0x01),
            ErrorKind::ConnectionRefused => VarInt(0x02),
            ErrorKind::FlowControl => VarInt(0x03),
            ErrorKind::StreamLimit => VarInt(0x04),
            ErrorKind::StreamState => VarInt(0x05),
            ErrorKind::FinalSize => VarInt(0x06),
            ErrorKind::FrameEncoding => VarInt(0x07),
            ErrorKind::TransportParameter => VarInt(0x08),
            ErrorKind::ConnectionIdLimit => VarInt(0x09),
            ErrorKind::ProtocolViolation => VarInt(0x0a),
            ErrorKind::InvalidToken => VarInt(0x0b),
            ErrorKind::Application => VarInt(0x0c),
            ErrorKind::CryptoBufferExceeded => VarInt(0x0d),
            ErrorKind::KeyUpdate => VarInt(0x0e),
            ErrorKind::AeadLimitReached => VarInt(0x0f),
            ErrorKind::NoViablePath => VarInt(0x10),
            ErrorKind::Crypto(x) => VarInt(0x0100 + x as u64),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{kind} in {frame_type:?}, reason: {reason}")]
pub struct Error {
    pub kind: ErrorKind,
    pub frame_type: FrameType,
    pub reason: Cow<'static, str>,
}

impl Error {
    pub fn new<T: Into<Cow<'static, str>>>(
        kind: ErrorKind,
        frame_type: FrameType,
        reason: T,
    ) -> Self {
        Self {
            kind,
            frame_type,
            reason: reason.into(),
        }
    }

    pub fn new_with_default_fty<T: Into<Cow<'static, str>>>(kind: ErrorKind, reason: T) -> Self {
        Self {
            kind,
            frame_type: FrameType::Padding,
            reason: reason.into(),
        }
    }
}

impl From<std::convert::Infallible> for Error {
    fn from(_: std::convert::Infallible) -> Self {
        unreachable!("never happen.")
    }
}

impl From<Error> for crate::frame::ConnectionCloseFrame {
    fn from(e: Error) -> Self {
        Self {
            error_kind: e.kind,
            frame_type: Some(e.frame_type),
            reason: e.reason,
        }
    }
}

#[cfg(test)]
mod tests {}
