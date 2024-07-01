use std::{borrow::Cow, fmt::Display};

use thiserror::Error;

use crate::{frame::FrameType, varint::VarInt};

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
            ErrorKind::None => VarInt::from(0x00u8),
            ErrorKind::Internal => VarInt::from(0x01u8),
            ErrorKind::ConnectionRefused => VarInt::from(0x02u8),
            ErrorKind::FlowControl => VarInt::from(0x03u8),
            ErrorKind::StreamLimit => VarInt::from(0x04u8),
            ErrorKind::StreamState => VarInt::from(0x05u8),
            ErrorKind::FinalSize => VarInt::from(0x06u8),
            ErrorKind::FrameEncoding => VarInt::from(0x07u8),
            ErrorKind::TransportParameter => VarInt::from(0x08u8),
            ErrorKind::ConnectionIdLimit => VarInt::from(0x09u8),
            ErrorKind::ProtocolViolation => VarInt::from(0x0au8),
            ErrorKind::InvalidToken => VarInt::from(0x0bu8),
            ErrorKind::Application => VarInt::from(0x0cu8),
            ErrorKind::CryptoBufferExceeded => VarInt::from(0x0du8),
            ErrorKind::KeyUpdate => VarInt::from(0x0eu8),
            ErrorKind::AeadLimitReached => VarInt::from(0x0fu8),
            ErrorKind::NoViablePath => VarInt::from(0x10u8),
            ErrorKind::Crypto(x) => VarInt::from(0x0100u16 | x as u16),
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

impl From<Error> for crate::frame::ConnectionCloseFrame {
    fn from(e: Error) -> Self {
        Self {
            error_kind: e.kind,
            frame_type: Some(e.frame_type),
            reason: e.reason,
        }
    }
}

impl From<crate::frame::ConnectionCloseFrame> for Error {
    fn from(value: crate::frame::ConnectionCloseFrame) -> Self {
        Self {
            kind: value.error_kind,
            frame_type: value.frame_type.unwrap_or(FrameType::Padding),
            reason: value.reason,
        }
    }
}

#[cfg(test)]
mod tests {}
