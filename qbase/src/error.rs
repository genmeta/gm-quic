use crate::{frame::FrameType, varint::VarInt};
use std::borrow::Cow;
use thiserror::Error;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ErrorKind {
    // the connection is being closed abruptly in the absence of any error
    None,
    // the endpoint encountered an internal error and cannot continue with the connection
    Internal,
    // the server refused to accept a new connection
    ConnectionRefused,
    // received more data than permitted in advertised data limits
    FlowControl,
    // received a frame for a stream identifier that exceeded advertised the stream
    // limit for the corresponding stream type
    StreamLimit,
    // received a frame for a stream that was not in a state that permitted that frame
    StreamState,
    // received a STREAM frame or a RESET_STREAM frame containing a different final
    // size to the one already established
    FinalSize,
    // received a frame that was badly formatted
    FrameEncoding,
    // received transport parameters that were badly formatted, included an invalid
    // value, was absent even though it is mandatory, was present though it is forbidden,
    // or is otherwise in error
    TransportParameter,
    // the number of connection IDs provided by the peer exceeds the advertised
    // active_connection_id_limit
    ConnectionIdLimit,
    // detected an error with protocol compliance that was not covered by more specific
    // error codes
    ProtocolViolation,
    // received an invalid Retry Token in a client Initial
    InvalidToken,
    // the application or application protocol caused the connection to be closed during
    // the handshake
    Application,
    // received more data in CRYPTO frames than can be buffered
    CryptoBufferExceeded,
    // key update error
    KeyUpdate,
    // the endpoint has reached the confidentiality or integrity limit for the AEAD algorithm
    AeadLimitReached,
    // no viable network path exists
    NoViablePath,
    // the cryptographic handshake failed
    Crypto(u8),
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
#[error("QUIC transport error occured in {frame_type:?}, kind: {kind:?}, reason: {reason}")]
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
}

impl From<Error> for crate::frame::ConnectionCloseFrame {
    fn from(e: Error) -> Self {
        Self {
            error_code: e.kind.into(),
            frame_type: Some(e.frame_type.into()),
            reason: e.reason.into_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
